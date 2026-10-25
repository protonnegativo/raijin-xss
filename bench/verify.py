"""Checks that every dalfox PoC is in a raijin-xss result.

A PoC is one object of dalfox's JSON output. Its identity is its URL (the PoC URL in "data"), its
parameter and its type (V, R or G), with the injection context ("inject_type"), the method, the CWE and,
for a grep match, the pattern named in "message_str". raijin-xss writes the type as the severity and
confidence: V is high/verified, R is medium/heuristic, G is low with no confidence.

A PoC is present when a finding has the same type, parameter, context ("BUILTIN" when the finding has
none), method (GET when it has none), CWE and grep pattern, and either:
  - lists the PoC URL itself in "locations" (after expanding "[1-5,7]" ranges and prepending "origin"), or
  - lists another PoC URL of the same location (the same URL with another value in the injected
    parameter; for a grep match, the same URL without its query) and counts the PoC in "payloads".
Then, for every finding, the PoCs that matched it must add up to "payloads" (or to the number of its
locations when "payloads" is left out), so a payload that is not listed is still counted. Exact repeats
of a PoC (the same fields, dalfox's message_id aside) count once. raijin-xss writes a URL's own "[" and "]" as %5B and %5D, so the check does too.

usage: python verify.py <dalfox.json> <raijin.json>
"""
import json, re, sys
from urllib.parse import unquote_plus

raw, out = sys.argv[1], sys.argv[2]
o = json.load(open(out))
origin = o.get("origin", "")
# the fields raijin-xss reads; message_id is a counter, so two PoCs that differ only there are repeats
FIELDS = ("type", "inject_type", "poc_type", "method", "data", "param", "payload", "evidence", "cwe", "severity", "message_str")
TYPE = {("high", "verified"): "V", ("medium", "heuristic"): "R", ("low", ""): "G"}


def load(path):
    text = open(path).read().strip()
    try:
        items = json.loads(text)
    except ValueError:  # a scan that was cut off: one object per line
        items = []
        for line in text.splitlines():
            line = line.strip().rstrip(",")
            if line.startswith("{"):
                try:
                    items.append(json.loads(line))
                except ValueError:
                    pass
    return [x for x in items if x.get("type")]


def grep(p):
    m = re.match(r"Found (.*?) via ", p.get("message_str", ""))
    return m.group(1) if p.get("type") == "G" and m else ""


def strip_query(u):
    return re.split(r"[?#]", u, maxsplit=1)[0]


def location_key(data, param):
    if not param:
        return strip_query(data)
    if "?" not in data:
        return data
    base, q = data.split("?", 1)
    q, _, frag = q.partition("#")
    parts, found = q.split("&"), False
    for i, kv in enumerate(parts):
        name = kv.split("=", 1)[0]
        if unquote_plus(name) == param:
            parts[i], found = name + "=", True
    if not found:
        return data
    return base + "?" + "&".join(parts) + ("#" + frag if frag else "")


def expand(loc):
    m = re.search(r"\[([0-9,\-]+)\]", loc)
    if not m:
        return [loc]
    out = []
    for part in m.group(1).split(","):
        a, _, b = part.partition("-")
        for n in range(int(a), int(b or a) + 1):
            out.append(loc[: m.start()] + str(n) + loc[m.end():])
    return out


def esc(u):
    return u.replace("[", "%5B").replace("]", "%5D")


entries = {}
for f in o["findings"]:
    typ = TYPE.get((f["severity"], f.get("confidence", "")), "?")
    key = (typ, f.get("method", "GET"), f.get("param", ""), f.get("context", "BUILTIN"), f.get("cwe", ""), f.get("grep", ""))
    urls = [origin + u for loc in f["locations"] for u in expand(loc)]
    e = entries.setdefault(key, [])
    e.append({"f": f, "urls": set(urls), "keys": {location_key(u, key[2]) for u in urls}, "matched": 0,
              "want": f.get("payloads") or len(urls), "payloads": set()})

miss, n, seen = [], 0, set()
for p in load(raw):
    ident = tuple(p.get(k, "") for k in FIELDS)
    if ident in seen:
        continue
    seen.add(ident)
    n += 1
    data = esc(p.get("data", ""))
    key = (p["type"], (p.get("method") or "GET").upper(), p.get("param", ""), p.get("inject_type", ""), p.get("cwe", ""), grep(p))
    lk = location_key(data, key[2])
    hit = None
    for e in entries.get(key, []):
        if data in e["urls"]:
            hit = e
            break
    if hit is None:
        for e in entries.get(key, []):
            if lk in e["keys"] and e["f"].get("payloads"):
                hit = e
                break
    if hit is None:
        miss.append((p["type"], p.get("param", ""), p.get("inject_type", ""), p.get("data", "")[:120]))
        continue
    hit["matched"] += 1
    hit["payloads"].add(p.get("payload", ""))

bad = []
for es in entries.values():
    for e in es:
        f = e["f"]
        if e["matched"] != e["want"]:
            bad.append((f["id"], "matched", e["matched"], "PoCs, says", e["want"]))
        if f.get("payload") and f["payload"] not in e["payloads"]:
            bad.append((f["id"], "payload is not one of its PoCs"))

truncated = "truncated" if o.get("budget") else ""
print(f"{n} dalfox PoCs, {len(miss)} missing from output, {len(bad)} findings with wrong counts", truncated)
for m in miss[:5]:
    print("  MISSING", m)
for b in bad[:5]:
    print("  COUNT", b)
sys.exit(1 if miss or bad else 0)
