# ⚡ Raijin XSS

**dalfox for AI agents: confirmed reflections with the payload and the context it landed in, one entry per parameter and context, verified first.**

`raijin-xss` is a tool of **Raijin**, an arsenal of offensive security tools built for AI agents. It runs [dalfox](https://github.com/hahwul/dalfox) underneath and returns the **Raijin Schema**: one compact JSON where every PoC dalfox reported is a ranked finding, the same parameter and injection context on many URLs is one entry that lists every URL with its payload, the dozens of payloads dalfox reflects at one place are one location and a count, and anything it had to cut is counted.

## Why not just run dalfox?

dalfox is built for people and pipelines. An agent pays for every byte it reads. Its JSON output is one object per PoC, and dalfox writes a PoC for every payload that came back: a textarea that reflects everything as text gives 105 objects for one parameter, each with the payload, the PoC URL, the evidence line, the CWE and dalfox's log message. Its text output is one line per PoC on stdout, plus a progress log on stderr that is bigger than the PoC lines.

Here is the same scan read by an agent (tokens, `o200k_base`):

```
Noisy scan: 11 pages, 121 PoCs (10 verified, 111 reflected) at 18 locations
  raijin-xss             █▏                      1,691 tokens
  dalfox text, same PoCs ██████▍                 9,439 tokens
  dalfox text + log      ███████████████▏       22,514 tokens
  dalfox --format json   ████████████████████   29,813 tokens

Findings scan: 6 pages, 83 PoCs (3 verified, 79 reflected, 1 grep) at 6 locations
  raijin-xss             ▋                         934 tokens
  dalfox text, same PoCs ████                    6,493 tokens
  dalfox --format json   ██████████▊            17,508 tokens
  dalfox text + log      ████████████████████   32,585 tokens
```

raijin-xss reads **17.6×** fewer tokens than `dalfox --format json` on the noisy scan and **18.7×** fewer on the findings scan. Against dalfox's text lines for the same PoCs it is **5.6×** and **7.0×** smaller. Each scan's bars are drawn to scale against its largest row. `dalfox text + log` is a separate scan with the same options (stdout and stderr): dalfox reports a different number of payloads from scan to scan, and in the findings scan the text run reported 191 PoCs against the JSON run's 83, so its bar is not the same PoCs (see [BENCHMARK.md](BENCHMARK.md)).

- **Nothing is lost.** Every PoC dalfox reported is in the output with its type, parameter, injection context, method and CWE, at its URL with a payload that worked there. `bench/verify.py` checked all 204 PoCs of both scans and none were missing.
- **One entry per parameter and context.** The 16 PoCs for `q` on 10 item pages are 4 findings (verified and reflected, in two contexts), each listing its PoC URLs. URLs that differ only in a number, with the same payload, are one location: `/item/[1-3]?q=...`.
- **One payload per location.** dalfox's 71 reflected payloads in one textarea are one PoC URL and `"payloads":71`. The other 70 stay in dalfox's JSON, saved to disk.
- **Verified first.** dalfox's V (the payload is in the DOM, or a dialog fired in headless Chrome) is high, R (reflected, did not run) is medium, G (a grep match: a SQL error, an SSTI result) is low.
- **Output is bounded.** On a huge scan, `--max-bytes` cuts the least important data first and counts every cut. dalfox's output grows with every payload.

## Install

```bash
go install github.com/protonnegativo/raijin-xss/cmd/raijin-xss@latest
```

You also need `dalfox` on `PATH`, or pass `--dalfox <path>`. Chrome is optional: dalfox uses it to verify payloads in JS and DOM XSS (`--headless=false` skips it).

## Usage

```bash
raijin-xss --scope scope.txt                                   # test every host the scope names
raijin-xss --scope scope.txt -u 'https://app.example.com/search?q=test'
raijin-xss --scope scope.txt -l urls-with-params.txt
cat urls.txt | raijin-xss --scope scope.txt -l -                 # targets from a pipe
raijin-xss --scope scope.txt --input dalfox.json                 # reduce output you already have
raijin-xss --scope scope.txt --input dalfox.json -l urls.txt     # ... and list the clean targets
raijin-xss --scope scope.txt -l urls.txt --state run.json        # mark findings that are new since last run
raijin-xss ... -- -H 'Cookie: session=...' --waf-evasion         # anything after -- goes to dalfox
```

`--scope` is required. One rule per line:

```
example.com
*.example.com
10.0.0.0/24
!admin.example.com
```

With no `-u`, `-l` or `--input`, raijin-xss tests what the scope names: every domain, every IP, and every address of ranges up to a /24, minus exclusions. dalfox needs URLs, so each host is tested as `https://<host>/` and parameter mining finds what it can from there; `next` then suggests `raijin-crawl` or `raijin-params` to find URLs with parameters. A wildcard names no host and a larger range is too big to sweep blindly, so for each one `next` gives the command that enumerates it first (`raijin-subs` or `raijin-ports`).

Targets outside the scope are dropped before dalfox runs, and PoCs outside the scope are dropped from the output. Both are counted in `omitted.out_of_scope`.

raijin-xss runs dalfox in file mode with 10 workers (dalfox's default is 100; `--workers` changes it), and never adds a blind XSS callback (`-b`), remote payloads, remote wordlists or a found action: nothing leaves the target. `--headless=false`, `--mining=false` and `--bav=false` turn off headless Chrome, parameter mining and the SQLi/SSTI/redirect/CRLF payloads behind grep matches.

## Output

```json
{
  "tool": "raijin-xss",
  "version": "0.1.0",
  "target": "bench/fixtures/findings/raw.json",
  "summary": "83 PoCs (3 verified, 79 reflected, 1 grep) at 6 locations: 6 findings (3 high, 2 medium, 1 low), 2 of 6 targets clean",
  "origin": "http://127.0.0.1:19301",
  "findings": [
    {
      "id": "v-name-2d66d779",
      "severity": "high",
      "confidence": "verified",
      "param": "name",
      "context": "inATTR-double(1)-URL",
      "cwe": "CWE-83",
      "payload": "\"&#x27;><iFrAme/src=jaVascRipt:alert.bind()(1) class=dalfox></iFramE>",
      "evidence": "2 line:  name=\"name\" value=\"a\"&#x27;><iFrAme/src=jaVascRipt:alert.bind()(1) class=dalfox>",
      "locations": ["/profile?name=a%22%26%23x27%3B%3E%3CiFrAme%2Fsrc%3DjaVascRipt%3Aalert.bind%28%29%281%29+class%3Ddalfox%3E%3C%2FiFramE%3E"]
    },
    {
      "id": "v-q-cc55ed8d",
      "severity": "high",
      "confidence": "verified",
      "param": "q",
      "context": "inHTML-URL",
      "cwe": "CWE-79",
      "payload": "'><svg/class='dalfox'onLoad=alert(1)>",
      "evidence": "2 line:  <p>You searched for a'><svg/class='dalfox'onLoad=alert(1)></p>",
      "locations": ["/search?q=a%27%3E%3Csvg%2Fclass%3D%27dalfox%27onLoad%3Dalert%281%29%3E"]
    },
    {
      "id": "r-cb-5a1c33c1",
      "severity": "medium",
      "confidence": "heuristic",
      "param": "cb",
      "context": "inJS-single(1)-URL",
      "cwe": "CWE-79",
      "payload": "\\'+</sCrIpt><SVg/onload=prompt(1)>//",
      "evidence": "2 line:  pt>var callback = 'a\\'+</sCrIpt><SVg/onload=prompt(1)>//'; console.log(callback)",
      "locations": ["/widget?cb=a%5C%27%2B%3C%2FsCrIpt%3E%3CSVg%2Fonload%3Dprompt%281%29%3E%2F%2F"],
      "payloads": 71
    },
    {
      "id": "g-dalfox-error-mysql1-b0d1f4a9",
      "severity": "low",
      "grep": "dalfox-error-mysql1",
      "locations": ["/report?id=%22%22"]
    }
  ],
  "groups": [
    {"id": "clean", "locations": ["/api/echo?msg=a", "/safe?q=a"]}
  ]
}
```

That is the real findings scan from the benchmark, pretty-printed here. Three things are shortened: 2 of the 6 findings are left out, `locations` arrays are written on one line, and the target is the replayed fixture. The tool writes it as one line, and a live run also has `raw`. The noisy scan's biggest entry, 71 payloads in one textarea, is one line:

```json
{"id":"r-msg-614a9bd8","severity":"medium","confidence":"heuristic","param":"msg","context":"inHTML-none(1)-URL","cwe":"CWE-79","payload":"<xmp><p title=\"</xmp><svg/onload=print(1) class=dalfox>","evidence":"2 line:  extarea name=\"msg\">a<xmp><p title=\"</xmp><svg/onload=print(1) class=dalfox></tex","locations":["/note?msg=a%3Cxmp%3E%3Cp+title%3D%22%3C%2Fxmp%3E%3Csvg%2Fonload%3Dprint%281%29+class%3Ddalfox%3E"],"payloads":71}
```

**Nothing dalfox found is dropped silently.** Every PoC is a location of a finding, or counted in its `payloads`. Only exact repeats collapse, and they are counted in `omitted.duplicates`.

What the reducer does:

- **One finding per type, parameter, context, method, CWE and grep pattern.** The context is dalfox's `inject_type`: where the payload landed (`inHTML-none(1)-URL` in the page body, `inATTR-double(1)-URL` in a double-quoted attribute, `inJS-single(1)-URL` in a single-quoted JS string...). The same parameter in another context, or found as R as well as V, is another finding: it is another way in.
- **Severity is dalfox's type.**

  | Type | Severity | Confidence | Meaning |
  |---|---|---|---|
  | V | high | `verified` | dalfox found the injected element in the DOM, or a dialog fired in headless Chrome |
  | R | medium | `heuristic` | the payload came back unencoded but dalfox could not make it run: a browser check is the next step |
  | G | low | (matched) | the response matched a grep pattern, such as a SQL error or an SSTI result; `grep` names it |

- **`locations`** are the PoC URLs, one per location, without the `origin`, sorted. A location is a URL without the value of the injected parameter, so a PoC URL is ready to open and carries the payload that worked there: the first one dalfox reported at that location. URLs that differ in one number are one location with the numbers as a range (`/item/[1-3]?q=...`), when their payloads are the same. A URL's own `[` and `]` are written `%5B` and `%5D`, so a bracket in a location is always a range. A grep match has no parameter: its location is the URL without its query.
- **`payloads`** is the number of PoCs dalfox reported for the finding. It is written only when dalfox reported more than one at a location; the others are in `raw`.
- **`payload` and `evidence`** are those of the first location: the payload as dalfox injected it (not URL-encoded), and the response line it landed in, as dalfox cut it. dalfox writes no payload for a PoC it verified in headless Chrome, and its grep matches have the placeholder `toGrepping`: both are left out, and the PoC URL has the payload.
- **`origin`** is the scheme and host every URL shares. Locations are written without it. When the scan covered several origins, `origin` is left out and locations are full URLs.
- **Groups:** `clean` lists the targets dalfox tested and reported nothing for (no PoC on the same scheme, host and path). It is only known when the targets are: in a live run, or with `--input` and `-u` or `-l`.
- **Ranking:** findings by severity, then confidence, then the number of locations, then parameter and `id`. The same input always gives the same order.
- **`id`** is the type in lowercase, the parameter (or grep pattern) and a short hash of the type, method, parameter, context, CWE and grep pattern, so the same finding has the same `id` in the next run. URLs are not part of it: a new page with the same bug is a new location of the same finding, which `--state` marks as new.
- **`raw`** is dalfox's full JSON, saved to disk. It holds every payload, every evidence line, dalfox's messages and severities. Reading it costs no tokens until the agent opens it, and it replays with `--input`.
- **Budget:** `--max-bytes` (16,000 by default) keeps the output bounded on huge scans. It cuts in this order until the JSON fits:
  1. the `clean` group's locations (it keeps its `count`);
  2. the group;
  3. the locations of the lowest-ranked findings, each keeping one location plus its `count`;
  4. the lowest-ranked findings.

  Every cut is counted in `omitted`, `budget.truncated` is set, and `next` points to the raw file. `--max-items` caps the number of findings (0, the default, keeps all).
- **Errors** say what to try next. If dalfox is missing, the exit code is 2.

Fields an agent can rebuild are left out to save tokens:

- `method` is left out when it is GET, `context` for a grep match (`BUILTIN`), and `param`, `grep`, `cwe`, `payload` and `evidence` when they are empty.
- `confidence` is left out for G (`matched`).
- `payloads` appears only when it is more than the number of locations, and `count` only when the budget cut `locations`.
- `origin`, `omitted`, `errors`, `next` and `groups` entries appear only when they are not empty.
- `budget` appears only when something was cut.

The JSON is compact (one line) by default because indentation costs 13% to 23% more tokens in the benchmark; `--pretty` indents it. `--format table` prints a short human view of the same result: every finding with its PoC URLs, without the payload and evidence.

The Raijin banner is **off by default**, so normal runs stay small. `--banner` prints it to **stderr** (never stdout, so the JSON is untouched), with the version taken from the binary. Colors are disabled when `NO_COLOR` is set or stderr is not a terminal.

## Flags

| Flag | Default | |
|---|---|---|
| `--scope` | (required) | scope file |
| `-u` / `-l` / `--input` | every host the scope names, as `https://<host>/` | one target URL (repeatable) / target file, `-` for stdin / existing dalfox JSON |
| `-p` | | only test this parameter (repeatable, dalfox `-p`) |
| `--workers` | 10 | concurrent workers (dalfox `-w`) |
| `--delay`, `--timeout` | | dalfox `--delay` (ms between requests to a host) / `--timeout` (s) |
| `--headless` | true | headless Chrome checks (false: dalfox `--skip-headless`) |
| `--mining` | true | parameter mining (false: dalfox `--skip-mining-all`) |
| `--bav` | true | SQLi, SSTI, redirect and CRLF payloads (false: dalfox `--skip-bav`) |
| `--max-items` | 0 | max findings (0 keeps all) |
| `--max-bytes` | 16000 | max JSON size; cuts are counted in `omitted` |
| `--raw` | temp file | where to save dalfox's full JSON |
| `--state` | | state file for new-since-last-run |
| `--format` | json | `json` or `table` |
| `--pretty` | false | indent the JSON |
| `--dalfox` | dalfox | path to the binary |
| `--banner` | false | print the banner to stderr |

## Development

```bash
go test ./...
go vet ./...
bench/run.sh            # replay bench/fixtures and count tokens
LIVE=1 bench/run.sh     # start the local lab, scan it again, refresh the fixtures
```

Standard library only. dalfox runs as a subprocess with `file <targets> --format json -o <raw> -S --no-spinner --no-color`, so the binary stays small and dalfox can be updated on its own. raijin-xss empties the raw file first, because dalfox appends to `-o`, and its stdin is `/dev/null`.

## Responsible use

Only scan what you are authorized to test. dalfox sends hundreds of payloads per parameter.
