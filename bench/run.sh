#!/usr/bin/env bash
# Reproducible token benchmark: dalfox output vs raijin-xss output on the same scan.
#
# usage: bench/run.sh [workdir]
#        LIVE=1 bench/run.sh [workdir]   start the local lab, scan it again and refresh bench/fixtures first
# needs: go, python3 with tiktoken (pip install tiktoken); LIVE=1 also needs dalfox
# optional: ANTHROPIC_API_KEY + pip install anthropic for exact Claude token counts
# env: PY=<python with tiktoken>, DALFOX=<path>
#
# Safety: LIVE=1 scans only the lab it starts itself (bench/lab.py) on 127.0.0.1, ports 19300 and
# 19301, with 10 workers, no blind callback, no remote payloads and no remote wordlists. It stops the
# lab when it exits. The four scans run at the same time; a live run takes about two minutes.
set -euo pipefail

W=${1:-$(mktemp -d)}
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
PY=${PY:-python3}
DALFOX=${DALFOX:-dalfox}
mkdir -p "$W"
echo "workdir: $W"

# Lab: one python process with two sites (see lab.py).
# noisy:    10 catalog pages that reflect "q" in the body the same way, and a textarea that reflects
#           every payload as text, so dalfox reports each one it tried.
# findings: one page per context (HTML body, attribute, JS string), an escaped parameter, a JSON echo
#           API and a parameter that answers a quote with a MySQL error.
declare -A port=([noisy]=19300 [findings]=19301)
# Both scans skip headless Chrome to stay short (with it, the JS string page alone takes minutes); the
# noisy scan also skips parameter mining.
declare -A rflags=([noisy]="--headless=false --mining=false" [findings]="--headless=false")
declare -A dflags=([noisy]="--skip-headless --skip-mining-all" [findings]="--skip-headless")
printf '127.0.0.1\n' > "$W/scope.txt"

(cd "$ROOT" && go build -o "$W/raijin-xss" ./cmd/raijin-xss)

targets() {
  case $1 in
    noisy)
      for i in $(seq 1 10); do echo "http://127.0.0.1:${port[noisy]}/item/$i?q=shoes&sort=price"; done
      echo "http://127.0.0.1:${port[noisy]}/note?msg=a" ;;
    findings)
      for p in "search?q=a" "profile?name=a" "widget?cb=a" "safe?q=a" "report?id=1" "api/echo?msg=a"; do
        echo "http://127.0.0.1:${port[findings]}/$p"
      done ;;
  esac
}

if [ "${LIVE:-}" = 1 ]; then
  for p in "${port[@]}"; do
    if ss -ltn | grep -q ":$p "; then echo "port $p is busy; free it first" >&2; exit 1; fi
  done
  python3 "$HERE/lab.py" "${port[noisy]}=shop" "${port[findings]}=app" > "$W/lab.log" 2>&1 &
  echo $! > "$W/pids"
  trap '[ -f "$W/pids" ] && xargs kill < "$W/pids" 2>/dev/null || true' EXIT
  sleep 1
  scans=()
  for name in noisy findings; do
    f=$HERE/fixtures/$name
    mkdir -p "$f"
    targets "$name" > "$f/targets.txt"
    # raijin-xss runs dalfox (file mode, --format json -o <raw> -S, 10 workers) and keeps its JSON as
    # raw: that file is the fixture.
    # shellcheck disable=SC2086
    "$W/raijin-xss" --dalfox "$DALFOX" --scope "$W/scope.txt" -l "$f/targets.txt" ${rflags[$name]} \
      --raw "$f/raw.json" > "$W/$name.live.json" &
    scans+=($!)
    # dalfox as an agent would run it, with the same options: the default text output (PoC lines on
    # stdout, banner and progress log on stderr).
    # shellcheck disable=SC2086
    "$DALFOX" file "$f/targets.txt" -w 10 --no-spinner --no-color ${dflags[$name]} < /dev/null \
      > "$f/text.txt" 2> "$f/text_stderr.txt" &
    scans+=($!)
  done
  wait "${scans[@]}"
fi

scenario() {
  local name=$1
  local f=$HERE/fixtures/$name o=$W/$name
  mkdir -p "$o"
  # raijin-xss replays raw with --input (and the target list for the clean group), so every row sees
  # the same scan.
  run() { (cd "$ROOT" && "$W/raijin-xss" --scope "$W/scope.txt" --input "bench/fixtures/$name/raw.json" -l "bench/fixtures/$name/targets.txt" "$@"); }
  # dalfox's text stdout for the same PoCs as raw: one "[POC][type][method][context] url" line each,
  # the format of text.txt. The text run is a separate scan and dalfox reports a different number of
  # payloads from scan to scan, so this row compares the same PoCs.
  python3 -c 'import json,sys
for l in open(sys.argv[1]):
    l = l.strip().rstrip(",]")
    if l.startswith("{") and l != "{}":
        p = json.loads(l)
        print("[POC][%s][%s][%s] %s" % (p["type"], p["method"], p["inject_type"], p["data"]))' "$f/raw.json" > "$o/text_same.txt"
  run > "$o/raijin.json"
  run --pretty > "$o/raijin_pretty.json"
  run --format table > "$o/raijin_table.txt"
  echo; echo "## $name: $(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["summary"])' "$o/raijin.json")"; echo
  python3 "$HERE/verify.py" "$f/raw.json" "$o/raijin.json"
  echo "separate dalfox text run: $(grep -c '^\[POC\]' "$f/text.txt") PoC lines"
  "$PY" "$HERE/count_tokens.py" \
    "dalfox --format json=$f/raw.json" \
    "dalfox text (stdout+stderr)=$f/text.txt+$f/text_stderr.txt" \
    "dalfox text, stdout only=$f/text.txt" \
    "dalfox text stdout, same PoCs as raw=$o/text_same.txt" \
    "raijin-xss JSON (default)=$o/raijin.json" \
    "raijin-xss --pretty=$o/raijin_pretty.json" \
    "raijin-xss --format table=$o/raijin_table.txt"
}

scenario noisy
scenario findings
