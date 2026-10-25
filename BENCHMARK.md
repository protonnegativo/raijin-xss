# Token benchmark: dalfox vs raijin-xss

How many tokens does an AI agent spend reading the result of an XSS scan, and does it lose anything? This benchmark scans a local lab with dalfox, counts the tokens in each output shape, and checks that every dalfox PoC is in the raijin-xss output.

Reproduce: `bench/run.sh` replays the saved scans in `bench/fixtures`. `LIVE=1 bench/run.sh` starts the lab, scans it again and refreshes the fixtures first (101 seconds on the run that made these fixtures; set `DALFOX=<path>` if dalfox is not on `PATH`). A live scan does not give the same fixtures: see "dalfox's payloads change from scan to scan" below.

## Setup

- **Lab:** `bench/lab.py`, one Python process serving two sites on `127.0.0.1`, ports 19300 and 19301. Every page reflects its query parameters in a known context.
  - **noisy** (`shop`, port 19300): 10 item pages (`/item/1?q=shoes&sort=price` to `/item/10`) that all reflect `q` in the body the same way and escape `sort`, and a note form (`/note?msg=`) whose textarea strips its own closing tag, so every payload reflects but stays text. 11 targets.
  - **findings** (`app`, port 19301): `q` in the body (`/search`), `name` in a double-quoted attribute (`/profile`), `cb` in a single-quoted JS string (`/widget`), an escaped parameter (`/safe`), a JSON API that echoes its input (`/api/echo`), and `id`, which answers a quote with a MySQL error (`/report`). 6 targets.
- **dalfox:** v2.9.2, file mode, 10 workers. Both scans skip headless Chrome (`--skip-headless`): with it, the JS string page alone took over three minutes. The noisy scan also skips parameter mining. No blind callback, no remote payloads or wordlists.
- **raijin-xss:** runs dalfox itself (`file <targets> --format json -o <raw> -S --no-spinner --no-color -w 10` plus the skip flags) and keeps its JSON as `raw`: that file is the fixture (`raw.json`). Defaults apply: no limit on findings, and `--max-bytes 16000`, which was not reached. All raijin-xss rows replay `raw.json` with `--input`, and the target list with `-l` for the clean group, so they see the same scan.
- **Baselines**, as an agent would run dalfox, with the same options:
  - `dalfox --format json`: the `raw` file. dalfox writes the same JSON to stdout.
  - Text: dalfox's default output, `[POC][V][GET][inHTML-URL] <url>` lines on stdout and the banner and progress log on stderr. A separate live scan, run at the same time, saved as `text.txt` and `text_stderr.txt`.
  - Text, same PoCs: the lines dalfox's text output would have for the PoCs in `raw`, one `[POC][type][method][context] <url>` line each, written by `bench/run.sh`. It is derived, because the text scan reported a different number of PoCs (see below), and it is the fairest comparison: the same PoCs, in dalfox's leanest shape.
- **Tokens:** counted with tiktoken (`o200k_base`). This is a **proxy**, because Claude's tokenizer is not public. `bench/count_tokens.py` also gives exact Claude counts if `ANTHROPIC_API_KEY` is set and the `anthropic` package is installed. `cl100k_base` gives the same ratios.

## Scenario 1: noisy

121 PoCs: 10 verified, 111 reflected, at 18 locations. raijin-xss returned 6 findings and no clean target:

- high: `q` in `inHTML-none(1)-URL` at 7 item pages, `q` in `inHTML-URL` at 3;
- medium: `q` reflected in the same two contexts at 4 and 2 item pages, and `msg` in the textarea, one location each with 71 and 34 payloads.

| Output | Bytes | Tokens | vs. dalfox JSON |
|---|---:|---:|---:|
| dalfox `--format json` | 75,290 | 29,813 | 1× |
| dalfox text (stdout+stderr), separate scan, 124 PoCs | 53,034 | 22,514 | 1.3× |
| dalfox text, stdout only, separate scan | 17,751 | 9,774 | 3.1× |
| dalfox text, same PoCs as raw | 17,179 | 9,439 | 3.2× |
| **raijin-xss JSON (default)** | 3,864 | **1,691** | **17.6×** |
| raijin-xss `--pretty` | 4,608 | 1,916 | 15.6× |
| raijin-xss `--format table` | 2,226 | 1,113 | 26.8× |

## Scenario 2: findings

83 PoCs: 3 verified, 79 reflected, 1 grep, at 6 locations. raijin-xss returned 6 findings and 2 clean targets:

- high: `cb` breaking out of the script into HTML (`inHTML-URL`), `name` in the attribute (CWE-83), `q` in the body;
- medium: `cb` reflected in the JS string (71 payloads) and in HTML (8 payloads), one location each;
- low: the MySQL error on `/report` (`dalfox-error-mysql1`);
- clean: `/safe` (escaped) and `/api/echo` (the JSON API: dalfox reported nothing there).

| Output | Bytes | Tokens | vs. dalfox JSON |
|---|---:|---:|---:|
| dalfox `--format json` | 44,411 | 17,508 | 1× |
| dalfox text (stdout+stderr), separate scan, 191 PoCs | 69,072 | 32,585 | 0.5× |
| dalfox text, stdout only, separate scan | 29,707 | 18,142 | 1.0× |
| dalfox text, same PoCs as raw | 11,413 | 6,493 | 2.7× |
| **raijin-xss JSON (default)** | 2,394 | **934** | **18.7×** |
| raijin-xss `--pretty` | 3,044 | 1,150 | 15.2× |
| raijin-xss `--format table` | 885 | 408 | 43× |

In a live run (not a replay) the raijin-xss JSON also has `raw`, the path of dalfox's saved JSON, a few more tokens.

## Nothing is lost

For each scenario, `bench/verify.py` checks every dalfox PoC (an object of the `raw` JSON) against the raijin-xss output. A PoC's identity is its URL (dalfox's `data`, the PoC URL), its parameter and its type, with its context (`inject_type`), method, CWE and, for a grep match, the pattern dalfox names in `message_str`. A PoC is present when a finding has the same type (as severity and confidence), parameter, context, method, CWE and grep pattern, and either lists the PoC URL itself (after expanding `[1-3]` ranges and prepending `origin`) or lists another PoC URL of the same location and counts the PoC in `payloads`. Then, for every finding, the PoCs that matched it must add up to `payloads` (or to its number of locations), and its `payload` must be one of them. Exact repeats count once.

- Scenario 1: 121 PoCs, **0 missing**, 0 findings with wrong counts.
- Scenario 2: 83 PoCs, **0 missing**, 0 findings with wrong counts.

The check fails when it should: with the first location of the noisy scan's first finding taken out, it reports that PoC (`/item/10`) missing; with the textarea's `payloads` lowered from 71 to 70, it reports the count.

What the JSON leaves out stays in dalfox's JSON, which raijin-xss saves to disk and points to in `raw`: the other payloads at each location with their evidence lines, dalfox's messages and its message IDs.

dalfox writes no `payload` or `evidence` for a PoC it verified in headless Chrome ("found dialog in headless"). The benchmark scans skip headless Chrome, so that shape is covered by a unit test with a real dalfox record from a headless scan of the same lab (`testdata/sample.json`): the PoC URL is kept and carries the payload.

## Reading the numbers

- **Against `dalfox --format json`**, the structured output an agent would parse, raijin-xss uses **17.6× fewer tokens** on the noisy scan and **18.7× fewer** on the findings scan. Most of it is the payloads dalfox reports at one location: 105 PoCs for the textarea and 79 for the JS string are 4 PoC URLs and 4 counts.
- **Against dalfox's text output for the same PoCs**, raijin-xss is **5.6×** (9,439 → 1,691) and **7.0×** (6,493 → 934) smaller. The text lines are already lean, one PoC URL each, but there is one line per payload, and they have no parameter name, no payload in readable form, no evidence, no CWE and no grep pattern (a G line is a bare URL).
- **Against a real text run (stdout and stderr)**, raijin-xss is 13× and 35× smaller, but those are other scans: dalfox reported 124 and 191 PoCs there, against 121 and 83 in the JSON runs.
- **The output stays bounded.** On a scan too big for `--max-bytes`, raijin-xss cuts the least important data first: the clean targets, then extra locations of low-ranked findings, then low-ranked findings. Every cut is counted in `omitted`, and `next` points to the raw file. Raw dalfox output has no upper bound.

## dalfox's payloads change from scan to scan

dalfox runs its payloads with concurrent workers and reports what comes back, so two scans of the same lab report different payloads, a different number of reflected ones, and sometimes a different context for the same parameter. The JSON and text scans of the findings site ran at the same time and reported 83 and 191 PoCs; an earlier, lone scan of the same site gave 127. That is why the fixtures are saved, and why the "same PoCs" text row exists. The verification and the raijin-xss rows always use the saved `raw.json`.

One thing changed before these numbers, from an earlier live run: dalfox appends to its `-o` file instead of replacing it, so a second scan with the same `--raw` path held both scans. raijin-xss now empties the raw file before it runs dalfox.
