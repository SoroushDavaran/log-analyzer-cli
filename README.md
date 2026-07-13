# 📊 Access Log Analyzer (CLI Tool + Interactive Shell)

An efficient, lightweight tool developed in pure Python to parse and analyze
server access logs adhering to the standard **Combined Log Format**.

This project simulates an Infrastructure/DevOps engineer's first line of
defense during service slowness or downtime — delving into massive, "dirty"
log files to extract critical, actionable insights quickly without
exhausting server memory. It ships in two flavors: a single-shot **CLI**
(`log_analyzer.py`) for scripts/pipelines/cron, and an **interactive shell**
(`log_shell.py`) for exploring one file with several different queries
without re-parsing it each time.

---

## ✨ Key Features

### 🔹 Core Requirements
*   **Defensive Parsing:** Leverages a pre-compiled regular expression to
    gracefully handle and skip malformed or incomplete log lines without
    crashing the application. `parse_line()` never raises — it always
    returns either a parsed dict or `None`.
*   **Streaming Iterator:** Processes the file line-by-line (`for line in f`),
    never materializing the whole file (or a list of all lines) in memory —
    memory usage scales with the number of *unique* IPs/paths/hours seen,
    not with file size.
*   **Essential Metrics:** Reports total requests, unique client IPs, overall
    error rate (4xx + 5xx), and total bytes transferred.
*   **Traffic Distribution:** Breaks down traffic volume hourly, complete
    with a clean **Unicode bar chart** to instantly spot peak/quiet hours.

### 🔸 Bonus Features
*   **Native Gzip Support:** Automatically detects and reads compressed
    `.gz` files on the fly (`open_log_file()`), still line-by-line —
    no manual extraction needed.
*   **Brute-Force Detection:** Flags IPs with an anomalous number of `401
    Unauthorized` responses on a login-like path (default substring
    `login`, customizable via `--login-path` / `--suspicious-threshold`).
*   **Dynamic Error-Spike Detection:** Compares each hour's 5xx rate against
    the *file's own average* rather than a fixed threshold, and flags hours
    that spike by a configurable multiplier (`--spike-multiplier`).
*   **Format Agnostic:** Renders a colorized, boxed text report by default,
    or `--json` for machine-readable output (safe to pipe into `jq`).
*   **Time-Range Filtering:** Restrict analysis to a window with `--start`
    / `--end`.
*   **Execution Time & Throughput:** Every report includes elapsed time and
    lines/second, measured with `time.perf_counter()` around the read loop.
*   **Interactive Colored Shell:** `log_shell.py` — load a file once, then
    run `top`, `hourly`, `suspicious`, `spikes`, `json`, etc. against the
    same in-memory analysis, no re-parsing between commands.
*   **Unit Tests:** 14 tests covering both line-level parsing edge cases and
    end-to-end aggregation (unique IPs, top endpoints, error rate, hourly
    buckets, brute-force detection, error-spike detection, time filtering).

---

## 📂 Project Structure

| File | Description |
| :--- | :--- |
| 📄 `log_analyzer.py` | Core parser + analyzer + CLI. Zero external dependencies. |
| 🐚 `log_shell.py` | Interactive REPL shell built on top of `LogAnalyzer` (colored, menu-driven). |
| 🧪 `test_log_analyzer.py` | Unit tests (`unittest`) for parsing and aggregation. |
| 🛠️ `generate_sample_log.py` | Generates a realistic, 24-hour "dirty" sample log for testing. |
| 🗃️ `sample_access.log.gz` | A pre-generated ~200k-line sample so you can try the tool immediately after cloning. |

> 💡 **Note on the sample log:** since no sample log was attached to the
> original prompt, `generate_sample_log.py` was written instead. It
> produces a production-like simulation — organic hourly traffic curve,
> ~0.5% malformed lines, a brute-force attack against `/login`, and a
> sudden 5xx outage window (hour 14) — so both `log_analyzer.py` and
> `log_shell.py` can be exercised against realistic data. If you have a
> real log file, just point either tool at its path — nothing else changes.

---

## 🚀 Getting Started

### Prerequisites
Pure **Python standard library** — no `pip install` required. Python 3.9+
recommended (the codebase relies on `from __future__ import annotations` so
modern type-hint syntax like `dict | None` works without evaluating at
runtime). Parsing is implemented with `re` rather than a ready-made log
parser, per the assignment's constraint that the library itself must not do
the parsing.

### CLI usage

```bash
# 1. Basic analysis on a plain text log
python log_analyzer.py sample_access.log.gz

# 2. Analyze a compressed gzip file directly (same command as above works
#    automatically — detection is based on the .gz extension)

# 3. Output the full report as structured JSON
python log_analyzer.py sample_access.log.gz --json

# 4. Customize the number of top busy endpoints shown (e.g. top 5)
python log_analyzer.py sample_access.log.gz --top 5

# 5. Restrict analysis to a specific time window
python log_analyzer.py sample_access.log.gz --start 2026-06-01T14:00:00 --end 2026-06-01T15:30:00

# 6. Tune brute-force / error-spike sensitivity, or the login path
python log_analyzer.py sample_access.log.gz --suspicious-threshold 5 --spike-multiplier 2.5 --login-path signin

python log_analyzer.py --help   # full flag reference
```

### Interactive shell usage

```bash
python log_shell.py
# or auto-load a file on startup:
python log_shell.py sample_access.log.gz
```

The shell prints a banner listing every command (in blue) as soon as it
starts:

```
Access Log Analyzer -- interactive shell
Type a command below. Available commands:

  load <path>              Load and analyze an access log file (.log or .gz)
  report                   Print the full report (same as log_analyzer.py's default output)
  top [N]                  Show the top N endpoints by traffic (default: 10)
  hourly                   Show the hourly request histogram
  suspicious [threshold]   Show IPs with suspicious 401-on-login activity
  spikes [multiplier]      Show hours with a 5xx error-rate spike
  json                     Print the full report as JSON
  status                   Show which file is currently loaded
  help                     Show this list of commands again
  exit / quit / Ctrl-D     Leave the shell

Start with: load sample_access.log
log>
```

A typical session — the file is parsed **once** on `load`, and every
following command reuses the same in-memory result:

```
log> load sample_access.log.gz
Loaded 'sample_access.log.gz': 187,979 parsed / 747 bad lines in 2.1s
   ... (full report prints automatically, same as the CLI's default output)
log> top 5
log> hourly
log> suspicious 5
log> spikes 2
log> json
log> exit
```

Colors (both in the CLI report and the shell) are only emitted when stdout
is an actual terminal and `NO_COLOR` isn't set — redirecting output to a
file (`python log_analyzer.py file.log > report.txt`) produces clean,
escape-code-free text.

### Developer & test commands

```bash
# Generate a fresh sample log with a custom line count
python generate_sample_log.py --lines 300000 --out sample_access.log

# Run the test suite with verbose output
python -m unittest test_log_analyzer.py -v
```

---

## 🖥️ Terminal Preview

```
╔══════════════════════════════════════════════════════════════╗
║ 📊 ACCESS LOG ANALYSIS REPORT                                 ║
╚══════════════════════════════════════════════════════════════╝

📌 [ SUMMARY ]
 ├─ Total lines read       : 187,979
 ├─ Parsed lines           : 187,232
 ├─ Bad/malformed lines    : 747 (0.40%)
 ├─ Unique IPs             : 184,510
 ├─ Error rate (4xx+5xx)   : 18.1%
 ├─ Total bytes sent       : 1,415,203,880 bytes
 └─ Log time range         : 2026-06-01T00:00:04+00:00  to  2026-06-01T23:59:58+00:00

🚦 [ STATUS CODE DISTRIBUTION ]
 ├─ 2xx : 142,110
 ├─ 3xx : 10,822
 ├─ 4xx : 17,201
 └─ 5xx : 17,099

🔥 [ TOP 3 BUSIEST ENDPOINTS ]
 ├─  1. /api/login                                    9,223
 ├─  2. /products/1877                                7,384
 └─  3. /products                                     7,323

🕒 [ REQUESTS PER HOUR (TRAFFIC TREND) ]
 ├─ 2026-06-01 00:00 │ █████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ 1,260
 ├─ 2026-06-01 09:00 │ ████████████████████████░░░░░░░░░░░ 5,807
 ├─ 2026-06-01 14:00 │ ████████████████████████████████████ 8,283
 └─ 2026-06-01 23:00 │ ████████████████░░░░░░░░░░░░░░░░░░░░ 3,820

🚨 [ SUSPICIOUS ACTIVITY (BRUTE-FORCE DETECTED) ]
 └─ IP 198.51.100.66    ➔ 1967 401 responses on login path

⚡ [ 5XX ERROR-RATE SPIKES ]
 └─ Hour 2026-06-01 14:00 : error rate 57.84% (avg: 7.71%) from 4791/8283 reqs

⏱️  [ PERFORMANCE METRICS ]
 ├─ Execution time : 2.17 s
 └─ Throughput     : 57,769.8 lines/sec

════════════════════════════════════════════════════════════════
```

(Sections are colorized in a real terminal — green for healthy counts,
yellow for warnings, red for errors/spikes. Hourly rows are truncated above
for brevity; the real output prints all 24 hours.)

---

## 🧠 Architectural & Design Decisions

*   **Regex pre-compilation:** the log-matching regex (`LOG_PATTERN`) is
    compiled once at module level. Regex is used instead of a naive
    `.split()` because quoted fields (request line, referrer, user-agent)
    can themselves contain whitespace, which breaks a fixed-position split.
*   **Single-pass stream:** every metric (endpoint counts, hourly buckets,
    status classes, brute-force tracking, min/max time) is computed in one
    pass over the file stream inside `LogAnalyzer.process_line()`. The file
    is never seeked or re-read.
*   **Hyphen size → 0:** in Combined Log Format, a `-` in the size field
    means "no response body." The parser converts it to `0` rather than
    treating it as a parse failure, to avoid dropping otherwise-valid lines.
*   **Dict-based report, not object-based:** `LogAnalyzer.to_report_dict()`
    builds one plain dict that both `print_text_report()` (text) and
    `json.dumps()` (JSON) consume — a single source of truth for what a
    "report" contains, instead of duplicating formatting logic per output
    format.
*   **CLI and shell are separate modules on purpose:** `log_analyzer.py`
    stays a simple, script-friendly, single-command tool (safe to use in a
    cron job or pipeline). `log_shell.py` is a thin interactive layer that
    only imports `LogAnalyzer`, `open_log_file`, and `print_text_report` —
    it never re-implements parsing or aggregation logic. The loaded file's
    *aggregated* statistics (Counters, not raw lines) are kept in memory so
    follow-up commands (`top 5`, `spikes 2`, ...) are instant.
*   **Terminal-aware coloring:** color codes are only emitted when
    `sys.stdout.isatty()` is true and `NO_COLOR` is unset, so redirecting
    output to a file or another program never leaks raw ANSI escape bytes.
*   **Known limitation:** `top_endpoints` counts paths exactly as they
    appear in the log, including any query string. To merge `/p?id=1` and
    `/p?id=2` into one bucket you'd normalize with
    `path.split("?")[0]` before counting — left out here to keep the
    default behavior faithful to what actually happened on the wire.

---

## 🛠️ Engineering Challenges

### 1. Dynamic baseline vs. static threshold (error-spike detection)

**The problem:** in an early design of "automatic error-spike detection,"
the tool flagged any hour where the 5xx rate crossed a fixed threshold
(e.g. 10%). In practice, static thresholds don't generalize: a naturally
noisy service with a 5% baseline error rate would trigger constant false
alarms, while a very stable service jumping from 0.01% to 4% (a real
incident) would slip under the radar entirely.

**The fix:** `detect_error_spikes()` first computes the *average* 5xx rate
across the whole file, then flags an hour only if its rate exceeds that
average by a configurable multiplier (`--spike-multiplier`, default 3×). A
`min_requests` floor also prevents low-traffic windows (e.g. 3am with 5
requests) from producing statistically meaningless false positives.

### 2. Comparing timezone-aware and timezone-naive datetimes

**The problem:** once `--start`/`--end` time filtering was added, the tool
started raising:

```
TypeError: can't compare offset-naive and offset-aware datetimes
```

The root cause: each log line's `timestamp` is parsed with `%z` (since
Combined Log Format includes a UTC offset like `+0000`), so it comes out
timezone-**aware**. But `--start`/`--end` are parsed from the CLI with
`strptime(value, "%Y-%m-%dT%H:%M:%S")` — no `%z` — so they're
timezone-**naive**. Python refuses to compare the two directly with `<`/`>`.

**The fix:** strip the timezone off the log's timestamp before comparing —
`dt.replace(tzinfo=None)` — and filter against "the local time as written
in the log," not true UTC. This is a deliberate simplification: it assumes
a single log file comes from one source with a consistent offset (true for
essentially every real access log), so naive-to-naive comparison on that
scale gives the correct result. Normalizing everything to UTC first would
only be necessary if merging logs from multiple sources with different
offsets — out of scope for this exercise.

### 3. Report format coupling between the CLI and the shell

**The problem:** early on, `print_text_report()` took a `LogAnalyzer`
object plus several keyword arguments (`top_n`, `elapsed_seconds`, ...).
When the report renderer was later redesigned to build one `report` dict
via `to_report_dict()` and print *that* instead (cleaner, and reusable for
both text and JSON output), `log_shell.py` — which called the old
signature — started throwing `TypeError: print_text_report() got an
unexpected keyword argument`.

**The fix:** every call site was updated to build the dict first
(`report = analyzer.to_report_dict(...)`) and pass that single dict into
`print_text_report()`. This also removed the last place where the shell and
the CLI could drift apart in how they render output.