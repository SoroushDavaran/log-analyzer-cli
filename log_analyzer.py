from __future__ import annotations
import argparse
import gzip
import json
import re
import sys
import time
from collections import Counter
from datetime import datetime

LOG_PATTERN = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<protocol>[^"]+)"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)\s+'
    r'"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)"\s*$'
)

TIMESTAMP_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


def parse_line(line: str) -> dict | None:
    line = line.rstrip("\n")
    if not line.strip():
        return None

    match = LOG_PATTERN.match(line)
    if not match:
        return None

    data = match.groupdict()

    try:
        dt = datetime.strptime(data["timestamp"], TIMESTAMP_FORMAT)
    except ValueError:
        return None

    try:
        status = int(data["status"])
        if not (100 <= status <= 599):
            return None
    except ValueError:
        return None

    size_raw = data["size"]
    if size_raw == "-":
        size = 0
    else:
        try:
            size = int(size_raw)
        except ValueError:
            return None

    return {
        "ip": data["ip"],
        "timestamp": dt,
        "method": data["method"],
        "path": data["path"],
        "protocol": data["protocol"],
        "status": status,
        "size": size,
        "referrer": data["referrer"],
        "user_agent": data["user_agent"],
    }

def open_log_file(path: str):
    if path.endswith(".gz"):
        return gzip.open(path, mode="rt", encoding="utf-8", errors="replace")
    return open(path, mode="rt", encoding="utf-8", errors="replace")

class LogAnalyzer:
    def __init__(self, login_path_substr: str = "login"):
        self.total_lines = 0
        self.parsed_count = 0
        self.bad_count = 0

        self.unique_ips: set[str] = set()
        self.endpoint_counter: Counter[str] = Counter()
        self.status_counter: Counter[int] = Counter()
        self.status_class_counter: Counter[str] = Counter()  # 2xx/3xx/4xx/5xx
        self.method_counter: Counter[str] = Counter()

        self.hourly_counter: Counter[str] = Counter()
        self.hourly_5xx_counter: Counter[str] = Counter()

        self.ip_login_401_counter: Counter[str] = Counter()
        self.login_path_substr = login_path_substr.lower()

        self.total_bytes = 0
        self.min_time: datetime | None = None
        self.max_time: datetime | None = None

    def process_line(self, line: str, start=None, end=None) -> None:
        self.total_lines += 1
        parsed = parse_line(line)
        if parsed is None:
            self.bad_count += 1
            return
        dt = parsed["timestamp"]
        if start is not None or end is not None:
            naive_dt = dt.replace(tzinfo=None)
            if start is not None and naive_dt < start:
                return
            if end is not None and naive_dt > end:
                return

        self.parsed_count += 1

        ip = parsed["ip"]
        self.unique_ips.add(ip)
        self.endpoint_counter[parsed["path"]] += 1
        self.status_counter[parsed["status"]] += 1
        self.method_counter[parsed["method"]] += 1
        self.total_bytes += parsed["size"]

        status_class = f"{parsed['status'] // 100}xx"
        self.status_class_counter[status_class] += 1

        hour_key = dt.strftime("%Y-%m-%d %H:00")
        self.hourly_counter[hour_key] += 1
        if status_class == "5xx":
            self.hourly_5xx_counter[hour_key] += 1

        if parsed["status"] == 401 and self.login_path_substr in parsed["path"].lower():
            self.ip_login_401_counter[ip] += 1

        if self.min_time is None or dt < self.min_time:
            self.min_time = dt
        if self.max_time is None or dt > self.max_time:
            self.max_time = dt

    # ---- report calculations ----

    def error_rate(self) -> float:
        if self.parsed_count == 0:
            return 0.0
        errors = sum(
            v for k, v in self.status_class_counter.items() if k in ("4xx", "5xx")
        )
        return errors / self.parsed_count * 100

    def top_endpoints(self, n: int = 10):
        return self.endpoint_counter.most_common(n)

    def suspicious_ips(self, threshold: int = 10):
        return [
            (ip, cnt)
            for ip, cnt in self.ip_login_401_counter.most_common()
            if cnt >= threshold
        ]

    def detect_error_spikes(self, multiplier: float = 3.0, min_requests: int = 20,
                             min_error_rate: float = 0.05):
        hours = sorted(self.hourly_counter.keys())
        if not hours:
            return []

        rates = {}
        for h in hours:
            total = self.hourly_counter[h]
            errs = self.hourly_5xx_counter.get(h, 0)
            rates[h] = errs / total if total else 0.0

        avg_rate = sum(rates.values()) / len(rates)
        baseline = max(avg_rate, 0.001)  # avoid division by zero / oversensitivity

        spikes = []
        for h in hours:
            total = self.hourly_counter[h]
            if total < min_requests:
                continue
            r = rates[h]
            if r >= baseline * multiplier and r >= min_error_rate:
                spikes.append({
                    "hour": h,
                    "total_requests": total,
                    "error_5xx_count": self.hourly_5xx_counter.get(h, 0),
                    "error_5xx_rate_pct": round(r * 100, 2),
                    "baseline_rate_pct": round(baseline * 100, 2),
                })
        return spikes

    def to_report_dict(self, top_n: int = 10, suspicious_threshold: int = 10,
                        spike_multiplier: float = 3.0, elapsed_seconds: float = 0.0):
        return {
            "summary": {
                "total_lines_read": self.total_lines,
                "parsed_lines": self.parsed_count,
                "bad_lines": self.bad_count,
                "bad_lines_pct": round(
                    (self.bad_count / self.total_lines * 100) if self.total_lines else 0, 2
                ),
                "unique_ips": len(self.unique_ips),
                "error_rate_pct": round(self.error_rate(), 2),
                "total_bytes_sent": self.total_bytes,
                "time_range": {
                    "start": self.min_time.isoformat() if self.min_time else None,
                    "end": self.max_time.isoformat() if self.max_time else None,
                },
            },
            "status_classes": dict(self.status_class_counter),
            "status_codes": dict(sorted(self.status_counter.items())),
            "methods": dict(self.method_counter),
            "top_endpoints": self.top_endpoints(top_n),
            "hourly_distribution": dict(sorted(self.hourly_counter.items())),
            "suspicious_login_ips": self.suspicious_ips(suspicious_threshold),
            "error_rate_spikes": self.detect_error_spikes(multiplier=spike_multiplier),
            "performance": {
                "elapsed_seconds": round(elapsed_seconds, 3),
                "lines_per_second": round(
                    self.total_lines / elapsed_seconds, 1
                ) if elapsed_seconds > 0 else None,
            },
        }

def print_text_report(report: dict) -> None:
    # ANSI Colors for Terminal Styling
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'

    s = report["summary"]
    
    # Header
    print(f"\n{BOLD}{CYAN}╔{'═' * 62}╗{RESET}")
    print(f"{BOLD}{CYAN}║{RESET} {BOLD}📊 ACCESS LOG ANALYSIS REPORT{RESET}{' ' * 33}{BOLD}{CYAN}║{RESET}")
    print(f"{BOLD}{CYAN}╚{'═' * 62}╝{RESET}\n")

    # Summary Section
    print(f"{BOLD}📌 [ SUMMARY ]{RESET}")
    print(f" ├─ {DIM}Total lines read{RESET}       : {BOLD}{s['total_lines_read']:,}{RESET}")
    print(f" ├─ {DIM}Parsed lines{RESET}           : {GREEN}{s['parsed_lines']:,}{RESET}")
    print(f" ├─ {DIM}Bad/malformed lines{RESET}    : {RED}{s['bad_lines']:,}{RESET} {DIM}({s['bad_lines_pct']}%){RESET}")
    print(f" ├─ {DIM}Unique IPs{RESET}             : {CYAN}{s['unique_ips']:,}{RESET}")
    print(f" ├─ {DIM}Error rate (4xx+5xx){RESET}   : {YELLOW}{s['error_rate_pct']}%{RESET}")
    print(f" ├─ {DIM}Total bytes sent{RESET}       : {s['total_bytes_sent']:,} bytes")
    tr = s["time_range"]
    print(f" └─ {DIM}Log time range{RESET}         : {tr['start']}  to  {tr['end']}\n")

    # Status Codes
    print(f"{BOLD}🚦 [ STATUS CODE DISTRIBUTION ]{RESET}")
    colors = {"2xx": GREEN, "3xx": CYAN, "4xx": YELLOW, "5xx": RED}
    classes = sorted(report["status_classes"])
    for i, cls in enumerate(classes):
        c = colors.get(cls, RESET)
        char = "└─" if i == len(classes) - 1 else "├─"
        print(f" {char} {c}{cls}{RESET} : {report['status_classes'][cls]:,}")
    if not classes:
        print(" └─ No data.")
    print()

    # Top Endpoints
    print(f"{BOLD}🔥 [ TOP {len(report['top_endpoints'])} BUSIEST ENDPOINTS ]{RESET}")
    endpoints = report["top_endpoints"]
    for i, (path, cnt) in enumerate(endpoints, 1):
        char = "└─" if i == len(endpoints) else "├─"
        print(f" {char} {i:2d}. {CYAN}{path:<45}{RESET} {BOLD}{cnt:,}{RESET}")
    if not endpoints:
        print(" └─ No data.")
    print()

    # Requests Per Hour (Beautiful Bar Chart)
    print(f"{BOLD}🕒 [ REQUESTS PER HOUR (TRAFFIC TREND) ]{RESET}")
    hourly = report["hourly_distribution"]
    if hourly:
        max_count = max(hourly.values())
        bar_width = 35
        items = list(hourly.items())
        for i, (hour, cnt) in enumerate(items):
            char = "└─" if i == len(items) - 1 else "├─"
            bar_len = int((cnt / max_count) * bar_width) if max_count else 0
            bar = "█" * bar_len
            empty = "░" * (bar_width - bar_len)
            print(f" {char} {DIM}{hour}{RESET} │ {CYAN}{bar}{DIM}{empty}{RESET} {BOLD}{cnt:,}{RESET}")
    else:
        print(" └─ No data to display.")
    print()

    # Suspicious Activity
    susp = report["suspicious_login_ips"]
    print(f"{BOLD}🚨 [ SUSPICIOUS ACTIVITY (BRUTE-FORCE DETECTED) ]{RESET}")
    if susp:
        for i, (ip, cnt) in enumerate(susp):
            char = "└─" if i == len(susp) - 1 else "├─"
            print(f" {char} IP {RED}{BOLD}{ip:<16}{RESET} ➔ {YELLOW}{cnt} 401 responses{RESET} on login path")
    else:
        print(f" └─ {GREEN}✓ No suspicious activity detected.{RESET}")
    print()

    # Error Spikes
    spikes = report["error_rate_spikes"]
    print(f"{BOLD}⚡ [ 5XX ERROR-RATE SPIKES ]{RESET}")
    if spikes:
        for i, sp in enumerate(spikes):
            char = "└─" if i == len(spikes) - 1 else "├─"
            print(
                f" {char} Hour {RED}{BOLD}{sp['hour']}{RESET} : error rate {RED}{sp['error_5xx_rate_pct']}%{RESET} "
                f"{DIM}(avg: {sp['baseline_rate_pct']}%) from {sp['error_5xx_count']}/{sp['total_requests']} reqs{RESET}"
            )
    else:
        print(f" └─ {GREEN}✓ No significant 5xx spikes found.{RESET}")
    print()

    # Performance
    perf = report["performance"]
    print(f"{BOLD}⏱️  [ PERFORMANCE METRICS ]{RESET}")
    print(f" ├─ {DIM}Execution time{RESET} : {perf['elapsed_seconds']} s")
    if perf["lines_per_second"]:
        print(f" └─ {DIM}Throughput{RESET}     : {perf['lines_per_second']:,} lines/sec")
    else:
        print(f" └─ {DIM}Throughput{RESET}     : N/A")
    
    print(f"\n{DIM}{'═' * 64}{RESET}\n")

def parse_cli_datetime(value: str) -> datetime:
    """Parse a user-supplied time-range boundary; accepted formats:
    YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS"""
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    raise argparse.ArgumentTypeError(
        f"Invalid time format: {value} (example: 2026-06-01T09:00:00)"
    )


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="log_analyzer.py",
        description="Access log analyzer (Combined Log Format)",
    )
    parser.add_argument("logfile", help="Path to the access log file (.log or .gz)")
    parser.add_argument("--top", type=int, default=10, metavar="N",
                         help="Number of top endpoints to show (default: 10)")
    parser.add_argument("--json", action="store_true",
                         help="Print the report as JSON")
    parser.add_argument("--start", type=parse_cli_datetime, default=None,
                         help="Only include requests after this time (e.g. 2026-06-01T09:00:00)")
    parser.add_argument("--end", type=parse_cli_datetime, default=None,
                         help="Only include requests before this time")
    parser.add_argument("--login-path", default="login", metavar="SUBSTR",
                         help="Substring identifying login endpoints (default: login)")
    parser.add_argument("--suspicious-threshold", type=int, default=10, metavar="N",
                         help="Minimum number of 401s on login paths to flag an IP as suspicious (default: 10)")
    parser.add_argument("--spike-multiplier", type=float, default=3.0, metavar="X",
                         help="Threshold multiplier for a 5xx error-rate spike vs. the average (default: 3.0)")
    return parser


def main(argv=None) -> int:
    args = build_arg_parser().parse_args(argv)

    analyzer = LogAnalyzer(login_path_substr=args.login_path)

    start_time = time.perf_counter()
    try:
        with open_log_file(args.logfile) as f:
            for line in f:
                analyzer.process_line(line, start=args.start, end=args.end)
    except FileNotFoundError:
        print(f"Error: file '{args.logfile}' not found.", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"Error opening file: {exc}", file=sys.stderr)
        return 1

    elapsed = time.perf_counter() - start_time

    report = analyzer.to_report_dict(
        top_n=args.top,
        suspicious_threshold=args.suspicious_threshold,
        spike_multiplier=args.spike_multiplier,
        elapsed_seconds=elapsed,
    )

    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print_text_report(report)

    return 0


if __name__ == "__main__":
    sys.exit(main())