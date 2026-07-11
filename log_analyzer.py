from __future__ import annotations
import argparse
import gzip
import re
import sys
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
    """Open the log file; transparently decompress it if it ends in .gz."""
    if path.endswith(".gz"):
        return gzip.open(path, mode="rt", encoding="utf-8", errors="replace")
    return open(path, mode="rt", encoding="utf-8", errors="replace")


class LogAnalyzer:
    def __init__(self):
        self.total_lines = 0
        self.parsed_count = 0
        self.bad_count = 0

        self.unique_ips: set[str] = set()
        self.endpoint_counter: Counter[str] = Counter()
        self.status_counter: Counter[int] = Counter()
        self.status_class_counter: Counter[str] = Counter()
        self.method_counter: Counter[str] = Counter()

        self.hourly_counter: Counter[str] = Counter()

        self.total_bytes = 0
        self.min_time: datetime | None = None
        self.max_time: datetime | None = None

    def process_line(self, line: str) -> None:
        self.total_lines += 1
        parsed = parse_line(line)
        if parsed is None:
            self.bad_count += 1
            return

        self.parsed_count += 1
        dt = parsed["timestamp"]

        self.unique_ips.add(parsed["ip"])
        self.endpoint_counter[parsed["path"]] += 1
        self.status_counter[parsed["status"]] += 1
        self.method_counter[parsed["method"]] += 1
        self.total_bytes += parsed["size"]

        status_class = f"{parsed['status'] // 100}xx"
        self.status_class_counter[status_class] += 1

        hour_key = dt.strftime("%Y-%m-%d %H:00")
        self.hourly_counter[hour_key] += 1

        if self.min_time is None or dt < self.min_time:
            self.min_time = dt
        if self.max_time is None or dt > self.max_time:
            self.max_time = dt

    def error_rate(self) -> float:
        if self.parsed_count == 0:
            return 0.0
        errors = sum(
            v for k, v in self.status_class_counter.items() if k in ("4xx", "5xx")
        )
        return errors / self.parsed_count * 100

    def top_endpoints(self, n: int = 10):
        return self.endpoint_counter.most_common(n)

    def to_report_dict(self, top_n: int = 10) -> dict:
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
        }


def print_text_report(report: dict) -> None:
    s = report["summary"]
    line = "=" * 62

    print(line)
    print("Access Log Analysis Report")
    print(line)

    print(f"Total lines read       : {s['total_lines_read']:,}")
    print(f"Parsed lines           : {s['parsed_lines']:,}")
    print(f"Bad/malformed lines    : {s['bad_lines']:,} ({s['bad_lines_pct']}%)")
    print(f"Unique IPs             : {s['unique_ips']:,}")
    print(f"Error rate (4xx + 5xx) : {s['error_rate_pct']}%")
    print(f"Total bytes sent       : {s['total_bytes_sent']:,} bytes")
    tr = s["time_range"]
    print(f"Log time range         : {tr['start']}  to  {tr['end']}")

    print("\n--- Status code distribution ---")
    for cls in sorted(report["status_classes"]):
        print(f"  {cls}: {report['status_classes'][cls]:,}")

    print("\n--- Top N busiest endpoints ---")
    for i, (path, cnt) in enumerate(report["top_endpoints"], 1):
        print(f"  {i:2d}. {path:<45} {cnt:,}")

    print("\n--- Requests per hour ---")
    hourly = report["hourly_distribution"]
    if hourly:
        max_count = max(hourly.values())
        bar_width = 40
        for hour, cnt in hourly.items():
            bar_len = int((cnt / max_count) * bar_width) if max_count else 0
            bar = "#" * bar_len
            print(f"  {hour} | {bar:<{bar_width}} {cnt:,}")
    else:
        print("  No data to display.")

    print(line)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="log_analyzer.py",
        description="Access log analyzer (Combined Log Format)",
    )
    parser.add_argument("logfile", help="Path to the access log file")
    parser.add_argument("--top", type=int, default=10, metavar="N",
                         help="Number of top endpoints to show (default: 10)")
    return parser


def main(argv=None) -> int:
    args = build_arg_parser().parse_args(argv)
    analyzer = LogAnalyzer()

    try:
        with open_log_file(args.logfile) as f:
            for line in f:
                analyzer.process_line(line)
    except FileNotFoundError:
        print(f"Error: file '{args.logfile}' not found.", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"Error opening file: {exc}", file=sys.stderr)
        return 1

    report = analyzer.to_report_dict(top_n=args.top)
    print_text_report(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
