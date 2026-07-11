#!/usr/bin/env python3
import argparse
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


def parse_line(line: str):
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
    return open(path, mode="rt", encoding="utf-8", errors="replace")


class LogAnalyzer:
    def __init__(self):
        self.total_lines = 0
        self.parsed_count = 0
        self.bad_count = 0

        self.unique_ips: set[str] = set()
        self.endpoint_counter: Counter[str] = Counter()
        self.status_class_counter: Counter[str] = Counter()

        self.hourly_counter: Counter[str] = Counter()

    def process_line(self, line: str) -> None:
        self.total_lines += 1
        parsed = parse_line(line)
        if parsed is None:
            self.bad_count += 1
            return

        self.parsed_count += 1
        self.unique_ips.add(parsed["ip"])
        self.endpoint_counter[parsed["path"]] += 1

        status_class = f"{parsed['status'] // 100}xx"
        self.status_class_counter[status_class] += 1

        hour_key = parsed["timestamp"].strftime("%Y-%m-%d %H:00")
        self.hourly_counter[hour_key] += 1

    def error_rate(self) -> float:
        if self.parsed_count == 0:
            return 0.0
        errors = sum(
            v for k, v in self.status_class_counter.items() if k in ("4xx", "5xx")
        )
        return errors / self.parsed_count * 100

    def top_endpoints(self, n: int = 10):
        return self.endpoint_counter.most_common(n)


def print_hourly_histogram(hourly_counter: Counter) -> None:
    if not hourly_counter:
        print("  No data to display.")
        return
    hourly = dict(sorted(hourly_counter.items()))
    max_count = max(hourly.values())
    bar_width = 40
    for hour, cnt in hourly.items():
        bar_len = int((cnt / max_count) * bar_width) if max_count else 0
        bar = "#" * bar_len
        print(f"  {hour} | {bar:<{bar_width}} {cnt}")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="log_analyzer.py",
        description="Access log analyzer (Combined Log Format)",
    )
    parser.add_argument("logfile", help="Path to the access log file")
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

    print(f"Total lines read   : {analyzer.total_lines}")
    print(f"Parsed requests    : {analyzer.parsed_count}")
    print(f"Bad/malformed      : {analyzer.bad_count}")
    print(f"Unique IPs         : {len(analyzer.unique_ips)}")
    print(f"Error rate (4xx+5xx): {analyzer.error_rate():.2f}%")

    print("\nTop 10 busiest endpoints:")
    for i, (path, cnt) in enumerate(analyzer.top_endpoints(10), 1):
        print(f"  {i:2d}. {path:<40} {cnt}")

    print("\nRequests per hour:")
    print_hourly_histogram(analyzer.hourly_counter)

    return 0


if __name__ == "__main__":
    sys.exit(main())
