#!/usr/bin/env python3
import argparse
import re
import sys
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


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="log_analyzer.py",
        description="Access log analyzer (Combined Log Format)",
    )
    parser.add_argument("logfile", help="Path to the access log file")
    return parser


def main(argv=None) -> int:
    args = build_arg_parser().parse_args(argv)

    total_lines = 0
    parsed_count = 0
    bad_count = 0

    try:
        with open_log_file(args.logfile) as f:
            for line in f:
                total_lines += 1
                if parse_line(line) is None:
                    bad_count += 1
                else:
                    parsed_count += 1
    except FileNotFoundError:
        print(f"Error: file '{args.logfile}' not found.", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"Error opening file: {exc}", file=sys.stderr)
        return 1

    print(f"Total lines read : {total_lines}")
    print(f"Parsed lines     : {parsed_count}")
    print(f"Bad/malformed    : {bad_count}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
