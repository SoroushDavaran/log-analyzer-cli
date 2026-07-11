#!/usr/bin/env python3
import argparse
import sys


def open_log_file(path: str):
    """Open the log file for reading."""
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
    try:
        with open_log_file(args.logfile) as f:
            for i in f:  # line by line
                total_lines += 1
    except FileNotFoundError:
        print(f"Error: file '{args.logfile}' not found.", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"Error opening file: {exc}", file=sys.stderr)
        return 1

    print(f"Total lines read: {total_lines}")
    return 0


if __name__ == "__main__":
    sys.exit(main())