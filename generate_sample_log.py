#!/usr/bin/env python3
"""
generate_sample_log.py
------------------------
Generates a "dirty" sample access log so log_analyzer.py can be tested
against it. This script is not part of the required deliverables -- it's
only here to produce test data (since no real sample file was attached
to the assignment).

Properties of the generated data:
  - 24 hours of traffic with a peak around midday
  - ~0.5% of lines are intentionally malformed/truncated
  - one IP that brute-forces /login (many 401 responses)
  - one time window with a 5xx error-rate spike (14:00-15:00)

Usage:
    python3 generate_sample_log.py --lines 300000 --out sample_access.log
"""

import argparse
import gzip
import random
from datetime import datetime, timedelta

PATHS = [
    "/", "/home", "/products", "/products/1877", "/products/42",
    "/cart", "/checkout", "/api/login", "/api/logout", "/search",
    "/about", "/contact", "/static/style.css", "/static/app.js",
    "/api/users/me", "/api/orders", "/images/logo.png",
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "Mozilla/5.0 (X11; Linux x86_64)",
    "curl/8.4.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)",
]

METHODS_WEIGHTED = ["GET"] * 8 + ["POST"] * 2

NORMAL_STATUS_WEIGHTED = [200] * 85 + [301, 302] * 3 + [404] * 8 + [500, 502, 503] * 2

ATTACKER_IP = "198.51.100.66"


def random_ip():
    return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def hourly_weight(hour: int) -> float:
    """Traffic peaks around midday/afternoon, drops sharply at night."""
    return 0.15 + 0.85 * (1 - abs(hour - 14) / 14)


def build_line(dt: datetime, ip: str, method: str, path: str, status: int, ua: str) -> str:
    size = 0 if status in (204, 304) else random.randint(150, 15000)
    ts = dt.strftime("%d/%b/%Y:%H:%M:%S +0000")
    return f'{ip} - - [{ts}] "{method} {path} HTTP/1.1" {status} {size} "-" "{ua}"'


def generate(num_lines: int, out_path: str, seed: int = 42) -> None:
    random.seed(seed)
    start = datetime(2026, 6, 1, 0, 0, 0)

    opener = gzip.open if out_path.endswith(".gz") else open
    mode = "wt"

    with opener(out_path, mode, encoding="utf-8") as f:
        for i in range(num_lines):
            hour = int((i / num_lines) * 24)
            minute = random.randint(0, 59)
            second = random.randint(0, 59)
            dt = start.replace(hour=0) + timedelta(hours=hour, minutes=minute, seconds=second)

            # ~0.5% of lines are intentionally malformed/truncated
            if random.random() < 0.005:
                broken_kind = random.choice(["truncated", "no_quotes", "garbage", "bad_status"])
                if broken_kind == "truncated":
                    f.write(f'{random_ip()} - - [{dt.strftime("%d/%b/%Y:%H:%M:%S")}\n')
                elif broken_kind == "no_quotes":
                    f.write(f'{random_ip()} - - [{dt.strftime("%d/%b/%Y:%H:%M:%S +0000")}] GET /x HTTP/1.1 200 100\n')
                elif broken_kind == "garbage":
                    f.write("###CORRUPTED-LINE-FROM-DISK-ERROR###\n")
                else:
                    f.write(f'{random_ip()} - - [{dt.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET /x HTTP/1.1" NAN 100 "-" "-"\n')
                continue

            # error spike window: hour 14-15 has a very high 5xx rate
            if 14 <= hour < 15 and random.random() < 0.55:
                status = random.choice([500, 502, 503])
                line = build_line(dt, random_ip(), "GET", random.choice(PATHS),
                                   status, random.choice(USER_AGENTS))
                f.write(line + "\n")
                continue

            # inject brute-force behavior on /login from a fixed IP, spread across the day
            if random.random() < 0.01:
                line = build_line(dt, ATTACKER_IP, "POST", "/api/login", 401,
                                   "curl/8.4.0")
                f.write(line + "\n")
                continue

            # normal traffic, weighted by hour (simulates the daily peak/trough)
            if random.random() > hourly_weight(hour):
                # skip this line to make the nighttime traffic drop more realistic
                continue

            ip = random_ip()
            method = random.choice(METHODS_WEIGHTED)
            path = random.choice(PATHS)
            status = random.choice(NORMAL_STATUS_WEIGHTED)
            ua = random.choice(USER_AGENTS)
            f.write(build_line(dt, ip, method, path, status, ua) + "\n")


def main():
    parser = argparse.ArgumentParser(description="Generate a sample access log for testing")
    parser.add_argument("--lines", type=int, default=300_000, help="Target (approximate) number of lines")
    parser.add_argument("--out", default="sample_access.log", help="Output file path (.log or .log.gz)")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    generate(args.lines, args.out, args.seed)
    print(f"Sample file generated: {args.out}")


if __name__ == "__main__":
    main()
