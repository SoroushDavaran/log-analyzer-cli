from __future__ import annotations
import cmd
import json
import os
import sys
import time
from log_analyzer import LogAnalyzer, open_log_file, print_text_report

class Colors:
    BLUE = "\033[38;5;39m"   
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"

    @classmethod
    def disable(cls):
        for attr in ("BLUE", "CYAN", "GREEN", "YELLOW", "RED", "BOLD", "DIM", "RESET"):
            setattr(cls, attr, "")


if not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
    Colors.disable()


def _rl_wrap(code: str) -> str:
    return f"\001{code}\002" if code else ""


BANNER_COMMANDS = [
    ("load <path>", "Load and analyze an access log file (.log or .gz)"),
    ("report", "Print the full report (same as log_analyzer.py's default output)"),
    ("top [N]", "Show the top N endpoints by traffic (default: 10)"),
    ("hourly", "Show the hourly request histogram"),
    ("suspicious [threshold]", "Show IPs with suspicious 401-on-login activity"),
    ("spikes [multiplier]", "Show hours with a 5xx error-rate spike"),
    ("json", "Print the full report as JSON"),
    ("status", "Show which file is currently loaded"),
    ("help", "Show this list of commands again"),
    ("exit / quit / Ctrl-D", "Leave the shell"),
]


def build_banner() -> str:
    lines = [
        f"{Colors.BOLD}{Colors.CYAN}Access Log Analyzer -- interactive shell{Colors.RESET}",
        f"{Colors.DIM}Type a command below. Available commands:{Colors.RESET}",
        "",
    ]
    for cmd_name, desc in BANNER_COMMANDS:
        lines.append(f"  {Colors.BLUE}{Colors.BOLD}{cmd_name:<24}{Colors.RESET} {desc}")
    lines.append("")
    lines.append(f"{Colors.DIM}Start with: {Colors.BLUE}load sample_access.log{Colors.RESET}")
    return "\n".join(lines)


class LogShell(cmd.Cmd):
    intro = build_banner()
    prompt = f"{_rl_wrap(Colors.BLUE)}{_rl_wrap(Colors.BOLD)}log>{_rl_wrap(Colors.RESET)} "

    def __init__(self, initial_path: str | None = None):
        super().__init__()
        self.analyzer: LogAnalyzer | None = None
        self.elapsed: float = 0.0
        self.loaded_path: str | None = None
        if initial_path:
            self._load(initial_path)

    def _require_loaded(self) -> bool:
        if self.analyzer is None:
            print(f"{Colors.RED}No log file loaded yet. "
                  f"Use: {Colors.BLUE}load <path>{Colors.RESET}")
            return False
        return True

    def _load(self, path: str) -> None:
        path = path.strip()
        if not path:
            print(f"{Colors.RED}Usage: load <path-to-logfile>{Colors.RESET}")
            return

        analyzer = LogAnalyzer()
        start = time.perf_counter()
        try:
            with open_log_file(path) as f:
                for line in f:  # همچنان خط‌به‌خط، حتی داخل شل
                    analyzer.process_line(line)
        except FileNotFoundError:
            print(f"{Colors.RED}Error: file '{path}' not found.{Colors.RESET}")
            return
        except OSError as exc:
            print(f"{Colors.RED}Error opening file: {exc}{Colors.RESET}")
            return

        self.elapsed = time.perf_counter() - start
        self.analyzer = analyzer
        self.loaded_path = path
        print(
            f"{Colors.GREEN}Loaded '{path}':{Colors.RESET} "
            f"{analyzer.parsed_count:,} parsed / {analyzer.bad_count:,} bad lines "
            f"in {self.elapsed:.3f}s"
        )
        print()
        report = analyzer.to_report_dict(elapsed_seconds=self.elapsed)
        print_text_report(report)

    def do_load(self, arg):
        "Load and analyze an access log file: load <path>"
        self._load(arg)

    def do_status(self, arg):
        "Show which file (if any) is currently loaded."
        if self.analyzer is None:
            print(f"{Colors.YELLOW}No file loaded.{Colors.RESET}")
            return
        print(f"{Colors.CYAN}Loaded file:{Colors.RESET} {self.loaded_path}")
        print(f"{Colors.CYAN}Parsed / bad lines:{Colors.RESET} "
              f"{self.analyzer.parsed_count:,} / {self.analyzer.bad_count:,}")

    def do_report(self, arg):
        "Print the full text report for the loaded file."
        if not self._require_loaded():
            return
        report = self.analyzer.to_report_dict(elapsed_seconds=self.elapsed)
        print_text_report(report)

    def do_top(self, arg):
        "Show the top N endpoints by traffic: top [N] (default 10)"
        if not self._require_loaded():
            return
        n = int(arg.strip()) if arg.strip().isdigit() else 10
        print(f"{Colors.CYAN}--- Top {n} endpoints ---{Colors.RESET}")
        for i, (path, cnt) in enumerate(self.analyzer.top_endpoints(n), 1):
            print(f"  {i:2d}. {path:<45} {cnt:,}")

    def do_hourly(self, arg):
        "Show the hourly request histogram."
        if not self._require_loaded():
            return
        hourly = self.analyzer.hourly_counter
        print(f"{Colors.CYAN}--- Hourly request distribution ---{Colors.RESET}")
        if not hourly:
            print("  No data to display.")
            return
        max_count = max(hourly.values())
        bar_width = 40
        for hour in sorted(hourly):
            cnt = hourly[hour]
            bar_len = int((cnt / max_count) * bar_width) if max_count else 0
            bar = "#" * bar_len
            print(f"  {hour} | {Colors.BLUE}{bar:<{bar_width}}{Colors.RESET} {cnt:,}")

    def do_suspicious(self, arg):
        "Show IPs with suspicious 401-on-login activity: suspicious [threshold] (default 10)"
        if not self._require_loaded():
            return
        threshold = int(arg.strip()) if arg.strip().isdigit() else 10
        susp = self.analyzer.suspicious_ips(threshold)
        print(f"{Colors.CYAN}--- Suspicious login activity (threshold={threshold}) ---{Colors.RESET}")
        if not susp:
            print("  Nothing found.")
            return
        for ip, cnt in susp:
            print(f"  {Colors.RED}IP {ip:<16}{Colors.RESET} -> {cnt} x 401 on login path")

    def do_spikes(self, arg):
        "Show hours with a 5xx error-rate spike: spikes [multiplier] (default 3.0)"
        if not self._require_loaded():
            return
        try:
            multiplier = float(arg.strip()) if arg.strip() else 3.0
        except ValueError:
            print(f"{Colors.RED}Invalid multiplier: {arg!r}{Colors.RESET}")
            return
        spikes = self.analyzer.detect_error_spikes(multiplier=multiplier)
        print(f"{Colors.CYAN}--- 5xx error-rate spikes (multiplier={multiplier}) ---{Colors.RESET}")
        if not spikes:
            print("  No significant spike found.")
            return
        for sp in spikes:
            print(
                f"  {Colors.RED}Hour {sp['hour']}{Colors.RESET}: "
                f"error rate {sp['error_5xx_rate_pct']}% "
                f"(avg: {sp['baseline_rate_pct']}%) "
                f"from {sp['error_5xx_count']}/{sp['total_requests']} requests"
            )

    def do_json(self, arg):
        "Print the full report as JSON."
        if not self._require_loaded():
            return
        report = self.analyzer.to_report_dict(elapsed_seconds=self.elapsed)
        print(json.dumps(report, ensure_ascii=False, indent=2))

    def do_help(self, arg):
        "Show the list of available commands."
        if arg:
            super().do_help(arg)
            return
        print(build_banner())

    def do_exit(self, arg):
        "Exit the shell."
        print(f"{Colors.DIM}Bye.{Colors.RESET}")
        return True

    do_quit = do_exit

    def do_EOF(self, arg):
        "Exit the shell on Ctrl-D."
        print()
        return self.do_exit(arg)

    def emptyline(self):
        pass

    def default(self, line):
        print(f"{Colors.RED}Unknown command: {line!r}. Type 'help' for a list.{Colors.RESET}")


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    initial_path = argv[0] if argv else None
    LogShell(initial_path=initial_path).cmdloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())