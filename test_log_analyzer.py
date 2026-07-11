import unittest
from datetime import datetime
from log_analyzer import LogAnalyzer, parse_line


VALID_LINE = (
    '203.0.113.42 - - [01/Jun/2026:09:14:22 +0000] '
    '"GET /products/1877 HTTP/1.1" 200 5324 "-" "Mozilla/5.0"'
)

VALID_LINE_NO_SIZE = (
    '198.51.100.7 - - [01/Jun/2026:10:00:00 +0000] '
    '"POST /api/login HTTP/1.1" 401 - "-" "curl/8.0"'
)


class TestParseLine(unittest.TestCase):
    def test_parses_valid_line_correctly(self):
        result = parse_line(VALID_LINE)
        self.assertIsNotNone(result)
        self.assertEqual(result["ip"], "203.0.113.42")
        self.assertEqual(result["method"], "GET")
        self.assertEqual(result["path"], "/products/1877")
        self.assertEqual(result["protocol"], "HTTP/1.1")
        self.assertEqual(result["status"], 200)
        self.assertEqual(result["size"], 5324)
        self.assertEqual(
            result["timestamp"],
            datetime(2026, 6, 1, 9, 14, 22, tzinfo=result["timestamp"].tzinfo),
        )

    def test_dash_size_is_zero(self):
        result = parse_line(VALID_LINE_NO_SIZE)
        self.assertIsNotNone(result)
        self.assertEqual(result["size"], 0)
        self.assertEqual(result["status"], 401)

    def test_empty_line_returns_none(self):
        self.assertIsNone(parse_line(""))
        self.assertIsNone(parse_line("\n"))
        self.assertIsNone(parse_line("   "))

    def test_truncated_line_returns_none(self):
        truncated = '203.0.113.42 - - [01/Jun/2026:09:14:22 +0000] "GET /prod'
        self.assertIsNone(parse_line(truncated))

    def test_missing_quotes_returns_none(self):
        broken = '203.0.113.42 - - [01/Jun/2026:09:14:22 +0000] GET /x HTTP/1.1 200 100 - -'
        self.assertIsNone(parse_line(broken))

    def test_invalid_status_code_returns_none(self):
        bad_status = (
            '203.0.113.42 - - [01/Jun/2026:09:14:22 +0000] '
            '"GET /x HTTP/1.1" XYZ 100 "-" "-"'
        )
        self.assertIsNone(parse_line(bad_status))

    def test_invalid_timestamp_returns_none(self):
        bad_ts = (
            '203.0.113.42 - - [not-a-date] '
            '"GET /x HTTP/1.1" 200 100 "-" "-"'
        )
        self.assertIsNone(parse_line(bad_ts))

    def test_garbage_line_does_not_raise(self):
        garbage_lines = [
            "this is not a log line at all",
            "12345",
            '"""""',
            None,
        ]
        for gl in garbage_lines:
            if gl is None:
                continue
            try:
                result = parse_line(gl)
            except Exception as exc:  # noqa: BLE001
                self.fail(f"parse_line raised an exception on bad input: {exc}")
            self.assertIsNone(result)


class TestLogAnalyzerAggregation(unittest.TestCase):
    def setUp(self):
        self.analyzer = LogAnalyzer()
        self.sample_lines = [
            # two successful requests from two different IPs on the same path
            '203.0.113.42 - - [01/Jun/2026:09:00:00 +0000] "GET /home HTTP/1.1" 200 500 "-" "UA"',
            '203.0.113.99 - - [01/Jun/2026:09:05:00 +0000] "GET /home HTTP/1.1" 200 500 "-" "UA"',
            # one server error
            '203.0.113.42 - - [01/Jun/2026:09:10:00 +0000] "GET /cart HTTP/1.1" 500 0 "-" "UA"',
            # one malformed line
            'this is a broken line',
            # one 404
            '203.0.113.5 - - [01/Jun/2026:10:00:00 +0000] "GET /missing HTTP/1.1" 404 0 "-" "UA"',
        ]
        for line in self.sample_lines:
            self.analyzer.process_line(line)

    def test_total_and_bad_line_counts(self):
        self.assertEqual(self.analyzer.total_lines, 5)
        self.assertEqual(self.analyzer.parsed_count, 4)
        self.assertEqual(self.analyzer.bad_count, 1)

    def test_unique_ip_count(self):
        # 203.0.113.42 appears twice, so it should only be counted once
        self.assertEqual(len(self.analyzer.unique_ips), 3)

    def test_top_endpoints(self):
        top = self.analyzer.top_endpoints(1)
        self.assertEqual(top[0], ("/home", 2))

    def test_error_rate(self):
        # out of 4 parsed lines, 2 are errors (500 and 404) -> 50%
        self.assertAlmostEqual(self.analyzer.error_rate(), 50.0)

    def test_hourly_distribution(self):
        hourly = self.analyzer.hourly_counter
        self.assertEqual(hourly["2026-06-01 09:00"], 3)
        self.assertEqual(hourly["2026-06-01 10:00"], 1)

    def test_suspicious_login_detection(self):
        analyzer = LogAnalyzer(login_path_substr="login")
        # simulate a brute-force attack: one IP with 15 401s on /login
        attacker_line_template = (
            '198.51.100.7 - - [01/Jun/2026:11:{sec:02d}:00 +0000] '
            '"POST /login HTTP/1.1" 401 0 "-" "UA"'
        )
        for i in range(15):
            analyzer.process_line(attacker_line_template.format(sec=i))
        # a normal user with a single 401
        analyzer.process_line(
            '203.0.113.5 - - [01/Jun/2026:11:20:00 +0000] "POST /login HTTP/1.1" 401 0 "-" "UA"'
        )

        suspicious = analyzer.suspicious_ips(threshold=10)
        self.assertEqual(len(suspicious), 1)
        self.assertEqual(suspicious[0][0], "198.51.100.7")
        self.assertEqual(suspicious[0][1], 15)

    def test_error_spike_detection(self):
        analyzer = LogAnalyzer()
        # baseline hours: low error rate across a few different hours
        for hour in range(8, 12):
            for i in range(20):
                status = 500 if i == 0 else 200  # ~5% errors in normal hours
                analyzer.process_line(
                    f'203.0.113.{i} - - [01/Jun/2026:{hour:02d}:00:00 +0000] '
                    f'"GET /x HTTP/1.1" {status} 100 "-" "UA"'
                )
        # hour 14: sharp error-rate spike (most requests return 500)
        for i in range(30):
            status = 500 if i < 25 else 200
            analyzer.process_line(
                f'203.0.113.{i} - - [01/Jun/2026:14:00:00 +0000] '
                f'"GET /x HTTP/1.1" {status} 100 "-" "UA"'
            )

        spikes = analyzer.detect_error_spikes(multiplier=2.0, min_requests=10)
        spike_hours = [s["hour"] for s in spikes]
        self.assertIn("2026-06-01 14:00", spike_hours)


if __name__ == "__main__":
    unittest.main()
