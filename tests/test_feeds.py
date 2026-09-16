from io import BytesIO
import unittest
from unittest.mock import patch
from urllib.error import HTTPError, URLError

from ioc_collector.feeds import FeedError, download_text, parse_feed, _retry_delay


URL = "https://feeds.example/list.txt"


class Response(BytesIO):
    status = 200

    def __init__(self, body=b"192.0.2.1\n", headers=None, url=URL):
        super().__init__(body)
        self.headers = {"Content-Type": "text/plain", **(headers or {})}
        self.url = url

    def geturl(self):
        return self.url


class FeedTests(unittest.TestCase):
    def test_bom_comments_and_deduplication(self):
        parsed = parse_feed("\ufeff# header\n; comment\n\n192.0.2[.]1\n192.0.2.1\n", "ip")
        self.assertEqual((len(parsed.indicators), parsed.rows, parsed.duplicates), (1, 2, 1))

    def test_invalid_row_is_counted(self):
        parsed = parse_feed("192.0.2.1\n" * 9 + "bad IP\n", "ip")
        self.assertEqual((parsed.invalid, parsed.duplicates), (1, 8))

    def test_empty_malformed_and_html_feeds_are_rejected(self):
        for text in ("", "# empty\n", "<html>error</html>", "192.0.2.1\nnot an ip\n"):
            with self.subTest(text=text), self.assertRaises(FeedError):
                parse_feed(text, "ip")

    @patch("ioc_collector.feeds.time.sleep")
    @patch("ioc_collector.feeds.urlopen")
    def test_transient_failure_is_retried(self, open_mock, sleep_mock):
        open_mock.side_effect = [URLError("temporary failure"), Response()]
        self.assertEqual(download_text(URL, retries=1), "192.0.2.1\n")
        self.assertEqual(open_mock.call_count, 2)
        sleep_mock.assert_called_once_with(1.0)

    @patch("ioc_collector.feeds.time.sleep")
    @patch("ioc_collector.feeds.urlopen")
    def test_rate_limit_respects_retry_after(self, open_mock, sleep_mock):
        open_mock.side_effect = [HTTPError(URL, 429, "rate limit", {"Retry-After": "3"}, None), Response()]
        download_text(URL, retries=1)
        sleep_mock.assert_called_once_with(3.0)

    @patch("ioc_collector.feeds.urlopen")
    def test_nonretryable_http_error(self, open_mock):
        open_mock.side_effect = HTTPError(URL, 404, "not found", {}, None)
        with self.assertRaises(FeedError):
            download_text(URL)
        self.assertEqual(open_mock.call_count, 1)

    @patch("ioc_collector.feeds.time.sleep")
    @patch("ioc_collector.feeds.urlopen", side_effect=URLError("unavailable"))
    def test_retry_count_is_bounded(self, open_mock, sleep_mock):
        with self.assertRaises(FeedError):
            download_text(URL, retries=2)
        self.assertEqual(open_mock.call_count, 3)
        self.assertEqual(sleep_mock.call_count, 2)

    def test_retry_after_is_capped(self):
        self.assertEqual(_retry_delay("999999", 0), 30)
        self.assertEqual(_retry_delay("invalid", 2), 4)

    def test_bad_responses_are_rejected(self):
        cases = [Response(b"01234567890"), Response(headers={"Content-Type": "text/html"}),
                 Response(headers={"Content-Length": "3"}),
                 Response(headers={"Content-Length": "not a number"}),
                 Response(headers={"Content-Encoding": "gzip"}), Response(b"\xff"),
                 Response(url="http://feeds.example/list.txt")]
        for response in cases:
            with self.subTest(response=response), patch("ioc_collector.feeds.urlopen", return_value=response):
                with self.assertRaises(FeedError):
                    download_text(URL, max_bytes=10, retries=0)

    def test_non_https_url_rejected_without_network(self):
        with patch("ioc_collector.feeds.urlopen") as open_mock, self.assertRaises(FeedError):
            download_text("http://feeds.example/list.txt")
        open_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main()
