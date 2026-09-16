import io
from contextlib import redirect_stdout, redirect_stderr
import os
from pathlib import Path
import unittest
from tempfile import TemporaryDirectory
from unittest.mock import patch
from urllib.error import HTTPError, URLError
from urllib.request import Request

from ioc_collector.feeds import FeedError, SafeRedirectHandler, download_text, parse_feed
from ioc_collector.normalize import Indicator, normalize
from ioc_collector.sources import SOURCES
from ioc_collector.cli import collect_main
from ioc_collector.database import Database

FIXTURES = Path(__file__).resolve().parent.parent / "examples" / "feeds"


class NewNormalizationTests(unittest.TestCase):
    def test_url_only_canonicalizes_scheme_authority_and_empty_path(self):
        self.assertEqual(normalize("hxxps://LOGIN[.]Example.:443/Account?A=1#Token", "url"),
                         Indicator("url", "https://login.example/Account?A=1#Token"))
        self.assertEqual(normalize("http://пример.test:80", "url").value,
                         "http://xn--e1afmkfd.test/")
        self.assertEqual(normalize("https://[2001:0db8::1]:8443/a", "url").value,
                         "https://[2001:db8::1]:8443/a")

    def test_url_scope_and_significant_components_are_preserved(self):
        base = normalize("https://example.test/Path?a=1&b=2#x", "url")
        for other in ("http://example.test/Path?a=1&b=2#x", "https://example.test/path?a=1&b=2#x",
                      "https://example.test/Path?b=2&a=1#x", "https://example.test/Path?a=1&b=2#y",
                      "https://example.test/%50ath?a=1&b=2#x"):
            self.assertNotEqual(base, normalize(other, "url"))
        for suffix in ("?", "#", "?#", "?#x", "?x#"):
            self.assertEqual(normalize("https://example.test/" + suffix, "url").value,
                             "https://example.test/" + suffix)

    def test_bad_urls_are_not_converted_to_domains(self):
        for value in ("example.test/path", "ftp://example.test/a", "https:///path", "https://x.test:0/",
                      "https://x.test:65536/", "https://x.test:/", "https://bad\\host.test/",
                      "https://[fe80::1%eth0]/", "https://x.test/a\nb"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                normalize(value, "url")

    def test_hash_types_lengths_and_case(self):
        for kind, length in (("md5", 32), ("sha1", 40), ("sha256", 64)):
            self.assertEqual(normalize("A" * length, kind), Indicator(kind, "a" * length))
            for value in ("g" * length, "a" * (length - 1), "a" * (length + 1)):
                with self.assertRaises(ValueError):
                    normalize(value, kind)

    def test_endpoint_port_is_preserved(self):
        self.assertEqual(normalize("192.0.2[.]1:00443", "ip_port").value, "192.0.2.1:443")
        self.assertEqual(normalize("[2001:0DB8::1]:443", "ip_port").value, "[2001:db8::1]:443")
        self.assertNotEqual(normalize("192.0.2.1:443", "ip_port"), normalize("192.0.2.1"))
        for value in ("example.test:443", "192.0.2.1:0", "192.0.2.1:65536", "2001:db8::1:443"):
            with self.assertRaises(ValueError):
                normalize(value, "ip_port")


class SourceParserTests(unittest.TestCase):
    def test_cins_ip_list_deduplicates_without_changing_type(self):
        result = parse_feed((FIXTURES / "cins_army.txt").read_text(), "ip")
        self.assertEqual((len(result.indicators), result.duplicates, result.invalid), (4, 1, 0))
        self.assertEqual({item.type for item in result.indicators}, {"ipv4"})

    def test_threatview_typed_lists_normalize_and_deduplicate(self):
        for file, kind, unique in (("threatview_ip.txt", "ip", 4),
                                   ("threatview_domain.txt", "domain", 2),
                                   ("threatview_md5.txt", "md5", 2)):
            with self.subTest(kind=kind):
                result = parse_feed((FIXTURES / file).read_text(), kind)
                self.assertEqual((len(result.indicators), result.duplicates), (unique, 1))

    def test_blocklist_preserves_both_ip_versions(self):
        result = parse_feed((FIXTURES / "blocklist_de.txt").read_text(), "ip")
        self.assertEqual(len(result.indicators), 4)
        self.assertEqual({item.type for item in result.indicators}, {"ipv4", "ipv6"})

    def test_empty_or_error_responses_cannot_erase_a_snapshot(self):
        for kind in ("ip", "domain", "md5"):
            for text in ("", "# temporary maintenance", '<html>error</html>', '{"error":"denied"}'):
                with self.subTest(kind=kind, text=text), self.assertRaises(FeedError):
                    parse_feed(text, kind)


class PublicSourceTests(unittest.TestCase):
    def test_live_cli_collects_all_three_sources_without_environment_credentials(self):
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "live.sqlite3"
            fixtures = {feed.url: (FIXTURES / feed.demo_file).read_text(encoding="utf-8")
                        for source in SOURCES for feed in source.feeds}
            def loader(url, **kwargs):
                self.assertEqual(set(kwargs), {"timeout", "retries"})
                return fixtures[url]
            with patch.dict(os.environ, {}, clear=True), patch("ioc_collector.collector.download_text", side_effect=loader) as download:
                with patch("ioc_collector.cli.configure_logging"), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    result = collect_main(["--db", str(path)])
                self.assertEqual(result, 0)
                self.assertEqual(download.call_count, 5)
            with Database(path, readonly=True) as db:
                self.assertEqual(db.stats()["total"], 10)
                self.assertEqual(db.stats()["levels"], {"Critical": 1, "High": 4, "Medium": 5})
                statuses = {source["id"]: source["status"] for source in db.stats()["sources"]}
                self.assertEqual(statuses, {"cins_army": "ok", "threatview": "ok", "blocklist_de": "ok"})

    def test_key_not_leaked_in_http_network_errors_or_retry_logs(self):
        key = "secret-for-test"
        url = "https://example.test/exports/" + key + "/recent.csv"
        for error in (HTTPError(url, 401, key, {}, None), URLError(url)):
            with patch("ioc_collector.feeds.urlopen", side_effect=error), self.assertRaises(FeedError) as raised:
                download_text(url, retries=0)
            self.assertNotIn(key, str(raised.exception))
        with patch("ioc_collector.feeds.urlopen", side_effect=URLError(url)), patch("ioc_collector.feeds.time.sleep"):
            with self.assertLogs("ioc_collector.feeds", "WARNING") as logs, self.assertRaises(FeedError):
                download_text(url, retries=1)
            self.assertNotIn(key, " ".join(logs.output))

    def test_redirect_cannot_send_key_to_different_origin_or_http(self):
        handler = SafeRedirectHandler()
        request = Request("https://example.test/api", headers={"Auth-Key": "test-key"})
        for target in ("http://example.test/api", "https://other.test/api", "https://example.test:444/api"):
            with self.assertRaises(FeedError):
                handler.redirect_request(request, None, 302, "redirect", {}, target)

    def test_same_origin_https_redirect_is_allowed(self):
        handler = SafeRedirectHandler()
        request = Request("https://example.test/feeds/current.txt")
        target = "https://example.test/feeds/latest.txt"
        redirect = handler.redirect_request(request, None, 302, "redirect", {}, target)
        self.assertEqual(redirect.full_url, target)


if __name__ == "__main__":
    unittest.main()
