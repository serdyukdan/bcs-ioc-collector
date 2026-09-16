import io
from contextlib import redirect_stdout, redirect_stderr
import json
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
    def test_phishtank_filters_unverified_and_offline_and_ignores_metadata_urls(self):
        result = parse_feed((FIXTURES / "phishtank.csv").read_text(), "phishtank")
        self.assertEqual((len(result.indicators), result.duplicates, result.skipped), (2, 1, 2))
        self.assertEqual({item.type for item in result.indicators}, {"url"})
        self.assertFalse(any("report" in item.value for item in result.indicators))

    def test_malwarebazaar_commented_header_hashes_and_footer(self):
        result = parse_feed((FIXTURES / "malwarebazaar.csv").read_text(), "malwarebazaar")
        self.assertEqual(len(result.indicators), 6)
        self.assertEqual({item.type for item in result.indicators}, {"sha256", "sha1", "md5"})

    def test_threatfox_preserves_types_and_deduplicates(self):
        result = parse_feed((FIXTURES / "threatfox.json").read_text(), "threatfox")
        self.assertEqual((len(result.indicators), result.duplicates), (6, 1))
        self.assertEqual({item.type for item in result.indicators}, {"url", "domain", "ip_port", "sha256", "md5"})

    def test_api_error_is_not_an_empty_successful_snapshot(self):
        for document in ({"query_status": "no_api_key"}, {"query_status": "ok", "data": {}},
                         {"query_status": "ok", "data": [None]}, [], {}):
            with self.subTest(document=document), self.assertRaises(FeedError):
                parse_feed(json.dumps(document), "threatfox")
        self.assertEqual(parse_feed('{"query_status":"no_result"}', "threatfox").indicators, set())

    def test_unknown_threatfox_type_fails_quality_check(self):
        with self.assertRaises(FeedError):
            parse_feed('{"query_status":"ok","data":[{"ioc":"test","ioc_type":"new-type"}]}', "threatfox")

    def test_broken_csv_does_not_clear_snapshot(self):
        for text in ("url,verified\nhttps://example.test/,yes\n", "url,verified,online\na,yes\n",
                     'url,verified,online\n"unterminated,yes,yes', "url,verified,online\nhttps://x.test/,maybe,yes"):
            with self.subTest(text=text), self.assertRaises(FeedError):
                parse_feed(text, "phishtank")

    def test_standard_csv_quoted_commas_in_urls(self):
        parsed = parse_feed('url,verified,online\n"https://example.test/?a=1,2",yes,yes\n', "phishtank")
        self.assertEqual(next(iter(parsed.indicators)).value, "https://example.test/?a=1,2")


class CredentialTests(unittest.TestCase):
    def test_cli_partial_success_without_keys_keeps_public_source(self):
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "live.sqlite3"
            data = (FIXTURES / "phishtank.csv").read_text()
            with patch.dict(os.environ, {}, clear=True), patch("ioc_collector.collector.download_text", return_value=data) as download:
                with patch("ioc_collector.cli.configure_logging"), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    result = collect_main(["--db", str(path)])
                self.assertEqual(result, 2)
                self.assertEqual(download.call_count, 1)
            with Database(path, readonly=True) as db:
                self.assertEqual(db.stats()["total"], 2)
                statuses = {source["id"]: source["status"] for source in db.stats()["sources"]}
                self.assertEqual(statuses, {"phishtank": "ok", "threatfox": "error", "malwarebazaar": "error"})

    def test_missing_abuse_key_fails_before_network_and_phishtank_still_works(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(SOURCES[0].feeds[0].request_parameters()[0],
                             "https://data.phishtank.com/data/online-valid.csv")
            for source in SOURCES[1:]:
                with self.assertRaisesRegex(ValueError, "ABUSECH_AUTH_KEY"):
                    source.feeds[0].request_parameters()

    def test_correct_authentication_and_payload_per_source(self):
        with patch.dict(os.environ, {"ABUSECH_AUTH_KEY": "test-key", "PHISHTANK_APP_KEY": "test-app"}):
            self.assertIn("/test-app/online-valid.csv", SOURCES[0].feeds[0].request_parameters()[0])
            url, headers, data = SOURCES[1].feeds[0].request_parameters()
            self.assertEqual(headers["Auth-Key"], "test-key")
            self.assertEqual(json.loads(data), {"query": "get_iocs", "days": 7})
            self.assertEqual(SOURCES[2].feeds[0].request_parameters()[0],
                             "https://mb-api.abuse.ch/v2/files/exports/test-key/recent.csv")

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

    def test_phishtank_can_use_its_own_https_download_cdn(self):
        handler = SafeRedirectHandler()
        request = Request("https://data.phishtank.com/data/online-valid.csv")
        target = "https://cdn.phishtank.com/datadumps/verified_online.csv?Expires=1&Signature=test"
        redirect = handler.redirect_request(request, None, 302, "redirect", {}, target)
        self.assertEqual(redirect.full_url, target)
        request.add_header("Auth-Key", "test-key")
        with self.assertRaises(FeedError):
            handler.redirect_request(request, None, 302, "redirect", {}, target)


if __name__ == "__main__":
    unittest.main()
