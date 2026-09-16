import unittest

from ioc_collector.normalize import Indicator, normalize


class NormalizationTests(unittest.TestCase):
    def test_defanged_ip(self):
        self.assertEqual(normalize(" 192.0.2[.]10 "), Indicator("ipv4", "192.0.2.10"))

    def test_ipv6_equivalence(self):
        self.assertEqual(normalize("2001:0DB8:0:0:0:0:0:1"), normalize("[2001:db8::1]"))

    def test_domain_equivalence(self):
        self.assertEqual(normalize("Bad[.]Example."), normalize("bad.example"))

    def test_unicode_and_punycode_equivalence(self):
        self.assertEqual(normalize("пример.test"), normalize("xn--e1afmkfd.test"))

    def test_no_parent_domain_collapsing(self):
        self.assertNotEqual(normalize("sub.bad.example"), normalize("bad.example"))

    def test_invalid_values(self):
        for value in ("", "999.1.2.3", "192.000.2.1", "single-label", "https://bad.example",
                      "-bad.example", "bad..example", "bad.example..", "bad example.com",
                      "foo\nbar.example", "foo\x00bar.example", "a" * 64 + ".example",
                      "fe80::1%eth0", "*.example", "_bad.example", "a.xn--a"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                normalize(value)

    def test_expected_feed_type_is_enforced(self):
        for value, kind in (("bad.example", "ip"), ("192.0.2.1", "domain"), ("bad.example", "url")):
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                normalize(value, kind)


if __name__ == "__main__":
    unittest.main()
