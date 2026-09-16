from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import unittest

from ioc_collector.collector import collect
from ioc_collector.database import Database
from ioc_collector.feeds import FeedError
from ioc_collector.normalize import Indicator, normalize
from ioc_collector.sources import Source, Feed, SOURCES


class CollectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "test.sqlite3"
        self.db = Database(self.path, dataset="demo")
        self.addCleanup(self.db.conn.close)

    def test_demo_priorities_deduplication_and_idempotence(self):
        for _ in range(2):
            result = collect(self.db, demo=True)
            self.assertEqual(result.exit_code, 0)
            self.assertEqual(self.db.stats()["levels"], {"Critical": 1, "High": 4, "Medium": 5})
            self.assertEqual(self.db.stats()["total"], 10)
        ip = self.db.query(level="Critical")[0]
        self.assertEqual(ip["sources"], ["blocklist_de", "cins_army", "threatview"])
        self.assertEqual(ip["value"], "192.0.2.10")

    def test_all_three_priority_levels_without_fabricating_provider_data(self):
        indicator = normalize("192.0.2.10")
        for count, level in enumerate(("Medium", "High", "Critical"), 1):
            self.db.replace_snapshot(Source(f"test_{count}", "Synthetic test source", ()), [indicator])
            self.assertEqual(self.db.query(level=level)[0]["source_count"], count)

    def test_snapshot_removal_lowers_priority_and_deletes_orphans(self):
        collect(self.db, demo=True)
        self.db.replace_snapshot(SOURCES[1], [normalize("bad.example")], now="2026-01-02T00:00:00Z")
        high = {item["value"]: item for item in self.db.query(level="High")}
        self.assertEqual(set(high), {"192.0.2.10", "198.51.100.4"})
        medium = {item["value"]: item for item in self.db.query(level="Medium")}
        self.assertEqual(high["192.0.2.10"]["source_count"], 2)
        self.assertEqual(high["192.0.2.10"]["updated_at"], "2026-01-02T00:00:00Z")
        self.assertNotIn("c2.example", medium)
        self.assertEqual(self.db.stats()["total"], 7)
        self.assertEqual(self.db.stats()["levels"]["Critical"], 0)

    def test_failure_preserves_good_snapshot_and_timestamp(self):
        collect(self.db, demo=True)
        before = self.db.query(level="Critical")[0]
        def failing_loader(feed):
            raise FeedError("temporary unavailability")
        result = collect(self.db, sources=[SOURCES[2]], loader=failing_loader)
        after = self.db.query(level="Critical")[0]
        self.assertEqual(result.exit_code, 1)
        self.assertEqual((after["source_count"], after["updated_at"]),
                         (before["source_count"], before["updated_at"]))
        self.assertEqual(after["source_details"][0]["status"], "error")

    def test_failed_first_source_does_not_stop_other_sources(self):
        def loader(feed):
            if feed == SOURCES[0].feeds[0]:
                raise FeedError("unavailable")
            return (Path(__file__).resolve().parent.parent / "examples" / "feeds" / feed.demo_file).read_text(encoding="utf-8")
        result = collect(self.db, loader=loader)
        self.assertEqual((result.succeeded, result.failed, result.exit_code), (2, 1, 2))
        self.assertEqual(self.db.query(level="High")[0]["source_count"], 2)

    def test_provider_with_two_feeds_is_updated_atomically(self):
        source = Source("test", "Synthetic multi-feed source", (
            Feed("ip", "https://example.test/ip", "ip", ""),
            Feed("domain", "https://example.test/domain", "domain", ""),
        ))
        collect(self.db, sources=[source], loader=lambda feed: "bad.example" if feed.kind == "domain" else "192.0.2.1")
        before = self.db.stats()["levels"]
        def loader(feed):
            if feed.kind == "domain":
                raise FeedError("domain feed unavailable")
            return "203.0.113.7"
        collect(self.db, sources=[source], loader=loader)
        self.assertEqual(self.db.stats()["levels"], before)
        self.assertIsNone(self.db.conn.execute("SELECT 1 FROM indicators WHERE value='203.0.113.7'").fetchone())

    def test_invalid_feed_does_not_erase_snapshot(self):
        collect(self.db, demo=True)
        before = self.db.stats()["levels"]
        collect(self.db, sources=[SOURCES[0]], loader=lambda feed: "<html>oops</html>")
        self.assertEqual(self.db.stats()["levels"], before)

    def test_database_error_rolls_back_entire_source(self):
        collect(self.db, demo=True)
        before = self.db.stats()
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.replace_snapshot(SOURCES[0], [Indicator("unsupported", "bad")])
        self.assertEqual(self.db.stats(), before)
        self.assertEqual(self.db.conn.execute("PRAGMA integrity_check").fetchone()[0], "ok")

    def test_demo_and_live_cannot_mix(self):
        with self.assertRaisesRegex(ValueError, "separate"):
            Database(self.path, dataset="live")

    def test_duplicate_subfeeds_cannot_inflate_source_count(self):
        source = Source("new", "new", (
            Feed("one", "https://example.test/one", "ip", "one.txt"),
            Feed("two", "https://example.test/two", "ip", "two.txt"),
        ))
        collect(self.db, sources=[source], loader=lambda feed: "192.0.2.1\n192.0.2.1")
        self.assertEqual(self.db.query(level="Medium")[0]["source_count"], 1)

    def test_source_count_matches_relational_data(self):
        collect(self.db, demo=True)
        mismatches = self.db.conn.execute("""
            SELECT i.id FROM indicators i JOIN observations o ON o.indicator_id=i.id
            GROUP BY i.id HAVING i.source_count != COUNT(DISTINCT o.source_id)
        """).fetchall()
        self.assertEqual(mismatches, [])

    def test_recovery_clears_error_and_updates_timestamp(self):
        collect(self.db, demo=True)
        self.db.record_failure(SOURCES[0], "timeout")
        collect(self.db, sources=[SOURCES[0]], demo=True)
        source = next(row for row in self.db.stats()["sources"] if row["id"] == SOURCES[0].id)
        self.assertEqual(source["status"], "ok")
        self.assertIsNone(source["error"])

    def test_sql_value_is_parameterized(self):
        collect(self.db, demo=True)
        self.assertEqual(self.db.query(level="High' OR 1=1 --"), [])
        self.assertEqual(self.db.stats()["total"], 10)


if __name__ == "__main__":
    unittest.main()
