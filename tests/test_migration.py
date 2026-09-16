from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from ioc_collector.database import Database
from ioc_collector.normalize import normalize
from ioc_collector.sources import SOURCES


class MigrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "legacy.sqlite3"
        conn = sqlite3.connect(self.path)
        conn.executescript((Path(__file__).parent / "fixtures/schema_v1.sql").read_text())
        conn.execute("INSERT INTO metadata VALUES ('schema_version','1')")
        conn.execute("INSERT INTO metadata VALUES ('dataset','live')")
        conn.execute("INSERT INTO sources(id,name,status,last_attempt,last_success) VALUES ('old','Old','ok','t1','t1')")
        conn.execute("INSERT INTO indicators(id,type,value,first_seen,updated_at) VALUES (42,'ipv4','192.0.2.1','t1','t1')")
        conn.execute("INSERT INTO observations VALUES (42,'old','t1','t1')")
        conn.commit()
        conn.close()

    def test_v1_is_backed_up_and_migrated_without_losing_observations(self):
        with Database(self.path, dataset="live") as db:
            self.assertEqual(db.schema_version, "2")
            self.assertEqual(db.query(level="Medium")[0]["sources"], ["old"])
            self.assertEqual(db.conn.execute("SELECT id FROM indicators").fetchone()[0], 42)
            db.replace_snapshot(SOURCES[0], [normalize("https://example.test/", "url")])
            self.assertEqual(db.conn.execute("PRAGMA integrity_check").fetchone()[0], "ok")
            self.assertEqual(db.conn.execute("PRAGMA foreign_key_check").fetchall(), [])
        backups = list(self.path.parent.glob("*.v1-*.bak"))
        self.assertEqual(len(backups), 1)
        with Database(backups[0], readonly=True) as old:
            self.assertEqual(old.schema_version, "1")
            self.assertEqual(old.stats()["total"], 1)
        with Database(self.path, dataset="live"):
            pass
        self.assertEqual(len(list(self.path.parent.glob("*.v1-*.bak"))), 1)

    def test_readonly_does_not_migrate_or_create_backup(self):
        with Database(self.path, readonly=True) as db:
            self.assertEqual(db.schema_version, "1")
        self.assertEqual(list(self.path.parent.glob("*.bak")), [])

    def test_wrong_dataset_is_rejected_before_migration(self):
        with self.assertRaisesRegex(ValueError, "separate"):
            Database(self.path, dataset="demo")
        with Database(self.path, readonly=True) as db:
            self.assertEqual(db.schema_version, "1")
        self.assertEqual(list(self.path.parent.glob("*.bak")), [])

    def test_removed_sources_cannot_inflate_new_priorities(self):
        with Database(self.path, dataset="live") as db:
            shared = normalize("192.0.2.1")
            db.replace_snapshot(SOURCES[1], [shared])
            self.assertEqual(db.query(level="High")[0]["source_count"], 2)
            self.assertEqual(db.synchronize_sources(SOURCES), ["old"])
            row = db.query(level="Medium")[0]
            self.assertEqual(row["sources"], ["threatview"])
            self.assertEqual(row["source_count"], 1)
            self.assertEqual(db.conn.execute("PRAGMA foreign_key_check").fetchall(), [])

    def test_obsolete_only_indicators_are_removed(self):
        with Database(self.path, dataset="live") as db:
            db.synchronize_sources(SOURCES)
            self.assertEqual(db.stats()["total"], 0)
            self.assertEqual(db.stats()["sources"], [])

    def test_backup_failure_leaves_v1_unchanged(self):
        with patch.object(Path, "open", side_effect=OSError("disk full")), self.assertRaises(OSError):
            Database(self.path, dataset="live")
        with Database(self.path, readonly=True) as db:
            self.assertEqual(db.schema_version, "1")
            self.assertEqual(db.stats()["total"], 1)

    def test_source_change_backs_up_v2_before_removing_old_data(self):
        with Database(self.path, dataset="live") as db:
            self.assertEqual(db.synchronize_sources(SOURCES), ["old"])
            self.assertEqual(db.synchronize_sources(SOURCES), [])
            self.assertEqual(db.stats()["total"], 0)
        backups = list(self.path.parent.glob("*.sources-*.bak"))
        self.assertEqual(len(backups), 1)
        with Database(backups[0], readonly=True) as original:
            self.assertEqual(original.schema_version, "2")
            self.assertEqual(original.stats()["total"], 1)
            self.assertEqual(original.query(level="Medium")[0]["sources"], ["old"])

    def test_failed_source_change_backup_preserves_current_sources(self):
        with Database(self.path, dataset="live") as db:
            with patch.object(db, "_backup", side_effect=OSError("disk full")), self.assertRaises(OSError):
                db.synchronize_sources(SOURCES)
            self.assertEqual(db.query(level="Medium")[0]["sources"], ["old"])


if __name__ == "__main__":
    unittest.main()
