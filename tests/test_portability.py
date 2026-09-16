"""First-run checks in a clean, non-ASCII path, without site-packages."""

import csv
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from ioc_collector.cli import query_main, write_table
from ioc_collector.database import Database
from ioc_collector.normalize import normalize
from ioc_collector.sources import Source

ROOT = Path(__file__).resolve().parent.parent


class FirstRunTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.project = self.base / "Чистая копия проекта"
        self.project.mkdir()
        for file in ("collect.py", "ioc.py"):
            shutil.copy2(ROOT / file, self.project / file)
        shutil.copytree(ROOT / "ioc_collector", self.project / "ioc_collector",
                        ignore=shutil.ignore_patterns("__pycache__"))
        shutil.copytree(ROOT / "examples" / "feeds", self.project / "examples" / "feeds")
        self.db = self.base / "Новая база" / "индикаторы.sqlite3"
        self.env = {k: v for k, v in os.environ.items()
                    if not k.startswith(("PYTHON", "ABUSECH", "PHISHTANK"))}
        # The CLI must produce UTF-8 even with a restrictive inherited code page.
        self.env["PYTHONIOENCODING"] = "ascii"

    def call(self, script, *args):
        return subprocess.run([sys.executable, "-S", str(self.project / script), *args],
                              cwd=self.base, env=self.env, capture_output=True, timeout=30,
                              text=True, encoding="utf-8")

    def collect(self):
        result = self.call("collect.py", "--demo", "--db", str(self.db))
        self.assertEqual(result.returncode, 0, result.stderr)
        return result

    def test_clean_first_run_and_repeat_from_another_directory(self):
        self.assertFalse(self.db.exists())
        first = self.collect()
        self.assertIn(str(self.db), first.stdout)
        self.collect()
        result = self.call("ioc.py", "--db", str(self.db), "--stats")
        self.assertEqual(result.returncode, 0, result.stderr)
        stats = json.loads(result.stdout)
        self.assertEqual(stats["total"], 10)
        self.assertEqual(stats["levels"], {"Critical": 1, "High": 4, "Medium": 5})
        self.assertTrue(all(s["status"] == "ok" for s in stats["sources"]))
        self.assertFalse((self.project / "data").exists())

    def test_help_needs_no_database_or_installed_packages(self):
        for script in ("collect.py", "ioc.py"):
            with self.subTest(script=script):
                result = self.call(script, "--help")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("--db", result.stdout)
        self.assertFalse(self.db.exists())

    def test_all_export_formats_in_unicode_output_directory(self):
        self.collect()
        for format_name in ("json", "csv", "txt", "table"):
            with self.subTest(format=format_name):
                output = self.base / "Результаты" / ("выгрузка." + format_name)
                result = self.call("ioc.py", "--db", str(self.db), "--level", "critical",
                                   "--format", format_name, "--output", str(output))
                self.assertEqual(result.returncode, 0, result.stderr)
                content = output.read_text(encoding="utf-8")
                if format_name == "json":
                    row = json.loads(content)[0]
                    self.assertEqual(row["source_count"], 3)
                elif format_name == "csv":
                    row = list(csv.DictReader(io.StringIO(content)))[0]
                    self.assertEqual(row["source_count"], "3")
                else:
                    self.assertIn("192.0.2.10", content)

    def test_sqlite_integer_overflow_is_an_argument_error(self):
        for flag in ("--limit", "--offset"):
            with self.subTest(flag=flag):
                result = self.call("ioc.py", "--db", str(self.db), "--level", "critical",
                                   flag, str(2**63))
                self.assertEqual(result.returncode, 2)
                self.assertNotIn("Traceback", result.stderr)
        self.assertFalse(self.db.exists())

    def test_invalid_network_options_fail_before_creating_database(self):
        for option, value in (("--timeout", "nan"), ("--timeout", "inf"), ("--timeout", "0"),
                              ("--retries", "-1"), ("--retries", "6")):
            with self.subTest(option=option, value=value):
                result = self.call("collect.py", "--db", str(self.db), option, value)
                self.assertEqual(result.returncode, 2)
                self.assertNotIn("Traceback", result.stderr)
        self.assertFalse(self.db.exists())

    def test_hardlink_export_cannot_overwrite_database(self):
        self.collect()
        alias = self.base / "alias.csv"
        os.link(self.db, alias)
        result = self.call("ioc.py", "--db", str(self.db), "--level", "critical",
                           "--format", "csv", "--output", str(alias))
        self.assertEqual(result.returncode, 1)
        self.assertIn("must not overwrite", result.stderr)
        with Database(self.db, readonly=True) as db:
            self.assertEqual(db.stats()["total"], 10)
            self.assertEqual(db.conn.execute("PRAGMA integrity_check").fetchone()[0], "ok")

    def test_failed_export_preserves_existing_file(self):
        self.collect()
        output = self.base / "existing.csv"
        output.write_text("previous export", encoding="utf-8")
        before = set(self.base.iterdir())
        def failed_write(rows, format_name, stream):
            stream.write("partial new export")
            raise OSError("disk full")
        with patch("ioc_collector.cli.write_rows", side_effect=failed_write):
            result = query_main(["--db", str(self.db), "--level", "critical",
                                 "--format", "csv", "--output", str(output)])
        self.assertEqual(result, 1)
        self.assertEqual(output.read_text(encoding="utf-8"), "previous export")
        self.assertEqual(set(self.base.iterdir()), before)

    def test_closed_output_pipe_does_not_report_a_crash(self):
        self.collect()
        with Database(self.db, dataset="demo") as db:
            db.replace_snapshot(Source("test", "Synthetic test source", ()),
                                [normalize(f"host{i}.example", "domain") for i in range(2000)])
        with subprocess.Popen([sys.executable, "-S", str(self.project / "ioc.py"),
                               "--db", str(self.db), "--level", "medium", "--limit", "0"],
                              cwd=self.base, env=self.env,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE) as process:
            self.assertTrue(process.stdout.read(100))
            process.stdout.close()
            code = process.wait(timeout=30)
            errors = process.stderr.read().decode("utf-8")
        self.assertEqual(code, 0, errors)
        self.assertNotIn("Traceback", errors)

    def test_table_wrap_keeps_header_and_rows_aligned(self):
        class Terminal(io.StringIO):
            def isatty(self):
                return True
        stream = Terminal()
        row = {"value": "long-" * 12 + "host.example", "type": "domain",
               "source_count": 3, "level": "Critical",
               "sources": ["blocklist_de", "cins_army", "threatview"],
               "updated_at": "2026-09-16T12:00:00.000000Z"}
        with patch("ioc_collector.cli.shutil.get_terminal_size", return_value=os.terminal_size((100, 24))):
            write_table([row], stream)
        lines = [line for line in stream.getvalue().splitlines() if "|" in line]
        separators = [i for i, char in enumerate(lines[0]) if char == "|"]
        self.assertGreater(len(lines), 2)
        for line in lines:
            self.assertEqual([i for i, char in enumerate(line) if char == "|"], separators)
            self.assertLessEqual(len(line), 100)


if __name__ == "__main__":
    unittest.main()
