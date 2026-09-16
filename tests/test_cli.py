import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

ROOT = Path(__file__).resolve().parent.parent


class CLITests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db = Path(self.temp.name) / "test.sqlite3"

    def run_cli(self, script, *args):
        return subprocess.run([sys.executable, str(ROOT / script), "--db", str(self.db), *args],
                              capture_output=True, text=True, encoding="utf-8", cwd=ROOT,
                              env={**os.environ, "PYTHONIOENCODING": "utf-8"})

    def test_demo_query_and_json_export(self):
        result = self.run_cli("collect.py", "--demo")
        self.assertEqual(result.returncode, 0, result.stderr)
        result = self.run_cli("ioc.py", "--level", "hIgH", "--format", "json")
        self.assertEqual(result.returncode, 0, result.stderr)
        rows = json.loads(result.stdout)
        self.assertEqual(len(rows), 3)
        self.assertTrue(all(row["source_count"] == 2 for row in rows))
        self.assertEqual({row["type"] for row in rows}, {"url", "sha256", "md5"})
        self.assertNotIn("WARNING", result.stdout)

    def test_csv_file_export(self):
        self.run_cli("collect.py", "--demo")
        output = Path(self.temp.name) / "high.csv"
        result = self.run_cli("ioc.py", "--level", "high", "--format", "csv", "--output", str(output))
        self.assertEqual(result.returncode, 0, result.stderr)
        text = output.read_text(encoding="utf-8")
        self.assertIn("https://login.example/Account?A=1", text)
        self.assertIn("a" * 64, text)
        self.assertEqual(len(text.splitlines()), 4)

    def test_critical_can_be_empty_with_disjoint_provider_types(self):
        self.run_cli("collect.py", "--demo")
        result = self.run_cli("ioc.py", "--level", "critical", "--format", "json")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), [])

    def test_missing_database_does_not_create_file(self):
        result = self.run_cli("ioc.py", "--level", "medium")
        self.assertEqual(result.returncode, 1)
        self.assertFalse(self.db.exists())

    def test_wrong_level_and_negative_limit(self):
        for args in (("--level", "urgent"), ("--level", "high", "--limit", "-1")):
            self.assertEqual(self.run_cli("ioc.py", *args).returncode, 2)

    def test_limit_offset_and_all(self):
        self.run_cli("collect.py", "--demo")
        result = self.run_cli("ioc.py", "--level", "medium", "--format", "json", "--limit", "0")
        all_rows = json.loads(result.stdout)
        result = self.run_cli("ioc.py", "--level", "medium", "--format", "json", "--limit", "1", "--offset", "1")
        self.assertEqual(json.loads(result.stdout), all_rows[1:2])

    def test_cannot_export_over_database(self):
        self.run_cli("collect.py", "--demo")
        result = self.run_cli("ioc.py", "--level", "high", "--output", str(self.db))
        self.assertEqual(result.returncode, 1)
        self.assertEqual(self.run_cli("ioc.py", "--stats").returncode, 0)


if __name__ == "__main__":
    unittest.main()
