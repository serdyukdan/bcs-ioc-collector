"""Console commands and exports. Diagnostics go to stderr; data goes to stdout."""

import argparse
import csv
import json
import logging
import math
from pathlib import Path
import shutil
import sqlite3
import sys
import textwrap
from typing import TextIO

from .collector import collect
from .database import Database

DEFAULT_DB = Path("data/iocs.sqlite3")
FIELDS = ("value", "type", "source_count", "level", "sources", "updated_at")


def nonnegative(value: str) -> int:
    number = int(value)
    if number < 0:
        raise argparse.ArgumentTypeError("Expected a nonnegative integer")
    return number


def timeout_value(value: str) -> float:
    number = float(value)
    if not math.isfinite(number) or not 0 < number <= 120:
        raise argparse.ArgumentTypeError("Timeout must be between 0 and 120 seconds")
    return number


def configure_logging() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")


def collect_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Collect public IoCs into SQLite")
    parser.add_argument("--db", type=Path, help="Database path (default: data/iocs.sqlite3)")
    parser.add_argument("--demo", action="store_true", help="Use synthetic offline fixtures; default DB: data/demo.sqlite3")
    parser.add_argument("--timeout", type=timeout_value, default=20, help="Socket timeout in seconds (default: 20)")
    parser.add_argument("--retries", type=int, choices=range(6), default=2,
                        help="Retries after the first attempt, 0..5 (default: 2)")
    args = parser.parse_args(argv)
    configure_logging()
    path = args.db or (Path("data/demo.sqlite3") if args.demo else DEFAULT_DB)
    try:
        with Database(path, dataset="demo" if args.demo else "live") as db:
            if args.demo:
                logging.warning("DEMO: synthetic indicators, no network requests")
            result = collect(db, demo=args.demo, timeout=args.timeout, retries=args.retries)
            stats = db.stats()
            print(f"Sources: ok={result.succeeded} failed={result.failed}")
            print(f"Database: {path} ({stats['dataset']})")
            print(f"Total: {stats['total']}")
            print(" ".join(f"{level}={count}" for level, count in stats["levels"].items()))
            return result.exit_code
    except (OSError, sqlite3.Error, ValueError) as exc:
        logging.error("%s", exc)
        return 1
    except KeyboardInterrupt:
        logging.error("Interrupted; completed provider snapshots remain saved")
        return 130


def write_table(rows: list[dict], output: TextIO) -> None:
    cells = [[",".join(item[key]) if key == "sources" else str(item[key])
              for key in FIELDS] for item in rows]
    widths = [max(len(name), *(len(row[index]) for row in cells))
              if cells else len(name) for index, name in enumerate(FIELDS)]
    if output.isatty():
        available = shutil.get_terminal_size(fallback=(120, 24)).columns
        # Keep the header legible; wrap long values inside their own column.
        while sum(widths) + 3 * (len(FIELDS) - 1) > available:
            shrinkable = [index for index, name in enumerate(FIELDS)
                          if widths[index] > len(name)]
            if not shrinkable:
                break
            index = max(shrinkable, key=lambda index: widths[index])
            widths[index] -= 1
    separator = "-+-".join("-" * width for width in widths)
    output.write(" | ".join(name.ljust(width) for name, width in zip(FIELDS, widths)) + "\n")
    output.write(separator + "\n")
    for row in cells:
        wrapped = [textwrap.wrap(value, width=width, break_on_hyphens=False) or [""]
                   for value, width in zip(row, widths)]
        height = max(map(len, wrapped))
        for line_index in range(height):
            output.write(" | ".join(
                (lines[line_index] if line_index < len(lines) else "").ljust(width)
                for lines, width in zip(wrapped, widths)) + "\n")
        if height > 1:
            output.write(separator + "\n")


def write_rows(rows: list[dict], format_name: str, output: TextIO) -> None:
    if format_name == "json":
        json.dump(rows, output, ensure_ascii=False, indent=2)
        output.write("\n")
    elif format_name == "csv":
        writer = csv.DictWriter(output, fieldnames=FIELDS)
        writer.writeheader()
        for item in rows:
            writer.writerow({key: ";".join(item[key]) if key == "sources" else item[key]
                             for key in FIELDS})
    elif format_name == "txt":
        for item in rows:
            output.write(item["value"] + "\n")
    else:
        write_table(rows, output)


def query_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Query IoCs by priority or show collection statistics")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--level", type=str.capitalize, choices=("Critical", "High", "Medium"))
    mode.add_argument("--stats", action="store_true", help="Show statistics and source health as JSON")
    parser.add_argument("--db", type=Path, default=DEFAULT_DB)
    parser.add_argument("--limit", type=nonnegative, default=100, help="Maximum rows; 0 = all (default: 100)")
    parser.add_argument("--offset", type=nonnegative, default=0)
    parser.add_argument("--format", choices=("table", "json", "csv", "txt"), default="table")
    parser.add_argument("--output", type=Path, help="Write UTF-8 output to a file instead of stdout")
    args = parser.parse_args(argv)
    configure_logging()
    try:
        if args.output and args.output.resolve() in {
            args.db.resolve(), Path(str(args.db) + "-wal").resolve(),
            Path(str(args.db) + "-shm").resolve(),
        }:
            raise ValueError("Export path must not overwrite the database or its sidecar files")
        with Database(args.db, readonly=True) as db:
            # Keep the result and its source details consistent during a concurrent collection.
            db.conn.execute("BEGIN")
            stats = db.stats()
            if db.dataset == "demo":
                logging.warning("DEMO database: synthetic indicators")
            failed = [s["id"] for s in stats["sources"] if s["status"] == "error"]
            if failed:
                logging.warning("Last collection failed for %s; last good snapshots may be stale", ", ".join(failed))
            rows = [] if args.stats else db.query(level=args.level, limit=args.limit, offset=args.offset)
        def emit(output: TextIO) -> None:
            if args.stats:
                json.dump(stats, output, ensure_ascii=False, indent=2)
                output.write("\n")
            else:
                write_rows(rows, args.format, output)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            with args.output.open("w", encoding="utf-8", newline="") as output:
                emit(output)
        else:
            emit(sys.stdout)
        if not args.stats:
            logging.info("Shown: %d of %d %s indicators (offset=%d)",
                         len(rows), stats["levels"][args.level], args.level, args.offset)
        return 0
    except (OSError, sqlite3.Error, ValueError) as exc:
        logging.error("%s", exc)
        return 1


def run(command) -> None:
    try:
        raise SystemExit(command())
    except BrokenPipeError:
        # Allow commands such as `python ioc.py ... | head`.
        raise SystemExit(0) from None
