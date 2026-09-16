"""Run collection: python collect.py [--demo] [--db path]."""

from ioc_collector.cli import collect_main, run

if __name__ == "__main__":
    run(collect_main)
