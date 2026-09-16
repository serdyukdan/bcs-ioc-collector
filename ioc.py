"""Run a query: python ioc.py --level critical [--db path]."""

from ioc_collector.cli import query_main, run

if __name__ == "__main__":
    run(query_main)
