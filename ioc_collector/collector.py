"""Collection orchestration; one failed provider does not stop the remaining ones."""

from dataclasses import dataclass
import logging
from pathlib import Path
from typing import Callable, Iterable

from .database import Database
from .feeds import FeedError, download_text, parse_feed
from .sources import Feed, Source, SOURCES

LOGGER = logging.getLogger(__name__)
DEMO_DIR = Path(__file__).resolve().parent.parent / "examples" / "feeds"


@dataclass
class CollectionResult:
    succeeded: int = 0
    failed: int = 0

    @property
    def exit_code(self) -> int:
        return 0 if not self.failed else (2 if self.succeeded else 1)


def collect(db: Database, *, sources: Iterable[Source] = SOURCES,
            demo: bool = False, timeout: float = 20, retries: int = 2,
            loader: Callable[[Feed], str] | None = None) -> CollectionResult:
    result = CollectionResult()
    for source in sources:
        try:
            indicators = set()
            invalid = duplicates = rows = 0
            # All feeds of a provider must succeed before replacing its snapshot.
            for feed in source.feeds:
                if loader is not None:
                    text = loader(feed)
                elif demo:
                    text = (DEMO_DIR / feed.demo_file).read_text(encoding="utf-8-sig")
                else:
                    text = download_text(feed.url, timeout=timeout, retries=retries)
                parsed = parse_feed(text, feed.kind)
                duplicates += parsed.duplicates + len(indicators & parsed.indicators)
                indicators.update(parsed.indicators)
                invalid += parsed.invalid
                rows += parsed.rows
                LOGGER.info("%s/%s: rows=%d unique=%d invalid=%d",
                            source.id, feed.name, parsed.rows, len(parsed.indicators), parsed.invalid)
            if not source.feeds:
                raise FeedError("Source has no feeds configured")
            db.replace_snapshot(source, indicators, invalid=invalid)
            result.succeeded += 1
            LOGGER.info("%s: OK unique=%d rows=%d duplicates=%d invalid=%d",
                        source.id, len(indicators), rows, duplicates, invalid)
        except (FeedError, OSError, ValueError) as exc:
            db.record_failure(source, str(exc))
            result.failed += 1
            LOGGER.error("%s: FAILED: %s; previous snapshot preserved", source.id, exc)
    return result
