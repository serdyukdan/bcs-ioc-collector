"""Bounded HTTPS requests and strict parsers for each source's actual format."""

from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import http.client
import logging
import ssl
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, HTTPRedirectHandler, build_opener
from urllib.parse import urlsplit

from .normalize import Indicator, normalize

LOGGER = logging.getLogger(__name__)
MAX_BYTES = 32 * 1024 * 1024


class FeedError(Exception):
    """A source failed to provide a usable, complete snapshot."""


class SafeRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        old, new = urlsplit(request.full_url), urlsplit(newurl)
        same_origin = (new.hostname, new.port or 443) == (old.hostname, old.port or 443)
        if new.scheme != "https" or not same_origin:
            raise FeedError("Cross-origin or non-HTTPS feed redirect rejected")
        return super().redirect_request(request, fp, code, msg, headers, newurl)


urlopen = build_opener(SafeRedirectHandler()).open


@dataclass
class ParsedFeed:
    indicators: set[Indicator]
    rows: int
    invalid: int
    duplicates: int


def parse_feed(text: str, kind: str) -> ParsedFeed:
    if any(tag in text[:512].lower() for tag in ("<!doctype html", "<html", "<body")):
        raise FeedError("HTML received instead of a feed")
    candidates = []
    for line in text.lstrip("\ufeff").splitlines():
        line = line.strip()
        if not line or line.startswith(("#", ";", "//")):
            continue
        candidates.append((line, kind))
    return _normalize_candidates(candidates)


def _normalize_candidates(candidates: list[tuple[str, str]]) -> ParsedFeed:
    indicators: set[Indicator] = set()
    rows = invalid = duplicates = 0
    for value, kind in candidates:
        rows += 1
        try:
            indicator = normalize(value, kind)
        except ValueError:
            invalid += 1
            continue
        if indicator in indicators:
            duplicates += 1
        indicators.add(indicator)
    # These feeds are normally nonempty. Never erase a known snapshot after a
    # silent server error, an empty response or an incompatible format change.
    if not indicators:
        raise FeedError("Empty feed or no valid indicators; previous snapshot preserved")
    if rows and invalid / rows > 0.10:
        raise FeedError(f"Too many invalid rows: {invalid}/{rows} (>10%)")
    return ParsedFeed(indicators, rows, invalid, duplicates)


def _retry_delay(retry_after: str | None, attempt: int) -> float:
    if retry_after:
        try:
            seconds = float(retry_after)
        except ValueError:
            try:
                seconds = (parsedate_to_datetime(retry_after)
                           - datetime.now(timezone.utc)).total_seconds()
            except (ValueError, TypeError, OverflowError):
                seconds = 2 ** attempt
        return min(30.0, max(0.0, seconds))
    return float(2 ** attempt)


def download_text(url: str, *, timeout: float = 20, retries: int = 2,
                  max_bytes: int = MAX_BYTES, headers: dict[str, str] | None = None,
                  data: bytes | None = None) -> str:
    """Retry transient HTTP/network errors. TLS verification remains enabled."""
    if not url.startswith("https://"):
        raise FeedError("Only HTTPS feed URLs are allowed")
    # Paths may contain API keys. Diagnostics must never print the request URL
    # or arbitrary exception text returned by HTTP/proxy libraries.
    label = urlsplit(url).hostname or "feed server"
    request = Request(url, data=data, headers={
        "User-Agent": "Public-IoC-Collector/1.0",
        "Accept": "application/json, text/csv, text/plain",
        "Accept-Encoding": "identity",
        **(headers or {}),
    })
    for attempt in range(retries + 1):
        retry_after = None
        try:
            with urlopen(request, timeout=timeout) as response:
                if not response.geturl().startswith("https://"):
                    raise FeedError("Feed redirected to a non-HTTPS URL")
                if response.status != 200:
                    raise FeedError(f"Unexpected HTTP status: {response.status}")
                if "text/html" in response.headers.get("Content-Type", "").lower():
                    raise FeedError("HTML response instead of a text feed")
                if response.headers.get("Content-Encoding", "identity").lower() != "identity":
                    raise FeedError("Unexpected compressed response to identity request")
                length = response.headers.get("Content-Length")
                if length and int(length) > max_bytes:
                    raise FeedError(f"Feed exceeds {max_bytes} bytes")
                body = response.read(max_bytes + 1)
                if len(body) > max_bytes:
                    raise FeedError(f"Feed exceeds {max_bytes} bytes")
                if length and len(body) != int(length):
                    raise FeedError("Truncated response; Content-Length does not match")
                return body.decode("utf-8-sig")
        except HTTPError as exc:
            retryable = exc.code in {408, 429, 500, 502, 503, 504}
            retry_after = exc.headers.get("Retry-After")
            message = f"HTTP {exc.code} from {label}"
            exc.close()
            if not retryable:
                raise FeedError(message) from None
        except (URLError, TimeoutError, OSError, http.client.HTTPException) as exc:
            if isinstance(exc, ssl.SSLCertVerificationError) or isinstance(
                    getattr(exc, "reason", None), ssl.SSLCertVerificationError):
                raise FeedError(f"TLS certificate verification failed for {label}") from None
            message = f"Network error from {label} ({type(exc).__name__})"
        except (UnicodeError, ValueError) as exc:
            raise FeedError(f"Invalid response from {label} ({type(exc).__name__})") from None
        if attempt == retries:
            raise FeedError(message)
        delay = _retry_delay(retry_after, attempt)
        LOGGER.warning("%s; retry in %.1f s", message, delay)
        time.sleep(delay)
    raise AssertionError("Unreachable")
