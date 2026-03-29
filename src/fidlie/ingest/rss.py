"""RSS feed ingestion module for DailyCTI.

Provides feed fetching with conditional request support (ETag / Last-Modified),
per-domain rate limiting, HTML stripping, date parsing, and URL normalization.
"""

from __future__ import annotations

import hashlib
import html
import re
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import feedparser

# Tracking query parameters to strip during URL normalization
_TRACKING_PARAMS = frozenset({
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "utm_term",
    "utm_content",
    "fbclid",
    "gclid",
    "gclsrc",
    "mc_cid",
    "mc_eid",
})

# Per-domain rate limit overrides (seconds between requests)
_DOMAIN_RATE_LIMITS: dict[str, float] = {
    "services.nvd.nist.gov": 6.0,
    "www.reddit.com": 2.0,
    "reddit.com": 2.0,
    "old.reddit.com": 2.0,
}

_DEFAULT_RATE_LIMIT = 1.0


# ---------------------------------------------------------------------------
# strip_html
# ---------------------------------------------------------------------------

def strip_html(text: str | None) -> str:
    """Remove HTML tags, decode entities, and collapse whitespace.

    Parameters
    ----------
    text : str | None
        Raw HTML string (or None).

    Returns
    -------
    str
        Plain text with tags removed and entities decoded.
    """
    if text is None:
        return ""
    if not text:
        return ""

    # Remove <script>...</script> and <style>...</style> blocks entirely
    cleaned = re.sub(r"<script[\s\S]*?</script>", "", text, flags=re.IGNORECASE)
    cleaned = re.sub(r"<style[\s\S]*?</style>", "", cleaned, flags=re.IGNORECASE)

    # Remove all remaining HTML tags
    cleaned = re.sub(r"<[^>]+>", "", cleaned)

    # Decode HTML entities
    cleaned = html.unescape(cleaned)

    # Collapse whitespace
    cleaned = re.sub(r"\s+", " ", cleaned).strip()

    return cleaned


# ---------------------------------------------------------------------------
# parse_published_date
# ---------------------------------------------------------------------------

def parse_published_date(date_input: Any) -> Optional[datetime]:
    """Parse a date from a feedparser entry into a datetime object.

    Handles ISO-8601, RFC-2822, epoch timestamps, date-only strings,
    and feedparser struct_time objects.

    Parameters
    ----------
    date_input : Any
        Date string, epoch timestamp string, struct_time, or None.

    Returns
    -------
    datetime | None
        Parsed datetime (timezone-aware when possible), or None if unparseable.
    """
    if date_input is None:
        return None

    if isinstance(date_input, datetime):
        return date_input

    # Handle struct_time from feedparser
    if hasattr(date_input, "tm_year"):
        try:
            import calendar
            epoch = calendar.timegm(date_input)
            return datetime.fromtimestamp(epoch, tz=timezone.utc)
        except (ValueError, OverflowError):
            return None

    if not isinstance(date_input, str):
        return None

    date_str = date_input.strip()
    if not date_str:
        return None

    # Try ISO-8601 with Z suffix
    if date_str.endswith("Z"):
        try:
            return datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        except ValueError:
            pass

    # Try ISO-8601 with offset
    try:
        return datetime.fromisoformat(date_str)
    except ValueError:
        pass

    # Try RFC-2822
    try:
        return parsedate_to_datetime(date_str)
    except (ValueError, TypeError):
        pass

    # Try epoch timestamp (pure digits, possibly with a decimal)
    if re.match(r"^\d+(\.\d+)?$", date_str):
        try:
            return datetime.fromtimestamp(float(date_str), tz=timezone.utc)
        except (ValueError, OverflowError, OSError):
            return None

    # Try date-only (YYYY-MM-DD)
    try:
        return datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        pass

    return None


# ---------------------------------------------------------------------------
# normalize_url
# ---------------------------------------------------------------------------

def normalize_url(url: str) -> str:
    """Normalize a URL for deduplication.

    - Lowercases scheme and host
    - Removes default ports (80 for http, 443 for https)
    - Strips fragment identifiers
    - Removes tracking query parameters (utm_*, fbclid, gclid, etc.)
    - Sorts remaining query parameters alphabetically
    - Removes trailing slash from path

    Parameters
    ----------
    url : str
        The URL to normalize.

    Returns
    -------
    str
        The normalized URL string.
    """
    parsed = urlparse(url)

    # Lowercase scheme and host
    scheme = parsed.scheme.lower()
    hostname = parsed.hostname.lower() if parsed.hostname else ""

    # Handle ports: strip defaults
    port = parsed.port
    if (scheme == "https" and port == 443) or (scheme == "http" and port == 80):
        port = None

    netloc = hostname
    if port:
        netloc = f"{hostname}:{port}"

    # Strip trailing slash from path
    path = parsed.path.rstrip("/")

    # Filter and sort query params
    params = parse_qs(parsed.query, keep_blank_values=True)
    filtered: list[tuple[str, str]] = []
    for key in sorted(params.keys()):
        if key.lower() not in _TRACKING_PARAMS:
            for val in params[key]:
                filtered.append((key, val))

    query = urlencode(filtered) if filtered else ""

    # No fragment
    return urlunparse((scheme, netloc, path, "", query, ""))


# ---------------------------------------------------------------------------
# parse_feed_entries
# ---------------------------------------------------------------------------

def parse_feed_entries(
    feed_data: list[dict[str, Any]],
    source_name: str = "",
) -> list[dict[str, Any]]:
    """Parse a list of feedparser entry dicts into normalized article dicts.

    Parameters
    ----------
    feed_data : list[dict]
        List of feedparser entry dictionaries.
    source_name : str, optional
        Name of the feed source.

    Returns
    -------
    list[dict]
        Normalized article dictionaries with keys: title, url, published,
        summary, author, tags, source, content_hash.
    """
    results: list[dict[str, Any]] = []

    for entry in feed_data:
        title = entry.get("title", "")
        link = entry.get("link", "")
        summary_raw = entry.get("summary", "")
        published_raw = entry.get("published")
        author = entry.get("author", "")

        # Extract tags
        tag_objects = entry.get("tags", [])
        tags: list[str] = []
        if tag_objects:
            for t in tag_objects:
                term = t.get("term", "") if isinstance(t, dict) else str(t)
                if term:
                    tags.append(term)

        # Normalize
        url = normalize_url(link) if link else ""
        summary = strip_html(summary_raw)
        published = parse_published_date(published_raw)

        # Content hash for dedup
        hash_input = f"{url}:{title}".encode("utf-8")
        content_hash = hashlib.sha256(hash_input).hexdigest()

        article = {
            "title": title,
            "url": link,  # Keep original link as url
            "published": published,
            "summary": summary,
            "author": author,
            "tags": tags,
            "source": source_name,
            "content_hash": content_hash,
            "normalized_url": url,
        }
        results.append(article)

    return results


# ---------------------------------------------------------------------------
# RSSFetcher
# ---------------------------------------------------------------------------

class RSSFetcher:
    """Async RSS feed fetcher with ETag/Last-Modified caching and rate limiting.

    Methods prefixed with ``_`` are designed to be overridden or mocked in tests.
    """

    def __init__(self) -> None:
        self._etag_store: dict[str, str] = {}
        self._last_modified_store: dict[str, str] = {}
        self._last_request_time: dict[str, float] = {}

    # -- Public API ---------------------------------------------------------

    async def fetch(self, url: str) -> list[dict[str, Any]] | None:
        """Fetch and parse an RSS feed.

        Parameters
        ----------
        url : str
            Feed URL.

        Returns
        -------
        list[dict] | None
            List of normalized article dicts, or None if 304/error/empty.
        """
        try:
            # Rate limiting
            await self._acquire_rate_token(url)

            # Build request headers
            headers: dict[str, str] = {}
            etag = self._get_stored_etag(url)
            if etag:
                headers["If-None-Match"] = etag

            last_modified = self._get_stored_last_modified(url)
            if last_modified:
                headers["If-Modified-Since"] = last_modified

            response = await self._http_get(url, headers=headers)

            if response.status_code == 304:
                return None

            if response.status_code != 200:
                return None

            body = response.text
            if not body or not body.strip():
                return None

            # Store conditional request headers for next time
            self._store_etag(url, response.headers)

            # Parse with feedparser
            feed = feedparser.parse(body)
            entries = feed.get("entries", [])

            if not entries:
                return None

            return parse_feed_entries(entries)

        except (ConnectionError, TimeoutError, OSError):
            return None

    # -- Rate limiting ------------------------------------------------------

    def get_rate_limit_for_domain(self, domain: str) -> float:
        """Return the rate limit (seconds between requests) for a domain."""
        # Check exact match first
        if domain in _DOMAIN_RATE_LIMITS:
            return _DOMAIN_RATE_LIMITS[domain]

        # Check if any known domain is a suffix
        for known_domain, rate in _DOMAIN_RATE_LIMITS.items():
            if domain.endswith(known_domain):
                return rate

        return _DEFAULT_RATE_LIMIT

    async def _acquire_rate_token(self, url: str) -> bool:
        """Enforce per-domain rate limiting. Returns True when ready."""
        import asyncio

        parsed = urlparse(url)
        domain = parsed.hostname or ""
        rate_limit = self.get_rate_limit_for_domain(domain)

        now = time.monotonic()
        last = self._last_request_time.get(domain, 0.0)
        elapsed = now - last

        if elapsed < rate_limit:
            await asyncio.sleep(rate_limit - elapsed)

        self._last_request_time[domain] = time.monotonic()
        return True

    # -- Conditional request storage ----------------------------------------

    def _get_stored_etag(self, url: str) -> str | None:
        return self._etag_store.get(url)

    def _get_stored_last_modified(self, url: str) -> str | None:
        return self._last_modified_store.get(url)

    def _store_etag(self, url: str, headers: dict[str, str]) -> None:
        """Store ETag and Last-Modified from response headers."""
        etag = headers.get("ETag")
        if etag:
            self._etag_store[url] = etag

        last_modified = headers.get("Last-Modified")
        if last_modified:
            self._last_modified_store[url] = last_modified

    # -- HTTP transport (mockable) ------------------------------------------

    async def _http_get(self, url: str, headers: dict[str, str] | None = None) -> Any:
        """Perform an async HTTP GET request.

        This is the low-level transport method that tests mock out.
        In production, this would use httpx.AsyncClient.
        """
        import httpx

        async with httpx.AsyncClient() as client:
            resp = await client.get(url, headers=headers or {}, timeout=30.0)
            return resp
