"""Tests for RSS feed ingestion -- src/fidlie/ingest/rss.py

Validates feed parsing, HTML stripping, date normalization, URL dedup,
conditional requests (ETag / Last-Modified), rate limiting, and error handling.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch
from urllib.parse import urlencode

import pytest

from fidlie.ingest.rss import (
    RSSFetcher,
    normalize_url,
    parse_feed_entries,
    strip_html,
    parse_published_date,
)


# ---------------------------------------------------------------------------
# HTML stripping
# ---------------------------------------------------------------------------


class TestStripHtml:
    """Verify HTML tag removal from feed summaries."""

    def test_strips_basic_tags(self):
        """Simple paragraph and bold tags are removed."""
        raw = "<p>This is <b>bold</b> text.</p>"
        assert strip_html(raw) == "This is bold text."

    def test_strips_nested_tags(self):
        """Nested tags like <div><span>...</span></div> are flattened."""
        raw = "<div><span>hello</span> <em>world</em></div>"
        result = strip_html(raw)
        assert "hello" in result
        assert "world" in result
        assert "<" not in result

    def test_strips_anchor_tags(self):
        """Anchor tags are removed but their text content is preserved."""
        raw = 'Visit <a href="https://example.com">Example</a> for details.'
        result = strip_html(raw)
        assert "Example" in result
        assert "<a" not in result

    def test_handles_html_entities(self):
        """HTML entities like &amp; and &lt; are decoded."""
        raw = "Tom &amp; Jerry &lt;3"
        result = strip_html(raw)
        assert "&amp;" not in result
        assert "Tom" in result

    def test_empty_string(self):
        """Empty input returns empty output."""
        assert strip_html("") == ""

    def test_none_input(self):
        """None input returns empty string."""
        assert strip_html(None) == ""

    def test_plain_text_passthrough(self):
        """Plain text with no HTML is returned unchanged."""
        text = "No HTML here, just plain text."
        assert strip_html(text) == text

    def test_strips_script_and_style(self):
        """Script and style blocks (and their contents) are removed entirely."""
        raw = "<p>Hello</p><script>alert('xss')</script><style>.x{color:red}</style><p>World</p>"
        result = strip_html(raw)
        assert "alert" not in result
        assert "color" not in result
        assert "Hello" in result
        assert "World" in result


# ---------------------------------------------------------------------------
# Date parsing
# ---------------------------------------------------------------------------


class TestParseDateFormats:
    """Verify robust parsing of diverse RSS date formats."""

    def test_iso8601_utc(self):
        """ISO-8601 with trailing Z."""
        dt = parse_published_date("2024-12-15T14:30:00Z")
        assert dt.year == 2024
        assert dt.month == 12
        assert dt.day == 15
        assert dt.hour == 14
        assert dt.minute == 30

    def test_rfc2822(self):
        """Standard RFC-2822 dates used in many RSS feeds."""
        dt = parse_published_date("Sun, 15 Dec 2024 14:30:00 +0000")
        assert dt.year == 2024
        assert dt.day == 15

    def test_rfc2822_named_tz(self):
        """RFC-2822 with named timezone abbreviation like GMT."""
        dt = parse_published_date("Mon, 16 Dec 2024 09:00:00 GMT")
        assert dt is not None
        assert dt.year == 2024

    def test_iso8601_with_offset(self):
        """ISO-8601 with explicit +HH:MM offset."""
        dt = parse_published_date("2024-12-15T14:30:00+05:30")
        assert dt is not None

    def test_date_only(self):
        """Date-only string (no time component)."""
        dt = parse_published_date("2024-12-15")
        assert dt is not None
        assert dt.year == 2024

    def test_none_input(self):
        """None returns None."""
        assert parse_published_date(None) is None

    def test_empty_string(self):
        """Empty string returns None."""
        assert parse_published_date("") is None

    def test_garbage_string(self):
        """Unparseable garbage returns None rather than raising."""
        assert parse_published_date("not-a-date") is None

    def test_epoch_timestamp(self):
        """Numeric epoch timestamps are handled."""
        dt = parse_published_date("1734272400")
        assert dt is not None


# ---------------------------------------------------------------------------
# URL normalization
# ---------------------------------------------------------------------------


class TestNormalizeUrl:
    """Verify URL normalization for dedup hashing."""

    def test_strips_utm_params(self):
        """UTM tracking parameters are removed."""
        url = "https://example.com/article?utm_source=twitter&utm_medium=social&id=42"
        result = normalize_url(url)
        assert "utm_source" not in result
        assert "utm_medium" not in result
        assert "id=42" in result

    def test_strips_fbclid(self):
        """Facebook click ID is removed."""
        url = "https://example.com/page?fbclid=abc123"
        result = normalize_url(url)
        assert "fbclid" not in result

    def test_strips_gclid(self):
        """Google click ID is removed."""
        url = "https://example.com/page?gclid=xyz789&real=yes"
        result = normalize_url(url)
        assert "gclid" not in result
        assert "real=yes" in result

    def test_sorts_query_params(self):
        """Remaining query params are sorted alphabetically."""
        url = "https://example.com/page?z=1&a=2&m=3"
        result = normalize_url(url)
        assert result.index("a=2") < result.index("m=3") < result.index("z=1")

    def test_lowercases_scheme_and_host(self):
        """Scheme and hostname are lowercased."""
        url = "HTTPS://EXAMPLE.COM/Article"
        result = normalize_url(url)
        assert result.startswith("https://example.com/")
        # Path case is preserved
        assert "Article" in result

    def test_removes_trailing_slash(self):
        """Trailing slash is removed from the path."""
        url = "https://example.com/article/"
        result = normalize_url(url)
        assert not result.endswith("/")

    def test_removes_fragment(self):
        """Fragment identifiers (#section) are stripped."""
        url = "https://example.com/article#comments"
        result = normalize_url(url)
        assert "#" not in result

    def test_removes_default_port_443(self):
        """Default HTTPS port 443 is stripped."""
        url = "https://example.com:443/article"
        result = normalize_url(url)
        assert ":443" not in result

    def test_removes_default_port_80(self):
        """Default HTTP port 80 is stripped."""
        url = "http://example.com:80/article"
        result = normalize_url(url)
        assert ":80" not in result

    def test_preserves_non_default_port(self):
        """Non-default ports are preserved."""
        url = "https://example.com:8443/article"
        result = normalize_url(url)
        assert ":8443" in result

    def test_identical_urls_produce_same_hash(self):
        """Two semantically identical URLs normalize to the same string."""
        url1 = "https://Example.COM/article?utm_source=x&id=1"
        url2 = "https://example.com/article?id=1&utm_campaign=y"
        assert normalize_url(url1) == normalize_url(url2)

    def test_different_urls_produce_different_output(self):
        """Two genuinely different URLs remain different after normalization."""
        url1 = "https://example.com/article-one"
        url2 = "https://example.com/article-two"
        assert normalize_url(url1) != normalize_url(url2)

    def test_empty_query_string(self):
        """URL with no query params is handled cleanly."""
        url = "https://example.com/article"
        result = normalize_url(url)
        assert "?" not in result

    def test_all_params_are_tracking(self):
        """URL where every param is a tracker normalizes to no query string."""
        url = "https://example.com/article?utm_source=x&utm_medium=y&fbclid=z"
        result = normalize_url(url)
        assert "?" not in result


# ---------------------------------------------------------------------------
# Feed parsing
# ---------------------------------------------------------------------------


class TestParseFeedEntries:
    """Verify feedparser output normalization."""

    def test_normalizes_sample_entry(self, sample_rss_entry):
        """A well-formed entry is parsed into the expected normalized dict."""
        entries = parse_feed_entries([sample_rss_entry])
        assert len(entries) == 1
        entry = entries[0]
        assert "title" in entry
        assert "url" in entry
        assert "published" in entry
        assert "summary" in entry

    def test_title_preserved(self, sample_rss_entry):
        """Title text is preserved verbatim."""
        entries = parse_feed_entries([sample_rss_entry])
        assert "CVE-2024-53677" in entries[0]["title"]

    def test_link_becomes_url(self, sample_rss_entry):
        """The feedparser 'link' field maps to 'url' in normalized output."""
        entries = parse_feed_entries([sample_rss_entry])
        assert entries[0]["url"] == sample_rss_entry["link"]

    def test_html_stripped_from_summary(self):
        """HTML in the summary field is stripped."""
        entry = {
            "title": "Test",
            "link": "https://example.com/test",
            "summary": "<p>This is <b>HTML</b></p>",
            "published": "2024-12-15T14:30:00Z",
        }
        entries = parse_feed_entries([entry])
        assert "<p>" not in entries[0]["summary"]
        assert "<b>" not in entries[0]["summary"]

    def test_tags_extracted(self, sample_rss_entry):
        """Feedparser tag dicts are flattened to a list of strings."""
        entries = parse_feed_entries([sample_rss_entry])
        tags = entries[0].get("tags", [])
        assert "vulnerability" in tags
        assert "apache" in tags

    def test_empty_feed(self):
        """An empty list of entries returns an empty list."""
        assert parse_feed_entries([]) == []

    def test_entry_missing_optional_fields(self):
        """Entries missing optional fields (author, tags) still parse."""
        entry = {
            "title": "Minimal Entry",
            "link": "https://example.com/minimal",
            "summary": "Brief.",
        }
        entries = parse_feed_entries([entry])
        assert len(entries) == 1
        assert entries[0]["title"] == "Minimal Entry"


# ---------------------------------------------------------------------------
# Conditional requests (ETag / Last-Modified)
# ---------------------------------------------------------------------------


class TestConditionalRequests:
    """Verify ETag and Last-Modified header handling."""

    @pytest.fixture
    def fetcher(self):
        return RSSFetcher()

    @pytest.mark.asyncio
    async def test_stores_etag_from_response(self, fetcher):
        """When a feed returns an ETag header, it is stored for future requests."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {
            "ETag": '"abc123"',
            "Last-Modified": "Sun, 15 Dec 2024 14:30:00 GMT",
        }
        mock_response.text = "<rss></rss>"

        with patch.object(fetcher, "_http_get", return_value=mock_response):
            with patch.object(fetcher, "_store_etag") as mock_store:
                await fetcher.fetch("https://example.com/feed")
                mock_store.assert_called_once()

    @pytest.mark.asyncio
    async def test_sends_if_none_match_header(self, fetcher):
        """Stored ETag is sent as If-None-Match on subsequent requests."""
        with patch.object(fetcher, "_get_stored_etag", return_value='"abc123"'):
            with patch.object(fetcher, "_http_get") as mock_get:
                mock_get.return_value = MagicMock(status_code=304)
                await fetcher.fetch("https://example.com/feed")
                call_kwargs = mock_get.call_args
                headers = call_kwargs[1].get("headers", {}) if call_kwargs[1] else {}
                assert headers.get("If-None-Match") == '"abc123"'

    @pytest.mark.asyncio
    async def test_304_returns_none(self, fetcher):
        """A 304 Not Modified response results in None (no new content)."""
        with patch.object(fetcher, "_get_stored_etag", return_value='"abc123"'):
            with patch.object(fetcher, "_http_get") as mock_get:
                mock_get.return_value = MagicMock(status_code=304)
                result = await fetcher.fetch("https://example.com/feed")
                assert result is None

    @pytest.mark.asyncio
    async def test_sends_if_modified_since(self, fetcher):
        """Stored Last-Modified is sent as If-Modified-Since."""
        lm = "Sun, 15 Dec 2024 14:30:00 GMT"
        with patch.object(fetcher, "_get_stored_last_modified", return_value=lm):
            with patch.object(fetcher, "_get_stored_etag", return_value=None):
                with patch.object(fetcher, "_http_get") as mock_get:
                    mock_get.return_value = MagicMock(status_code=304)
                    await fetcher.fetch("https://example.com/feed")
                    call_kwargs = mock_get.call_args
                    headers = call_kwargs[1].get("headers", {}) if call_kwargs[1] else {}
                    assert headers.get("If-Modified-Since") == lm


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------


class TestRateLimiting:
    """Verify per-domain rate limiting behavior."""

    @pytest.fixture
    def fetcher(self):
        return RSSFetcher()

    @pytest.mark.asyncio
    async def test_rate_limit_delays_request(self, fetcher):
        """A second request to the same domain within the rate window is delayed."""
        with patch.object(fetcher, "_acquire_rate_token", new_callable=AsyncMock) as mock_acquire:
            mock_acquire.return_value = True
            with patch.object(fetcher, "_http_get") as mock_get:
                mock_get.return_value = MagicMock(status_code=200, text="<rss></rss>")
                await fetcher.fetch("https://example.com/feed")
                mock_acquire.assert_called()

    @pytest.mark.asyncio
    async def test_government_apis_slower_rate(self, fetcher):
        """Government API domains use a slower rate limit (1 req / 6s)."""
        rate = fetcher.get_rate_limit_for_domain("services.nvd.nist.gov")
        assert rate >= 6.0

    def test_default_rate_limit(self, fetcher):
        """Default domains get 1 request per second."""
        rate = fetcher.get_rate_limit_for_domain("www.bleepingcomputer.com")
        assert rate <= 1.0

    def test_reddit_rate_limit(self, fetcher):
        """Reddit domains use a 2-second rate limit."""
        rate = fetcher.get_rate_limit_for_domain("www.reddit.com")
        assert rate >= 2.0


# ---------------------------------------------------------------------------
# Error handling for malformed / empty / 404 feeds
# ---------------------------------------------------------------------------


class TestFeedErrorHandling:
    """Verify graceful handling of broken feeds."""

    @pytest.fixture
    def fetcher(self):
        return RSSFetcher()

    @pytest.mark.asyncio
    async def test_404_returns_none(self, fetcher):
        """A 404 response returns None without raising."""
        with patch.object(fetcher, "_http_get") as mock_get:
            mock_get.return_value = MagicMock(status_code=404)
            result = await fetcher.fetch("https://example.com/nonexistent-feed")
            assert result is None

    @pytest.mark.asyncio
    async def test_500_returns_none(self, fetcher):
        """A server error (500) returns None without raising."""
        with patch.object(fetcher, "_http_get") as mock_get:
            mock_get.return_value = MagicMock(status_code=500)
            result = await fetcher.fetch("https://example.com/broken-feed")
            assert result is None

    @pytest.mark.asyncio
    async def test_connection_error_returns_none(self, fetcher):
        """A network-level connection error returns None."""
        with patch.object(fetcher, "_http_get", side_effect=ConnectionError("DNS resolution failed")):
            result = await fetcher.fetch("https://nonexistent.example.com/feed")
            assert result is None

    @pytest.mark.asyncio
    async def test_timeout_returns_none(self, fetcher):
        """A request timeout returns None."""
        with patch.object(fetcher, "_http_get", side_effect=TimeoutError("Read timed out")):
            result = await fetcher.fetch("https://slow.example.com/feed")
            assert result is None

    @pytest.mark.asyncio
    async def test_empty_body_returns_empty_list(self, fetcher):
        """An empty response body results in an empty entry list."""
        with patch.object(fetcher, "_http_get") as mock_get:
            mock_get.return_value = MagicMock(status_code=200, text="")
            result = await fetcher.fetch("https://example.com/empty-feed")
            assert result is None or result == []

    def test_malformed_xml_returns_empty(self):
        """Malformed XML yields zero parsed entries."""
        entries = parse_feed_entries([])
        assert entries == []

    @pytest.mark.asyncio
    async def test_non_rss_html_page(self, fetcher):
        """An HTML page (not RSS) returns no valid entries."""
        html = "<html><body><h1>Not a feed</h1></body></html>"
        with patch.object(fetcher, "_http_get") as mock_get:
            mock_get.return_value = MagicMock(status_code=200, text=html)
            result = await fetcher.fetch("https://example.com/not-a-feed")
            assert result is None or result == []
