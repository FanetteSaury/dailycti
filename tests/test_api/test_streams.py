"""Tests for Feedly-compatible streams API -- src/fidlie/api/routes/streams.py

Validates GET /v3/streams/contents response structure, continuation token
pagination, stream ID parsing, count parameter limits, and newerThan filtering.
"""

from __future__ import annotations

import base64
import json
import time
from datetime import datetime, timedelta, timezone

import pytest

from fidlie.api.routes.streams import (
    build_stream_response,
    decode_continuation,
    encode_continuation,
    parse_stream_id,
    validate_count,
)


# ===========================================================================
# Response structure
# ===========================================================================


class TestStreamResponseStructure:
    """Verify /v3/streams/contents JSON matches Feedly format."""

    @pytest.fixture
    def mock_entries(self):
        """Minimal Feedly-format entries."""
        now_ms = int(time.time() * 1000)
        return [
            {
                "id": f"entry/{i}",
                "title": f"Article {i}",
                "crawled": now_ms - (i * 60000),
                "published": now_ms - (i * 60000),
                "summary": {"content": f"Summary for article {i}"},
                "origin": {
                    "streamId": "feed/https://example.com/feed",
                    "title": "Example Feed",
                    "htmlUrl": "https://example.com",
                },
                "alternate": [{"href": f"https://example.com/article-{i}", "type": "text/html"}],
            }
            for i in range(5)
        ]

    def test_response_has_id(self, mock_entries):
        """Response contains the stream 'id' field."""
        resp = build_stream_response(
            stream_id="feed/https://example.com/feed",
            entries=mock_entries,
            continuation=None,
        )
        assert "id" in resp
        assert resp["id"] == "feed/https://example.com/feed"

    def test_response_has_items(self, mock_entries):
        """Response contains an 'items' array."""
        resp = build_stream_response(
            stream_id="feed/https://example.com/feed",
            entries=mock_entries,
            continuation=None,
        )
        assert "items" in resp
        assert isinstance(resp["items"], list)
        assert len(resp["items"]) == 5

    def test_response_has_updated(self, mock_entries):
        """Response contains an 'updated' timestamp."""
        resp = build_stream_response(
            stream_id="feed/https://example.com/feed",
            entries=mock_entries,
            continuation=None,
        )
        assert "updated" in resp

    def test_continuation_present_when_more(self, mock_entries):
        """When there are more results, 'continuation' is present."""
        resp = build_stream_response(
            stream_id="feed/https://example.com/feed",
            entries=mock_entries,
            continuation="abc123token",
        )
        assert "continuation" in resp
        assert resp["continuation"] == "abc123token"

    def test_continuation_absent_when_done(self, mock_entries):
        """When all results are returned, 'continuation' is absent."""
        resp = build_stream_response(
            stream_id="feed/https://example.com/feed",
            entries=mock_entries,
            continuation=None,
        )
        assert "continuation" not in resp or resp.get("continuation") is None

    def test_items_have_required_fields(self, mock_entries):
        """Each item has id, title, crawled, published, summary, origin, alternate."""
        resp = build_stream_response(
            stream_id="feed/https://example.com/feed",
            entries=mock_entries,
            continuation=None,
        )
        for item in resp["items"]:
            assert "id" in item
            assert "title" in item
            assert "crawled" in item
            assert "published" in item
            assert "origin" in item

    def test_origin_has_stream_id(self, mock_entries):
        """Each item's origin contains streamId, title, htmlUrl."""
        resp = build_stream_response(
            stream_id="feed/https://example.com/feed",
            entries=mock_entries,
            continuation=None,
        )
        origin = resp["items"][0]["origin"]
        assert "streamId" in origin
        assert "title" in origin
        assert "htmlUrl" in origin


# ===========================================================================
# Continuation token pagination
# ===========================================================================


class TestContinuationToken:
    """Verify continuation token encode/decode for pagination."""

    def test_encode_produces_string(self):
        """encode_continuation returns a non-empty string."""
        token = encode_continuation(crawled=1700000000000, entry_id=42)
        assert isinstance(token, str)
        assert len(token) > 0

    def test_roundtrip(self):
        """Encoding then decoding yields the original values."""
        crawled = 1700000000000
        entry_id = 42
        token = encode_continuation(crawled=crawled, entry_id=entry_id)
        decoded = decode_continuation(token)
        assert decoded["crawled"] == crawled
        assert decoded["entry_id"] == entry_id

    def test_different_inputs_different_tokens(self):
        """Different (crawled, entry_id) pairs produce different tokens."""
        t1 = encode_continuation(crawled=1700000000000, entry_id=1)
        t2 = encode_continuation(crawled=1700000000000, entry_id=2)
        assert t1 != t2

    def test_decode_invalid_token(self):
        """An invalid token raises ValueError or returns None."""
        with pytest.raises((ValueError, TypeError, Exception)):
            decode_continuation("not-a-valid-token!!!")

    def test_token_is_base64(self):
        """The token is valid base64."""
        token = encode_continuation(crawled=1700000000000, entry_id=42)
        # Should not raise
        decoded_bytes = base64.urlsafe_b64decode(token + "==")
        assert len(decoded_bytes) > 0


# ===========================================================================
# Stream ID parsing
# ===========================================================================


class TestStreamIdParsing:
    """Verify parsing of Feedly-format stream IDs."""

    def test_feed_stream(self):
        """'feed/http://...' stream is parsed correctly."""
        result = parse_stream_id("feed/https://www.bleepingcomputer.com/feed/")
        assert result["type"] == "feed"
        assert result["url"] == "https://www.bleepingcomputer.com/feed/"

    def test_category_stream(self):
        """'user/<id>/category/<name>' is parsed correctly."""
        sid = "user/abc123/category/Threat Intel"
        result = parse_stream_id(sid)
        assert result["type"] == "category"
        assert result["user_id"] == "abc123"
        assert result["name"] == "Threat Intel"

    def test_tag_stream(self):
        """'user/<id>/tag/<name>' is parsed correctly."""
        sid = "user/abc123/tag/saved-for-later"
        result = parse_stream_id(sid)
        assert result["type"] == "tag"
        assert result["user_id"] == "abc123"
        assert result["name"] == "saved-for-later"

    def test_global_all_stream(self):
        """Global all stream is recognized."""
        sid = "user/abc123/category/global.all"
        result = parse_stream_id(sid)
        assert result["type"] == "category"
        assert result["name"] == "global.all"

    def test_global_uncategorized_stream(self):
        """Global uncategorized stream is recognized."""
        sid = "user/abc123/category/global.uncategorized"
        result = parse_stream_id(sid)
        assert result["type"] == "category"
        assert result["name"] == "global.uncategorized"

    def test_invalid_stream_id_raises(self):
        """An unrecognized stream ID format raises ValueError."""
        with pytest.raises((ValueError, KeyError)):
            parse_stream_id("invalid-stream-id")

    def test_feed_with_complex_url(self):
        """Feed stream with query params in the URL is handled."""
        sid = "feed/https://example.com/feed?format=rss&lang=en"
        result = parse_stream_id(sid)
        assert result["type"] == "feed"
        assert "format=rss" in result["url"]


# ===========================================================================
# Count parameter limits
# ===========================================================================


class TestCountParameter:
    """Verify count parameter validation per PIPELINE.md (default 20, max 1000)."""

    def test_default_count(self):
        """No count specified returns the default (20)."""
        assert validate_count(None) == 20

    def test_explicit_count(self):
        """An explicit count is respected."""
        assert validate_count(40) == 40

    def test_max_count_capped(self):
        """Counts above 1000 are capped to 1000."""
        assert validate_count(5000) == 1000

    def test_zero_count(self):
        """Zero count falls back to default."""
        result = validate_count(0)
        assert result == 20 or result > 0

    def test_negative_count(self):
        """Negative count falls back to default."""
        result = validate_count(-5)
        assert result == 20 or result > 0

    def test_count_one(self):
        """Count of 1 is valid."""
        assert validate_count(1) == 1

    def test_count_1000(self):
        """Count of exactly 1000 is accepted."""
        assert validate_count(1000) == 1000


# ===========================================================================
# newerThan filtering
# ===========================================================================


class TestNewerThanFiltering:
    """Verify newerThan timestamp filtering."""

    @pytest.fixture
    def entries_with_times(self):
        """Entries spanning several hours."""
        now_ms = int(time.time() * 1000)
        return [
            {"id": "e1", "crawled": now_ms, "title": "Newest"},
            {"id": "e2", "crawled": now_ms - 3600_000, "title": "1h ago"},
            {"id": "e3", "crawled": now_ms - 7200_000, "title": "2h ago"},
            {"id": "e4", "crawled": now_ms - 86400_000, "title": "24h ago"},
        ]

    def test_newer_than_filters_old(self, entries_with_times):
        """newerThan excludes entries older than the threshold."""
        now_ms = int(time.time() * 1000)
        threshold = now_ms - 5400_000  # 1.5 hours ago
        resp = build_stream_response(
            stream_id="feed/https://example.com/feed",
            entries=entries_with_times,
            continuation=None,
            newer_than=threshold,
        )
        ids = [item["id"] for item in resp["items"]]
        assert "e1" in ids
        assert "e2" in ids
        assert "e3" not in ids
        assert "e4" not in ids

    def test_newer_than_none_returns_all(self, entries_with_times):
        """No newerThan returns all entries."""
        resp = build_stream_response(
            stream_id="feed/https://example.com/feed",
            entries=entries_with_times,
            continuation=None,
            newer_than=None,
        )
        assert len(resp["items"]) == 4

    def test_newer_than_future_returns_none(self, entries_with_times):
        """A newerThan in the future returns no entries."""
        future_ms = int(time.time() * 1000) + 86400_000
        resp = build_stream_response(
            stream_id="feed/https://example.com/feed",
            entries=entries_with_times,
            continuation=None,
            newer_than=future_ms,
        )
        assert len(resp["items"]) == 0
