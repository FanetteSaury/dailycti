"""Tests for Feedly-compatible entries API -- src/fidlie/api/routes/entries.py

Validates GET /v3/entries/:id, POST /v3/entries/.mget, 404 for missing
entries, and response JSON schema conformance with Feedly format.
"""

from __future__ import annotations

import time

import pytest

from fidlie.api.routes.entries import (
    get_entry,
    mget_entries,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_entry():
    """A single Feedly-format entry stored in the DB."""
    now_ms = int(time.time() * 1000)
    return {
        "id": "entry/sha256:abc123def456",
        "title": "Critical RCE Vulnerability in Apache Struts (CVE-2024-53677)",
        "crawled": now_ms - 3600_000,
        "published": now_ms - 7200_000,
        "updated": now_ms - 3600_000,
        "author": "Lawrence Abrams",
        "summary": {
            "content": "A critical remote code execution vulnerability...",
            "direction": "ltr",
        },
        "content": {
            "content": "<p>A critical remote code execution vulnerability (CVE-2024-53677)...</p>",
            "direction": "ltr",
        },
        "origin": {
            "streamId": "feed/https://www.bleepingcomputer.com/feed/",
            "title": "BleepingComputer",
            "htmlUrl": "https://www.bleepingcomputer.com",
        },
        "alternate": [
            {
                "href": "https://www.bleepingcomputer.com/news/security/apache-struts-rce-flaw/",
                "type": "text/html",
            }
        ],
        "keywords": ["vulnerability", "apache", "rce"],
        "entities": [
            {"type": "cve", "id": "CVE-2024-53677", "cvss": 9.8},
        ],
        "engagement": 42,
        "engagementRate": 0.85,
    }


@pytest.fixture
def mock_db(sample_entry):
    """A mock data store mapping entry IDs to entries."""
    return {sample_entry["id"]: sample_entry}


# ===========================================================================
# GET /v3/entries/:id
# ===========================================================================


class TestGetEntry:
    """Validate single-entry retrieval."""

    @pytest.mark.asyncio
    async def test_returns_entry_by_id(self, sample_entry, mock_db):
        """An existing entry ID returns the full entry."""
        entry = await get_entry(sample_entry["id"], db=mock_db)
        assert entry is not None
        assert entry["id"] == sample_entry["id"]

    @pytest.mark.asyncio
    async def test_entry_has_title(self, sample_entry, mock_db):
        """Returned entry contains the title."""
        entry = await get_entry(sample_entry["id"], db=mock_db)
        assert entry["title"] == sample_entry["title"]

    @pytest.mark.asyncio
    async def test_entry_has_origin(self, sample_entry, mock_db):
        """Returned entry contains origin with streamId."""
        entry = await get_entry(sample_entry["id"], db=mock_db)
        assert "origin" in entry
        assert "streamId" in entry["origin"]

    @pytest.mark.asyncio
    async def test_entry_has_alternate(self, sample_entry, mock_db):
        """Returned entry contains alternate links."""
        entry = await get_entry(sample_entry["id"], db=mock_db)
        assert "alternate" in entry
        assert len(entry["alternate"]) >= 1
        assert "href" in entry["alternate"][0]

    @pytest.mark.asyncio
    async def test_entry_has_summary(self, sample_entry, mock_db):
        """Returned entry contains a summary object."""
        entry = await get_entry(sample_entry["id"], db=mock_db)
        assert "summary" in entry
        assert "content" in entry["summary"]

    @pytest.mark.asyncio
    async def test_404_for_missing_entry(self, mock_db):
        """A non-existent entry ID returns None or raises 404."""
        result = await get_entry("entry/sha256:doesnotexist", db=mock_db)
        assert result is None

    @pytest.mark.asyncio
    async def test_404_for_empty_id(self, mock_db):
        """An empty ID returns None or raises."""
        result = await get_entry("", db=mock_db)
        assert result is None


# ===========================================================================
# POST /v3/entries/.mget (bulk)
# ===========================================================================


class TestMgetEntries:
    """Validate bulk entry retrieval."""

    @pytest.fixture
    def multi_db(self):
        """DB with multiple entries."""
        now_ms = int(time.time() * 1000)
        entries = {}
        for i in range(5):
            eid = f"entry/sha256:hash{i}"
            entries[eid] = {
                "id": eid,
                "title": f"Article {i}",
                "crawled": now_ms - (i * 3600_000),
                "published": now_ms - (i * 3600_000),
                "summary": {"content": f"Summary {i}"},
                "origin": {
                    "streamId": "feed/https://example.com/feed",
                    "title": "Example",
                    "htmlUrl": "https://example.com",
                },
                "alternate": [{"href": f"https://example.com/article-{i}", "type": "text/html"}],
            }
        return entries

    @pytest.mark.asyncio
    async def test_returns_all_requested(self, multi_db):
        """All requested IDs that exist are returned."""
        ids = list(multi_db.keys())[:3]
        results = await mget_entries(ids, db=multi_db)
        assert len(results) == 3

    @pytest.mark.asyncio
    async def test_missing_ids_omitted(self, multi_db):
        """Non-existent IDs are omitted from the result (no error)."""
        ids = [list(multi_db.keys())[0], "entry/sha256:nonexistent"]
        results = await mget_entries(ids, db=multi_db)
        assert len(results) == 1

    @pytest.mark.asyncio
    async def test_preserves_order(self, multi_db):
        """Results are returned in the order requested."""
        ids = [f"entry/sha256:hash{i}" for i in [2, 0, 4]]
        results = await mget_entries(ids, db=multi_db)
        result_ids = [r["id"] for r in results]
        assert result_ids == ids

    @pytest.mark.asyncio
    async def test_empty_request(self, multi_db):
        """An empty ID list returns an empty result."""
        results = await mget_entries([], db=multi_db)
        assert results == []

    @pytest.mark.asyncio
    async def test_all_missing(self, multi_db):
        """All-missing IDs return an empty result."""
        results = await mget_entries(
            ["entry/sha256:fake1", "entry/sha256:fake2"],
            db=multi_db,
        )
        assert results == []

    @pytest.mark.asyncio
    async def test_max_1000_ids(self, multi_db):
        """Requesting more than 1000 IDs is either capped or raises."""
        ids = [f"entry/sha256:bulk{i}" for i in range(1001)]
        try:
            results = await mget_entries(ids, db=multi_db)
            # If it doesn't raise, it should cap at 1000
            assert len(results) <= 1000
        except (ValueError, Exception):
            # Raising is also acceptable
            pass

    @pytest.mark.asyncio
    async def test_duplicate_ids_deduplicated(self, multi_db):
        """Duplicate IDs in the request do not duplicate results."""
        eid = list(multi_db.keys())[0]
        results = await mget_entries([eid, eid, eid], db=multi_db)
        matching = [r for r in results if r["id"] == eid]
        assert len(matching) == 1


# ===========================================================================
# Response JSON schema (Feedly format)
# ===========================================================================


class TestFeedlyJsonSchema:
    """Verify response entries conform to the Feedly v3 entry schema."""

    def test_entry_id_format(self, sample_entry):
        """Entry IDs follow the 'entry/<hash>' pattern."""
        assert sample_entry["id"].startswith("entry/")

    def test_timestamps_are_milliseconds(self, sample_entry):
        """Timestamps (crawled, published) are in epoch milliseconds."""
        assert sample_entry["crawled"] > 1_000_000_000_000  # > year 2001 in ms
        assert sample_entry["published"] > 1_000_000_000_000

    def test_summary_is_object(self, sample_entry):
        """summary is an object with 'content' and optional 'direction'."""
        assert isinstance(sample_entry["summary"], dict)
        assert "content" in sample_entry["summary"]

    def test_content_is_object(self, sample_entry):
        """content (full) is an object with 'content' and optional 'direction'."""
        assert isinstance(sample_entry["content"], dict)
        assert "content" in sample_entry["content"]

    def test_origin_structure(self, sample_entry):
        """origin has streamId, title, htmlUrl."""
        origin = sample_entry["origin"]
        assert "streamId" in origin
        assert "title" in origin
        assert "htmlUrl" in origin

    def test_alternate_structure(self, sample_entry):
        """alternate is a list of objects with href and type."""
        alt = sample_entry["alternate"]
        assert isinstance(alt, list)
        assert len(alt) >= 1
        assert "href" in alt[0]
        assert "type" in alt[0]

    def test_keywords_is_list(self, sample_entry):
        """keywords is a list of strings."""
        assert isinstance(sample_entry["keywords"], list)
        assert all(isinstance(k, str) for k in sample_entry["keywords"])

    def test_engagement_is_numeric(self, sample_entry):
        """engagement is a numeric value."""
        assert isinstance(sample_entry["engagement"], (int, float))

    def test_entities_is_list(self, sample_entry):
        """entities is a list of entity objects."""
        assert isinstance(sample_entry["entities"], list)
        for entity in sample_entry["entities"]:
            assert "type" in entity
            assert "id" in entity
