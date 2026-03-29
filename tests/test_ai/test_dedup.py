"""Tests for article deduplication -- src/fidlie/ai/dedup.py

Validates URL-hash dedup, MinHash content fingerprinting, Jaccard similarity
thresholds, cluster representative selection, and grouping behaviour.
"""

from __future__ import annotations

import hashlib

import pytest

from fidlie.ai.dedup import (
    Deduplicator,
    compute_url_hash,
    fingerprint_text,
    jaccard_similarity,
    select_cluster_representative,
)


# ---------------------------------------------------------------------------
# URL-hash deduplication
# ---------------------------------------------------------------------------


class TestUrlHashDedup:
    """First-pass dedup: exact normalized-URL SHA-256 match."""

    def test_same_url_same_hash(self):
        """Two identical URLs produce the same SHA-256 hash."""
        url = "https://example.com/article"
        assert compute_url_hash(url) == compute_url_hash(url)

    def test_different_urls_different_hash(self):
        """Two different URLs produce different hashes."""
        assert compute_url_hash("https://a.com/x") != compute_url_hash("https://b.com/y")

    def test_hash_is_sha256_hex(self):
        """The hash value is a 64-character hex string (SHA-256)."""
        h = compute_url_hash("https://example.com/article")
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)

    def test_utm_variants_collapse(self):
        """URLs differing only in UTM params produce the same hash."""
        url1 = "https://example.com/article?utm_source=twitter"
        url2 = "https://example.com/article?utm_source=linkedin"
        assert compute_url_hash(url1) == compute_url_hash(url2)

    def test_trailing_slash_ignored(self):
        """Trailing slash does not affect the hash."""
        assert compute_url_hash("https://example.com/a/") == compute_url_hash(
            "https://example.com/a"
        )

    def test_fragment_ignored(self):
        """Fragment identifiers are stripped before hashing."""
        assert compute_url_hash("https://example.com/a#top") == compute_url_hash(
            "https://example.com/a"
        )


# ---------------------------------------------------------------------------
# MinHash content fingerprinting
# ---------------------------------------------------------------------------


class TestMinHashFingerprint:
    """Second-pass dedup: MinHash signatures for content similarity."""

    def test_returns_minhash_object(self):
        """fingerprint_text returns a datasketch MinHash instance."""
        mh = fingerprint_text("This is a sample article about a critical vulnerability.")
        # Check it has the expected interface
        assert hasattr(mh, "hashvalues")

    def test_identical_text_same_fingerprint(self):
        """Identical input text produces identical MinHash digests."""
        text = "A critical RCE vulnerability has been found in Apache Struts."
        mh1 = fingerprint_text(text)
        mh2 = fingerprint_text(text)
        assert list(mh1.hashvalues) == list(mh2.hashvalues)

    def test_completely_different_text_low_similarity(self):
        """Completely unrelated texts have Jaccard similarity well below 0.85."""
        mh1 = fingerprint_text(
            "A critical vulnerability in Apache Struts allows remote code execution "
            "via crafted file upload parameters. CISA has added CVE-2024-53677 to "
            "the Known Exploited Vulnerabilities catalog."
        )
        mh2 = fingerprint_text(
            "The latest quarterly earnings report for Acme Corporation shows a "
            "fifteen percent increase in revenue driven by strong demand for cloud "
            "computing services in the Asia-Pacific region."
        )
        sim = jaccard_similarity(mh1, mh2)
        assert sim < 0.85

    def test_near_identical_text_high_similarity(self):
        """Near-identical articles (minor rewording) score above 0.85."""
        text_a = (
            "A critical remote code execution vulnerability CVE-2024-53677 has been "
            "discovered in Apache Struts, affecting versions 2.0.0 through 6.3.0.2. "
            "The flaw has a CVSS score of 9.8 and allows unauthenticated attackers "
            "to execute arbitrary code."
        )
        text_b = (
            "A critical remote code execution vulnerability CVE-2024-53677 was "
            "found in Apache Struts affecting versions 2.0.0 through 6.3.0.2. "
            "The flaw has a CVSS score of 9.8 and allows unauthenticated attackers "
            "to execute arbitrary code on servers."
        )
        mh_a = fingerprint_text(text_a)
        mh_b = fingerprint_text(text_b)
        sim = jaccard_similarity(mh_a, mh_b)
        assert sim >= 0.85

    def test_num_perm_is_128(self):
        """MinHash uses 128 permutations as specified in PIPELINE.md."""
        mh = fingerprint_text("test text for permutation count check")
        assert len(mh.hashvalues) == 128

    def test_empty_text_does_not_crash(self):
        """Empty string input does not raise an exception."""
        mh = fingerprint_text("")
        assert mh is not None


# ---------------------------------------------------------------------------
# Jaccard similarity
# ---------------------------------------------------------------------------


class TestJaccardSimilarity:
    """Verify the Jaccard similarity helper."""

    def test_identical_fingerprints_equal_one(self):
        """Two fingerprints from the same text yield similarity of 1.0."""
        text = "The threat actor APT28 deployed malware targeting government networks."
        mh = fingerprint_text(text)
        assert jaccard_similarity(mh, mh) == pytest.approx(1.0)

    def test_similarity_is_symmetric(self):
        """J(A, B) == J(B, A)."""
        mh1 = fingerprint_text("Apache Struts vulnerability allows remote code execution.")
        mh2 = fingerprint_text("VMware vSphere bug permits denial of service attacks.")
        assert jaccard_similarity(mh1, mh2) == pytest.approx(
            jaccard_similarity(mh2, mh1)
        )

    def test_similarity_range(self):
        """Jaccard similarity is always in [0.0, 1.0]."""
        mh1 = fingerprint_text("First article about ransomware attack on hospital.")
        mh2 = fingerprint_text("Second article about phishing campaign targeting banks.")
        sim = jaccard_similarity(mh1, mh2)
        assert 0.0 <= sim <= 1.0


# ---------------------------------------------------------------------------
# Cluster representative selection
# ---------------------------------------------------------------------------


class TestClusterRepresentative:
    """When duplicates are found, the longest article becomes the representative."""

    def test_selects_longest_text(self):
        """The article with the most extracted text wins."""
        articles = [
            {"id": "a", "text": "Short.", "url": "https://a.com/1"},
            {
                "id": "b",
                "text": "This is a much longer article with considerably more detail.",
                "url": "https://b.com/2",
            },
            {"id": "c", "text": "Medium length text here.", "url": "https://c.com/3"},
        ]
        rep = select_cluster_representative(articles)
        assert rep["id"] == "b"

    def test_merges_source_urls(self):
        """All source URLs from duplicates are merged onto the representative."""
        articles = [
            {"id": "a", "text": "Short.", "url": "https://a.com/1", "source": "Source A"},
            {
                "id": "b",
                "text": "This is a much longer article with lots more detail and context.",
                "url": "https://b.com/2",
                "source": "Source B",
            },
        ]
        rep = select_cluster_representative(articles)
        assert "alternate_urls" in rep or "sources" in rep
        # The representative should reference both original URLs
        all_urls = [a["url"] for a in articles]
        merged = rep.get("alternate_urls", rep.get("sources", []))
        for url in all_urls:
            if url != rep["url"]:
                assert url in merged or any(url in str(s) for s in merged)

    def test_single_article_is_representative(self):
        """A cluster of one returns that article as-is."""
        articles = [{"id": "only", "text": "Solo article.", "url": "https://only.com/1"}]
        rep = select_cluster_representative(articles)
        assert rep["id"] == "only"

    def test_empty_cluster_raises(self):
        """An empty cluster raises ValueError."""
        with pytest.raises((ValueError, IndexError)):
            select_cluster_representative([])


# ---------------------------------------------------------------------------
# Full deduplicator integration (grouping behavior)
# ---------------------------------------------------------------------------


class TestDeduplicatorGrouping:
    """Integration-level tests for the Deduplicator class."""

    @pytest.fixture
    def dedup(self):
        return Deduplicator(similarity_threshold=0.85)

    def test_exact_url_duplicates_grouped(self, dedup):
        """Two articles with the same normalized URL end up in one group."""
        articles = [
            {
                "url": "https://example.com/article?utm_source=twitter",
                "text": "Some content about a vuln.",
                "title": "Vuln found",
            },
            {
                "url": "https://example.com/article?utm_source=linkedin",
                "text": "Some content about a vuln.",
                "title": "Vuln found",
            },
        ]
        unique = dedup.deduplicate(articles)
        assert len(unique) == 1

    def test_similar_content_grouped(self, dedup):
        """Two articles with near-identical text are grouped."""
        base_text = (
            "A critical remote code execution vulnerability CVE-2024-53677 "
            "has been discovered in Apache Struts, affecting versions 2.0.0 "
            "through 6.3.0.2. The flaw has a CVSS score of 9.8."
        )
        articles = [
            {"url": "https://a.com/struts-vuln", "text": base_text, "title": "Apache Struts RCE"},
            {
                "url": "https://b.com/struts-vuln",
                "text": base_text + " Administrators should patch immediately.",
                "title": "Apache Struts RCE Flaw",
            },
        ]
        unique = dedup.deduplicate(articles)
        assert len(unique) == 1

    def test_different_content_not_grouped(self, dedup):
        """Two articles about completely different topics remain separate."""
        articles = [
            {
                "url": "https://a.com/struts",
                "text": (
                    "A critical remote code execution vulnerability CVE-2024-53677 "
                    "has been discovered in Apache Struts affecting versions through 6.3.0.2."
                ),
                "title": "Apache Struts Vuln",
            },
            {
                "url": "https://b.com/phishing",
                "text": (
                    "A new phishing campaign targeting financial institutions in Europe "
                    "has been detected using sophisticated social engineering techniques "
                    "to steal banking credentials from corporate executives."
                ),
                "title": "Phishing Campaign",
            },
        ]
        unique = dedup.deduplicate(articles)
        assert len(unique) == 2

    def test_empty_input(self, dedup):
        """Empty input returns empty output."""
        assert dedup.deduplicate([]) == []

    def test_single_article(self, dedup):
        """Single article passes through unchanged."""
        articles = [{"url": "https://a.com/solo", "text": "Solo article.", "title": "Solo"}]
        unique = dedup.deduplicate(articles)
        assert len(unique) == 1
