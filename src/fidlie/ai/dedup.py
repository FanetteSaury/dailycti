"""Article deduplication -- URL-hash and MinHash content fingerprinting.

Provides two-pass deduplication:
1. Exact URL dedup (normalized URL SHA-256)
2. Content similarity dedup (MinHash Jaccard > threshold)
"""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from datasketch import MinHash


def _normalize_url(url: str) -> str:
    """Normalize a URL by stripping UTM params, fragments, and trailing slashes."""
    parsed = urlparse(url)

    # Strip fragment
    # Filter out utm_* params and sort remaining
    params = parse_qs(parsed.query, keep_blank_values=True)
    filtered = {k: v for k, v in sorted(params.items()) if not k.startswith("utm_")}
    query = urlencode(filtered, doseq=True)

    # Strip trailing slash from path
    path = parsed.path.rstrip("/")

    normalized = urlunparse((
        parsed.scheme,
        parsed.netloc,
        path,
        parsed.params,
        query,
        "",  # no fragment
    ))
    return normalized


def compute_url_hash(url: str) -> str:
    """Normalize URL (strip utm_*, sort params, strip fragment/trailing slash) and return SHA-256 hex."""
    normalized = _normalize_url(url)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def fingerprint_text(text: str) -> MinHash:
    """Create a MinHash fingerprint of text using 128 permutations.

    Uses word-level bigrams (2-shingles) plus individual words for
    content similarity detection. This combination gives high Jaccard
    scores for near-identical text with minor rewording (matching
    Feedly's ~85% dedup threshold).
    """
    mh = MinHash(num_perm=128, seed=42)
    # Word unigrams + bigrams: more elements in the set gives MinHash
    # a more stable Jaccard estimate. Unigrams provide high overlap
    # for near-identical text; bigrams capture phrase-level similarity.
    words = re.findall(r"\w+", text.lower())
    elements = set(words)
    for i in range(len(words) - 1):
        elements.add(f"{words[i]} {words[i+1]}")
    for elem in elements:
        mh.update(elem.encode("utf-8"))
    return mh


def jaccard_similarity(fp1: MinHash, fp2: MinHash) -> float:
    """Compute Jaccard similarity between two MinHash fingerprints."""
    return fp1.jaccard(fp2)


def select_cluster_representative(articles: list[dict]) -> dict:
    """Pick the article with the longest content as the cluster representative.

    Merges alternate URLs from other articles into the representative.
    Raises ValueError if articles is empty.
    """
    if not articles:
        raise ValueError("Cannot select representative from empty cluster")

    # Pick article with longest text
    rep = max(articles, key=lambda a: len(a.get("text", "")))
    rep = dict(rep)  # shallow copy

    # Merge alternate URLs
    alternate_urls = [a["url"] for a in articles if a["url"] != rep["url"]]
    if alternate_urls:
        rep["alternate_urls"] = alternate_urls

    return rep


class Deduplicator:
    """Two-pass article deduplicator.

    Pass 1: Group by normalized URL hash (exact match).
    Pass 2: Group remaining by MinHash content similarity (> threshold).
    """

    def __init__(self, similarity_threshold: float = 0.85):
        self.similarity_threshold = similarity_threshold

    def deduplicate(self, articles: list[dict]) -> list[dict]:
        """Deduplicate articles, returning unique representatives."""
        if not articles:
            return []

        # Pass 1: Group by URL hash
        url_groups: dict[str, list[dict]] = defaultdict(list)
        for article in articles:
            h = compute_url_hash(article["url"])
            url_groups[h].append(article)

        # Select representative from each URL group
        url_reps = []
        for group in url_groups.values():
            url_reps.append(select_cluster_representative(group))

        if len(url_reps) <= 1:
            return url_reps

        # Pass 2: Group by content similarity
        fingerprints = [fingerprint_text(a.get("text", "")) for a in url_reps]
        used = [False] * len(url_reps)
        result = []

        for i in range(len(url_reps)):
            if used[i]:
                continue
            cluster = [url_reps[i]]
            used[i] = True
            for j in range(i + 1, len(url_reps)):
                if used[j]:
                    continue
                sim = jaccard_similarity(fingerprints[i], fingerprints[j])
                if sim >= self.similarity_threshold:
                    cluster.append(url_reps[j])
                    used[j] = True
            result.append(select_cluster_representative(cluster))

        return result
