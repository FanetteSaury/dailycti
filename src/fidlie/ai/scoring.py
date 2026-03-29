"""Priority scoring -- 6-factor weighted scoring formula.

Computes composite priority scores for articles based on:
1. Source authority (tier-based)
2. CVSS score (normalized)
3. Exploit availability (max of signals)
4. Mention velocity (log-normalized)
5. Recency (exponential decay)
6. Product prevalence (lookup-based)
"""

from __future__ import annotations

import math
from datetime import datetime, timezone


def score_source_authority(
    tier: int,
    config: dict,
    source_name: str | None = None,
) -> float:
    """Return authority score for a source tier.

    Tier 1 = 1.0, Tier 2 = 0.7, Tier 3 = 0.4.
    Specific source overrides are checked first.
    """
    sa_config = config["source_authority"]

    # Check overrides first
    if source_name and source_name in sa_config.get("overrides", {}):
        return sa_config["overrides"][source_name]

    tier_map = {
        1: sa_config["tier_1"],
        2: sa_config["tier_2"],
        3: sa_config["tier_3"],
    }
    return tier_map.get(tier, sa_config["tier_3"])


def normalize_cvss(score: float | None, default: float = 0.3) -> float:
    """Normalize a CVSS score to [0.0, 1.0].

    None returns the default value (0.3).
    """
    if score is None:
        return default
    return score / 10.0


def score_exploit_availability(
    cisa_kev: bool = False,
    exploit_db: bool = False,
    poc_github: bool = False,
    vendor_confirmed: bool = False,
    config: dict | None = None,
) -> float:
    """Score exploit availability based on multiple signals.

    Returns the maximum score among active signals.
    """
    if config is None:
        ea = {
            "cisa_kev_listed": 1.0,
            "exploit_db_available": 0.8,
            "poc_on_github": 0.7,
            "vendor_confirmed_exploited": 0.9,
            "no_known_exploit": 0.0,
        }
    else:
        ea = config["exploit_availability"]

    scores = [ea["no_known_exploit"]]

    if cisa_kev:
        scores.append(ea["cisa_kev_listed"])
    if exploit_db:
        scores.append(ea["exploit_db_available"])
    if poc_github:
        scores.append(ea["poc_on_github"])
    if vendor_confirmed:
        scores.append(ea["vendor_confirmed_exploited"])

    return max(scores)


def score_mention_velocity(
    source_count: int,
    config: dict | None = None,
) -> float:
    """Score mention velocity using log-normalized source count.

    0 sources = 0.0, max_sources_cap sources = 1.0.
    """
    if source_count <= 0:
        return 0.0

    if config is None:
        max_cap = 20
    else:
        max_cap = config["mention_velocity"]["max_sources_cap"]

    # Clamp to cap
    clamped = min(source_count, max_cap)

    # Log normalization: log(1 + count) / log(1 + cap)
    score = math.log(1 + clamped) / math.log(1 + max_cap)
    return min(score, 1.0)


def calculate_recency_score(
    published_at: datetime,
    config: dict | None = None,
) -> float:
    """Calculate recency score using exponential decay.

    Just published = 1.0, one half-life old = 0.5, beyond max_age = 0.0.
    """
    if config is None:
        half_life_hours = 12
        max_age_hours = 72
    else:
        half_life_hours = config["recency"]["half_life_hours"]
        max_age_hours = config["recency"]["max_age_hours"]

    now = datetime.now(timezone.utc)
    age_hours = (now - published_at).total_seconds() / 3600.0

    if age_hours < 0:
        return 1.0

    if age_hours >= max_age_hours:
        return 0.0

    # Exponential decay: 0.5^(age / half_life)
    return math.pow(0.5, age_hours / half_life_hours)


def _score_product_prevalence(product: str | None, config: dict) -> float:
    """Score product prevalence based on config lookup."""
    if not product:
        return config["product_prevalence"]["default_score"]

    product_lower = product.lower()

    for p in config["product_prevalence"].get("high", []):
        if p.lower() in product_lower or product_lower in p.lower():
            return 0.9

    for p in config["product_prevalence"].get("medium", []):
        if p.lower() in product_lower or product_lower in p.lower():
            return 0.55

    return config["product_prevalence"]["default_score"]


class PriorityScorer:
    """Computes composite priority from 6 weighted factors.

    Supports audience-specific weight profiles.
    """

    def __init__(self, config: dict, audience: str | None = None):
        self.config = config

        if audience and audience in config.get("audience_profiles", {}):
            self.weights = config["audience_profiles"][audience]["weights"]
        else:
            self.weights = config["weights"]

        self.thresholds = config.get("thresholds", {})

    def score(self, article: dict) -> float:
        """Compute composite priority score for an article."""
        factors = {
            "source_authority": score_source_authority(
                tier=article.get("source_tier", 3),
                config=self.config,
                source_name=article.get("source_name"),
            ),
            "cvss_score": normalize_cvss(
                article.get("cvss"),
                default=self.config["cvss"]["default_no_cve"],
            ),
            "exploit_availability": score_exploit_availability(
                cisa_kev=article.get("cisa_kev", False),
                exploit_db=article.get("exploit_db", False),
                poc_github=article.get("poc_github", False),
                vendor_confirmed=article.get("vendor_confirmed", False),
                config=self.config,
            ),
            "mention_velocity": score_mention_velocity(
                source_count=article.get("source_count_24h", 0),
                config=self.config,
            ),
            "recency": calculate_recency_score(
                published_at=article.get("published", datetime.now(timezone.utc)),
                config=self.config,
            ),
            "product_prevalence": _score_product_prevalence(
                product=article.get("product"),
                config=self.config,
            ),
        }

        total = sum(
            self.weights.get(factor, 0) * value
            for factor, value in factors.items()
        )
        return max(0.0, min(1.0, total))

    def should_include(self, article: dict) -> bool:
        """Check if article meets the newsletter inclusion threshold."""
        s = self.score(article)
        return s >= self.thresholds.get("include_in_newsletter", 0.35)

    def is_executive_tldr(self, article: dict) -> bool:
        """Check if article meets the executive TL;DR threshold."""
        s = self.score(article)
        return s >= self.thresholds.get("executive_tldr", 0.75)

    def is_critical_alert(self, article: dict) -> bool:
        """Check if article meets the critical alert threshold."""
        s = self.score(article)
        return s >= self.thresholds.get("critical_alert", 0.90)
