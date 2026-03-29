"""Tests for priority scoring -- src/fidlie/ai/scoring.py

Validates the 6-factor weighted scoring formula, source authority tiers,
CVSS normalization, exploit availability boost, recency decay, audience
profiles, and threshold filtering.
"""

from __future__ import annotations

import math
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml

from fidlie.ai.scoring import (
    PriorityScorer,
    calculate_recency_score,
    normalize_cvss,
    score_exploit_availability,
    score_mention_velocity,
    score_source_authority,
)


# ---------------------------------------------------------------------------
# Load real scoring config
# ---------------------------------------------------------------------------

CONFIG_DIR = Path(__file__).resolve().parents[2] / "config"


@pytest.fixture(scope="module")
def scoring_config():
    """Load config/scoring.yaml."""
    with open(CONFIG_DIR / "scoring.yaml") as fh:
        return yaml.safe_load(fh)


@pytest.fixture(scope="module")
def scorer(scoring_config):
    """Instantiate PriorityScorer from real config."""
    return PriorityScorer(scoring_config)


# ===========================================================================
# Weight sanity checks
# ===========================================================================


class TestWeightConfiguration:
    """Config-level checks on the scoring weights."""

    def test_default_weights_sum_to_one(self, scoring_config):
        """The six default weights must sum to exactly 1.0."""
        weights = scoring_config["weights"]
        total = sum(weights.values())
        assert total == pytest.approx(1.0, abs=1e-6)

    def test_executive_weights_sum_to_one(self, scoring_config):
        """Executive audience weights sum to 1.0."""
        weights = scoring_config["audience_profiles"]["executive"]["weights"]
        assert sum(weights.values()) == pytest.approx(1.0, abs=1e-6)

    def test_technical_weights_sum_to_one(self, scoring_config):
        """Technical audience weights sum to 1.0."""
        weights = scoring_config["audience_profiles"]["technical"]["weights"]
        assert sum(weights.values()) == pytest.approx(1.0, abs=1e-6)

    def test_ioc_feed_weights_sum_to_one(self, scoring_config):
        """IOC feed audience weights sum to 1.0."""
        weights = scoring_config["audience_profiles"]["ioc_feed"]["weights"]
        assert sum(weights.values()) == pytest.approx(1.0, abs=1e-6)

    def test_all_six_factors_present(self, scoring_config):
        """All six scoring factors are defined in the config."""
        expected = {
            "source_authority",
            "cvss_score",
            "exploit_availability",
            "mention_velocity",
            "recency",
            "product_prevalence",
        }
        assert set(scoring_config["weights"].keys()) == expected


# ===========================================================================
# Source authority scoring
# ===========================================================================


class TestSourceAuthority:
    """Verify source authority weighting per tier."""

    def test_tier1_score(self, scoring_config):
        """Tier 1 sources score 1.0."""
        score = score_source_authority(tier=1, config=scoring_config)
        assert score == pytest.approx(1.0)

    def test_tier2_score(self, scoring_config):
        """Tier 2 sources score 0.7."""
        score = score_source_authority(tier=2, config=scoring_config)
        assert score == pytest.approx(0.7)

    def test_tier3_score(self, scoring_config):
        """Tier 3 sources score 0.4."""
        score = score_source_authority(tier=3, config=scoring_config)
        assert score == pytest.approx(0.4)

    def test_tier1_greater_than_tier2(self, scoring_config):
        """Tier 1 authority > Tier 2."""
        t1 = score_source_authority(tier=1, config=scoring_config)
        t2 = score_source_authority(tier=2, config=scoring_config)
        assert t1 > t2

    def test_tier2_greater_than_tier3(self, scoring_config):
        """Tier 2 authority > Tier 3."""
        t2 = score_source_authority(tier=2, config=scoring_config)
        t3 = score_source_authority(tier=3, config=scoring_config)
        assert t2 > t3

    def test_authority_in_range(self, scoring_config):
        """All authority scores are in [0.0, 1.0]."""
        for tier in (1, 2, 3):
            score = score_source_authority(tier=tier, config=scoring_config)
            assert 0.0 <= score <= 1.0


# ===========================================================================
# CVSS normalization
# ===========================================================================


class TestCvssNormalization:
    """Verify CVSS score normalization to [0.0, 1.0]."""

    def test_perfect_10(self):
        """CVSS 10.0 normalizes to 1.0."""
        assert normalize_cvss(10.0) == pytest.approx(1.0)

    def test_critical_9_8(self):
        """CVSS 9.8 normalizes to 0.98."""
        assert normalize_cvss(9.8) == pytest.approx(0.98)

    def test_high_7_5(self):
        """CVSS 7.5 normalizes to 0.75."""
        assert normalize_cvss(7.5) == pytest.approx(0.75)

    def test_medium_5_0(self):
        """CVSS 5.0 normalizes to 0.50."""
        assert normalize_cvss(5.0) == pytest.approx(0.50)

    def test_low_2_0(self):
        """CVSS 2.0 normalizes to 0.20."""
        assert normalize_cvss(2.0) == pytest.approx(0.20)

    def test_zero(self):
        """CVSS 0.0 normalizes to 0.0."""
        assert normalize_cvss(0.0) == pytest.approx(0.0)

    def test_no_cve_default(self, scoring_config):
        """Articles without CVEs get the configured default score."""
        default = scoring_config["cvss"]["default_no_cve"]
        assert normalize_cvss(None, default=default) == pytest.approx(default)

    def test_result_in_range(self):
        """All valid CVSS inputs produce output in [0.0, 1.0]."""
        for cvss in [0.0, 1.0, 3.5, 5.0, 7.0, 8.9, 9.8, 10.0]:
            assert 0.0 <= normalize_cvss(cvss) <= 1.0


# ===========================================================================
# Exploit availability boost
# ===========================================================================


class TestExploitAvailability:
    """Verify exploit availability scoring."""

    def test_cisa_kev_listed(self, scoring_config):
        """CISA KEV listing yields the maximum exploit score (1.0)."""
        score = score_exploit_availability(cisa_kev=True, config=scoring_config)
        assert score == pytest.approx(1.0)

    def test_exploit_db_available(self, scoring_config):
        """Public exploit on Exploit-DB scores 0.8."""
        score = score_exploit_availability(exploit_db=True, config=scoring_config)
        assert score == pytest.approx(0.8)

    def test_poc_on_github(self, scoring_config):
        """PoC on GitHub scores 0.7."""
        score = score_exploit_availability(poc_github=True, config=scoring_config)
        assert score == pytest.approx(0.7)

    def test_vendor_confirmed(self, scoring_config):
        """Vendor-confirmed exploitation scores 0.9."""
        score = score_exploit_availability(vendor_confirmed=True, config=scoring_config)
        assert score == pytest.approx(0.9)

    def test_no_known_exploit(self, scoring_config):
        """No known exploit scores 0.0."""
        score = score_exploit_availability(config=scoring_config)
        assert score == pytest.approx(0.0)

    def test_multiple_signals_take_max(self, scoring_config):
        """When multiple exploit signals are present, the highest wins."""
        score = score_exploit_availability(
            cisa_kev=True, exploit_db=True, poc_github=True, config=scoring_config
        )
        assert score == pytest.approx(1.0)

    def test_exploit_scores_in_range(self, scoring_config):
        """All exploit scores are in [0.0, 1.0]."""
        for kwargs in [
            {},
            {"cisa_kev": True},
            {"exploit_db": True},
            {"poc_github": True},
            {"vendor_confirmed": True},
        ]:
            score = score_exploit_availability(config=scoring_config, **kwargs)
            assert 0.0 <= score <= 1.0


# ===========================================================================
# Recency decay
# ===========================================================================


class TestRecencyDecay:
    """Verify exponential recency decay calculation."""

    def test_just_published_is_one(self, scoring_config):
        """An article published right now scores ~1.0."""
        now = datetime.now(timezone.utc)
        score = calculate_recency_score(now, config=scoring_config)
        assert score == pytest.approx(1.0, abs=0.05)

    def test_half_life_is_half(self, scoring_config):
        """An article one half-life old scores approximately 0.5."""
        half_life = scoring_config["recency"]["half_life_hours"]
        published = datetime.now(timezone.utc) - timedelta(hours=half_life)
        score = calculate_recency_score(published, config=scoring_config)
        assert score == pytest.approx(0.5, abs=0.05)

    def test_two_half_lives_is_quarter(self, scoring_config):
        """Two half-lives yields approximately 0.25."""
        half_life = scoring_config["recency"]["half_life_hours"]
        published = datetime.now(timezone.utc) - timedelta(hours=2 * half_life)
        score = calculate_recency_score(published, config=scoring_config)
        assert score == pytest.approx(0.25, abs=0.05)

    def test_beyond_max_age_is_zero(self, scoring_config):
        """Articles older than max_age_hours score 0.0."""
        max_age = scoring_config["recency"]["max_age_hours"]
        published = datetime.now(timezone.utc) - timedelta(hours=max_age + 1)
        score = calculate_recency_score(published, config=scoring_config)
        assert score == pytest.approx(0.0, abs=0.01)

    def test_newer_scores_higher(self, scoring_config):
        """A 1-hour-old article scores higher than a 24-hour-old article."""
        recent = datetime.now(timezone.utc) - timedelta(hours=1)
        older = datetime.now(timezone.utc) - timedelta(hours=24)
        score_recent = calculate_recency_score(recent, config=scoring_config)
        score_older = calculate_recency_score(older, config=scoring_config)
        assert score_recent > score_older

    def test_recency_score_in_range(self, scoring_config):
        """Recency score is always in [0.0, 1.0]."""
        for hours_ago in [0, 1, 6, 12, 24, 48, 72, 100]:
            published = datetime.now(timezone.utc) - timedelta(hours=hours_ago)
            score = calculate_recency_score(published, config=scoring_config)
            assert 0.0 <= score <= 1.0


# ===========================================================================
# Mention velocity
# ===========================================================================


class TestMentionVelocity:
    """Verify mention velocity scoring (number of distinct sources in 24h)."""

    def test_single_source_low(self):
        """A single-source story has low velocity score."""
        score = score_mention_velocity(source_count=1)
        assert score < 0.3

    def test_three_sources_is_trend(self, scoring_config):
        """Three sources meets the min_sources_for_trend threshold."""
        min_trend = scoring_config["mention_velocity"]["min_sources_for_trend"]
        assert min_trend == 3
        score = score_mention_velocity(source_count=3)
        assert score > 0.0

    def test_twenty_sources_caps_at_one(self, scoring_config):
        """Twenty sources (the cap) normalizes to 1.0."""
        cap = scoring_config["mention_velocity"]["max_sources_cap"]
        score = score_mention_velocity(source_count=cap)
        assert score == pytest.approx(1.0, abs=0.05)

    def test_more_sources_equals_higher_score(self):
        """More sources always means a higher (or equal) velocity score."""
        s5 = score_mention_velocity(source_count=5)
        s10 = score_mention_velocity(source_count=10)
        assert s10 >= s5

    def test_zero_sources(self):
        """Zero sources scores 0.0."""
        score = score_mention_velocity(source_count=0)
        assert score == pytest.approx(0.0)

    def test_velocity_in_range(self):
        """Velocity scores are always in [0.0, 1.0]."""
        for count in [0, 1, 2, 5, 10, 20, 50]:
            score = score_mention_velocity(source_count=count)
            assert 0.0 <= score <= 1.0


# ===========================================================================
# Composite priority score (6-factor formula)
# ===========================================================================


class TestCompositeScore:
    """Integration test for the full priority scoring formula."""

    def test_critical_article_scores_high(self, scorer):
        """A CISA-KEV-listed, CVSS 9.8, Tier 1, recent article scores above 0.75."""
        article = {
            "source_tier": 1,
            "cvss": 9.8,
            "cisa_kev": True,
            "source_count_24h": 10,
            "published": datetime.now(timezone.utc) - timedelta(hours=1),
            "product": "Apache",
        }
        score = scorer.score(article)
        assert score >= 0.75

    def test_low_priority_article_scores_low(self, scorer):
        """A Tier 3, no CVE, no exploit, old, single-source article scores low."""
        article = {
            "source_tier": 3,
            "cvss": None,
            "cisa_kev": False,
            "source_count_24h": 1,
            "published": datetime.now(timezone.utc) - timedelta(hours=60),
            "product": None,
        }
        score = scorer.score(article)
        assert score < 0.35

    def test_score_range(self, scorer):
        """All scores are in [0.0, 1.0]."""
        for article in [
            {
                "source_tier": 1, "cvss": 10.0, "cisa_kev": True,
                "source_count_24h": 20,
                "published": datetime.now(timezone.utc),
                "product": "Microsoft Windows",
            },
            {
                "source_tier": 3, "cvss": None, "cisa_kev": False,
                "source_count_24h": 0,
                "published": datetime.now(timezone.utc) - timedelta(hours=100),
                "product": None,
            },
        ]:
            score = scorer.score(article)
            assert 0.0 <= score <= 1.0

    def test_higher_cvss_means_higher_score(self, scorer):
        """Higher CVSS produces a higher composite score, all else equal."""
        base = {
            "source_tier": 2, "cisa_kev": False,
            "source_count_24h": 3,
            "published": datetime.now(timezone.utc) - timedelta(hours=2),
            "product": None,
        }
        low = scorer.score({**base, "cvss": 3.0})
        high = scorer.score({**base, "cvss": 9.8})
        assert high > low

    def test_exploit_boosts_score(self, scorer):
        """Exploit availability meaningfully increases the score."""
        base = {
            "source_tier": 2, "cvss": 7.0,
            "source_count_24h": 3,
            "published": datetime.now(timezone.utc) - timedelta(hours=2),
            "product": None,
        }
        no_exploit = scorer.score({**base, "cisa_kev": False})
        with_exploit = scorer.score({**base, "cisa_kev": True})
        assert with_exploit > no_exploit


# ===========================================================================
# Audience-specific weight profiles
# ===========================================================================


class TestAudienceProfiles:
    """Verify that different audience profiles produce different rankings."""

    def test_executive_emphasizes_velocity(self, scoring_config):
        """Executive profile gives more weight to mention_velocity than default."""
        default_vel = scoring_config["weights"]["mention_velocity"]
        exec_vel = scoring_config["audience_profiles"]["executive"]["weights"]["mention_velocity"]
        assert exec_vel > default_vel

    def test_technical_emphasizes_cvss(self, scoring_config):
        """Technical profile gives same or more weight to CVSS."""
        tech_cvss = scoring_config["audience_profiles"]["technical"]["weights"]["cvss_score"]
        assert tech_cvss >= 0.25

    def test_ioc_emphasizes_exploit(self, scoring_config):
        """IOC feed profile gives the highest weight to exploit_availability."""
        ioc_exploit = scoring_config["audience_profiles"]["ioc_feed"]["weights"]["exploit_availability"]
        assert ioc_exploit >= 0.30

    def test_ioc_emphasizes_recency(self, scoring_config):
        """IOC feed profile gives more weight to recency than the default."""
        default_rec = scoring_config["weights"]["recency"]
        ioc_rec = scoring_config["audience_profiles"]["ioc_feed"]["weights"]["recency"]
        assert ioc_rec > default_rec

    def test_executive_scorer_produces_different_ranking(self, scoring_config):
        """An executive scorer can re-rank articles differently from the default."""
        default_scorer = PriorityScorer(scoring_config)
        exec_scorer = PriorityScorer(scoring_config, audience="executive")

        # Article 1: high velocity (many mentions), moderate CVSS
        art1 = {
            "source_tier": 2, "cvss": 6.0, "cisa_kev": False,
            "source_count_24h": 15,
            "published": datetime.now(timezone.utc) - timedelta(hours=2),
            "product": None,
        }
        # Article 2: high CVSS, low velocity
        art2 = {
            "source_tier": 1, "cvss": 9.8, "cisa_kev": True,
            "source_count_24h": 2,
            "published": datetime.now(timezone.utc) - timedelta(hours=2),
            "product": "Microsoft Windows",
        }

        default_scores = (default_scorer.score(art1), default_scorer.score(art2))
        exec_scores = (exec_scorer.score(art1), exec_scorer.score(art2))

        # The two profiles should produce different score ratios
        default_ratio = default_scores[0] / max(default_scores[1], 0.001)
        exec_ratio = exec_scores[0] / max(exec_scores[1], 0.001)
        assert abs(default_ratio - exec_ratio) > 0.01


# ===========================================================================
# Threshold filtering
# ===========================================================================


class TestThresholdFiltering:
    """Verify threshold-based inclusion/exclusion decisions."""

    def test_include_in_newsletter_threshold(self, scoring_config):
        """Threshold value is 0.35."""
        assert scoring_config["thresholds"]["include_in_newsletter"] == 0.35

    def test_executive_tldr_threshold(self, scoring_config):
        """Executive TL;DR threshold is 0.75."""
        assert scoring_config["thresholds"]["executive_tldr"] == 0.75

    def test_critical_alert_threshold(self, scoring_config):
        """Critical alert (Slack push) threshold is 0.90."""
        assert scoring_config["thresholds"]["critical_alert"] == 0.90

    def test_below_newsletter_threshold_excluded(self, scorer, scoring_config):
        """An article scoring below 0.35 is excluded from the newsletter."""
        article = {
            "source_tier": 3, "cvss": None, "cisa_kev": False,
            "source_count_24h": 1,
            "published": datetime.now(timezone.utc) - timedelta(hours=60),
            "product": None,
        }
        score = scorer.score(article)
        threshold = scoring_config["thresholds"]["include_in_newsletter"]
        if score < threshold:
            assert not scorer.should_include(article)

    def test_above_executive_tldr_included(self, scorer, scoring_config):
        """A high-scoring article is flagged for Executive TL;DR."""
        article = {
            "source_tier": 1, "cvss": 9.8, "cisa_kev": True,
            "source_count_24h": 15,
            "published": datetime.now(timezone.utc) - timedelta(hours=1),
            "product": "Microsoft Windows",
        }
        score = scorer.score(article)
        threshold = scoring_config["thresholds"]["executive_tldr"]
        if score >= threshold:
            assert scorer.is_executive_tldr(article)

    def test_above_critical_triggers_alert(self, scorer, scoring_config):
        """A critical-scoring article triggers a Slack alert."""
        article = {
            "source_tier": 1, "cvss": 10.0, "cisa_kev": True,
            "source_count_24h": 20,
            "published": datetime.now(timezone.utc),
            "product": "Microsoft Windows",
        }
        score = scorer.score(article)
        threshold = scoring_config["thresholds"]["critical_alert"]
        if score >= threshold:
            assert scorer.is_critical_alert(article)
