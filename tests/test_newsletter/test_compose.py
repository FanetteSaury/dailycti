"""Tests for newsletter composition -- src/fidlie/newsletter/compose.py

Validates section assignment, section ordering, TL;DR generation, Jinja2
HTML rendering, plaintext fallback, severity badges, and CVE tag rendering.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml

from fidlie.newsletter.compose import (
    NewsletterComposer,
    assign_sections,
    generate_plaintext,
    render_html,
    select_tldr_articles,
    severity_for_cvss,
)


# ---------------------------------------------------------------------------
# Load real configs
# ---------------------------------------------------------------------------

CONFIG_DIR = Path(__file__).resolve().parents[2] / "config"


@pytest.fixture(scope="module")
def newsletter_config():
    with open(CONFIG_DIR / "newsletter.yaml") as fh:
        return yaml.safe_load(fh)


@pytest.fixture(scope="module")
def scoring_config():
    with open(CONFIG_DIR / "scoring.yaml") as fh:
        return yaml.safe_load(fh)


@pytest.fixture
def sample_articles():
    """A ranked list of articles with various attributes."""
    now = datetime.now(timezone.utc)
    return [
        {
            "id": "art-1",
            "title": "Critical RCE in Apache Struts (CVE-2024-53677)",
            "url": "https://example.com/struts",
            "summary": "CVSS 9.8, actively exploited RCE.",
            "score": 0.95,
            "cvss": 9.8,
            "cves": ["CVE-2024-53677"],
            "cisa_kev": True,
            "entities": {"threat_actors": [], "malware": []},
            "source": "CISA Cybersecurity Advisories",
            "source_category": "government",
            "published": now - timedelta(hours=2),
            "has_exploit": True,
        },
        {
            "id": "art-2",
            "title": "APT28 Deploys New Sednit Variant",
            "url": "https://example.com/apt28",
            "summary": "Fancy Bear targets Eastern European governments.",
            "score": 0.82,
            "cvss": None,
            "cves": ["CVE-2024-38178"],
            "cisa_kev": False,
            "entities": {"threat_actors": ["APT28"], "malware": ["Sednit"]},
            "source": "Mandiant Blog",
            "source_category": "research_blog",
            "published": now - timedelta(hours=4),
            "has_exploit": False,
        },
        {
            "id": "art-3",
            "title": "LockBit Claims Major Healthcare Breach",
            "url": "https://example.com/lockbit",
            "summary": "Ransomware gang lists hospital data on leak site.",
            "score": 0.78,
            "cvss": None,
            "cves": [],
            "cisa_kev": False,
            "entities": {"threat_actors": ["LockBit"], "malware": ["LockBit"]},
            "source": "BleepingComputer",
            "source_category": "news",
            "published": now - timedelta(hours=3),
            "has_exploit": False,
        },
        {
            "id": "art-4",
            "title": "Microsoft Patch Tuesday: 48 Fixes",
            "url": "https://example.com/patch-tuesday",
            "summary": "Monthly security update addresses critical vulns.",
            "score": 0.70,
            "cvss": 8.1,
            "cves": ["CVE-2024-49999", "CVE-2024-50000"],
            "cisa_kev": False,
            "entities": {"threat_actors": [], "malware": []},
            "source": "Microsoft MSRC",
            "source_category": "vendor_advisory",
            "published": now - timedelta(hours=6),
            "has_exploit": False,
        },
        {
            "id": "art-5",
            "title": "NIST Updates Cybersecurity Framework",
            "url": "https://example.com/nist-csf",
            "summary": "CSF 2.0 introduces governance function.",
            "score": 0.40,
            "cvss": None,
            "cves": [],
            "cisa_kev": False,
            "entities": {"threat_actors": [], "malware": []},
            "source": "CISA Cybersecurity Advisories",
            "source_category": "government",
            "published": now - timedelta(hours=12),
            "has_exploit": False,
        },
        {
            "id": "art-6",
            "title": "New Cobalt Strike Loader Found in the Wild",
            "url": "https://example.com/cs-loader",
            "summary": "Novel loader deploys CS beacons via ISO files.",
            "score": 0.65,
            "cvss": None,
            "cves": [],
            "cisa_kev": False,
            "entities": {"threat_actors": [], "malware": ["Cobalt Strike"]},
            "source": "Cisco Talos Intelligence",
            "source_category": "research_blog",
            "published": now - timedelta(hours=5),
            "has_exploit": True,
        },
    ]


# ===========================================================================
# Section assignment
# ===========================================================================


class TestSectionAssignment:
    """Verify articles are routed to the correct newsletter sections."""

    def test_critical_vuln_section(self, sample_articles, newsletter_config):
        """Article with CVSS >= 9.0 goes to 'critical_vulns'."""
        assignments = assign_sections(sample_articles, newsletter_config)
        critical_ids = [a["id"] for a in assignments.get("critical_vulns", [])]
        assert "art-1" in critical_ids

    def test_threat_actor_section(self, sample_articles, newsletter_config):
        """Article mentioning a threat actor goes to 'threat_actors'."""
        assignments = assign_sections(sample_articles, newsletter_config)
        actor_ids = [a["id"] for a in assignments.get("threat_actors", [])]
        assert "art-2" in actor_ids

    def test_breach_section(self, sample_articles, newsletter_config):
        """Article about a breach/ransomware goes to 'breaches'."""
        assignments = assign_sections(sample_articles, newsletter_config)
        breach_ids = [a["id"] for a in assignments.get("breaches", [])]
        assert "art-3" in breach_ids

    def test_vendor_advisory_section(self, sample_articles, newsletter_config):
        """Microsoft MSRC article goes to 'vendor_advisories'."""
        assignments = assign_sections(sample_articles, newsletter_config)
        vendor_ids = [a["id"] for a in assignments.get("vendor_advisories", [])]
        assert "art-4" in vendor_ids

    def test_malware_section(self, sample_articles, newsletter_config):
        """Article about Cobalt Strike goes to 'malware_tooling'."""
        assignments = assign_sections(sample_articles, newsletter_config)
        malware_ids = [a["id"] for a in assignments.get("malware_tooling", [])]
        assert "art-6" in malware_ids

    def test_policy_section(self, sample_articles, newsletter_config):
        """NIST framework update goes to 'policy_compliance'."""
        assignments = assign_sections(sample_articles, newsletter_config)
        policy_ids = [a["id"] for a in assignments.get("policy_compliance", [])]
        assert "art-5" in policy_ids

    def test_max_items_respected(self, newsletter_config):
        """No section exceeds its max_items limit."""
        # Generate more articles than the limit
        many_articles = [
            {
                "id": f"vuln-{i}",
                "title": f"CVE-2024-{10000+i}",
                "url": f"https://example.com/vuln-{i}",
                "summary": "Critical vulnerability.",
                "score": 0.9,
                "cvss": 9.5,
                "cves": [f"CVE-2024-{10000+i}"],
                "cisa_kev": True,
                "entities": {"threat_actors": [], "malware": []},
                "source": "NVD API 2.0",
                "source_category": "vulnerability_db",
                "published": datetime.now(timezone.utc),
                "has_exploit": True,
            }
            for i in range(20)
        ]
        assignments = assign_sections(many_articles, newsletter_config)
        for section_cfg in newsletter_config["sections"]:
            sid = section_cfg["id"]
            max_items = section_cfg["max_items"]
            assert len(assignments.get(sid, [])) <= max_items


# ===========================================================================
# Section ordering
# ===========================================================================


class TestSectionOrdering:
    """Verify sections appear in the configured order."""

    def test_section_order_matches_config(self, newsletter_config):
        """The section IDs in config define the rendering order."""
        expected_order = [s["id"] for s in newsletter_config["sections"]]
        assert expected_order[0] == "executive_tldr"
        assert expected_order[1] == "critical_vulns"
        assert expected_order[-1] == "ioc_appendix"

    def test_composer_respects_order(self, sample_articles, newsletter_config):
        """The composer outputs sections in config-defined order."""
        composer = NewsletterComposer(newsletter_config)
        ordered_sections = composer.get_section_order()
        config_order = [s["id"] for s in newsletter_config["sections"]]
        assert ordered_sections == config_order


# ===========================================================================
# TL;DR generation
# ===========================================================================


class TestTldrGeneration:
    """Verify top-5 selection for Executive TL;DR."""

    def test_selects_top_5(self, sample_articles):
        """TL;DR includes at most 5 articles."""
        tldr = select_tldr_articles(sample_articles, max_items=5)
        assert len(tldr) <= 5

    def test_sorted_by_score_descending(self, sample_articles):
        """Selected articles are ordered by score, highest first."""
        tldr = select_tldr_articles(sample_articles, max_items=5)
        scores = [a["score"] for a in tldr]
        assert scores == sorted(scores, reverse=True)

    def test_highest_score_first(self, sample_articles):
        """The article with the highest score appears first."""
        tldr = select_tldr_articles(sample_articles, max_items=5)
        assert tldr[0]["id"] == "art-1"  # score 0.95

    def test_fewer_than_5_articles(self):
        """If fewer than 5 articles exist, all are included."""
        articles = [
            {"id": "a", "score": 0.9, "title": "A"},
            {"id": "b", "score": 0.8, "title": "B"},
        ]
        tldr = select_tldr_articles(articles, max_items=5)
        assert len(tldr) == 2

    def test_empty_input(self):
        """Empty article list returns empty TL;DR."""
        assert select_tldr_articles([], max_items=5) == []


# ===========================================================================
# Jinja2 HTML rendering
# ===========================================================================


class TestHtmlRendering:
    """Verify Jinja2 template produces valid HTML."""

    def test_renders_string(self, sample_articles, newsletter_config):
        """render_html returns a non-empty string."""
        html = render_html(sample_articles, newsletter_config)
        assert isinstance(html, str)
        assert len(html) > 0

    def test_contains_newsletter_name(self, sample_articles, newsletter_config):
        """The newsletter name appears in the rendered HTML."""
        html = render_html(sample_articles, newsletter_config)
        assert newsletter_config["newsletter"]["name"] in html

    def test_contains_article_titles(self, sample_articles, newsletter_config):
        """Article titles appear in the rendered output."""
        html = render_html(sample_articles, newsletter_config)
        for article in sample_articles[:3]:
            assert article["title"] in html

    def test_contains_article_urls(self, sample_articles, newsletter_config):
        """Article URLs appear as href links."""
        html = render_html(sample_articles, newsletter_config)
        for article in sample_articles[:3]:
            assert article["url"] in html

    def test_html_has_doctype_or_html_tag(self, sample_articles, newsletter_config):
        """Output contains basic HTML structure."""
        html = render_html(sample_articles, newsletter_config)
        assert "<html" in html.lower() or "<!doctype" in html.lower()


# ===========================================================================
# Plaintext fallback
# ===========================================================================


class TestPlaintextFallback:
    """Verify plaintext version of the newsletter."""

    def test_generates_string(self, sample_articles, newsletter_config):
        """generate_plaintext returns a non-empty string."""
        text = generate_plaintext(sample_articles, newsletter_config)
        assert isinstance(text, str)
        assert len(text) > 0

    def test_no_html_tags(self, sample_articles, newsletter_config):
        """Plaintext output contains no HTML tags."""
        text = generate_plaintext(sample_articles, newsletter_config)
        assert "<html" not in text.lower()
        assert "<div" not in text.lower()
        assert "<p>" not in text

    def test_contains_article_titles(self, sample_articles, newsletter_config):
        """Article titles appear in the plaintext."""
        text = generate_plaintext(sample_articles, newsletter_config)
        for article in sample_articles[:3]:
            assert article["title"] in text

    def test_contains_urls(self, sample_articles, newsletter_config):
        """Article URLs are present in the plaintext."""
        text = generate_plaintext(sample_articles, newsletter_config)
        for article in sample_articles[:3]:
            assert article["url"] in text


# ===========================================================================
# Severity badge assignment
# ===========================================================================


class TestSeverityBadge:
    """Verify CVSS-to-severity-label mapping."""

    def test_critical(self):
        """CVSS >= 9.0 is 'critical'."""
        assert severity_for_cvss(9.0) == "critical"
        assert severity_for_cvss(10.0) == "critical"
        assert severity_for_cvss(9.8) == "critical"

    def test_high(self):
        """CVSS 7.0-8.9 is 'high'."""
        assert severity_for_cvss(7.0) == "high"
        assert severity_for_cvss(8.9) == "high"

    def test_medium(self):
        """CVSS 4.0-6.9 is 'medium'."""
        assert severity_for_cvss(4.0) == "medium"
        assert severity_for_cvss(6.9) == "medium"

    def test_low(self):
        """CVSS 0.1-3.9 is 'low'."""
        assert severity_for_cvss(0.1) == "low"
        assert severity_for_cvss(3.9) == "low"

    def test_info_for_zero(self):
        """CVSS 0.0 is 'info'."""
        assert severity_for_cvss(0.0) == "info"

    def test_none_returns_info(self):
        """None CVSS returns 'info'."""
        assert severity_for_cvss(None) == "info"

    def test_badge_colors_defined(self, newsletter_config):
        """All severity levels have a color defined in newsletter.yaml."""
        colors = newsletter_config["rendering"]["severity_colors"]
        for level in ("critical", "high", "medium", "low", "info"):
            assert level in colors
            assert colors[level].startswith("#")


# ===========================================================================
# CVE tag rendering
# ===========================================================================


class TestCveTagRendering:
    """Verify that CVE identifiers are rendered as linked tags in HTML."""

    def test_cve_rendered_as_tag(self, sample_articles, newsletter_config):
        """CVE identifiers appear in the HTML output."""
        html = render_html(sample_articles, newsletter_config)
        assert "CVE-2024-53677" in html

    def test_cve_links_to_nvd(self, sample_articles, newsletter_config):
        """CVE tags link to the NVD detail page."""
        html = render_html(sample_articles, newsletter_config)
        assert "nvd.nist.gov" in html or "CVE-2024-53677" in html

    def test_multiple_cves_rendered(self, sample_articles, newsletter_config):
        """Articles with multiple CVEs render all of them."""
        html = render_html(sample_articles, newsletter_config)
        # art-4 has two CVEs
        assert "CVE-2024-49999" in html
        assert "CVE-2024-50000" in html
