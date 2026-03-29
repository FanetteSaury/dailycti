"""Newsletter composition -- section assignment, TL;DR, HTML/plaintext rendering.

Provides utilities to compose a cybersecurity newsletter from scored articles,
assign them to configured sections, and render both HTML and plaintext output.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import jinja2


# ---------------------------------------------------------------------------
# Severity mapping
# ---------------------------------------------------------------------------

def severity_for_cvss(score: float | None) -> str:
    """Map a CVSS float to a severity label string.

    Returns one of: "critical", "high", "medium", "low", "info".
    """
    if score is None or score == 0.0:
        return "info"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


# ---------------------------------------------------------------------------
# TL;DR selection
# ---------------------------------------------------------------------------

def select_tldr_articles(articles: list[dict], max_items: int = 5) -> list[dict]:
    """Select top *max_items* articles by priority score for executive TL;DR."""
    if not articles:
        return []
    sorted_arts = sorted(articles, key=lambda a: a.get("score", 0), reverse=True)
    return sorted_arts[:max_items]


# ---------------------------------------------------------------------------
# Section assignment
# ---------------------------------------------------------------------------

def _article_matches_section(article: dict, section_cfg: dict) -> bool:
    """Return True if *article* belongs in the section described by *section_cfg*."""
    sid = section_cfg["id"]

    # executive_tldr and ioc_appendix are handled separately
    if sid == "executive_tldr":
        return False
    if sid == "ioc_appendix":
        return False

    filters = section_cfg.get("filters", {})

    # --- critical_vulns: CVSS >= threshold or CISA KEV ---
    if sid == "critical_vulns":
        min_cvss = filters.get("min_cvss", 9.0)
        cvss = article.get("cvss")
        if cvss is not None and cvss >= min_cvss:
            return True
        if article.get("cisa_kev"):
            return True
        return False

    # --- exploits_zerodays: has_exploit ---
    if sid == "exploits_zerodays":
        if filters.get("requires_exploit") and article.get("has_exploit"):
            return True
        return False

    # --- threat_actors: entities contain threat actors ---
    if sid == "threat_actors":
        entities = article.get("entities", {})
        actors = entities.get("threat_actors", [])
        if actors:
            return True
        return False

    # --- breaches: keyword match in title/summary ---
    if sid == "breaches":
        keywords = filters.get("keywords", [])
        text = (article.get("title", "") + " " + article.get("summary", "")).lower()
        for kw in keywords:
            if kw.lower() in text:
                return True
        return False

    # --- malware_tooling: entities contain malware ---
    if sid == "malware_tooling":
        entities = article.get("entities", {})
        malware = entities.get("malware", [])
        if malware:
            return True
        return False

    # --- vendor_advisories: source or category match ---
    if sid == "vendor_advisories":
        sources = filters.get("sources", [])
        categories = filters.get("categories", [])
        if article.get("source") in sources:
            return True
        if article.get("source_category") in categories:
            return True
        return False

    # --- policy_compliance: keyword or source match ---
    if sid == "policy_compliance":
        keywords = filters.get("keywords", [])
        sources = filters.get("sources", [])
        text = (article.get("title", "") + " " + article.get("summary", "")).lower()
        for kw in keywords:
            if kw.lower() in text:
                return True
        if article.get("source") in sources:
            return True
        return False

    return False


def assign_sections(articles: list[dict], config: dict) -> dict[str, list[dict]]:
    """Assign articles to newsletter sections based on config filters.

    Returns a dict mapping section_id -> list of articles.
    """
    sections_cfg = config.get("sections", [])
    assignments: dict[str, list[dict]] = {}

    for section_cfg in sections_cfg:
        sid = section_cfg["id"]
        max_items = section_cfg.get("max_items", 10)
        matched: list[dict] = []
        for article in articles:
            if _article_matches_section(article, section_cfg):
                matched.append(article)
                if len(matched) >= max_items:
                    break
        if matched:
            assignments[sid] = matched

    return assignments


# ---------------------------------------------------------------------------
# HTML rendering
# ---------------------------------------------------------------------------

# Section display metadata
_SECTION_META: dict[str, dict[str, str]] = {
    "critical_vulns": {"color": "#dc2626", "icon": "\U0001f6a8", "name": "Critical Vulnerabilities"},
    "exploits_zerodays": {"color": "#b91c1c", "icon": "\u2694\ufe0f", "name": "Active Exploits & Zero-Days"},
    "threat_actors": {"color": "#7c3aed", "icon": "\U0001f3ad", "name": "Threat Actor Spotlight"},
    "breaches": {"color": "#ea580c", "icon": "\U0001f4a5", "name": "Data Breaches & Incidents"},
    "malware_tooling": {"color": "#059669", "icon": "\U0001f9ea", "name": "Malware & Tooling"},
    "vendor_advisories": {"color": "#2563eb", "icon": "\U0001f4e6", "name": "Vendor Advisories & Patches"},
    "policy_compliance": {"color": "#0d9488", "icon": "\U0001f4dc", "name": "Policy, Compliance & Regulation"},
    "ioc_appendix": {"color": "#6b7280", "icon": "\U0001f50d", "name": "IOC Appendix"},
}


def _prepare_template_data(articles: list[dict], config: dict) -> dict[str, Any]:
    """Build the template context dict from articles and config."""
    nl_cfg = config.get("newsletter", {})
    newsletter_name = nl_cfg.get("name", "DailyCTI Brief")
    tagline = nl_cfg.get("tagline", "")
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    # TL;DR items
    tldr = select_tldr_articles(articles, max_items=5)
    tldr_items = []
    for a in tldr:
        tldr_items.append({
            "title": a.get("title", ""),
            "summary": a.get("summary", ""),
            "link": a.get("url", ""),
            "source": a.get("source", ""),
            "cves": a.get("cves", []),
        })

    # Sections
    assignments = assign_sections(articles, config)
    sections_cfg = config.get("sections", [])
    sections = []
    for scfg in sections_cfg:
        sid = scfg["id"]
        if sid == "executive_tldr":
            continue
        section_articles = assignments.get(sid, [])
        if not section_articles:
            continue
        meta = _SECTION_META.get(sid, {"color": "#6b7280", "icon": "", "name": scfg.get("name", sid)})
        rendered_articles = []
        for a in section_articles:
            published = a.get("published")
            if hasattr(published, "strftime"):
                published_short = published.strftime("%b %d, %H:%M UTC")
            else:
                published_short = str(published) if published else ""
            rendered_articles.append({
                "title": a.get("title", ""),
                "link": a.get("url", ""),
                "source": a.get("source", ""),
                "summary": a.get("summary", ""),
                "cves": a.get("cves", []),
                "severity": severity_for_cvss(a.get("cvss")),
                "published_short": published_short,
            })
        sections.append({
            "name": meta["name"],
            "color": meta["color"],
            "icon": meta["icon"],
            "articles": rendered_articles,
        })

    sources = set(a.get("source", "") for a in articles)
    return {
        "newsletter_name": newsletter_name,
        "tagline": tagline,
        "date_str": date_str,
        "article_count": len(articles),
        "source_count": len(sources),
        "tldr_items": tldr_items,
        "sections": sections,
    }


def render_html(articles: list[dict], config: dict, template_path: str | Path | None = None) -> str:
    """Render newsletter HTML using the Jinja2 template.

    Parameters
    ----------
    articles:
        Scored article dicts.
    config:
        The parsed newsletter.yaml config.
    template_path:
        Optional explicit path to a Jinja2 HTML template.  When *None* the
        default ``demo/newsletter_template.html`` is used.
    """
    if template_path is None:
        template_path = Path(__file__).resolve().parents[3] / "demo" / "newsletter_template.html"
    else:
        template_path = Path(template_path)

    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(str(template_path.parent)),
        autoescape=True,
    )
    template = env.get_template(template_path.name)
    context = _prepare_template_data(articles, config)
    return template.render(**context)


# ---------------------------------------------------------------------------
# Plaintext fallback
# ---------------------------------------------------------------------------

def generate_plaintext(articles: list[dict], config: dict) -> str:
    """Generate a plaintext version of the newsletter (no HTML tags)."""
    nl_cfg = config.get("newsletter", {})
    newsletter_name = nl_cfg.get("name", "DailyCTI Brief")
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    lines: list[str] = []
    lines.append(f"{newsletter_name} - {date_str}")
    lines.append("=" * len(lines[0]))
    lines.append("")

    # TL;DR
    tldr = select_tldr_articles(articles, max_items=5)
    if tldr:
        lines.append("EXECUTIVE TL;DR")
        lines.append("-" * 15)
        for a in tldr:
            cve_str = ""
            if a.get("cves"):
                cve_str = f" ({', '.join(a['cves'])})"
            lines.append(f"  * {a['title']}{cve_str}")
            lines.append(f"    {a.get('summary', '')}")
            lines.append(f"    {a.get('url', '')}")
            lines.append("")

    # Sections
    assignments = assign_sections(articles, config)
    sections_cfg = config.get("sections", [])
    for scfg in sections_cfg:
        sid = scfg["id"]
        if sid == "executive_tldr":
            continue
        section_articles = assignments.get(sid, [])
        if not section_articles:
            continue
        section_name = scfg.get("name", sid)
        lines.append(section_name.upper())
        lines.append("-" * len(section_name))
        for a in section_articles:
            severity = severity_for_cvss(a.get("cvss"))
            sev_label = f"[{severity.upper()}] " if severity != "info" else ""
            cve_str = ""
            if a.get("cves"):
                cve_str = f" ({', '.join(a['cves'])})"
            lines.append(f"  {sev_label}{a['title']}{cve_str}")
            lines.append(f"    {a.get('summary', '')}")
            lines.append(f"    Source: {a.get('source', '')}")
            lines.append(f"    Link: {a.get('url', '')}")
            lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# NewsletterComposer orchestrator
# ---------------------------------------------------------------------------

class NewsletterComposer:
    """Orchestrator class that ties together section assignment, TL;DR
    generation, and rendering into a single workflow.
    """

    def __init__(self, newsletter_config: dict, scoring_config: dict | None = None):
        self.config = newsletter_config
        self.scoring_config = scoring_config

    def get_section_order(self) -> list[str]:
        """Return the ordered list of section IDs from the config."""
        return [s["id"] for s in self.config.get("sections", [])]

    def compose(self, articles: list[dict]) -> dict[str, Any]:
        """Run the full composition pipeline and return newsletter data."""
        assignments = assign_sections(articles, self.config)
        tldr = select_tldr_articles(articles, max_items=5)
        return {
            "tldr": tldr,
            "sections": assignments,
            "section_order": self.get_section_order(),
        }

    def render_html(self, articles: list[dict], template_path: str | Path | None = None) -> str:
        """Render the newsletter as HTML."""
        return render_html(articles, self.config, template_path=template_path)

    def render_plaintext(self, articles: list[dict]) -> str:
        """Render the newsletter as plaintext."""
        return generate_plaintext(articles, self.config)
