#!/usr/bin/env python3
"""DailyCTI Demo -- Compose newsletter HTML from scraped articles."""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

DEMO_DIR = Path(__file__).parent
ARTICLES_FILE = DEMO_DIR / "articles.json"
TEMPLATE_FILE = "newsletter_template.html"
OUTPUT_HTML = DEMO_DIR / "newsletter_output.html"
OUTPUT_TXT = DEMO_DIR / "newsletter_output.txt"

# --- Section Definitions (matching config/newsletter.yaml) ---
SECTIONS = [
    {
        "id": "critical_vulns",
        "name": "Critical Vulnerabilities",
        "icon": "🔴",
        "color": "#dc2626",
        "categories": ["vulnerability"],
        "severity_filter": ["critical", "high"],
    },
    {
        "id": "exploits_zerodays",
        "name": "Active Exploits & Zero-Days",
        "icon": "⚡",
        "color": "#ea580c",
        "categories": ["vulnerability"],
        "severity_filter": ["critical"],
        "keyword_boost": ["exploit", "zero-day", "0-day", "proof-of-concept", "poc", "actively exploited"],
    },
    {
        "id": "threat_actors",
        "name": "Threat Actor Spotlight",
        "icon": "🎯",
        "color": "#7c3aed",
        "categories": ["threat_actor"],
    },
    {
        "id": "breaches",
        "name": "Data Breaches & Incidents",
        "icon": "🔓",
        "color": "#dc2626",
        "categories": ["breach"],
    },
    {
        "id": "malware_tooling",
        "name": "Malware & Tooling",
        "icon": "🦠",
        "color": "#059669",
        "categories": ["malware"],
    },
    {
        "id": "vendor_advisories",
        "name": "Vendor Advisories & Patches",
        "icon": "🛡️",
        "color": "#2563eb",
        "categories": ["vendor_advisory"],
    },
    {
        "id": "policy_compliance",
        "name": "Policy, Compliance & Regulation",
        "icon": "📋",
        "color": "#64748b",
        "categories": ["policy"],
    },
]


def score_article(article: dict) -> float:
    """Simple priority scoring for TL;DR selection."""
    score = 0.0

    # Tier bonus
    if article["tier"] == 1:
        score += 0.3
    elif article["tier"] == 2:
        score += 0.15

    # CVE bonus
    if article["cves"]:
        score += 0.25

    # Severity bonus
    severity_scores = {"critical": 0.4, "high": 0.25, "medium": 0.1, "low": 0.0}
    score += severity_scores.get(article["severity"], 0)

    # Recency bonus (articles from today get a boost)
    try:
        pub = datetime.fromisoformat(article["published"].replace("Z", "+00:00"))
        age_hours = (datetime.now(timezone.utc) - pub).total_seconds() / 3600
        if age_hours < 12:
            score += 0.15
        elif age_hours < 24:
            score += 0.1
    except (ValueError, TypeError):
        pass

    return score


def format_date_short(iso_date: str) -> str:
    """Format ISO date to short display format."""
    try:
        dt = datetime.fromisoformat(iso_date.replace("Z", "+00:00"))
        return dt.strftime("%b %d, %Y")
    except (ValueError, TypeError):
        return "Unknown date"


def assign_to_sections(articles: list[dict]) -> list[dict]:
    """Assign articles to newsletter sections. An article appears in the best-fit section only."""
    used_links = set()
    result_sections = []

    for section_def in SECTIONS:
        section_articles = []
        for article in articles:
            if article["link"] in used_links:
                continue

            # Category match
            if article["category"] not in section_def["categories"]:
                continue

            # Severity filter (if defined)
            if "severity_filter" in section_def:
                if article["severity"] not in section_def["severity_filter"]:
                    continue

            # Keyword boost filter (if defined) -- article must contain at least one keyword
            if "keyword_boost" in section_def:
                text = (article["title"] + " " + article["summary"]).lower()
                if not any(kw in text for kw in section_def["keyword_boost"]):
                    continue

            article_copy = dict(article)
            article_copy["published_short"] = format_date_short(article["published"])
            section_articles.append(article_copy)

        # Sort by score, take top items
        section_articles.sort(key=score_article, reverse=True)
        section_articles = section_articles[:8]

        for a in section_articles:
            used_links.add(a["link"])

        result_sections.append({
            "id": section_def["id"],
            "name": section_def["name"],
            "icon": section_def["icon"],
            "color": section_def["color"],
            "articles": section_articles,
        })

    # Catch-all: remaining articles go to a "General Security News" overflow
    remaining = [a for a in articles if a["link"] not in used_links]
    if remaining:
        for a in remaining:
            a["published_short"] = format_date_short(a["published"])
        remaining.sort(key=score_article, reverse=True)
        result_sections.append({
            "id": "general",
            "name": "General Security News",
            "icon": "📰",
            "color": "#475569",
            "articles": remaining[:10],
        })

    return result_sections


def generate_tldr(articles: list[dict], top_n: int = 5) -> list[dict]:
    """Select top articles for Executive TL;DR."""
    scored = sorted(articles, key=score_article, reverse=True)
    tldr = []
    seen_sources = set()
    for article in scored:
        # Diversity: max 2 articles from same source in TL;DR
        if seen_sources.get(article["source"], 0) >= 2 if isinstance(seen_sources, dict) else False:
            continue
        tldr.append(article)
        if isinstance(seen_sources, set):
            seen_sources = {}
        seen_sources[article["source"]] = seen_sources.get(article["source"], 0) + 1
        if len(tldr) >= top_n:
            break
    return tldr


def generate_plaintext(articles: list[dict], sections: list[dict], tldr: list[dict], date_str: str) -> str:
    """Generate plaintext version of the newsletter."""
    lines = []
    lines.append("=" * 60)
    lines.append(f"DAILYCTI BRIEF -- {date_str}")
    lines.append("=" * 60)
    lines.append("")

    lines.append("EXECUTIVE TL;DR")
    lines.append("-" * 40)
    for item in tldr:
        cve_str = f" ({', '.join(item['cves'])})" if item.get("cves") else ""
        lines.append(f"  * {item['title']}{cve_str}")
        lines.append(f"    {item['summary'][:150]}")
        lines.append(f"    [{item['source']}] {item['link']}")
        lines.append("")

    for section in sections:
        if not section["articles"]:
            continue
        lines.append("")
        lines.append(f"{section['name'].upper()} ({len(section['articles'])} items)")
        lines.append("-" * 40)
        for article in section["articles"]:
            severity = f"[{article['severity'].upper()}]" if article.get("severity") else ""
            cves = f" ({', '.join(article['cves'])})" if article.get("cves") else ""
            lines.append(f"  {severity} {article['title']}{cves}")
            lines.append(f"    {article['summary'][:200]}")
            lines.append(f"    Source: {article['source']} | {article.get('published_short', '')}")
            lines.append(f"    {article['link']}")
            lines.append("")

    lines.append("=" * 60)
    lines.append("Powered by DailyCTI -- Open-source cybersecurity intelligence")
    lines.append("All summaries are AI-generated. Verify with primary sources.")
    lines.append("=" * 60)
    return "\n".join(lines)


def main():
    print("=" * 60)
    print("DailyCTI Demo -- Newsletter Composer")
    print("=" * 60)
    print()

    # Load articles
    if not ARTICLES_FILE.exists():
        print(f"ERROR: {ARTICLES_FILE} not found. Run scrape_feeds.py first.")
        sys.exit(1)

    articles = json.loads(ARTICLES_FILE.read_text())
    print(f"Loaded {len(articles)} articles from {ARTICLES_FILE.name}")

    # Generate TL;DR
    tldr = generate_tldr(articles, top_n=5)
    print(f"Executive TL;DR: {len(tldr)} items")

    # Assign to sections
    sections = assign_to_sections(articles)
    for s in sections:
        if s["articles"]:
            print(f"  {s['name']}: {len(s['articles'])} articles")

    # Count unique sources
    sources = set(a["source"] for a in articles)

    # Today's date
    date_str = datetime.now(timezone.utc).strftime("%B %d, %Y")

    # Render HTML
    env = Environment(
        loader=FileSystemLoader(str(DEMO_DIR)),
        autoescape=True,
    )
    template = env.get_template(TEMPLATE_FILE)
    html_output = template.render(
        newsletter_name="DailyCTI Daily CTI Brief",
        tagline="Your daily cybersecurity intelligence, curated by AI",
        date_str=date_str,
        article_count=len(articles),
        source_count=len(sources),
        tldr_items=tldr,
        sections=sections,
    )

    OUTPUT_HTML.write_text(html_output)
    print(f"\nHTML newsletter: {OUTPUT_HTML}")

    # Render plaintext
    plaintext = generate_plaintext(articles, sections, tldr, date_str)
    OUTPUT_TXT.write_text(plaintext)
    print(f"Plaintext version: {OUTPUT_TXT}")

    # Quick stats
    total_in_newsletter = sum(len(s["articles"]) for s in sections)
    print(f"\nTotal articles in newsletter: {total_in_newsletter}")
    print(f"Articles not assigned: {len(articles) - total_in_newsletter}")
    print("\nDone! Open newsletter_output.html in a browser to preview.")


if __name__ == "__main__":
    main()
