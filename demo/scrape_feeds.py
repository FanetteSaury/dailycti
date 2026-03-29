#!/usr/bin/env python3
"""DailyCTI Demo -- Scrape live cybersecurity RSS feeds and save articles as JSON."""

import html
import json
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import feedparser

DEMO_DIR = Path(__file__).parent
OUTPUT_FILE = DEMO_DIR / "articles.json"

# --- Feed Sources ---
FEEDS = [
    {
        "name": "BleepingComputer",
        "url": "https://www.bleepingcomputer.com/feed/",
        "tier": 1,
    },
    {
        "name": "The Hacker News",
        "url": "https://feeds.feedburner.com/TheHackersNews",
        "tier": 1,
    },
    {
        "name": "Krebs on Security",
        "url": "https://krebsonsecurity.com/feed/",
        "tier": 1,
    },
    {
        "name": "SecurityWeek",
        "url": "https://www.securityweek.com/feed/",
        "tier": 2,
    },
    {
        "name": "Unit 42 (Palo Alto)",
        "url": "https://unit42.paloaltonetworks.com/feed/",
        "tier": 2,
    },
    {
        "name": "Cisco Talos",
        "url": "https://blog.talosintelligence.com/rss/",
        "tier": 2,
    },
    {
        "name": "CISA Advisories",
        "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
        "tier": 1,
    },
    {
        "name": "Dark Reading",
        "url": "https://www.darkreading.com/rss.xml",
        "tier": 2,
    },
    {
        "name": "The Record",
        "url": "https://therecord.media/feed",
        "tier": 2,
    },
    {
        "name": "GitGuardian Detection Engine",
        "url": "https://docs.gitguardian.com/releases/detection-engine/rss.xml",
        "tier": 1,
    },
]

# --- Category Keywords ---
CATEGORY_KEYWORDS = {
    "vulnerability": [
        "cve", "vulnerability", "vulnerabilities", "patch", "exploit", "zero-day",
        "0-day", "rce", "remote code execution", "sql injection", "xss",
        "buffer overflow", "privilege escalation", "authentication bypass",
        "cvss", "critical flaw", "security flaw", "security bug",
    ],
    "malware": [
        "malware", "ransomware", "trojan", "botnet", "backdoor", "rootkit",
        "infostealer", "stealer", "loader", "dropper", "rat ", "c2 server",
        "cobalt strike", "lockbit", "blackcat", "alphv", "cl0p", "akira",
        "black basta", "qakbot", "emotet", "pikabot",
    ],
    "breach": [
        "breach", "data leak", "leaked", "exposed", "compromised", "stolen data",
        "data theft", "hack ", "hacked", "cyberattack", "cyber attack",
        "incident", "unauthorized access",
    ],
    "threat_actor": [
        "apt", "threat actor", "threat group", "nation-state", "espionage",
        "fancy bear", "lazarus", "sandworm", "volt typhoon", "salt typhoon",
        "scattered spider", "campaign targeting", "state-sponsored",
    ],
    "vendor_advisory": [
        "advisory", "patch tuesday", "security update", "microsoft patch",
        "chrome update", "firefox update", "apple security", "cisco advisory",
        "fortinet", "ivanti", "palo alto", "advisory released",
    ],
    "policy": [
        "regulation", "compliance", "gdpr", "nist", "executive order",
        "sanctions", "indictment", "arrested", "law enforcement", "sec ",
        "fcc ", "legislation", "policy", "government",
    ],
}

SEVERITY_KEYWORDS = {
    "critical": ["critical", "cvss 9", "cvss 10", "zero-day", "0-day", "actively exploited", "rce", "remote code execution"],
    "high": ["high", "cvss 7", "cvss 8", "important", "severe"],
    "medium": ["medium", "moderate", "cvss 4", "cvss 5", "cvss 6"],
    "low": ["low", "informational", "minor"],
}

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
HTML_TAG_PATTERN = re.compile(r"<[^>]+>")


def clean_html(text: str) -> str:
    """Strip HTML tags and decode entities."""
    if not text:
        return ""
    text = HTML_TAG_PATTERN.sub("", text)
    text = html.unescape(text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def truncate(text: str, max_len: int = 250) -> str:
    """Truncate text to max_len, ending at a word boundary."""
    if len(text) <= max_len:
        return text
    truncated = text[:max_len].rsplit(" ", 1)[0]
    return truncated.rstrip(".,;:") + "..."


def categorize(title: str, summary: str) -> str:
    """Categorize an article based on keyword matching."""
    text = (title + " " + summary).lower()
    scores = {}
    for category, keywords in CATEGORY_KEYWORDS.items():
        score = sum(1 for kw in keywords if kw in text)
        if score > 0:
            scores[category] = score
    if scores:
        return max(scores, key=scores.get)
    return "vulnerability"  # default


def assign_severity(title: str, summary: str) -> str:
    """Assign severity based on keyword matching."""
    text = (title + " " + summary).lower()
    for severity, keywords in SEVERITY_KEYWORDS.items():
        if any(kw in text for kw in keywords):
            return severity
    return "medium"  # default


def extract_cves(title: str, summary: str) -> list[str]:
    """Extract CVE IDs from text."""
    text = title + " " + summary
    return sorted(set(CVE_PATTERN.findall(text)))


def parse_date(entry) -> str:
    """Parse published date from feed entry."""
    for field in ("published_parsed", "updated_parsed"):
        parsed = getattr(entry, field, None)
        if parsed:
            try:
                dt = datetime(*parsed[:6], tzinfo=timezone.utc)
                return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
            except (ValueError, TypeError):
                pass
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def fetch_feed(feed_config: dict) -> list[dict]:
    """Fetch and parse a single RSS feed, returning up to 5 articles."""
    name = feed_config["name"]
    url = feed_config["url"]
    tier = feed_config["tier"]

    print(f"  Fetching {name}...", end=" ", flush=True)
    try:
        parsed = feedparser.parse(url)
        if parsed.bozo and not parsed.entries:
            print(f"ERROR: {parsed.bozo_exception}")
            return []
    except Exception as e:
        print(f"ERROR: {e}")
        return []

    articles = []
    for entry in parsed.entries[:5]:
        title = clean_html(getattr(entry, "title", "Untitled"))
        link = getattr(entry, "link", "")
        raw_summary = getattr(entry, "summary", "") or getattr(entry, "description", "")
        summary = truncate(clean_html(raw_summary))

        if not title or not link:
            continue

        category = categorize(title, summary)
        severity = assign_severity(title, summary)
        cves = extract_cves(title, summary)

        articles.append({
            "title": title,
            "link": link,
            "published": parse_date(entry),
            "summary": summary,
            "source": name,
            "tier": tier,
            "category": category,
            "severity": severity,
            "cves": cves,
        })

    print(f"{len(articles)} articles")
    return articles


def main():
    print("=" * 60)
    print("DailyCTI Demo -- RSS Feed Scraper")
    print("=" * 60)
    print()

    all_articles = []

    print(f"Scraping {len(FEEDS)} feeds...")
    print()
    for feed in FEEDS:
        articles = fetch_feed(feed)
        all_articles.extend(articles)
        time.sleep(0.5)  # Be polite

    # Sort by published date (newest first)
    all_articles.sort(key=lambda a: a["published"], reverse=True)

    # Save to JSON
    OUTPUT_FILE.write_text(json.dumps(all_articles, indent=2, ensure_ascii=False))

    # Print stats
    print()
    print(f"Total articles: {len(all_articles)}")
    print()

    print("By source:")
    sources = {}
    for a in all_articles:
        sources[a["source"]] = sources.get(a["source"], 0) + 1
    for src, count in sorted(sources.items(), key=lambda x: -x[1]):
        print(f"  {src}: {count}")

    print()
    print("By category:")
    categories = {}
    for a in all_articles:
        categories[a["category"]] = categories.get(a["category"], 0) + 1
    for cat, count in sorted(categories.items(), key=lambda x: -x[1]):
        print(f"  {cat}: {count}")

    cve_count = sum(1 for a in all_articles if a["cves"])
    print(f"\nArticles with CVEs: {cve_count}")

    all_cves = []
    for a in all_articles:
        all_cves.extend(a["cves"])
    if all_cves:
        print(f"Unique CVEs found: {len(set(all_cves))}")
        for cve in sorted(set(all_cves))[:10]:
            print(f"  {cve}")

    print(f"\nSaved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
