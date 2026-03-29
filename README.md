# DailyCTI

**Know what happened in cyber last night. 2 minutes. Every morning.**

<p align="center">
  <img src="src/images/notebooklm_presentation_cute.png" alt="DailyCTI -- Cyber Intel by Morning Coffee" width="700">
</p>

---

## The Problem

It's 8:47 AM. You grab coffee, open your laptop, and the world has moved.

A zero-day dropped at 3 AM. A threat actor pivoted to your industry overnight. A vendor patch went live that nobody on your team knows about yet. A breach just hit your competitor.

You find out at 2 PM, from a Slack thread, three levels deep. By then it's damage control.

This isn't just a SOC analyst problem. It's a **CISO problem** -- you're briefing the board with yesterday's news. It's a **security engineer problem** -- you're patching blind. It's an **IT manager problem** -- your team has no idea what's trending in the threat landscape. It's a **founder problem** -- your startup is building in a space you can't keep up with.

The cyber world publishes 500+ articles a day across 80+ sources. CISA, NVD, Krebs, BleepingComputer, Unit 42, Talos, Dark Reading, The Record. Nobody reads all of them. Most people read none of them.

**The teams that don't get breached aren't smarter. They're better informed.** And right now, staying informed costs $2,000/year per seat on commercial platforms.

## The Solution

**DailyCTI gives you the full picture in 2 minutes, with your morning coffee.**

It scrapes 83 cybersecurity sources overnight, runs them through an AI engine that deduplicates, extracts CVEs and IOCs, maps to MITRE ATT&CK, scores by severity -- and delivers a clean, prioritized newsletter to your inbox before you leave the house.

```
You sleep. DailyCTI doesn't.

83 sources scraped. 500+ articles deduplicated. CVEs extracted. IOCs pulled.
MITRE ATT&CK mapped. Scored. Ranked. Summarized. Rendered. Delivered.

By the time you pour your coffee, it's in your inbox.
```

---

## What You Get

**9-section daily newsletter:**

| Section | What's In It |
|---------|-------------|
| Executive TL;DR | Top 5 stories, bullet points, CISO-ready |
| Critical Vulnerabilities | CVSS 9+, actively exploited, zero-days |
| Active Exploits | Weaponized PoCs, CISA KEV additions |
| Threat Actors | APT campaigns, ransomware ops, new TTPs |
| Data Breaches | Confirmed compromises, leak site activity |
| Malware & Tools | New families, variant updates, tool releases |
| Vendor Patches | Microsoft, Google, Apple, Cisco, Fortinet |
| Policy & Compliance | Government directives, regulatory changes |
| IOC Appendix | Structured IPs, domains, hashes, YARA refs |

**Plus:**

- AI-powered deduplication (same story from 10 outlets? You see it once)
- CVE enrichment with CVSS scores from NVD
- Threat actor resolution (APT28 = Fancy Bear = Forest Blizzard -- we normalize)
- MITRE ATT&CK auto-tagging on every article
- IOC extraction including defanged indicators (hxxps://, [.]com)
- Priority scoring: source authority, CVSS, exploit status, mention velocity, recency
- Three audience tiers: Executive (2 min read), Technical (5 min deep-dive), IOC Feed (machine-readable for automation)

---

## Quick Start

```bash
git clone https://github.com/your-org/dailycti.git
cd dailycti
cp .env.example .env       # Add your Anthropic API key
docker-compose up -d        # PostgreSQL + Redis + DailyCTI
dailycti run                # Scrape → Process → Generate → Deliver
```

That's it. Newsletter in your inbox.

**Don't want Docker?** The demo works standalone:

```bash
pip install feedparser jinja2 python-dotenv
cp demo/.env.example demo/.env   # Add SMTP credentials
python demo/run_demo.py           # Scrape 10 feeds → compose → send
```

---

## How It Works

```
┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│   INGEST     │───>│   PROCESS    │───>│    CURATE     │───>│   GENERATE   │───>│   DELIVER    │
│              │    │              │    │              │    │              │    │              │
│ 83 sources   │    │ Dedup        │    │ Claude AI    │    │ MJML+Jinja2  │    │ SMTP/SES     │
│ RSS, API,    │    │ Entity NER   │    │ Scoring      │    │ HTML+MD+TXT  │    │ Slack        │
│ TAXII        │    │ CVE enrich   │    │ Clustering   │    │ 9 sections   │    │ Webhooks     │
│              │    │ IOC extract  │    │ ATT&CK map   │    │              │    │ STIX export  │
└──────────────┘    └──────────────┘    └──────────────┘    └──────────────┘    └──────────────┘
       │                   │                   │                   │                   │
       └───────────────────┴───────────────────┴───────────────────┴───────────────────┘
                                    PostgreSQL 16 + Redis 7
```

---

## Why Not Just Use [X]?

| | DailyCTI | Feedly TI | Risky Bulletin | SANS NewsBites | CyberWire |
|---|---|---|---|---|---|
| **Price** | Free | $2K+/yr | Free | Free | Freemium |
| **AI curation** | Claude | Leo | Manual | Manual | Manual |
| **IOC extraction** | Automatic | Automatic | No | No | No |
| **ATT&CK mapping** | Automatic | Automatic | No | No | No |
| **Self-hosted** | Yes | No | No | No | No |
| **Customizable** | Everything | Limited | No | No | No |
| **API** | Full REST | Yes | No | No | No |
| **Sources** | 83 (configurable) | 1000s | ~20 | ~15 | ~20 |
| **Your data** | Stays on your infra | Their cloud | N/A | N/A | N/A |

DailyCTI isn't trying to replace your SIEM or your threat intel platform. It's the **2-minute morning read** that makes sure nobody in your ecosystem is flying blind -- from the analyst to the CISO to the founder who just needs to know what's happening.

---

## Configuration

Everything lives in `config/` as YAML:

- **`sources.yaml`** -- 83 feeds, 3 tiers, configurable polling intervals
- **`scoring.yaml`** -- Priority algorithm weights (tweak what matters to your org)
- **`newsletter.yaml`** -- Sections, layout, delivery settings, audience tiers
- **`entities.yaml`** -- Threat actor aliases, malware family names
- **`mitre_mappings.yaml`** -- ATT&CK keyword-to-technique rules

Don't like a source? Remove it. Want to add your vendor's advisory feed? One line of YAML.

---

## CLI

```bash
dailycti run              # Full pipeline: ingest → process → curate → generate → deliver
dailycti ingest           # Just fetch articles
dailycti process          # Just run NLP pipeline
dailycti curate           # Just score and cluster
dailycti generate         # Just render newsletter
dailycti deliver          # Just send
dailycti api              # Start REST API server
dailycti run --dry-run    # Everything except sending
```

---

## API

DailyCTI exposes a v3-compatible REST API for programmatic access:

```bash
# Get latest articles
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/v3/streams/contents?streamId=user/1/category/global.all

# Search feeds
curl http://localhost:8000/v3/search/feeds?q=ransomware

# Get extracted IOCs
curl http://localhost:8000/v3/tti/indicators
```

Full endpoint list: `/v3/streams`, `/v3/entries`, `/v3/feeds`, `/v3/collections`, `/v3/tags`, `/v3/markers`, `/v3/priorities`, `/v3/threats`, `/v3/vulnerabilities`, `/v3/tti/indicators`, `/v3/mixes`

---

## Project Status

| Metric | Value |
|--------|-------|
| Tests | 238 passing (100%) |
| Sources | 83 configured |
| Newsletter sections | 9 |
| Subscribers | 2 (and growing) |
| Daily cost | ~$0.60 (Claude API) |
| Known CVEs | 0 in production deps |

Phase 1 (newsletter pipeline) is complete and delivering. Phase 2 (REST API) and Phase 3 (subscriber personalization) are in progress.

---

## Contributing

See [MANAGEMENT.md](docs/MANAGEMENT.md) for the governance framework:

- Branch-per-feature, no direct commits to `main`
- 7-step merge gate: tests → architecture review → security audit → CTO approval
- All work logged in [TASKLOG.md](docs/TASKLOG.md)

---

## License

MIT. See [LICENSE](LICENSE).

---

*Built for everyone in cyber who just wants to know what happened overnight -- before the morning coffee with colleagues and the alerts start firing up.*
