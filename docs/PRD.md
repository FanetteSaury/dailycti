# DailyCTI -- Product Requirements Document

**Version:** 1.0
**Date:** 2026-03-27
**Status:** Draft
**Author:** DailyCTI Core Team
**License:** MIT

---

## Table of Contents

1. [Vision & Mission](#1-vision--mission)
2. [Platform Architecture Scope](#2-platform-architecture-scope)
3. [Target Users](#3-target-users)
4. [Newsletter Sections](#4-newsletter-sections)
5. [Success Metrics](#5-success-metrics)
6. [Competitive Positioning](#6-competitive-positioning)
7. [Non-Goals (v1)](#7-non-goals-v1)
8. [Compliance & Legal](#8-compliance--legal)
9. [Technical Constraints](#9-technical-constraints)
10. [Future Roadmap (v2+)](#10-future-roadmap-v2)

---

## 1. Vision & Mission

### Vision

DailyCTI is an open-source CTI newsletter platform, purpose-built from the ground up for cybersecurity intelligence. It provides industry-standard feed aggregation, AI-powered analysis, collections, boards, search, tagging, a v3-compatible REST API, and third-party integrations -- then channels all of that machinery toward a single high-value output: **the best daily cybersecurity newsletter available to security professionals**.

### Mission

- **Build a complete open-source, self-hosted CTI platform**: feeds, AI engine, collections, boards, search, tagging, REST API, and integrations.
- **Deliver a best-in-class daily cybersecurity newsletter** that competes with and surpasses commercial threat intelligence digests in coverage, speed, and signal-to-noise ratio.
- **Expose a v3-compatible REST API** so that security teams, scripts, and downstream tooling can consume DailyCTI's curated intelligence programmatically.
- **Remain fully open-source and config-driven**, with zero vendor lock-in, no mandatory SaaS subscription, and a single-cron-job deployment model that any small security team can operate.

### Core Principles

1. **Intelligence, not information.** Every article that reaches a reader has been deduplicated, scored, entity-extracted, ATT&CK-mapped, and summarized. Raw noise never ships.
2. **Speed matters.** Mean Time To Intelligence (MTTI) must stay under four hours from first publication to newsletter delivery.
3. **Transparency.** Scoring weights, source lists, and AI prompts are all visible in version-controlled YAML. Nothing is a black box.
4. **Extensibility.** Plugin adapters for output (Slack, MISP, TheHive, email, webhook) and input (RSS, TAXII, custom scrapers) are first-class citizens.

---

## 2. Platform Architecture Scope

DailyCTI provides capabilities equivalent to commercial feed aggregation platforms. The table below maps each industry-standard feature to its DailyCTI implementation, followed by detailed descriptions of each subsystem.

### 2.1 Feature Mapping

| Feature | DailyCTI Implementation | Technology |
|---|---|---|
| RSS/Atom feed aggregation | Multi-protocol ingestion | `feedparser`, `httpx`, `taxii2-client` |
| AI curation engine | DailyCTI AI | Claude API -- dedup, NER, scoring, summarization |
| Collections / Boards | Curated topic groups | YAML-configured + SQLite/Postgres-backed |
| Feed search & discovery | Indexed source registry | Full-text search over source metadata |
| Priority rules | Scoring profiles | Configurable weighted formula per audience |
| Entity extraction (CVE, IOC, APT) | NLP pipeline | `spaCy`, `ioc-finder`, regex, `rapidfuzz` |
| MITRE ATT&CK tagging | Hybrid auto-mapper | TRAM + Claude classification |
| Story clustering / dedup | Embedding clusters | `sentence-transformers` + HDBSCAN |
| Threat dashboards | Newsletter sections + IOC appendix | Structured Jinja2 templates |
| STIX/TAXII export | Structured output | `stix2` library serialization |
| REST API (v3) | FastAPI service | v3-compatible REST API endpoints |
| OAuth / developer tokens | JWT authentication | `python-jose` token issuance and validation |
| Newsletters / digests | Automated generation + delivery | Jinja2 + MJML rendering, SES delivery |
| Integrations (Slack, MISP, TheHive) | Output adapters | Extensible webhook + plugin architecture |
| MTTI measurement | Pipeline timestamps | Ingestion-to-delivery latency tracking |
| Priority rules | Per-audience weight configs | YAML profiles (executive, technical, IOC) |
| Mixes (curated stream) | Priority-scored stream | AI-ranked article stream with continuation tokens |

### 2.2 Feed Engine

The Feed Engine is responsible for discovering, polling, normalizing, and storing articles from heterogeneous sources.

- **Protocol support:** RSS 2.0, Atom 1.0, JSON Feed 1.1, STIX/TAXII 2.1 collections, and raw HTML scraping via `httpx` + `selectolax`.
- **Polling scheduler:** Adaptive polling intervals per source. High-value sources (NVD, CISA KEV, vendor SIRTs) poll every 15 minutes; lower-priority blogs poll every 2 hours. Intervals adjust based on historical publish frequency.
- **Normalization:** Every ingested item is converted to a canonical `FeedEntry` schema: `entry_id`, `source_id`, `title`, `content_html`, `content_text`, `url`, `published_at`, `ingested_at`, `authors`, `tags`, `raw_payload`.
- **Deduplication (stage 1):** URL canonicalization and content-hash comparison at ingest time to prevent obvious duplicates from entering the pipeline.
- **Source registry:** A YAML manifest (`config/sources.yaml`) defines every feed with metadata: `id`, `name`, `url`, `protocol`, `category`, `reliability_score`, `poll_interval`, `enabled`.
- **Health monitoring:** Failed fetches increment a per-source error counter. After three consecutive failures the source is marked degraded and an operator alert is emitted.

### 2.3 AI Curation Engine (DailyCTI AI)

DailyCTI AI is the platform's AI curation engine that prioritizes, summarizes, and tags articles, powered entirely by the Claude API.

- **Deduplication (stage 2):** Semantic dedup via `sentence-transformers` (`all-MiniLM-L6-v2`). Articles are embedded and clustered with HDBSCAN. Within each cluster the highest-scored article is retained; others are merged as "related coverage."
- **Named Entity Recognition (NER):** A multi-layer pipeline extracts structured entities:
  - `spaCy` (custom cybersecurity model) for organizations, people, locations.
  - `ioc-finder` for IPs, domains, URLs, hashes (MD5/SHA1/SHA256), email addresses.
  - Regex patterns for CVE IDs (`CVE-\d{4}-\d{4,}`), CWE IDs, CVSS vectors.
  - `rapidfuzz` fuzzy matching against known APT group aliases (MITRE groups JSON).
- **Scoring:** Each article receives a composite priority score (0--100) computed as a weighted sum:
  - `source_reliability` (0--1) x weight
  - `cvss_severity` (normalized) x weight
  - `exploit_availability` (boolean bump)
  - `entity_density` (CVE/IOC count) x weight
  - `recency` (decay function from `published_at`) x weight
  - `audience_relevance` (per-profile keyword match) x weight
  - Weights are defined per audience profile in `config/scoring.yaml`.
- **MITRE ATT&CK mapping:** A two-pass approach:
  1. TRAM (Threat Report ATT&CK Mapper) assigns candidate technique IDs.
  2. Claude validates and refines the mapping, resolving ambiguous matches and adding sub-technique precision (e.g., T1566.001 vs T1566.002).
- **Summarization:** Claude generates three summary tiers per article:
  - One-line headline (max 120 characters).
  - Executive bullet (2-3 sentences, non-technical).
  - Technical abstract (full paragraph with IOC references).

### 2.4 Data Model

The core data model follows industry-standard feed aggregation concepts while extending them for threat intelligence.

| Entity | Key Fields | Notes |
|---|---|---|
| `Source` | id, name, url, protocol, category, reliability, poll_interval | YAML + DB |
| `FeedEntry` | entry_id, source_id, title, content, url, published_at, ingested_at | Canonical article |
| `Entity` | id, entry_id, type (CVE, IP, HASH, DOMAIN, APT, ...), value, confidence | Extracted NER |
| `Cluster` | cluster_id, representative_entry_id, member_ids[], topic_label | Dedup groups |
| `Score` | entry_id, profile_id, composite_score, component_scores{} | Per-audience |
| `Collection` | id, name, description, source_ids[] | Topic grouping |
| `Board` | id, name, entry_ids[], owner | Manual curation |
| `Tag` | id, entry_id, namespace (ATT&CK, TLP, custom), value | Multi-taxonomy |
| `Newsletter` | id, date, profile_id, sections{}, html, status | Rendered output |
| `AudienceProfile` | id, name, scoring_weights{}, template, recipients[] | Delivery config |

### 2.5 REST API Surface (v3 Compatibility)

DailyCTI exposes a FastAPI service that provides a v3-compatible REST API, enabling integration with existing tooling.

| v3 Endpoint | DailyCTI Endpoint | Method | Description |
|---|---|---|---|
| `/v3/streams/contents` | `/v3/streams/contents` | GET | Fetch stream entries with continuation |
| `/v3/streams/ids` | `/v3/streams/ids` | GET | Fetch entry IDs only |
| `/v3/entries/{id}` | `/v3/entries/{id}` | GET | Single entry detail |
| `/v3/entries/.mget` | `/v3/entries/.mget` | POST | Batch entry retrieval |
| `/v3/search/feeds` | `/v3/search/feeds` | GET | Source discovery |
| `/v3/collections` | `/v3/collections` | GET/POST | List or create collections |
| `/v3/collections/{id}` | `/v3/collections/{id}` | GET/PUT/DELETE | Manage a collection |
| `/v3/boards` | `/v3/boards` | GET/POST | List or create boards |
| `/v3/tags` | `/v3/tags` | GET | List all tags |
| `/v3/tags/{id}` | `/v3/tags/{id}` | PUT/DELETE | Manage tags on entries |
| `/v3/profile` | `/v3/profile` | GET | Current user profile |
| `/v3/markers` | `/v3/markers` | GET/POST | Read/unread state |

- **Stream ID convention:** DailyCTI follows the industry-standard URI scheme: `feed/http://example.com/rss`, `user/{userId}/category/{label}`, `user/{userId}/tag/{label}`.
- **Pagination:** All stream endpoints support `continuation` tokens. Tokens are opaque base64-encoded cursor strings containing `(last_score, last_entry_id)`. Default page size is 20; max is 1000.
- **Rate limiting:** Token-bucket algorithm, default 250 requests/minute per API key.

### 2.6 Authentication

- **JWT tokens** issued via `/v3/auth/token` endpoint.
- Access tokens expire after 1 hour; refresh tokens after 30 days.
- API keys (long-lived developer tokens) supported for automation.
- All tokens are signed with RS256 (RSA 2048-bit keys).
- CORS configuration via `config/api.yaml`.

### 2.7 Integrations

DailyCTI provides a comprehensive integration ecosystem through a plugin adapter interface.

| Integration | Type | Description |
|---|---|---|
| Email (SES) | Output | Primary newsletter delivery via Amazon SES |
| Slack | Output | Post daily digest or critical alerts to channels |
| MISP | Output | Push IOCs as MISP events/attributes |
| TheHive | Output | Create alerts with observables |
| Webhook | Output | Generic HTTP POST to any endpoint |
| STIX/TAXII | Output | Publish STIX 2.1 bundles to TAXII server |
| STIX/TAXII | Input | Ingest from TAXII 2.1 collections |
| Custom scraper | Input | Plugin interface for non-RSS sources |

Each adapter implements a simple interface: `async def emit(newsletter: Newsletter, config: dict) -> bool`.

---

## 3. Target Users

### 3.1 Primary Personas

| Persona | Role | Needs | Consumption Mode |
|---|---|---|---|
| **SOC Analyst** | Tier 1-3 analyst in a security operations center | Actionable IOCs, exploit alerts, patch status | Technical newsletter + IOC feed |
| **Threat Hunter** | Proactive threat detection specialist | APT TTPs, ATT&CK mappings, malware analysis | Technical newsletter + API queries |
| **CISO / VP Security** | Executive security leadership | Risk summary, business impact, regulatory changes | Executive TL;DR newsletter |
| **Security Engineer** | Builds and maintains security tooling | Vendor patches, tool releases, CVE details | Technical newsletter + API |
| **GRC / Compliance** | Governance, risk, and compliance staff | Regulatory updates, standards changes, breach notifications | Executive + Policy section |

### 3.2 Audience Tiers

DailyCTI generates distinct newsletter variants tuned to each tier:

1. **Executive Tier**
   - 3-5 bullet TL;DR summary written at CISO level.
   - No raw IOCs, no CVE numbers in body text.
   - Business-impact framing ("affects 40% of Fortune 500 VPN deployments").
   - Read time target: 2 minutes.

2. **Technical Tier**
   - Full nine-section newsletter with all detail.
   - Inline CVE IDs, CVSS scores, ATT&CK technique references.
   - Code snippets for PoC references (redacted where appropriate).
   - Read time target: 8-10 minutes.

3. **IOC Feed Tier**
   - Machine-readable STIX 2.1 bundle attached or linked.
   - Structured CSV/JSON of all extracted indicators.
   - Designed for direct ingestion into SIEM, SOAR, or TIP platforms.
   - No narrative text.

---

## 4. Newsletter Sections

The daily newsletter comprises nine sections. Each section has defined content criteria, source priority, inclusion thresholds, and display format.

### 4.1 Executive TL;DR

- **Content criteria:** The 3-5 most consequential stories of the day, distilled into single-sentence bullets. Each bullet must answer: *what happened*, *who is affected*, and *what action is recommended*.
- **Source priority:** All sources eligible; selection driven by composite priority score.
- **Inclusion threshold:** Only articles scoring >= 80 on the executive scoring profile.
- **Display format:** Numbered bullet list. No technical jargon. Each bullet hyperlinked to the full story in the Technical section below. Auto-generated by Claude with a system prompt enforcing executive-level language.

### 4.2 Critical Vulnerabilities

- **Content criteria:** Vulnerabilities with CVSS base score >= 9.0, any actively exploited vulnerability regardless of CVSS, confirmed zero-days, and any CVE added to the CISA Known Exploited Vulnerabilities (KEV) catalog in the past 24 hours.
- **Source priority:** NVD, CISA KEV, vendor SIRTs (Microsoft MSRC, Google Project Zero, Apple Security, Cisco PSIRT, Fortinet PSIRT), then security researcher blogs.
- **Inclusion threshold:** CVSS >= 9.0 OR `exploit_in_wild == true` OR KEV match.
- **Display format:** Table with columns: CVE ID, CVSS Score, Affected Product, Exploit Status (None / PoC / In-Wild), Patch Available (Yes/No/Workaround), one-line summary. Sorted by CVSS descending, then exploit status.

### 4.3 Active Exploits & Zero-Days

- **Content criteria:** Newly published exploit code (Exploit-DB, GitHub PoC repos, Packet Storm), zero-day disclosures before vendor patch, weaponization status updates (from PoC to crimeware/APT adoption).
- **Source priority:** Exploit-DB, GitHub advisory/PoC tracking, Google Project Zero, ZDI, vendor security blogs.
- **Inclusion threshold:** Any new public exploit for a CVE with CVSS >= 7.0, or any zero-day regardless of score.
- **Display format:** Grouped by CVE. Each entry includes: CVE ID, exploit source URL, weaponization stage (PoC / Weaponized / Actively Exploited), affected versions, link to patch if available.

### 4.4 Threat Actor Spotlight

- **Content criteria:** New APT campaign reports, ransomware operation updates (new victims, infrastructure changes, RaaS affiliate activity), novel TTPs documented in the past 24 hours, attribution updates.
- **Source priority:** Mandiant/Google TAG, CrowdStrike, Recorded Future, Cisco Talos, ESET, Symantec, government CERT advisories (CISA, NCSC, ANSSI, BSI).
- **Inclusion threshold:** Any named threat actor activity with at least two corroborating sources, or a single high-reliability source (tier-1 vendor report).
- **Display format:** Per-actor block: Actor Name (aliases), Campaign Name, Targets (sector/geography), TTPs (ATT&CK technique IDs as badges), IOC count, one-paragraph summary. ATT&CK techniques rendered as clickable references to attack.mitre.org.

### 4.5 Data Breaches & Incidents

- **Content criteria:** Confirmed data breaches with verified data exposure, ransomware leak site posts (with editorial note on verification status), breach notifications filed with regulators, significant DDoS or service disruption events.
- **Source priority:** HaveIBeenPwned, breach notification filings (SEC 8-K, state AG offices), DataBreaches.net, ransomware leak site monitors, mainstream tech press (BleepingComputer, The Record).
- **Inclusion threshold:** Confirmed breach affecting >= 10,000 records, or any publicly traded company, or any critical infrastructure sector entity.
- **Display format:** Table: Organization, Date Disclosed, Records Affected, Data Types Exposed, Attack Vector, Regulatory Filing (Yes/No), summary sentence.

### 4.6 Malware & Tooling

- **Content criteria:** New malware families identified, significant updates to known families (new C2 protocols, evasion techniques), new offensive security tool releases, updates to widely used red-team frameworks.
- **Source priority:** Malware analysis blogs (ANY.RUN, Joe Sandbox, Hatching Triage), AV vendor blogs (Sophos, Kaspersky, ESET), GitHub (offensive tool repos), security researcher Twitter/Mastodon threads.
- **Inclusion threshold:** New family identification from a tier-1 vendor, or a tool release with >= 100 GitHub stars within 24 hours, or an update to a tracked malware family.
- **Display format:** Per-item block: Malware/Tool Name, Type (RAT, stealer, loader, ransomware, red-team tool), platform, notable capabilities, MITRE ATT&CK techniques, IOC summary, analysis source link.

### 4.7 Vendor Advisories & Patches

- **Content criteria:** Security advisories from major vendors released in the past 24 hours, with emphasis on Patch Tuesday cycles, emergency out-of-band patches, and advisories for widely deployed enterprise software.
- **Source priority:** Microsoft MSRC, Google Chrome/Android, Apple Security Updates, Cisco, Fortinet, Palo Alto Networks, VMware, Adobe, SAP, Oracle, Linux kernel security list.
- **Inclusion threshold:** Any advisory with CVSS >= 7.0, or any advisory for a product in the tracked-products list (configurable in `config/products.yaml`).
- **Display format:** Grouped by vendor. Table: Advisory ID, Product, Severity, CVE Count, Key CVEs, Patch URL. Special callout box for any advisory that patches an actively exploited vulnerability.

### 4.8 Policy, Compliance & Regulation

- **Content criteria:** New government cybersecurity directives and executive orders, NIST framework updates and draft publications, SEC cyber disclosure rule developments, industry-specific regulatory changes (HIPAA, PCI-DSS, DORA, NIS2), international standards body updates.
- **Source priority:** Federal Register, NIST CSRC, SEC EDGAR, CISA directives, EU ENISA, UK NCSC, industry working groups.
- **Inclusion threshold:** Any new binding directive, final rule publication, or significant draft with public comment period. Exclude routine administrative notices.
- **Display format:** Bullet list with: Issuing Authority, Document Title, Effective Date (if applicable), one-sentence impact summary, link to full text.

### 4.9 IOC Appendix

- **Content criteria:** All machine-readable indicators of compromise extracted from articles included in the day's newsletter. Deduplicated across all sections.
- **Source priority:** Inherited from parent article source reliability.
- **Inclusion threshold:** All IOCs from articles scoring >= 50 on the technical profile. Confidence threshold >= 0.7 on NER extraction.
- **Display format:** Structured table with columns: Type (IP, Domain, Hash-MD5, Hash-SHA256, URL, Email), Value, Context (associated CVE or malware family), Source Article, TLP Marking. Additionally: list of referenced YARA rule names with links to source. A STIX 2.1 bundle download link is provided at the end.

---

## 5. Success Metrics

| Metric | Target | Measurement Method |
|---|---|---|
| **MTTI (Mean Time To Intelligence)** | < 4 hours | Median delta between `source.published_at` and `newsletter.delivered_at` across all included articles |
| **CISA KEV Coverage** | >= 95% within 24 hours | Percentage of new KEV entries that appear in the next newsletter after addition |
| **False Positive Rate** | < 5% | Weekly manual review of 50 random scored articles; FP = included but irrelevant or inaccurate |
| **Newsletter Read Time** | < 10 minutes (Technical tier) | Word count / 250 WPM; validated via email analytics (time-on-email) |
| **API Response Latency** | < 200ms (p95) for stream queries | Application performance monitoring on `/v3/streams/contents` |
| **Source Uptime** | > 99% successful fetches | `(successful_polls / total_polls)` per 30-day rolling window |
| **Entity Extraction Recall** | > 90% for CVE IDs | Benchmark against manually annotated test corpus (500 articles) |
| **Dedup Precision** | > 95% | Clustered articles manually verified; FP = incorrectly merged distinct stories |
| **Subscriber Growth** | 20% MoM for first 6 months | Email list count from SES / mailing list provider |
| **Unsubscribe Rate** | < 2% per month | SES suppression list tracking |

---

## 6. Competitive Positioning

### 6.1 Comparison Matrix

| Capability | DailyCTI (Open-Source) | Feedly TI ($2,004/yr) | Risky Bulletin | SANS NewsBites | CyberWire Daily | OpenCTI | MISP | TLDR Sec |
|---|---|---|---|---|---|---|---|---|
| **Cost** | Free (self-hosted) | $2,004/yr | Free | Free | Free (basic) | Free (self-hosted) | Free (self-hosted) | Free |
| **Delivery** | Daily email + API | Web + API | Daily email | Twice-weekly | Daily podcast + email | Web dashboard | Web + API | Weekly email |
| **AI Summarization** | Claude (abstractive) | Leo (proprietary) | Manual | Manual editorial | Manual editorial | None | None | Manual |
| **Entity Extraction** | Automated NLP pipeline | Leo NER | None | None | None | Connector-based | MISP attributes | None |
| **MITRE ATT&CK Mapping** | TRAM + Claude auto-map | Leo auto-tag | Occasional manual | None | None | Manual + connectors | Galaxies (manual) | None |
| **IOC Appendix** | Structured STIX export | Board export | None | None | None | Full STIX/TAXII | Full STIX/TAXII | None |
| **REST API** | v3-compatible | Feedly v3 | None | None | None | GraphQL | PyMISP REST | None |
| **Source Customization** | Full (YAML config) | UI-based | Fixed editorial | Fixed editorial | Fixed editorial | Connector config | Feed config | Fixed editorial |
| **Self-Hosted** | Yes | No (SaaS) | No | No | No | Yes | Yes | No |
| **Audience Tiers** | Exec / Tech / IOC | Priority views | Single | Single | Single | Role-based views | Org-level sharing | Single |
| **Open Source** | MIT license | Proprietary | N/A | N/A | N/A | Apache 2.0 | AGPL 3.0 | N/A |
| **Update Frequency** | Daily (configurable) | Real-time | Daily | Twice-weekly | Daily | Real-time | Event-driven | Weekly |

### 6.2 Key Differentiators

1. **vs Feedly TI:** DailyCTI is free, self-hosted, and produces a finished newsletter product rather than requiring manual board curation. Feedly TI is a discovery and research platform; DailyCTI is an automated intelligence production pipeline.
2. **vs Risky Bulletin / SANS / CyberWire / TLDR Sec:** These are editorially curated newsletters with fixed source sets and human-written summaries. DailyCTI offers full source customization, automated entity extraction, machine-readable IOC output, and a REST API -- none of which editorial newsletters provide.
3. **vs OpenCTI / MISP:** These are threat intelligence platforms focused on IOC management and correlation. They lack newsletter generation, AI summarization, and are designed for analysts actively working cases, not for daily briefing consumption. DailyCTI complements them as a feed source (via STIX/TAXII export) rather than replacing them.

---

## 7. Non-Goals (v1)

The following capabilities are explicitly out of scope for version 1.0. They may appear on the future roadmap but will not be built in the initial release.

- **Real-time alerting.** v1 operates on a daily batch cycle. Sub-hour push notifications for critical events are deferred to v2.
- **Paid subscription or monetization.** DailyCTI v1 is entirely free and open-source. No paywall, no premium tier, no telemetry.
- **SIEM/SOAR replacement.** DailyCTI produces intelligence. It does not ingest logs, generate detections, or orchestrate response playbooks. It feeds into SIEMs and SOARs via its integrations but does not replace them.
- **Web UI dashboard.** v1 is headless: CLI tooling, YAML configuration, API access, and email output. A web-based dashboard for browsing and triaging articles is a v2 feature.
- **Multi-tenant user management.** v1 assumes a single-team deployment. User roles, team isolation, and shared workspaces are deferred.
- **Mobile application.** Consumption in v1 is via email client and API. Native mobile apps are a v2+ consideration.

---

## 8. Compliance & Legal

### 8.1 Copyright & Fair Use

- **Abstractive summaries only.** DailyCTI never republishes full-text article content. All summaries are original text generated by Claude, describing the facts of the source material.
- **Source attribution.** Every summary includes a hyperlink to the original article, the source name, and the publication date.
- **No full-text storage for redistribution.** Raw `content_html` is stored locally for NLP processing but is never included in newsletter output or API responses to third parties.
- **Image and media exclusion.** Newsletter output contains no images, diagrams, or other media from source articles.

### 8.2 Traffic Light Protocol (TLP)

- DailyCTI parses TLP markings from STIX `marking-definition` objects and from in-text TLP headers.
- **TLP:CLEAR and TLP:GREEN** content may be included in newsletters and API responses.
- **TLP:AMBER and TLP:RED** content is never published in newsletters, never exposed via the public API, and is flagged in the database for analyst-only internal review.
- Operators can configure TLP handling policy in `config/tlp.yaml`.

### 8.3 GDPR & Privacy

- **Consent.** Subscribers must explicitly opt in via double opt-in email confirmation.
- **Unsubscribe.** Every newsletter includes a one-click unsubscribe link (RFC 8058 `List-Unsubscribe-Post` header).
- **Data minimization.** Subscriber data is limited to email address, audience tier preference, and subscription date. No tracking pixels, no click tracking, no behavioral analytics.
- **Right to erasure.** CLI command `dailycti subscriber delete <email>` purges all subscriber data.
- **Data processing.** Article content is processed by the Claude API. Operators must review Anthropic's data processing terms for their deployment context.

### 8.4 Government & Public Domain Content

- **CISA, NVD, NIST publications:** United States government works, public domain under 17 U.S.C. 105. No copyright restrictions on use.
- **MITRE ATT&CK:** Licensed under Apache 2.0. Attribution required; modifications must be noted.
- **CVE data:** CVE is sponsored by CISA and managed by the CVE Program. Usage governed by CVE Terms of Use (attribution required).
- **Exploit-DB:** Content varies by author license. DailyCTI links to exploits but does not republish code.

---

## 9. Technical Constraints

### 9.1 Deployment Model

- **Single daily cron job.** The entire pipeline -- ingest, process, score, render, deliver -- runs as a single invocation: `dailycti run --date today`. Operators schedule this via cron, systemd timer, or CI/CD pipeline.
- **No long-running services required for newsletter generation.** The FastAPI server is an optional, separately deployed component for API consumers.
- **Target runtime:** Complete pipeline execution in under 30 minutes for 200 sources and up to 2,000 daily articles.

### 9.2 AI Backend

- **All AI processing via Claude API.** No local GPU required. DailyCTI uses `anthropic` Python SDK.
- **Model:** Claude Sonnet (default) for summarization and scoring; Claude Haiku for high-volume classification tasks (ATT&CK mapping, TLP parsing). Model selection configurable in `config/ai.yaml`.
- **Token budget:** Estimated 500K-1M tokens per daily run. Operators must provision their own Anthropic API key.
- **Fallback:** If the Claude API is unavailable, the pipeline produces a degraded newsletter (no AI summaries, scores based on heuristic rules only) rather than failing entirely.

### 9.3 Configuration

- **Config-driven architecture.** All behavior is controlled by YAML files in the `config/` directory:
  - `config/sources.yaml` -- Feed definitions and polling schedules.
  - `config/scoring.yaml` -- Per-audience scoring weight profiles.
  - `config/sections.yaml` -- Newsletter section definitions and inclusion thresholds.
  - `config/delivery.yaml` -- Email, Slack, webhook, MISP output configuration.
  - `config/ai.yaml` -- Claude model selection, prompt templates, token budgets.
  - `config/api.yaml` -- FastAPI server settings, CORS, rate limits.
  - `config/tlp.yaml` -- Traffic Light Protocol handling rules.
  - `config/products.yaml` -- Tracked vendor products for advisory matching.
- **Environment variables** for secrets: `ANTHROPIC_API_KEY`, `AWS_SES_*`, `SLACK_WEBHOOK_URL`, `MISP_URL`, `MISP_API_KEY`.
- **No hardcoded values.** Every threshold, weight, interval, and template is externalizable.

### 9.4 Plugin Architecture

- **Input plugins** implement `async def poll(config: dict) -> list[FeedEntry]`.
- **Output plugins** implement `async def emit(newsletter: Newsletter, config: dict) -> bool`.
- **Processing plugins** implement `async def process(entry: FeedEntry, config: dict) -> FeedEntry`.
- Plugins are auto-discovered from the `src/plugins/` directory via entry-point registration.
- Third-party plugins installable via `pip install dailycti-plugin-<name>`.

### 9.5 Storage

- **Default:** SQLite for single-node deployments. Zero configuration required.
- **Optional:** PostgreSQL for teams wanting concurrent API access and multi-node deployment.
- **Article retention:** Configurable, default 90 days. Older entries are archived to compressed JSON and purged from the active database.
- **Embedding cache:** Sentence-transformer embeddings stored alongside entries to avoid recomputation during dedup.

---

## 10. Future Roadmap (v2+)

### v2.0 -- Interactive Platform

- **Web dashboard UI.** React-based single-page application for browsing the article stream, managing collections and boards, reviewing AI scoring, and previewing newsletters before send.
- **Real-time critical alert mode.** For CVSS 10.0 or confirmed zero-day-in-the-wild events, bypass the daily batch and push an immediate alert via Slack, email, and webhook within 15 minutes of detection.
- **User accounts and team workspaces.** Multi-user support with role-based access control (admin, editor, viewer).

### v2.5 -- Intelligence Customization

- **Custom AI model fine-tuning.** Fine-tune classification models on organization-specific relevance feedback to improve scoring precision over time.
- **Custom entity dictionaries.** Allow operators to define organization-specific entity lists (internal product names, custom threat actor tracking names) for NER enrichment.
- **Feedback loop.** Analysts can mark articles as relevant/irrelevant; ratings feed back into scoring weights via automated retraining.

### v3.0 -- Multi-Tenant SaaS

- **Multi-tenant SaaS deployment.** Hosted version with per-organization isolation, managed infrastructure, and usage-based billing.
- **Marketplace for source packs.** Community-contributed source bundles (e.g., "Healthcare ISAC pack," "Financial sector pack") installable in one click.
- **Mobile application.** Native iOS and Android apps with push notifications for critical alerts.
- **Bi-directional SIEM integration.** Ingest SIEM alert context to enrich newsletter scoring with internal telemetry (e.g., "this CVE affects assets in your environment").

### Ongoing

- **Source library expansion.** Continuous addition of new feeds, TAXII collections, and scraper plugins.
- **NLP model improvements.** Upgrade spaCy models, embedding models, and HDBSCAN tuning as the cybersecurity NLP landscape evolves.
- **Community contributions.** Plugin ecosystem, source pack sharing, and template library maintained by the open-source community.

---

*This document is a living specification. It will be updated as DailyCTI evolves from initial prototype to production-grade intelligence platform. All contributions welcome under the MIT license.*
