# Feasibility Study: Personalized Newsletter via Subscriber Questionnaire

**Status:** Draft for CTO Review
**Date:** 2026-03-27
**Author:** Product/Engineering Feasibility Analyst
**Scope:** DailyCTI Daily CTI Brief -- subscriber-driven personalization

---

## 1. Concept Overview

### What We Are Proposing

Today, DailyCTI generates a single daily CTI newsletter with three audience tiers (Executive Brief, Full Technical, IOC Feed). All subscribers within a tier receive identical content. The newsletter pipeline runs once, scores all articles against a fixed set of weights defined in `scoring.yaml`, assigns them to nine fixed sections in `compose.py`, and delivers the same HTML to every subscriber on the list.

We propose adding a **subscriber questionnaire** that captures each reader's role, interests, industry, geographic context, and format preferences. These responses would then drive per-subscriber (or per-profile-cluster) customization of:

- **Which sections appear** (e.g., a GRC analyst sees Policy/Compliance prominently but not the IOC Appendix)
- **How articles are scored and ranked** (e.g., a healthcare CISO sees healthcare-related breaches boosted)
- **What depth and length** the newsletter provides (5-minute executive scan vs. 20-minute deep dive)
- **Which entities are tracked** (specific threat actors, vendors, products)
- **When delivery happens** (timezone-aware, frequency choice)

The goal is to move from "one newsletter, three tiers" to "one newsletter engine, N personalized outputs" -- without requiring each subscriber to manually curate boards and AI feeds.

### Why a Questionnaire (Not Self-Serve Curation)

Commercial platform personalization models require each user to be a power user: creating AI feeds, training the AI engine with thumbs-up/thumbs-down, organizing boards. This works for threat intel analysts but not for the broader audience DailyCTI targets (CISOs, compliance officers, DevSecOps engineers). A questionnaire is a **low-friction onboarding mechanism** that captures preferences in 2-3 minutes and translates them into the same scoring/filtering parameters that power users spend weeks tuning.

---

## 2. Questionnaire Design

### 2.1 Role-Based Parameters

**Q1: What is your primary job function?** (Single select)

| Option | Internal Tag | Scoring Impact |
|---|---|---|
| SOC Analyst | `role:soc_analyst` | Boost exploit availability, IOC content, recency |
| Threat Hunter | `role:threat_hunter` | Boost threat actor sections, malware tooling, MITRE refs |
| CISO / VP Security | `role:ciso` | Boost executive TL;DR, mention velocity (board-level stories), breaches |
| GRC / Compliance | `role:grc` | Boost policy/compliance section, regulatory sources |
| Security Engineer | `role:sec_engineer` | Boost vendor advisories, critical vulns, product prevalence |
| DevSecOps | `role:devsecops` | Boost AppSec, supply chain, open-source vuln sources (Snyk, GitHub Advisory, OSV) |
| Incident Responder | `role:ir` | Boost exploits/zero-days, IOC appendix, recency weight |
| Pentester / Red Team | `role:red_team` | Boost exploit availability, PoC/GitHub, Exploit-DB, tooling |

**Q2: What is your seniority level?** (Single select)

| Option | Internal Tag | Scoring Impact |
|---|---|---|
| Executive (C-suite, VP) | `seniority:executive` | Use `executive` audience profile weights; default to TL;DR-first |
| Manager (Team Lead, Director) | `seniority:manager` | Blend of executive + technical weights |
| Individual Contributor | `seniority:ic` | Use `technical` audience profile weights |

**Q3: How large is your security team?** (Single select)

| Option | Internal Tag | Impact |
|---|---|---|
| Solo practitioner | `team:solo` | Include broader coverage (no team to share with); higher max_items |
| Small (< 10 people) | `team:small` | Standard coverage |
| Medium (10-50 people) | `team:medium` | Can afford to specialize; tighter section filtering |
| Large (50+ people) | `team:large` | Focus on strategic/trending items; reduce noise |

### 2.2 Interest-Based Parameters

**Q4: Select your top 3 interest areas.** (Multi-select, min 1, max 3)

| Interest Area | Maps To Section(s) | Scoring Boost |
|---|---|---|
| Vulnerabilities | `critical_vulns`, `vendor_advisories` | +0.10 to `cvss_score` weight |
| Malware | `malware_tooling` | +0.10 to entity match on malware families |
| APT / Threat Actors | `threat_actors` | +0.10 to threat actor entity scoring |
| Ransomware | `breaches`, `threat_actors` | Keyword boost for ransomware terms |
| Data Breaches | `breaches` | +0.10 to `mention_velocity` (breach stories trend) |
| Cloud Security | `vendor_advisories` | Boost AWS/Azure/GCP source authority |
| Application Security | `vendor_advisories`, `malware_tooling` | Boost Snyk, GitHub Advisory, OSV sources |
| Network Security | `vendor_advisories` | Boost Cisco, Fortinet, Palo Alto sources |
| OT / ICS Security | `vendor_advisories`, `threat_actors` | Boost CISA ICS advisories, Dragos |
| Supply Chain | `malware_tooling`, `vendor_advisories` | Boost open-source vuln sources |
| Identity / IAM | `vendor_advisories`, `policy_compliance` | Boost identity-focused keywords |
| Compliance / Policy | `policy_compliance` | Boost regulatory source authority |

**Q5: What industry vertical do you operate in?** (Single select)

| Industry | Internal Tag | Impact |
|---|---|---|
| Financial Services | `industry:finance` | Boost SEC, PCI-DSS keywords; financial breach stories |
| Healthcare | `industry:healthcare` | Boost HIPAA keywords; healthcare breach stories |
| Government / Public Sector | `industry:government` | Boost CISA, FedRAMP, CyberScoop sources |
| Technology | `industry:technology` | Boost AppSec, cloud security, supply chain |
| Energy / Utilities | `industry:energy` | Boost OT/ICS content, Dragos, CISA ICS advisories |
| Manufacturing | `industry:manufacturing` | Boost OT/ICS, supply chain |
| Retail / E-commerce | `industry:retail` | Boost PCI-DSS, web app security, phishing |
| Education | `industry:education` | Boost ransomware (top-targeted sector), phishing |
| Defense / Aerospace | `industry:defense` | Boost APT content, nation-state tracking, CyberScoop |
| Telecommunications | `industry:telecom` | Boost network security, APT (telecom targeting) |
| Other | `industry:other` | No industry-specific boosts |

**Q6: Are there specific vendors/products you want to track?** (Multi-select, optional)

Options: Microsoft, Cisco, Palo Alto Networks, Fortinet, CrowdStrike, AWS, Azure, GCP, Linux, VMware, Citrix, Ivanti, SonicWall, Atlassian, SAP, Oracle, Apple, Google Chrome, Android, WordPress, Other (free text)

*Impact:* Override `product_prevalence` scoring -- selected products get score 1.0 regardless of default tier. Articles mentioning these products are boosted.

**Q7: Are there specific threat actors you want to track?** (Multi-select, optional)

Options: APT28 (Fancy Bear), APT29 (Cozy Bear), APT41, Lazarus Group, Volt Typhoon, Sandworm, Scattered Spider, LockBit, BlackCat/ALPHV, Cl0p, Play, Akira, Black Basta, Rhysida, Other (free text)

*Impact:* Articles mentioning tracked threat actors receive a +0.15 scoring boost via entity matching in `entities.py`. These articles are guaranteed inclusion in the `threat_actors` section regardless of base score.

### 2.3 Location-Based Parameters

**Q8: What is your primary operating region?** (Single select)

| Region | Internal Tag | Source Priority Boost |
|---|---|---|
| North America | `region:na` | CISA, Canadian CCCS, CyberScoop |
| Europe | `region:eu` | ENISA, NCSC UK, GDPR-related content |
| Asia-Pacific | `region:apac` | JPCERT/CC, ACSC Australia |
| Middle East | `region:me` | Geopolitical APT content |
| Latin America | `region:latam` | General; no region-specific sources yet |
| Africa | `region:africa` | General; no region-specific sources yet |

**Q9: What country are you based in?** (Dropdown, optional)

*Impact:* Determines regulatory relevance:
- US: CISA, SEC, FedRAMP content boosted
- UK: NCSC UK, UK-specific compliance
- EU member states: ENISA, GDPR, NIS2 content boosted
- Australia: ACSC content boosted
- Canada: CCCS content boosted
- Japan: JPCERT/CC content boosted

**Q10: What is your timezone?** (Dropdown, auto-detected from browser)

*Impact:* Delivery time optimization. Newsletter arrives at subscriber's preferred morning hour (default: 07:00 local time).

### 2.4 Depth and Format Parameters

**Q11: Which newsletter tier do you prefer?** (Single select)

| Tier | Description | Maps To |
|---|---|---|
| Executive TL;DR Only | 2-minute read, top 5 stories | `audience_tiers.executive` sections |
| Full Technical Brief | Complete newsletter, all 9 sections | `audience_tiers.technical` sections |
| IOC Feed Only | Machine-readable IOC data (STIX 2.1) | `audience_tiers.ioc_feed` sections |

**Q12: How long do you want to spend reading?** (Single select)

| Option | Internal Tag | Impact |
|---|---|---|
| Brief (~5 min) | `length:brief` | max_items per section reduced to 3; shorter AI summaries |
| Standard (~10 min) | `length:standard` | Default max_items from newsletter.yaml |
| Deep-dive (~20 min) | `length:deep` | max_items increased 1.5x; longer AI summaries; include more context |

**Q13: Include IOC Appendix?** (Yes/No, default based on role)

*Impact:* Toggle `ioc_appendix` section on/off. Default Yes for SOC Analyst, Threat Hunter, IR. Default No for CISO, GRC.

**Q14: Include MITRE ATT&CK references?** (Yes/No, default based on role)

*Impact:* Toggle ATT&CK technique IDs in article metadata. Default Yes for Threat Hunter, IR, Red Team. Default No for CISO, GRC.

**Q15: How often do you want to receive the newsletter?** (Single select)

| Option | Internal Tag | Impact |
|---|---|---|
| Daily | `frequency:daily` | Current default behavior |
| 3x per week (Mon/Wed/Fri) | `frequency:3x` | Aggregate 48h of content per issue |
| Weekly digest (Monday) | `frequency:weekly` | Aggregate 7 days; increase max_items proportionally |

---

## 3. How Personalization Maps to the Existing Architecture

### 3.1 Mapping Table

| Questionnaire Parameter | Existing Module | Current State | Changes Needed | Complexity |
|---|---|---|---|---|
| **Job Role** (Q1) | `scoring.py` / `scoring.yaml` `audience_profiles` | 3 profiles: executive, technical, ioc_feed | Add 8 role-specific weight profiles (or map roles to existing profiles + modifiers) | **M** |
| **Seniority** (Q2) | `scoring.py` `PriorityScorer.__init__` | Selects audience profile by name | Add seniority as a weight blend factor (executive weights for executives, technical for ICs, weighted average for managers) | **S** |
| **Team Size** (Q3) | `compose.py` `assign_sections` | Fixed max_items per section | Adjust max_items multiplier based on team size (solo = 1.2x, large = 0.8x) | **S** |
| **Interest Areas** (Q4) | `compose.py` section filtering + `scoring.py` weights | Sections are fixed; no interest-based boosting | Add per-subscriber section priority ordering + scoring weight modifiers per interest tag | **L** |
| **Industry** (Q5) | `scoring.yaml` `product_prevalence` + `source_authority` overrides | Global product/source scores | Add industry-specific keyword boost list and source authority overrides per industry | **M** |
| **Vendors/Products** (Q6) | `scoring.yaml` `product_prevalence` | Static high/medium/default tiers | Override product_prevalence to 1.0 for subscriber-selected products | **S** |
| **Threat Actors** (Q7) | `entities.py` `match_threat_actor` + `compose.py` threat_actors section | Matches actors but no per-subscriber preference | Add subscriber's tracked actors as mandatory-include filter in section assignment | **M** |
| **Region** (Q8) | `scoring.yaml` `source_authority` overrides | Global source authority scores | Add region-to-source-boost mapping (e.g., region:eu boosts ENISA from 0.7 to 0.95) | **S** |
| **Country** (Q9) | `compose.py` `policy_compliance` section filters | Fixed keyword list | Add country-to-regulation keyword mapping (US: SEC, CISA; UK: NCSC; EU: GDPR, NIS2) | **S** |
| **Timezone** (Q10) | `deliver.py` `NewsletterDelivery.send` | Single cron at 05:00 UTC | Per-subscriber delivery time calculation from timezone preference | **M** |
| **Newsletter Tier** (Q11) | `newsletter.yaml` `audience_tiers` | 3 static tier definitions | Already implemented. Map questionnaire choice to existing tier. | **S** |
| **Preferred Length** (Q12) | `compose.py` `assign_sections` + AI summary prompts | Fixed max_items, fixed summary length | Scale max_items per section by length multiplier; adjust AI prompt length instructions | **M** |
| **IOC Appendix** (Q13) | `newsletter.yaml` section enabled flag | Globally enabled | Per-subscriber section inclusion/exclusion list | **S** |
| **MITRE ATT&CK** (Q14) | Not yet implemented | No ATT&CK references in article rendering | New feature: conditionally include ATT&CK technique IDs in article cards | **M** |
| **Frequency** (Q15) | `newsletter.yaml` `schedule.cron` | Single daily cron | Per-subscriber delivery schedule with content aggregation window | **L** |

### 3.2 Detailed Module Impact

#### `scoring.py` -- PriorityScorer

The `PriorityScorer` class currently accepts an `audience` string and looks up a fixed weight profile from `scoring.yaml`. Personalization requires:

1. **Dynamic weight construction.** Instead of selecting from 3 fixed profiles, construct weights by starting from a base profile (mapped from role + seniority) and applying additive modifiers from interest areas. For example, a Threat Hunter (base: technical weights) who selects "APT/Threat Actors" as an interest gets +0.05 added to `source_authority` weight for threat-intel sources.

2. **Per-subscriber product prevalence override.** The `_score_product_prevalence` function currently uses a global high/medium list. Add an optional `product_overrides` parameter that promotes subscriber-selected products to score 1.0.

3. **Entity-based scoring boost.** Currently not in the scoring formula. Add a 7th factor `entity_relevance` (weight ~0.05-0.10, redistributed from existing factors) that boosts articles matching subscriber-tracked threat actors or malware families.

**Estimated change:** ~150 lines of new code + config schema extension.

#### `compose.py` -- Section Assignment

The `assign_sections` function iterates all sections and matches articles using hard-coded filter logic. Personalization requires:

1. **Section inclusion/exclusion.** Accept a list of enabled section IDs (derived from tier choice + IOC/ATT&CK toggles). Skip disabled sections entirely.

2. **Per-section max_items scaling.** Accept a multiplier from the length preference (brief=0.5x, standard=1.0x, deep=1.5x) applied to each section's `max_items`.

3. **Interest-based section ordering.** Reorder sections so that the subscriber's top interest areas appear first. This is cosmetic but impactful for engagement.

4. **Mandatory article inclusion.** If a subscriber tracks specific threat actors or products, articles matching those entities bypass the normal scoring threshold and are forcibly included in the relevant section.

**Estimated change:** ~100 lines of new code. The `NewsletterComposer.compose` method needs a `subscriber_profile` parameter.

#### `deliver.py` -- Newsletter Delivery

Currently sends to a flat recipient list with a single SMTP call. Personalization requires:

1. **Per-subscriber (or per-variant) send loop.** Instead of one `sendmail` call to all recipients, iterate over subscriber groups and send the appropriate variant.

2. **Timezone-aware scheduling.** Replace single cron with per-timezone batched delivery. Group subscribers by target delivery hour and dispatch in waves.

3. **Frequency management.** Track each subscriber's last delivery timestamp. For 3x/week subscribers, skip Tue/Thu/Sat/Sun runs. For weekly subscribers, aggregate content since last delivery.

**Estimated change:** ~200 lines of new code + new scheduler logic.

#### `newsletter.yaml` -- Configuration

Minimal changes needed to the base config. Per-subscriber customization should live in a separate data store (subscriber preferences), not in `newsletter.yaml`. The base config continues to define the *superset* of available sections and default settings.

---

## 4. Data Model Changes

### 4.1 New Models Required

#### Subscriber Model

```
Subscriber:
  id: UUID
  email: str (unique, indexed)
  name: str (optional)
  created_at: datetime
  updated_at: datetime
  is_active: bool (default true)
  unsubscribed_at: datetime (nullable)
  confirmation_token: str (for double opt-in)
  confirmed: bool (default false)
```

#### Subscriber Preferences Model

```
SubscriberPreferences:
  subscriber_id: UUID (FK -> Subscriber)

  # Role-based
  job_role: enum (soc_analyst, threat_hunter, ciso, grc, sec_engineer, devsecops, ir, red_team)
  seniority: enum (executive, manager, ic)
  team_size: enum (solo, small, medium, large)

  # Interest-based
  interest_areas: list[str]  # max 3, from defined enum
  industry: str (enum)
  tracked_products: list[str]
  tracked_threat_actors: list[str]

  # Location-based
  region: str (enum)
  country: str (ISO 3166-1 alpha-2, optional)
  timezone: str (IANA timezone, e.g. "America/New_York")

  # Depth/format
  newsletter_tier: enum (executive, technical, ioc_feed)
  preferred_length: enum (brief, standard, deep)
  include_ioc_appendix: bool
  include_mitre_attack: bool
  frequency: enum (daily, 3x_week, weekly)

  # Computed (derived from questionnaire, cached)
  scoring_profile: JSON  # Pre-computed weight overrides
  section_config: JSON   # Pre-computed section inclusion + ordering
  delivery_hour_utc: int  # Computed from timezone (default: 07:00 local)

  updated_at: datetime
```

#### Delivery Log Model

```
DeliveryLog:
  id: UUID
  subscriber_id: UUID (FK -> Subscriber)
  newsletter_variant_id: str  # Identifies which variant was sent
  sent_at: datetime
  frequency_period: str  # "daily", "3x_week", "weekly"
  article_count: int
  status: enum (sent, failed, bounced)
```

### 4.2 Storage Considerations

Current subscriber count: ~20 (per `newsletter.yaml` comment). At this scale, a simple SQLite database or even a YAML/JSON file would suffice. However, for forward-looking design:

- **Phase 1 (< 100 subscribers):** JSON file or SQLite, loaded at newsletter generation time.
- **Phase 2 (100-1000 subscribers):** PostgreSQL with proper indexing on `delivery_hour_utc` and `frequency`.
- **Phase 3 (1000+ subscribers):** PostgreSQL + Redis cache for computed scoring profiles.

### 4.3 Profile Computation Pipeline

When a subscriber updates their questionnaire:

1. Map `job_role` + `seniority` to a base audience weight profile.
2. Apply `interest_areas` modifiers to the base weights.
3. Build `product_overrides` list from `tracked_products`.
4. Build `entity_watchlist` from `tracked_threat_actors`.
5. Compute `section_config` from `newsletter_tier` + `include_ioc_appendix` + `include_mitre_attack` + `interest_areas` (for ordering).
6. Compute `delivery_hour_utc` from `timezone`.
7. Serialize and cache the computed profile as JSON in `scoring_profile` and `section_config`.

This computation runs **on questionnaire submission**, not at newsletter generation time. The newsletter pipeline reads pre-computed profiles.

---

## 5. Newsletter Generation Changes

### 5.1 Current Pipeline (Single Path)

```
Ingest feeds (83 sources)
    -> Deduplicate articles
    -> Extract entities (CVEs, IOCs, threat actors)
    -> Score ALL articles with PriorityScorer(audience="technical")
    -> Assign articles to sections via compose.py
    -> Render HTML + plaintext
    -> Send to ALL recipients via single SMTP call
```

### 5.2 Proposed Pipeline (Personalized)

```
Ingest feeds (83 sources)                          [UNCHANGED]
    -> Deduplicate articles                         [UNCHANGED]
    -> Extract entities                             [UNCHANGED]
    -> Score ALL articles with BASE scorer          [NEW: compute base scores once]
    -> For each subscriber profile cluster:
        -> Apply profile-specific score adjustments [NEW: lightweight re-scoring]
        -> Filter sections per profile              [NEW: section inclusion/exclusion]
        -> Adjust max_items per length preference   [NEW: length scaling]
        -> Generate AI summaries (if not cached)    [CHANGED: cache-first]
        -> Render HTML + plaintext variant          [CHANGED: per-variant render]
    -> Batch-send per delivery schedule             [CHANGED: scheduled delivery]
```

### 5.3 Optimization Strategy: Profile Clustering

Generating a truly unique newsletter per subscriber is expensive. With 20 subscribers, it is manageable. At 500+ subscribers, we need clustering.

**Approach: Compute variant keys, generate once per key.**

A variant key is a deterministic hash of the parameters that affect content selection:

```
variant_key = hash(
    newsletter_tier,          # 3 values
    sorted(interest_areas),   # C(12,3) = 220 combinations
    industry,                 # 11 values
    preferred_length,         # 3 values
    include_ioc_appendix,     # 2 values
    include_mitre_attack,     # 2 values
    sorted(tracked_products), # variable
    sorted(tracked_actors),   # variable
    region                    # 6 values
)
```

In practice, with 20 subscribers, we will likely have 8-15 unique variants. Even at 500 subscribers, clustering will yield far fewer than 500 unique newsletters because many subscribers will share profiles (e.g., "SOC Analyst, IC, interested in Vulnerabilities + Malware + APT, Technology industry, North America, Standard length, Full Technical" is a very common persona).

**Estimated variant count by subscriber count:**

| Subscribers | Estimated Unique Variants | Generation Cost |
|---|---|---|
| 20 | 5-12 | Trivial |
| 100 | 15-30 | Low |
| 500 | 30-60 | Moderate |
| 1000+ | 50-100 | Requires caching strategy |

### 5.4 AI Cost Implications

The most expensive step is AI summarization (Claude API calls). Personalization strategy for AI costs:

1. **Summarize once, filter per variant.** Generate AI summaries for ALL articles that pass the base inclusion threshold (score >= 0.35). Store summaries. Each variant selects from the pre-summarized pool. AI cost stays constant regardless of variant count.

2. **AI Overview per variant (expensive).** The Executive TL;DR is a cross-article synthesis. If different variants include different articles in the TL;DR, each variant needs its own synthesis call. Mitigation: generate TL;DR per variant cluster, not per subscriber.

3. **Cost estimate at current scale (20 subscribers, ~5 variants):**
   - Base article summaries: ~50-100 articles/day x 1 call each = ~$0.50-1.00/day (unchanged)
   - TL;DR synthesis: 5 variants x 1 call each = ~$0.10/day (up from 1 call)
   - Total incremental cost: ~$0.08/day = ~$2.40/month

4. **Cost estimate at 500 subscribers (~40 variants):**
   - Base article summaries: unchanged (~$0.50-1.00/day)
   - TL;DR synthesis: 40 variants x 1 call each = ~$0.80/day
   - Total incremental cost: ~$0.70/day = ~$21/month

### 5.5 Rendering Cost

HTML rendering via Jinja2 is CPU-cheap. Generating 40 variants adds seconds, not minutes. MJML compilation is the heavier step but still sub-second per variant. At 100 variants, total render time would be under 60 seconds.

---

## 6. Feedly Comparison

### 6.1 Personalization Approach Comparison

| Aspect | Commercial Platforms | DailyCTI (Proposed) |
|---|---|---|
| **Personalization model** | User-driven: each user builds their own boards, AI feeds, and AI training | Questionnaire-driven: subscriber answers 15 questions, system computes profile |
| **Effort to personalize** | High -- requires Feedly expertise, ongoing curation, weeks to optimize | Low -- 2-3 minute questionnaire, instant profile |
| **Granularity** | Per-user, infinite flexibility | Per-profile-cluster, bounded by questionnaire options |
| **Feedback loop** | AI thumbs-up/thumbs-down trains per-user model | Not yet proposed (see recommendation) |
| **Who bears the cost** | User (time investment) | System (computation, multiple variants) |

### 6.2 Feature-by-Feature Mapping

#### Commercial AI Priority Rules vs. DailyCTI Questionnaire-Driven Scoring

Commercial AI curation engines use machine-learned priority rules trained per-user from explicit feedback (thumbs-up/down on articles) and implicit signals (read time, saves, shares). Each user's AI model is unique.

DailyCTI's questionnaire approach is a **declarative shortcut** to the same outcome. Instead of learning from behavior over weeks, we ask the subscriber to declare their priorities upfront. The mapping:

| Commercial AI Signal | DailyCTI Questionnaire Equivalent |
|---|---|
| Thumbs-up on vuln articles | Q4: Interest area = "Vulnerabilities" |
| Thumbs-down on policy articles | Q4: Not selecting "Compliance/Policy" |
| Frequent reads from CrowdStrike | Q6: Track vendor = "CrowdStrike" |
| Saves articles about APT28 | Q7: Track threat actor = "APT28" |
| Priority rule: "CVSS > 9" | Q1: Role = SOC Analyst (implies high CVSS weight) |
| Priority rule: "mentions my industry" | Q5: Industry = "Healthcare" |

**Advantage over commercial platforms:** Immediate personalization without a cold-start problem. Commercial AI engines need 50-100 training signals to become useful. DailyCTI's questionnaire produces a usable profile on day one.

**Disadvantage vs. commercial platforms:** No implicit learning. If a subscriber's interests evolve, they must re-take the questionnaire. Commercial AI engines adapt automatically. (Mitigated by Phase E: feedback loop.)

#### Board-Based Newsletter vs. DailyCTI Interest-Based Section Filtering

In Feedly, newsletter sections are tied to specific Boards or AI Feeds. Different subscribers can receive different newsletters because each newsletter template points to different boards. However, this requires **separate newsletter templates** -- it is not per-subscriber personalization within a single newsletter.

DailyCTI's approach is more flexible: a single newsletter template with per-subscriber section inclusion/exclusion and ordering. This is architecturally simpler (one template, N renders) vs. the commercial approach (N templates, N renders).

#### Per-User AI Training vs. DailyCTI Questionnaire + Future Feedback Loop

The strongest personalization feature in commercial platforms is continuous per-user model refinement. The AI engine tracks which articles each user reads, saves, or dismisses, and adjusts priority weights accordingly.

DailyCTI does not currently have this capability. The questionnaire is a **one-shot profile**. To close the gap, a future phase would add:

- Click tracking in newsletter emails (which articles does the subscriber click?)
- Implicit interest inference from click patterns
- Periodic "preference refresh" prompts (quarterly email: "Has your role or interests changed?")
- A/B testing of scoring weights per subscriber cluster

This is explicitly deferred to post-MVP (see Implementation Plan, Phase E).

---

## 7. Implementation Plan

### Phase A: Subscriber Preferences Model + Questionnaire Endpoint

**Goal:** Capture subscriber preferences and store them.

**Work:**
1. Design and implement `Subscriber` and `SubscriberPreferences` data models (SQLite for MVP).
2. Build a questionnaire web form (simple HTML/JS page or API endpoint).
3. Build profile computation pipeline (questionnaire responses -> scoring profile JSON).
4. Add double opt-in email flow for new subscribers.
5. Migrate existing ~20 subscribers to the new model with default preferences (Full Technical, Standard length, Daily).

**Deliverables:**
- `/api/subscribe` endpoint (POST questionnaire responses)
- `/api/preferences` endpoint (GET/PUT subscriber preferences)
- Subscriber database schema + migration
- Questionnaire web form

### Phase B: Per-Profile Scoring Weights

**Goal:** PriorityScorer accepts subscriber profiles and produces personalized scores.

**Work:**
1. Extend `PriorityScorer.__init__` to accept a `subscriber_profile` dict (computed from questionnaire) in addition to the existing `audience` string.
2. Implement weight blending: base profile (from role/seniority) + interest modifiers + product/entity overrides.
3. Add `entity_relevance` as a 7th scoring factor for tracked threat actors/products.
4. Write comprehensive unit tests for all role/interest/industry combinations.

**Deliverables:**
- Updated `scoring.py` with profile-aware scoring
- Updated `scoring.yaml` with per-role weight profiles and modifier definitions
- Test suite covering edge cases

### Phase C: Per-Subscriber Section Filtering

**Goal:** compose.py generates different section configurations per subscriber profile.

**Work:**
1. Add `subscriber_profile` parameter to `assign_sections` and `NewsletterComposer.compose`.
2. Implement section inclusion/exclusion based on tier + toggles.
3. Implement max_items scaling based on preferred_length.
4. Implement section reordering based on interest_areas priority.
5. Implement mandatory inclusion for tracked entities.

**Deliverables:**
- Updated `compose.py` with profile-aware section assignment
- Updated `NewsletterComposer` with subscriber context

### Phase D: Multi-Variant Newsletter Generation

**Goal:** Pipeline generates N newsletter variants (one per profile cluster) instead of one.

**Work:**
1. Implement variant key computation and subscriber clustering.
2. Implement "score once, filter per variant" pipeline.
3. Implement per-variant TL;DR AI synthesis (with caching).
4. Implement per-variant HTML/plaintext rendering.
5. Update `deliver.py` to send correct variant to each subscriber.

**Deliverables:**
- Variant generation pipeline
- Caching layer for AI summaries
- Updated delivery loop

### Phase E: Delivery Scheduling + Feedback Loop

**Goal:** Timezone-aware delivery and implicit preference learning.

**Work:**
1. Replace single cron with multi-wave delivery scheduler (group by delivery_hour_utc).
2. Implement frequency management (daily/3x-week/weekly) with content aggregation.
3. Add click tracking (unique tracking URLs per subscriber per article).
4. Build click analytics pipeline to infer interest drift.
5. Implement quarterly "preference refresh" email prompts.

**Deliverables:**
- Multi-wave delivery scheduler
- Click tracking infrastructure
- Analytics dashboard (basic)
- Preference refresh email flow

---

## 8. Feasibility Assessment

### Phase-by-Phase Rating

| Phase | Description | Technical Complexity (1-5) | Effort (days) | Risk | Dependencies |
|---|---|---|---|---|---|
| **A** | Subscriber preferences + questionnaire | 2 | 5-7 | Low. Standard CRUD + web form. Risk: designing a questionnaire that subscribers actually complete (UX challenge, not technical). | None |
| **B** | Per-profile scoring weights | 3 | 4-6 | Medium. Weight blending math is straightforward, but tuning the modifiers to produce meaningfully different rankings without breaking quality requires careful testing. Risk: over-personalization makes some variants miss critical stories. | Phase A |
| **C** | Per-subscriber section filtering | 2 | 3-5 | Low. compose.py is well-structured; adding profile awareness is additive. Risk: edge cases where a subscriber's filtered sections contain zero articles on a quiet news day. | Phase A, Phase B |
| **D** | Multi-variant generation | 4 | 8-12 | Medium-High. This is the most architecturally significant change. The pipeline goes from single-path to multi-path. Risk: increased generation time, AI cost scaling, cache invalidation bugs, variant explosion with custom product/actor lists. | Phase B, Phase C |
| **E** | Delivery scheduling + feedback | 3 | 6-10 | Medium. Timezone delivery is well-understood but adds operational complexity (monitoring, retry per-wave). Click tracking requires care around email privacy (Apple Mail Privacy Protection, etc.). Risk: click data is too sparse to drive meaningful preference updates. | Phase D |

### Total Estimated Effort

| Scenario | Phases | Calendar Time | Engineering Days |
|---|---|---|---|
| MVP (questionnaire + basic personalization) | A + B + C | 4-5 weeks | 12-18 days |
| Full (all phases) | A + B + C + D + E | 10-14 weeks | 26-40 days |

### Risk Register

| Risk | Impact | Likelihood | Mitigation |
|---|---|---|---|
| Questionnaire completion rate is low (subscribers abandon halfway) | Personalization has no data to work with | Medium | Keep questionnaire to 15 questions max. Pre-fill defaults based on role selection. Allow partial completion (role alone provides value). |
| Over-personalization causes subscribers to miss critical stories | Subscribers miss a major zero-day because it was outside their interest profile | Low-Medium | Always include CVSS >= 9.5 and CISA KEV articles regardless of profile. "Critical override" threshold bypasses personalization. |
| AI cost scales unexpectedly with variant count | Monthly API costs exceed budget | Low (at current scale) | Cache AI summaries aggressively. Cap variant count at 50. Monitor cost per newsletter run. |
| Variant generation time exceeds delivery window | Newsletter arrives late | Low-Medium | Parallelize variant rendering. Pre-compute scoring profiles (not at generation time). Set hard timeout with fallback to default variant. |
| Privacy concerns with click tracking | Subscribers object to tracking; regulatory issues | Medium | Make click tracking opt-in. Use server-side tracking only (no third-party pixels). Comply with GDPR/CCPA. Provide transparent privacy policy. |

---

## 9. Recommendation

### Verdict: GO -- phased rollout recommended

Personalization via subscriber questionnaire is **technically feasible** within the existing DailyCTI architecture. The codebase is well-structured for this extension:

- `scoring.py` already supports audience-specific weight profiles -- extending to questionnaire-driven profiles is a natural evolution.
- `compose.py` already has section-level filtering logic -- adding profile-aware inclusion/exclusion is additive, not a rewrite.
- `newsletter.yaml` already defines 3 audience tiers -- the questionnaire maps directly to and extends these tiers.
- The current subscriber count (~20) means variant generation cost is negligible.

### What to Build First (Phases A + B + C)

**Ship the MVP in 4-5 weeks.** This gives subscribers a questionnaire and produces meaningfully different newsletters without the complexity of multi-variant generation. At this stage, the system generates one newsletter per audience tier (3 variants max), with per-subscriber scoring and section ordering applied within each tier.

This MVP delivers 80% of the personalization value:
- Role-appropriate content ranking
- Interest-based section ordering and boost
- Industry-relevant story prioritization
- Configurable depth (brief/standard/deep)
- IOC and MITRE ATT&CK toggles

### What to Defer

1. **Phase D (multi-variant generation):** Defer until subscriber count exceeds 50 or until MVP feedback indicates that tier-level personalization is insufficient. The complexity jump from "3 variants" to "N variants" is significant and not justified at ~20 subscribers.

2. **Phase E (delivery scheduling + feedback loop):** Defer until Phase D is stable. Timezone delivery is a nice-to-have at 20 subscribers (all likely in 1-2 timezones). Click-based feedback requires a larger subscriber base to produce statistically meaningful signals.

3. **Per-subscriber AI Overview synthesis:** Defer entirely. The cost-to-value ratio of generating unique TL;DR summaries per variant is poor. Instead, generate TL;DR from the top-scored articles per tier (3 TL;DR variants at most). Subscribers within the same tier share the same TL;DR.

### Critical Design Guardrail

Regardless of personalization, every subscriber should receive articles that score above 0.90 (the current `critical_alert` threshold in `scoring.yaml`). No personalization filter should suppress a story that the system classifies as critical. This is a safety net against the "filter bubble" problem in security intelligence -- a CISO who only selected "Compliance/Policy" as their interest must still learn about a zero-day in their infrastructure.

**Implementation:** Add a `critical_override` flag in the personalization pipeline. Articles exceeding the critical threshold are injected into every variant's Executive TL;DR, regardless of profile match.

---

## Appendix A: Questionnaire Wireframe (Suggested Flow)

```
Step 1 of 4: Your Role
  [Q1] Job function (dropdown)
  [Q2] Seniority (radio buttons)
  [Q3] Team size (radio buttons)
  [Next ->]

Step 2 of 4: Your Interests
  [Q4] Top 3 interest areas (checkbox grid, max 3)
  [Q5] Industry (dropdown)
  [Q6] Vendors to track (searchable multi-select, optional)
  [Q7] Threat actors to track (searchable multi-select, optional)
  [Next ->]

Step 3 of 4: Your Location
  [Q8] Region (dropdown)
  [Q9] Country (dropdown, optional)
  [Q10] Timezone (auto-detected, editable)
  [Next ->]

Step 4 of 4: Newsletter Preferences
  [Q11] Newsletter tier (radio with descriptions)
  [Q12] Reading time (radio with descriptions)
  [Q13] Include IOCs? (toggle, pre-filled from role)
  [Q14] Include MITRE ATT&CK? (toggle, pre-filled from role)
  [Q15] Frequency (radio)
  [Subscribe ->]
```

Estimated completion time: 2-3 minutes. Steps 2-4 have smart defaults pre-filled from Step 1 role selection to minimize friction.

## Appendix B: Role-to-Default-Preference Mapping

| Role | Default Tier | Default Length | IOC Default | ATT&CK Default | Top Interests (pre-selected) |
|---|---|---|---|---|---|
| SOC Analyst | Technical | Standard | Yes | Yes | Vulnerabilities, Malware, Data Breaches |
| Threat Hunter | Technical | Deep | Yes | Yes | APT/Threat Actors, Malware, Vulnerabilities |
| CISO | Executive | Brief | No | No | Data Breaches, Ransomware, Compliance/Policy |
| GRC/Compliance | Executive | Standard | No | No | Compliance/Policy, Data Breaches, Supply Chain |
| Security Engineer | Technical | Standard | No | Yes | Vulnerabilities, Cloud Security, Network Security |
| DevSecOps | Technical | Standard | No | No | Application Security, Supply Chain, Cloud Security |
| Incident Responder | Technical | Deep | Yes | Yes | Vulnerabilities, Malware, Ransomware |
| Pentester/Red Team | Technical | Deep | No | Yes | Vulnerabilities, APT/Threat Actors, Malware |

These defaults are editable by the subscriber -- they reduce questionnaire friction, not subscriber choice.
