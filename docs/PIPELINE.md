# DailyCTI Pipeline Architecture

> Technical reference for the DailyCTI cybersecurity intelligence platform -- an open-source
> CTI newsletter platform, purpose-built for producing
> automated cybersecurity newsletters.

---

## 1. Architecture Overview

```
┌──────────────────────────────────────────────────────────────┐
│                     DAILYCTI ARCHITECTURE                       │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐               │
│  │  RSS/Atom │    │ REST APIs │    │STIX/TAXII│               │
│  │  80+ feeds│    │ NVD,CISA │    │  MITRE   │               │
│  └────┬─────┘    └────┬─────┘    └────┬─────┘               │
│       └───────────────┼───────────────┘                      │
│                       ▼                                      │
│  ┌─────────────────────────────────────────┐                 │
│  │        STAGE 1: INGEST                   │                │
│  │  feedparser · httpx · taxii2-client      │                │
│  │  Rate limiter · ETags · URL dedup        │                │
│  └────────────────────┬────────────────────┘                 │
│                       ▼                                      │
│  ┌─────────────────────────────────────────┐                 │
│  │        STAGE 2: DAILYCTI AI               │                │
│  │  MinHash dedup · spaCy NER · ioc-finder │                │
│  │  CVE regex · ATT&CK mapper · Scoring    │                │
│  │  Claude summarization · Trend detection  │                │
│  └────────────────────┬────────────────────┘                 │
│                       ▼                                      │
│  ┌─────────────────────────────────────────┐                 │
│  │        STAGE 3: CURATE                   │                │
│  │  Story clustering (HDBSCAN)             │                │
│  │  Section assignment · Top-N selection    │                │
│  └──────┬─────────────────────┬────────────┘                 │
│         ▼                     ▼                              │
│  ┌──────────────┐   ┌─────────────────┐                      │
│  │ STAGE 4:     │   │  DAILYCTI API     │                      │
│  │ NEWSLETTER   │   │  (FastAPI)      │                      │
│  │ Jinja2+MJML  │   │  /v3/streams    │                      │
│  │ HTML+MD+TXT  │   │  /v3/entries    │                      │
│  └──────┬───────┘   │  /v3/threats    │                      │
│         ▼           │  /v3/priorities │                      │
│  ┌──────────────┐   └────────┬────────┘                      │
│  │ STAGE 5:     │            │                               │
│  │ DELIVER      │   ┌────────▼────────┐                      │
│  │ SES · Slack  │   │  INTEGRATIONS   │                      │
│  │ STIX export  │   │  Slack · MISP   │                      │
│  └──────────────┘   │  Webhooks       │                      │
│                     └─────────────────┘                      │
│                                                              │
│  ┌─────────────────────────────────────────┐                 │
│  │           STORAGE LAYER                  │                │
│  │  PostgreSQL (articles, entities, feeds)  │                │
│  │  Redis (dedup, rate limits, cache)       │                │
│  └─────────────────────────────────────────┘                 │
└──────────────────────────────────────────────────────────────┘
```

The pipeline operates as a five-stage directed acyclic graph. Each stage is independently
scalable and communicates through PostgreSQL (durable state) and Redis (ephemeral state).
A full cycle -- from RSS poll to delivered newsletter -- targets a Mean Time To Intelligence
(MTTI) of under four hours.

---

## 2. v3-Compatible REST API Surface

DailyCTI exposes a FastAPI application that provides a v3-compatible REST API. This allows
existing client libraries, browser extensions, and mobile apps to connect to a
self-hosted DailyCTI instance without modification.

### Endpoint Map

| Endpoint | Method | DailyCTI Implementation | Description |
|---|---|---|---|
| `/v3/streams/contents` | GET | Query PostgreSQL with continuation tokens | Fetch articles from a stream |
| `/v3/streams/ids` | GET | Lightweight ID-only query | Fetch entry IDs only |
| `/v3/entries/:id` | GET | Direct DB lookup by entry hash | Single article |
| `/v3/entries/.mget` | POST | Bulk DB lookup (batch of up to 1000 IDs) | Multiple articles |
| `/v3/feeds/:feedId` | GET | Source registry lookup | Feed metadata |
| `/v3/feeds/.mget` | POST | Bulk source lookup | Multiple feeds |
| `/v3/search/feeds` | GET | Full-text search over source catalog (pg_trgm) | Feed discovery |
| `/v3/subscriptions` | GET/POST | User subscription management | Subscribe/list feeds |
| `/v3/collections` | GET/POST | Named feed groups with ordering | Collection management |
| `/v3/boards` | GET | Saved article boards | Board management |
| `/v3/tags` | GET/PUT/DELETE | User tags stored in `tags` table | Tag management |
| `/v3/markers` | GET/POST | Read/unread/saved state bitmask per user | Marker management |
| `/v3/priorities` | GET/POST/DELETE | AI priority filter rules | AI curation rules |
| `/v3/threats` | GET | Threat actor/malware DB (ATT&CK-backed) | CTI entity lookup |
| `/v3/vulnerabilities` | GET | CVE enrichment data (NVD + CISA KEV) | Vulnerability lookup |
| `/v3/tti/indicators` | GET | Extracted IOCs from processed articles | IOC query |
| `/v3/mixes/contents` | GET | AI-ranked top articles (priority score desc) | Best-of stream |
| `/v3/profile` | GET | User profile and preferences | Profile data |

### Stream ID Conventions

DailyCTI follows the industry-standard stream ID format:

- **Feed stream**: `feed/http://example.com/rss` -- a single RSS/Atom source.
- **Category stream**: `user/<userId>/category/<categoryName>` -- all feeds in a named
  collection (e.g., `user/abc123/category/Threat Intel`).
- **Tag stream**: `user/<userId>/tag/<tagName>` -- all articles with a given tag
  (e.g., `user/abc123/tag/saved-for-later`).
- **Global streams**: `user/<userId>/category/global.all` (all articles),
  `user/<userId>/category/global.uncategorized` (feeds not in any collection).

### Pagination with Continuation Tokens

All stream endpoints return a `continuation` field when more results are available. The token
is an opaque Base64-encoded string containing the last entry's `crawled` timestamp and its
database primary key. The client passes it back as a query parameter to fetch the next page.
Default page size is 20; maximum is 1000.

```
GET /v3/streams/contents?streamId=feed/http://...&count=40&continuation=<token>
```

When no `continuation` field is present in the response, the client has reached the end of
the stream.

---

## 3. Stage 1: Ingestion Engine

### Source Catalog

DailyCTI monitors 80+ cybersecurity sources organized into three polling tiers based on
publication velocity and criticality.

#### Tier 1 -- Critical (poll every 15 minutes, 12 sources)

| # | Source | URL | Type | Focus |
|---|--------|-----|------|-------|
| 1 | CISA KEV | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | JSON | Known exploited vulnerabilities catalog |
| 2 | CISA Advisories | `https://www.cisa.gov/cybersecurity-advisories/all.xml` | RSS | ICS advisories, alerts, analysis reports |
| 3 | NVD API 2.0 | `https://services.nvd.nist.gov/rest/json/cves/2.0` | REST | CVE database with CVSS scores |
| 4 | BleepingComputer | `https://www.bleepingcomputer.com/feed/` | RSS | Breaking security news, ransomware |
| 5 | The Hacker News | `https://feeds.feedburner.com/TheHackersNews` | RSS | Security news, vulnerability disclosure |
| 6 | Krebs on Security | `https://krebsonsecurity.com/feed/` | RSS | Investigative cybercrime reporting |
| 7 | abuse.ch URLhaus | `https://urlhaus-api.abuse.ch/v1/` | API | Malicious URL intelligence |
| 8 | abuse.ch ThreatFox | `https://threatfox-api.abuse.ch/api/v1/` | API | IOC sharing platform |
| 9 | abuse.ch MalwareBazaar | `https://mb-api.abuse.ch/api/v1/` | API | Malware sample exchange |
| 10 | MSRC | `https://api.msrc.microsoft.com/cvrf/v3.0/updates` | RSS+API | Microsoft security updates |
| 11 | Google Project Zero | `https://googleprojectzero.blogspot.com/feeds/posts/default?alt=rss` | RSS | Zero-day research and disclosure |
| 12 | GitGuardian Detection Engine | `https://docs.gitguardian.com/releases/detection-engine/rss.xml` | RSS | Secret detection rule updates |

#### Tier 2 -- High Value (poll every 30 minutes, 25 sources)

| # | Source | URL | Type | Focus |
|---|--------|-----|------|-------|
| 1 | Unit 42 (Palo Alto) | `https://unit42.paloaltonetworks.com/feed/` | RSS | APT research, malware analysis |
| 2 | Mandiant (Google Cloud) | `https://www.mandiant.com/resources/blog/rss.xml` | RSS | Threat intelligence, incident response |
| 3 | Cisco Talos | `https://blog.talosintelligence.com/feeds/posts/default?alt=rss` | RSS | Threat research, vulnerability discovery |
| 4 | CrowdStrike | `https://www.crowdstrike.com/blog/feed/` | RSS | Adversary tracking, endpoint threats |
| 5 | SentinelOne Labs | `https://www.sentinelone.com/labs/feed/` | RSS | Threat research, malware research |
| 6 | Dark Reading | `https://www.darkreading.com/rss.xml` | RSS | Enterprise security news |
| 7 | SecurityWeek | `https://feeds.feedburner.com/securityweek` | RSS | Security industry news, analysis |
| 8 | The Record (Recorded Future) | `https://therecord.media/feed/` | RSS | Cybersecurity news journalism |
| 9 | NCSC UK | `https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml` | RSS | UK government advisories |
| 10 | ENISA | `https://www.enisa.europa.eu/publications/rss` | RSS | EU cybersecurity agency reports |
| 11 | AlienVault OTX | `https://otx.alienvault.com/api/v1/pulses/subscribed` | API | Community threat intelligence |
| 12 | Exploit-DB | `https://www.exploit-db.com/rss.xml` | RSS | Public exploit database |
| 13 | ESET WeLiveSecurity | `https://www.welivesecurity.com/feed/` | RSS | Malware research, threat campaigns |
| 14 | Sophos News | `https://news.sophos.com/en-us/feed/` | RSS | Threat research, ransomware tracking |
| 15 | Trend Micro | `https://www.trendmicro.com/en_us/research/rss.xml` | RSS | APT tracking, vulnerability research |
| 16 | Kaspersky Securelist | `https://securelist.com/feed/` | RSS | APT campaigns, malware analysis |
| 17 | Check Point Research | `https://research.checkpoint.com/feed/` | RSS | Threat intelligence, mobile security |
| 18 | Elastic Security Labs | `https://www.elastic.co/security-labs/rss/feed.xml` | RSS | Detection engineering, malware analysis |
| 19 | CERT/CC | `https://www.kb.cert.org/vuls/atomfeed/` | Atom | Vulnerability coordination |
| 20 | Recorded Future Blog | `https://www.recordedfuture.com/feed` | RSS | Threat intelligence analysis |
| 21 | Symantec (Broadcom) | `https://symantec-enterprise-blogs.security.com/blogs/rss.xml` | RSS | Threat hunting, malware families |
| 22 | Fortinet FortiGuard | `https://www.fortinet.com/blog/threat-research/rss.xml` | RSS | Vulnerability research, zero-days |
| 23 | Risky.biz | `https://risky.biz/feeds/risky-business/` | RSS | Security news podcast and newsletter |
| 24 | Google TAG | `https://blog.google/threat-analysis-group/rss/` | RSS | Nation-state threat tracking |
| 25 | Qualys Threat Research | `https://blog.qualys.com/category/vulnerabilities-threat-research/feed` | RSS | Vulnerability research, cloud security |

#### Tier 3 -- Supplementary (poll every 60 minutes, 30+ sources)

| # | Source | URL | Type | Focus |
|---|--------|-----|------|-------|
| 1 | Reddit r/netsec | `https://www.reddit.com/r/netsec/.rss` | RSS | Community security research |
| 2 | Reddit r/cybersecurity | `https://www.reddit.com/r/cybersecurity/.rss` | RSS | General cybersecurity discussion |
| 3 | Reddit r/blueteamsec | `https://www.reddit.com/r/blueteamsec/.rss` | RSS | Defensive security community |
| 4 | Mastodon infosec.exchange | `https://infosec.exchange/api/v1/timelines/public?local=true` | API | Infosec Mastodon community |
| 5 | Schneier on Security | `https://www.schneier.com/feed/` | RSS | Cryptography, policy, security commentary |
| 6 | OSV (Google) | `https://osv.dev/` | API | Open source vulnerability database |
| 7 | GitHub Advisories | `https://github.com/advisories.atom` | Atom | Open source package vulnerabilities |
| 8 | Packet Storm | `https://packetstormsecurity.com/feeds/` | RSS | Exploits, advisories, tools |
| 9 | SC Media | `https://www.scmagazine.com/feed` | RSS | Enterprise security news |
| 10 | Infosecurity Magazine | `https://www.infosecurity-magazine.com/rss/news/` | RSS | Industry news and analysis |
| 11 | CyberScoop | `https://cyberscoop.com/feed/` | RSS | Government cybersecurity policy |
| 12 | ACSC (Australia) | `https://www.cyber.gov.au/about-us/view-all-content/alerts-and-advisories/rss.xml` | RSS | Australian government advisories |
| 13 | Canadian CCCS | `https://www.cyber.gc.ca/api/v2/rss/feed` | RSS | Canadian government advisories |
| 14 | JPCERT/CC | `https://www.jpcert.or.jp/english/rss/jpcert-en.rdf` | RSS | Japanese CERT advisories |
| 15 | PhishTank | `https://data.phishtank.com/data/online-valid.json` | JSON | Verified phishing URL database |
| 16 | OpenPhish | `https://openphish.com/feed.txt` | TXT | Phishing intelligence feeds |
| 17 | GreyNoise | `https://api.greynoise.io/v3/` | API | Internet scanner/attack telemetry |
| 18 | Pulsedive | `https://pulsedive.com/api/` | API | Community threat intelligence |
| 19 | Troy Hunt | `https://www.troyhunt.com/rss/` | RSS | Breaches, HIBP, web security |
| 20 | Graham Cluley | `https://grahamcluley.com/feed/` | RSS | Security commentary and news |
| 21 | Daniel Miessler | `https://danielmiessler.com/feed/` | RSS | Security concepts, AI/security intersection |
| 22 | SANS ISC | `https://isc.sans.edu/rssfeed.xml` | RSS | Internet Storm Center diaries |
| 23 | Naked Security (Sophos) | `https://nakedsecurity.sophos.com/feed/` | RSS | Consumer-friendly security news |
| 24 | Threatpost Archive | `https://threatpost.com/feed/` | RSS | Security news archive |
| 25 | Wordfence | `https://www.wordfence.com/blog/feed/` | RSS | WordPress security research |
| 26 | Rapid7 Blog | `https://blog.rapid7.com/rss/` | RSS | Vulnerability research, Metasploit |
| 27 | ZDI (Zero Day Initiative) | `https://www.zerodayinitiative.com/rss/published/` | RSS | Vulnerability disclosure program |
| 28 | Tenable Blog | `https://www.tenable.com/blog/feed` | RSS | Vulnerability management research |
| 29 | PortSwigger Research | `https://portswigger.net/research/rss` | RSS | Web security research |
| 30 | Trail of Bits | `https://blog.trailofbits.com/feed/` | RSS | Security engineering, audits |

### Ingestion Technical Details

#### HTTP Client Configuration

```python
# httpx async client with connection pooling
client = httpx.AsyncClient(
    timeout=httpx.Timeout(connect=5.0, read=15.0, write=5.0, pool=10.0),
    limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
    follow_redirects=True,
    headers={"User-Agent": "DailyCTI/1.0 (cybersecurity-newsletter-bot)"},
)
```

#### Conditional Requests (ETags and Last-Modified)

Every feed response's `ETag` and `Last-Modified` headers are stored in Redis with a key
pattern of `etag:<feed_id>` and a TTL of 7 days. On subsequent polls, headers
`If-None-Match` and `If-Modified-Since` are sent. A `304 Not Modified` response skips
parsing entirely, reducing bandwidth by approximately 60%.

#### Rate Limiting

A per-domain token bucket rate limiter backed by Redis controls outbound request rates:

- **Default**: 1 request per second per domain
- **Government APIs (NVD, CISA)**: 1 request per 6 seconds (without API key)
- **NVD with API key**: 50 requests per 30 seconds
- **Reddit**: 1 request per 2 seconds (OAuth user-agent required)
- **abuse.ch APIs**: 10 requests per minute

Rate limit state is stored in Redis using the `SETNX`/`PTTL` pattern for atomic
token acquisition.

#### URL Deduplication

Before any article enters the processing pipeline, its URL is normalized and hashed:

1. Strip tracking parameters: `utm_source`, `utm_medium`, `utm_campaign`, `utm_content`,
   `utm_term`, `fbclid`, `gclid`, `ref`, `source`.
2. Sort remaining query parameters alphabetically.
3. Lowercase the scheme and hostname.
4. Remove trailing slashes, default ports, and fragment identifiers.
5. Compute SHA-256 of the normalized URL.
6. Check membership in `Redis SET dedup:urls` (30-day TTL via periodic cleanup).
7. If present, skip. If absent, `SADD` and proceed.

#### Content Extraction

Full-text extraction uses **trafilatura** as the primary engine, chosen over newspaper3k
for its superior handling of JavaScript-rendered pages, paywalled content fallback, and
cleaner output on blog platforms:

```python
downloaded = trafilatura.fetch_url(url)
text = trafilatura.extract(
    downloaded,
    include_comments=False,
    include_tables=True,
    favor_recall=True,
    output_format="txt",
)
```

When trafilatura fails (returns `None`), the pipeline falls back to `newspaper3k` and
finally to raw `BeautifulSoup` tag stripping.

#### NVD API Integration

The NVD API 2.0 is polled for recently modified CVEs using the `lastModStartDate` and
`lastModEndDate` parameters. Without an API key, the rate limit is 5 requests per 30-second
window. With a key (free registration), it increases to 50 requests per 30 seconds.

```
GET https://services.nvd.nist.gov/rest/json/cves/2.0?lastModStartDate=2026-03-27T00:00:00.000&lastModEndDate=2026-03-27T04:00:00.000
```

#### CISA KEV Integration

The Known Exploited Vulnerabilities catalog is downloaded as a single JSON file daily. The
pipeline diffs the current catalog against the previous version (stored in PostgreSQL) and
flags newly added CVEs as high-priority items for immediate inclusion.

---

## 4. Stage 2: DailyCTI AI Curation Engine

DailyCTI AI is the core intelligence layer -- the platform's AI curation engine. It
performs deduplication, entity extraction, priority scoring, and summarization.

### 4.1 Deduplication

Deduplication runs in two passes to balance speed and accuracy.

**First pass -- URL hash (sub-millisecond per article):**
After URL normalization (strip `utm_*`, sort query params, lowercase hostname), compute
SHA-256. Check against the Redis `dedup:urls` set. Exact URL matches are dropped immediately.

**Second pass -- MinHash content fingerprinting (~5 ms per article):**
For articles that survive the URL pass, generate a MinHash signature using the `datasketch`
library with 128 permutations. Compare against all signatures ingested in the last 72 hours
using a MinHash LSH index (threshold 0.85). A Jaccard similarity above 0.85 is classified
as a duplicate.

```python
from datasketch import MinHash, MinHashLSH

lsh = MinHashLSH(threshold=0.85, num_perm=128)

def fingerprint(text: str) -> MinHash:
    m = MinHash(num_perm=128)
    for shingle in ngrams(text.lower().split(), n=3):
        m.update(" ".join(shingle).encode("utf-8"))
    return m
```

**Cluster representative selection:**
When duplicates are found, the system selects the article with the longest extracted text
as the primary representative. Metadata (source attributions, URLs) from all duplicates
is merged onto the representative.

### 4.2 Entity Extraction

#### CVE Extraction and Enrichment

CVE identifiers are extracted via regex `CVE-\d{4}-\d{4,7}` applied to both the title and
body. Each extracted CVE is enriched by querying the NVD API (with local cache in
PostgreSQL, TTL 24 hours) to attach:

- CVSS v3.1 base score and vector string
- CWE classification
- Affected CPE configurations
- CISA KEV status (boolean: is this CVE in the catalog?)
- EPSS score (Exploit Prediction Scoring System)

#### IOC Extraction

The `ioc-finder` library handles extraction of indicators of compromise, including defanged
variants:

- IPv4/IPv6 addresses (including `1.2.3[.]4` defanged notation)
- Domain names (including `example[.]com`)
- URLs (including `hxxps://` and `hxxp://`)
- Email addresses
- File hashes: MD5, SHA-1, SHA-256
- ASN numbers
- CIDR ranges

All extracted IOCs are stored in the `entities` table with type classification and the
source article foreign key.

#### Threat Actor Matching

Threat actor names are matched against the MITRE ATT&CK Groups knowledge base (800+ actor
profiles) using `rapidfuzz` for fuzzy string matching:

```python
from rapidfuzz import process, fuzz

match, score, _ = process.extractOne(
    candidate_name,
    attack_group_names,
    scorer=fuzz.token_sort_ratio,
)
if score >= 85:
    # Confirmed match against ATT&CK group
```

This handles aliases (e.g., "Fancy Bear" / "APT28" / "Sofacy" all resolve to G0007).

#### Malware Family Matching

Similar fuzzy matching against the ATT&CK Software knowledge base (1500+ malware families
and tools). Threshold set at 85% similarity.

#### Organization and Product NER

spaCy with the `en_core_web_trf` (transformer-based) model extracts ORG and PRODUCT
entities. A post-processing step filters out common false positives using a curated
stoplist of 200+ terms (e.g., "Monday", "Windows" when used colloquially).

#### MITRE ATT&CK Technique Mapping

A two-pass approach:

1. **Rule-based keyword matching**: A lookup table maps 500+ keywords and phrases to ATT&CK
   technique IDs (e.g., "phishing attachment" -> T1566.001, "credential dumping" -> T1003).
2. **Claude API refinement**: For articles scoring in the top 20% by priority, the full
   text is sent to Claude Sonnet with a structured prompt requesting ATT&CK technique IDs,
   returning higher-precision mappings.

### 4.3 Priority Scoring Algorithm

Every article receives a composite priority score on a 0.0--1.0 scale:

```
priority = (source_weight    * 0.20) +
           (cvss_normalized  * 0.25) +
           (exploit_available * 0.20) +
           (mention_velocity * 0.15) +
           (recency_decay    * 0.10) +
           (product_prevalence * 0.10)
```

| Factor | Range | Calculation |
|--------|-------|-------------|
| `source_weight` | 0.0 -- 1.0 | Static weight per source. Tier 1 = 0.9--1.0, Tier 2 = 0.6--0.8, Tier 3 = 0.3--0.5. Manually curated based on historical signal quality. |
| `cvss_normalized` | 0.0 -- 1.0 | Highest CVSS v3.1 base score among all CVEs in the article, divided by 10. Articles with no CVEs receive 0.0. |
| `exploit_available` | 0.0 or 1.0 | Binary. Set to 1.0 if any CVE in the article appears in CISA KEV, has a public exploit in Exploit-DB, or has an EPSS score above 0.7. |
| `mention_velocity` | 0.0 -- 1.0 | Number of distinct sources mentioning the same story cluster in the last 24 hours, normalized by dividing by 10 (capped at 1.0). |
| `recency_decay` | 0.0 -- 1.0 | Exponential decay: `exp(-0.03 * hours_since_publication)`. An article published 0 hours ago scores 1.0; 24 hours ago scores 0.49; 48 hours ago scores 0.24. |
| `product_prevalence` | 0.0 -- 1.0 | Proportion of the subscriber base that uses at least one affected product (from CPE matching against a subscriber technology profile). Defaults to 0.5 when unknown. |

Articles with `priority >= 0.7` are classified **Critical**, `0.5--0.69` as **High**,
`0.3--0.49` as **Medium**, and below 0.3 as **Info**.

### 4.4 Summarization

Summarization is a two-step process optimized for cost and quality.

**Step 1 -- Extractive pre-filter (sumy TextRank):**
Reduce the article body to approximately 30% of its original length using TextRank sentence
extraction. This lowers the token count sent to the LLM.

```python
from sumy.parsers.plaintext import PlaintextParser
from sumy.nlp.tokenizers import Tokenizer
from sumy.summarizers.text_rank import TextRankSummarizer

parser = PlaintextParser.from_string(article_text, Tokenizer("english"))
summarizer = TextRankSummarizer()
sentences = summarizer(parser.document, sentences_count=max(3, len(body_sentences) // 3))
```

**Step 2 -- Abstractive summary (Claude Sonnet):**
The extracted sentences are sent to Claude Sonnet with a structured prompt:

```
Summarize this cybersecurity article in 2-3 sentences. Cover:
1. What happened or was discovered
2. Who is affected (products, vendors, industries)
3. What action defenders should take

Article: {extracted_text}
```

**Cost estimate**: Average input is ~800 tokens after extraction, output is ~100 tokens.
At Claude Sonnet pricing, this is approximately $0.003 per article. At 200 articles/day,
the daily summarization cost is approximately $0.60.

---

## 5. Stage 3: Curation Engine

### 5.1 Story Clustering

Related articles are grouped into story clusters so the newsletter presents one entry per
story rather than five articles about the same vulnerability.

**Embedding**: Each article's title and first 512 characters of body text are embedded using
`sentence-transformers/all-MiniLM-L6-v2` (384-dimensional vectors, ~30 ms per article on
CPU).

**Clustering**: HDBSCAN groups articles by semantic similarity:

```python
from hdbscan import HDBSCAN

clusterer = HDBSCAN(
    min_cluster_size=2,
    min_samples=1,
    metric="euclidean",
    cluster_selection_epsilon=0.3,
)
labels = clusterer.fit_predict(embeddings)
```

**Representative selection**: Within each cluster, the article with the highest priority
score is selected as the representative. All other articles are listed as "Related
coverage" with source attribution links.

### 5.2 Section Assignment

Each newsletter is divided into sections based on the dominant entity types in each article:

| Section | Assignment Rule |
|---------|----------------|
| Critical Vulnerabilities | Contains CVE with CVSS >= 9.0 or is in CISA KEV |
| Active Exploits | `exploit_available` flag is set, or mentions PoC/exploit code |
| Threat Actor Activity | Contains matched ATT&CK group entity |
| Malware & Ransomware | Contains matched ATT&CK software entity with type "malware" |
| Data Breaches | NER detects ORG + keywords: "breach", "leak", "exposed", "compromised" |
| Government & Policy | Source is a government CERT/advisory feed |
| Research & Tools | Source is a vendor research blog or contains GitHub links |
| Industry News | Default bucket for articles not matching above rules |

Articles may appear in multiple sections if they match multiple rules. The primary section
is determined by the first matching rule in priority order (top of table = highest).

### 5.3 Top-N Selection

Each section is capped at a configurable number of stories (default: 5 for Critical, 4 for
Active Exploits, 3 for all others). Selection is by descending priority score. Stories that
do not make the cut are still available via the DailyCTI API but are excluded from the
newsletter.

### 5.4 Trend Detection

The pipeline tracks entity mention volume over a rolling 7-day window. A spike is detected
when the current day's mention count exceeds the rolling mean plus 2 standard deviations:

```python
is_trending = today_count > rolling_mean_7d + (2 * rolling_std_7d)
```

Trending entities (CVEs, threat actors, malware families) receive a "Trending" badge in the
newsletter and a 0.1 bonus added to their articles' priority scores.

---

## 6. Stage 4: Newsletter Generation

### Template System

Newsletters are rendered using **Jinja2** templates compiled to three output formats:

| Format | Engine | Use Case |
|--------|--------|----------|
| HTML email | Jinja2 + MJML (compiled to inline-CSS HTML) | Primary email delivery |
| Markdown | Jinja2 | Slack/Teams posting, archive |
| Plaintext | Jinja2 (strip tags + textwrap) | Fallback, accessibility |

MJML is used as the HTML templating layer because it produces email-client-compatible HTML
with responsive layouts. The MJML source is compiled to HTML at build time via `mjml-cli`.

### Severity Color Badges

Each article in the newsletter displays a colored severity badge:

| Severity | Color | Hex | Priority Range |
|----------|-------|-----|----------------|
| Critical | Red | `#DC2626` | >= 0.70 |
| High | Orange | `#EA580C` | 0.50 -- 0.69 |
| Medium | Yellow | `#CA8A04` | 0.30 -- 0.49 |
| Info | Blue | `#2563EB` | < 0.30 |

### Newsletter Structure

```
Subject: DailyCTI Daily Threat Brief -- {date} -- {top_story_headline}

1. Executive Summary (3--5 bullet points, auto-generated)
2. Critical Vulnerabilities (up to 5 stories)
3. Active Exploits (up to 4 stories)
4. Threat Actor Activity (up to 3 stories)
5. Malware & Ransomware (up to 3 stories)
6. Data Breaches (up to 3 stories)
7. Government & Policy (up to 3 stories)
8. Research & Tools (up to 3 stories)
9. Industry News (up to 3 stories)
10. Trending Entities (sidebar: CVEs, actors, malware spiking)
11. IOC Table (top 20 IOCs extracted today)
12. MITRE ATT&CK Heatmap (techniques seen this week)
```

---

## 7. Stage 5: Distribution and Storage

### 7.1 PostgreSQL Schema

The primary data store uses PostgreSQL 16 with the following core tables:

| Table | Purpose | Key Columns |
|-------|---------|-------------|
| `articles` | Ingested and processed articles | `id`, `url_hash`, `title`, `body`, `summary`, `priority_score`, `source_published_at`, `ingested_at`, `processed_at` |
| `entities` | Extracted IOCs, CVEs, actors, malware | `id`, `article_id`, `entity_type`, `value`, `confidence`, `attack_id` |
| `feeds` | Source registry (80+ feeds) | `id`, `url`, `title`, `tier`, `poll_interval`, `etag`, `last_modified` |
| `collections` | User-defined feed groups | `id`, `user_id`, `label`, `feed_ids[]` |
| `tags` | User tags on articles | `id`, `user_id`, `article_id`, `label` |
| `markers` | Read/unread/saved state | `user_id`, `article_id`, `read`, `saved`, `updated_at` |
| `users` | User accounts and preferences | `id`, `email`, `api_key`, `preferences_jsonb` |
| `newsletters` | Generated newsletter archive | `id`, `date`, `html`, `markdown`, `plaintext`, `stats_jsonb` |
| `subscribers` | Newsletter recipient list | `id`, `email`, `frequency`, `sections_filter`, `verified` |

Indexes: `articles(url_hash)` unique, `articles(source_published_at DESC)`,
`entities(entity_type, value)`, `entities(article_id)`, `markers(user_id, article_id)` unique.

Partitioning: `articles` is range-partitioned by `ingested_at` on a monthly basis to keep
query performance stable as the table grows.

### 7.2 Redis Usage

| Key Pattern | Data Structure | TTL | Purpose |
|-------------|---------------|-----|---------|
| `dedup:urls` | SET | 30 days | URL dedup hashes |
| `dedup:minhash:<id>` | STRING (binary) | 72 hours | MinHash signatures |
| `ratelimit:<domain>` | STRING (counter) | 1--30 seconds | Per-domain rate limiting |
| `etag:<feed_id>` | HASH (etag, last_modified) | 7 days | Conditional request headers |
| `session:<token>` | HASH | 24 hours | API session data |
| `cache:nvd:<cve_id>` | STRING (JSON) | 24 hours | NVD API response cache |
| `cache:stream:<stream_id>:<page>` | STRING (JSON) | 5 minutes | Stream content cache |

### 7.3 Email Delivery (Amazon SES)

Newsletters are delivered via Amazon SES with the following configuration:

- **SPF**: `v=spf1 include:amazonses.com ~all` on the sending domain
- **DKIM**: 2048-bit RSA key pair, selector `dailycti._domainkey`
- **DMARC**: `v=DMARC1; p=quarantine; rua=mailto:dmarc@dailycti.io`
- **Bounce handling**: SES SNS notifications -> Lambda -> unsubscribe on hard bounce
- **Rate**: SES sandbox allows 1 msg/sec; production allows 50 msg/sec
- **Tracking**: Open pixel and click-through tracking via SES configuration set

### 7.4 Slack Integration

A Slack bot posts the daily newsletter summary to configured channels using Block Kit
formatting. Critical/high-severity articles are also posted as individual messages with
thread replies containing the full summary and IOC list.

### 7.5 STIX Export

All extracted entities and relationships can be exported as STIX 2.1 bundles for import
into MISP, OpenCTI, or other threat intelligence platforms. The export endpoint is
`GET /v3/stix/bundle?date=YYYY-MM-DD`.

---

## 8. MTTI (Mean Time To Intelligence) Tracking

DailyCTI tracks four timestamps for every article to measure pipeline latency:

| Timestamp | Column | Source |
|-----------|--------|--------|
| Source published | `source_published_at` | RSS `<pubDate>` or API timestamp |
| Ingested | `ingested_at` | Recorded when article enters Stage 1 |
| Processed | `processed_at` | Recorded when Stage 2 completes |
| Delivered | `delivered_at` | Recorded when newsletter is sent or API serves it |

**MTTI = delivered_at - source_published_at**

### Performance Targets

| Metric | Target | Typical |
|--------|--------|---------|
| Ingestion latency (published -> ingested) | < 30 min | ~15 min (Tier 1) |
| Processing latency (ingested -> processed) | < 60 min | ~20 min |
| Newsletter generation | < 10 min | ~3 min |
| Total MTTI | < 4 hours | ~2.5 hours |

MTTI is tracked per article and aggregated into daily/weekly dashboards. Articles exceeding
the 4-hour target are flagged for investigation (usually caused by slow source publication
or API rate limiting).

---

## 9. Technology Stack

| Layer | Technology | Version | Purpose |
|-------|-----------|---------|---------|
| Language | Python | 3.12+ | Primary runtime |
| Web framework | FastAPI | 0.115+ | v3-compatible REST API |
| ASGI server | Uvicorn | 0.30+ | HTTP server |
| Task scheduler | APScheduler | 3.10+ | Feed polling orchestration |
| Async HTTP | httpx | 0.27+ | Outbound HTTP with connection pooling |
| RSS parsing | feedparser | 6.0+ | RSS/Atom feed parsing |
| TAXII client | taxii2-client | 2.3+ | STIX/TAXII feed ingestion |
| Content extraction | trafilatura | 1.12+ | Article full-text extraction |
| Content fallback | newspaper3k | 0.2+ | Fallback text extraction |
| NLP | spaCy | 3.7+ | Named entity recognition |
| NLP model | en_core_web_trf | 3.7+ | Transformer-based NER pipeline |
| Dedup | datasketch | 1.6+ | MinHash LSH deduplication |
| Fuzzy matching | rapidfuzz | 3.9+ | Threat actor/malware name matching |
| IOC extraction | ioc-finder | 8.0+ | Indicator of compromise parsing |
| Extractive summary | sumy | 0.11+ | TextRank sentence extraction |
| LLM | Claude Sonnet (Anthropic) | latest | Abstractive summarization, ATT&CK mapping |
| Embeddings | sentence-transformers | 3.0+ | Article embedding (all-MiniLM-L6-v2) |
| Clustering | hdbscan | 0.8+ | Story clustering |
| Database | PostgreSQL | 16+ | Primary data store |
| Cache/queue | Redis | 7.2+ | Dedup, rate limits, caching |
| Email templates | MJML | 4.15+ | Responsive HTML email |
| Templating | Jinja2 | 3.1+ | Newsletter rendering |
| Email delivery | Amazon SES | v2 API | SMTP delivery |
| STIX export | stix2 | 3.0+ | STIX 2.1 bundle generation |
| Testing | pytest | 8.0+ | Unit and integration tests |
| Linting | ruff | 0.5+ | Code formatting and linting |
| Containerization | Docker | 24+ | Deployment packaging |
| Orchestration | Docker Compose | 2.27+ | Local/production deployment |

---

## 10. Data Flow Example

The following walkthrough traces a single article from RSS discovery to newsletter delivery.

### 10.1 Source Publication

At `2026-03-27T08:12:00Z`, BleepingComputer publishes an article titled
*"Critical Cisco IOS XE Flaw Exploited in the Wild -- Patch Now"*.

### 10.2 Stage 1: Ingestion (T+13 minutes)

At `T+13 min`, the Tier 1 poller fetches `https://www.bleepingcomputer.com/feed/`. The
`ETag` has changed since the last poll, so `feedparser` parses the response. The new entry's
URL is normalized and SHA-256 hashed. The hash is not in `dedup:urls`, so it is added and
the article proceeds. `trafilatura` extracts 1,847 words of body text.

**Record created**: `articles` row with `ingested_at = 2026-03-27T08:25:00Z`.

### 10.3 Stage 2: DailyCTI AI (T+31 minutes)

**Dedup**: MinHash fingerprint is computed and checked against the LSH index. No near-
duplicates found (a Talos blog post about the same CVE arrives 20 minutes later and will be
merged as a duplicate with Jaccard similarity 0.91).

**Entity extraction**:
- CVE regex finds `CVE-2026-20198` (CVSS 10.0, in CISA KEV)
- IOC finder extracts 3 IP addresses and 2 domains from the article body
- Threat actor matching: no known group attributed
- spaCy NER: ORG="Cisco", PRODUCT="IOS XE"
- ATT&CK mapping (rule-based): T1190 (Exploit Public-Facing Application)

**Priority scoring**:
```
source_weight      = 0.95 (BleepingComputer, Tier 1)  * 0.20 = 0.190
cvss_normalized    = 1.00 (CVSS 10.0 / 10)            * 0.25 = 0.250
exploit_available  = 1.00 (in CISA KEV)               * 0.20 = 0.200
mention_velocity   = 0.30 (3 sources so far / 10)     * 0.15 = 0.045
recency_decay      = 0.98 (31 min old)                * 0.10 = 0.098
product_prevalence = 0.70 (Cisco IOS XE is widespread) * 0.10 = 0.070
                                              TOTAL PRIORITY = 0.853
```

Classification: **Critical** (>= 0.70).

**Summarization**: TextRank extracts 6 key sentences. Claude Sonnet produces:
*"A critical authentication bypass vulnerability (CVE-2026-20198, CVSS 10.0) in Cisco IOS XE
is being actively exploited in the wild, allowing unauthenticated remote attackers to create
privileged accounts on affected devices. Cisco has released patches and organizations running
IOS XE should update immediately or apply the recommended mitigations."*

**Record updated**: `processed_at = 2026-03-27T08:43:00Z`.

### 10.4 Stage 3: Curation (T+35 minutes)

The article is embedded with `all-MiniLM-L6-v2`. HDBSCAN places it in a new cluster
(cluster #47 for the day). The later Talos article will join this cluster.

Section assignment: **Critical Vulnerabilities** (CVSS >= 9.0 and in CISA KEV).

The article ranks #1 in the Critical Vulnerabilities section by priority score.

### 10.5 Stage 4: Newsletter Generation (T+6 hours, scheduled 14:00 UTC)

The daily newsletter is generated at `14:00 UTC`. The Cisco IOS XE story is the lead item.
Jinja2 renders the MJML template with:
- Red severity badge
- 2-sentence summary
- CVE link to NVD
- CISA KEV badge
- 3 extracted IOCs
- ATT&CK technique T1190
- "Related coverage" link to the Talos blog post

MJML compiles to inline-CSS HTML. Markdown and plaintext variants are also generated.

### 10.6 Stage 5: Delivery (T+6 hours 3 minutes)

- **Email**: Amazon SES sends the HTML newsletter to 2,400 subscribers in batches of 50/sec.
- **Slack**: Block Kit message posted to #threat-intel channel.
- **API**: Article is immediately available at `/v3/entries/<id>` and in the stream
  `/v3/streams/contents?streamId=user/*/category/global.all`.

**Record updated**: `delivered_at = 2026-03-27T14:03:00Z`.

**Final MTTI**: `14:03 - 08:12 = 5 hours 51 minutes` (newsletter was scheduled; the article
was available via API at `T+35 minutes` = 08:47, giving an API MTTI of 35 minutes).

---

*Last updated: 2026-03-27*
