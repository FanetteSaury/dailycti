"""Entity extraction -- CVEs, IOCs, threat actors, and malware families.

Extracts structured threat intelligence entities from unstructured text,
including defanged indicators of compromise.
"""

from __future__ import annotations

import re

from rapidfuzz import fuzz


# ---------------------------------------------------------------------------
# CVE extraction
# ---------------------------------------------------------------------------

_CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}")


def extract_cves(text: str) -> list[str]:
    """Extract CVE identifiers from text. Returns sorted unique list."""
    matches = _CVE_PATTERN.findall(text)
    return sorted(set(matches))


# ---------------------------------------------------------------------------
# IOC extraction (IPs, domains, hashes, URLs) with defanged support
# ---------------------------------------------------------------------------

# IPv4: standard and defanged (e.g. 185[.]174[.]100[.]56)
_IPV4_PATTERN = re.compile(
    r"\b(\d{1,3}(?:\[\.\]|\.)\d{1,3}(?:\[\.\]|\.)\d{1,3}(?:\[\.\]|\.)\d{1,3})\b"
)

# Domain: standard and defanged (e.g. evil-c2[.]example[.]com)
_DOMAIN_PATTERN = re.compile(
    r"\b((?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?(?:\[\.\]|\.))+(?:com|net|org|io|info|biz|co|us|uk|de|fr|ru|cn|in|xyz|top|site|online|club|cc|me|tv|edu|gov|mil))\b"
)

# Hashes
_SHA256_PATTERN = re.compile(r"\b([a-fA-F0-9]{64})\b")
_SHA1_PATTERN = re.compile(r"\b([a-fA-F0-9]{40})\b")
_MD5_PATTERN = re.compile(r"\b([a-fA-F0-9]{32})\b")

# URLs: standard and defanged (hxxps://, hxxp://)
_URL_PATTERN = re.compile(
    r"((?:hxxps?|https?):\/\/[^\s,;\"'<>]+)"
)

# Loopback / private ranges to exclude
_EXCLUDED_IPS = {
    "127.0.0.1", "0.0.0.0",
}


def _refang(text: str) -> str:
    """Convert defanged indicators back to standard form."""
    result = text.replace("[.]", ".").replace("[:]", ":")
    result = result.replace("hxxp://", "http://").replace("hxxps://", "https://")
    result = result.replace("hXXp://", "http://").replace("hXXps://", "https://")
    return result


def _is_private_ip(ip: str) -> bool:
    """Check if an IP is loopback or commonly excluded."""
    if ip in _EXCLUDED_IPS:
        return True
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        octets = [int(p) for p in parts]
    except ValueError:
        return False
    # 127.x.x.x
    if octets[0] == 127:
        return True
    # 0.x.x.x
    if octets[0] == 0:
        return True
    return False


def _is_valid_ip(ip: str) -> bool:
    """Validate that an IP has valid octets (0-255)."""
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def extract_iocs(text: str) -> dict[str, list[str]]:
    """Extract indicators of compromise from text, including defanged forms.

    Returns dict with keys: ipv4, domains, sha256, sha1, md5, urls
    """
    result: dict[str, list[str]] = {
        "ipv4": [],
        "domains": [],
        "sha256": [],
        "sha1": [],
        "md5": [],
        "urls": [],
    }

    # Extract SHA-256 first (so we can exclude them from shorter hash matches)
    sha256_matches = set(_SHA256_PATTERN.findall(text))
    result["sha256"] = sorted(sha256_matches)

    # SHA-1 (40 hex chars, not part of a SHA-256)
    sha1_candidates = set(_SHA1_PATTERN.findall(text))
    # Exclude substrings of SHA-256 matches
    sha1_filtered = set()
    for h in sha1_candidates:
        if not any(h in s for s in sha256_matches):
            sha1_filtered.add(h)
    result["sha1"] = sorted(sha1_filtered)

    # MD5 (32 hex chars, not part of longer hashes)
    all_longer = sha256_matches | sha1_filtered
    md5_candidates = set(_MD5_PATTERN.findall(text))
    md5_filtered = set()
    for h in md5_candidates:
        if not any(h in s for s in all_longer):
            md5_filtered.add(h)
    result["md5"] = sorted(md5_filtered)

    # URLs (defanged and standard)
    url_matches = _URL_PATTERN.findall(text)
    refanged_urls = []
    for u in url_matches:
        refanged = _refang(u)
        refanged_urls.append(refanged)
    result["urls"] = sorted(set(refanged_urls))

    # IPv4 addresses
    ipv4_raw = _IPV4_PATTERN.findall(text)
    ipv4s = set()
    for ip in ipv4_raw:
        refanged_ip = _refang(ip)
        if _is_valid_ip(refanged_ip) and not _is_private_ip(refanged_ip):
            ipv4s.add(refanged_ip)
    result["ipv4"] = sorted(ipv4s)

    # Domains (defanged and standard)
    domain_raw = _DOMAIN_PATTERN.findall(text)
    domains = set()
    for d in domain_raw:
        refanged_d = _refang(d)
        # Skip if it looks like part of a URL we already extracted
        # and skip very short or generic domains
        if refanged_d and len(refanged_d) > 3:
            domains.add(refanged_d)
    result["domains"] = sorted(domains)

    return result


# ---------------------------------------------------------------------------
# Threat actor matching
# ---------------------------------------------------------------------------

_FUZZY_THRESHOLD = 80  # minimum score for fuzzy match


def match_threat_actor(
    name: str,
    actors_db: dict,
) -> dict | None:
    """Fuzzy match a name against the threat actor database.

    Returns dict with canonical_name and metadata, or None if no match.
    """
    if not name or not actors_db:
        return None

    best_score = 0
    best_canonical = None
    best_data = None

    name_lower = name.lower().strip()

    for canonical, data in actors_db.items():
        # Check canonical name
        score = fuzz.ratio(name_lower, canonical.lower())
        if score > best_score:
            best_score = score
            best_canonical = canonical
            best_data = data

        # Check aliases
        aliases = data.get("aliases", [])
        for alias in aliases:
            score = fuzz.ratio(name_lower, alias.lower())
            if score > best_score:
                best_score = score
                best_canonical = canonical
                best_data = data

    if best_score >= _FUZZY_THRESHOLD and best_canonical is not None:
        return {
            "canonical_name": best_canonical,
            "origin": best_data.get("origin"),
            "targets": best_data.get("targets", []),
        }

    return None


# ---------------------------------------------------------------------------
# Malware family matching
# ---------------------------------------------------------------------------


def match_malware_family(
    name: str,
    families_db: list[dict],
) -> dict | None:
    """Fuzzy match a name against the malware families database.

    Returns dict with canonical_name and type, or None if no match.
    """
    if not name or not families_db:
        return None

    best_score = 0
    best_family = None

    name_lower = name.lower().strip()

    for family in families_db:
        canonical = family["name"]
        # Check canonical name
        score = fuzz.ratio(name_lower, canonical.lower())
        if score > best_score:
            best_score = score
            best_family = family

        # Check aliases
        for alias in family.get("aliases", []):
            score = fuzz.ratio(name_lower, alias.lower())
            if score > best_score:
                best_score = score
                best_family = family

    if best_score >= _FUZZY_THRESHOLD and best_family is not None:
        return {
            "canonical_name": best_family["name"],
            "type": best_family.get("type"),
        }

    return None
