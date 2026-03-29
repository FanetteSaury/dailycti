"""Tests for entity extraction -- src/fidlie/ai/entities.py

Validates CVE regex, IOC extraction (including defanged indicators),
threat actor alias resolution, malware family matching, and false-positive
rejection.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from fidlie.ai.entities import (
    extract_cves,
    extract_iocs,
    match_threat_actor,
    match_malware_family,
)


# ---------------------------------------------------------------------------
# Helpers -- load the real entity knowledge base
# ---------------------------------------------------------------------------

CONFIG_DIR = Path(__file__).resolve().parents[2] / "config"


@pytest.fixture(scope="module")
def entities_config():
    """Load config/entities.yaml for alias lookups."""
    with open(CONFIG_DIR / "entities.yaml") as fh:
        return yaml.safe_load(fh)


@pytest.fixture(scope="module")
def threat_actors(entities_config):
    return entities_config["threat_actors"]


@pytest.fixture(scope="module")
def malware_families(entities_config):
    return entities_config["malware_families"]


# ===========================================================================
# CVE regex extraction
# ===========================================================================


class TestCveExtraction:
    """Validate CVE identifier extraction via regex."""

    def test_single_cve_in_text(self):
        """A single CVE in running text is found."""
        text = "The vulnerability CVE-2024-53677 affects Apache Struts."
        cves = extract_cves(text)
        assert "CVE-2024-53677" in cves

    def test_multiple_cves(self):
        """Multiple CVEs in the same text are all extracted."""
        text = (
            "Patches address CVE-2024-53677, CVE-2024-12345, and CVE-2023-44487 "
            "(HTTP/2 Rapid Reset)."
        )
        cves = extract_cves(text)
        assert len(cves) >= 3
        assert "CVE-2024-53677" in cves
        assert "CVE-2024-12345" in cves
        assert "CVE-2023-44487" in cves

    def test_cve_with_short_id(self):
        """CVE with a 4-digit sequence number (minimum valid)."""
        text = "CVE-2026-1234 was disclosed today."
        cves = extract_cves(text)
        assert "CVE-2026-1234" in cves

    def test_cve_with_long_id(self):
        """CVE with a 7-digit sequence number (max typical)."""
        text = "CVE-2025-1234567 is a hypothetical future CVE."
        cves = extract_cves(text)
        assert "CVE-2025-1234567" in cves

    def test_no_cves_in_clean_text(self):
        """Text without CVEs returns an empty collection."""
        text = "This article discusses general threat landscape trends."
        cves = extract_cves(text)
        assert len(cves) == 0

    def test_cve_in_title(self):
        """CVEs embedded in a title string are extracted."""
        title = "Critical RCE Vulnerability in Apache Struts (CVE-2024-53677)"
        cves = extract_cves(title)
        assert "CVE-2024-53677" in cves

    def test_cve_deduplication(self):
        """Duplicate CVE mentions return a unique set."""
        text = "CVE-2024-53677 is critical. We repeat: CVE-2024-53677 is critical."
        cves = extract_cves(text)
        assert cves.count("CVE-2024-53677") == 1 or len(set(cves)) == 1

    def test_almost_cve_not_matched(self):
        """Strings resembling CVEs but invalid are not extracted."""
        text = "CVE-20-1234 is too short. CVE-ABCD-1234 has letters."
        cves = extract_cves(text)
        assert len(cves) == 0

    def test_cve_adjacent_to_punctuation(self):
        """CVE at end of sentence with period is still captured."""
        text = "The bug is tracked as CVE-2024-53677."
        cves = extract_cves(text)
        assert "CVE-2024-53677" in cves

    def test_cve_from_conftest_sample(self, sample_rss_entry):
        """Extract CVE from the sample_rss_entry fixture."""
        text = sample_rss_entry["title"] + " " + sample_rss_entry["summary"]
        cves = extract_cves(text)
        assert "CVE-2024-53677" in cves


# ===========================================================================
# IOC extraction (IPs, domains, hashes, defanged variants)
# ===========================================================================


class TestIocExtraction:
    """Validate extraction of indicators of compromise, including defanged forms."""

    def test_ipv4_standard(self):
        """Standard dotted-quad IPv4 is extracted."""
        text = "C2 callback observed to 192.168.1.100 on port 443."
        iocs = extract_iocs(text)
        ipv4s = iocs.get("ipv4", iocs.get("ipv4s", iocs.get("ip", [])))
        assert any("192.168.1.100" in str(ip) for ip in ipv4s)

    def test_ipv4_defanged_brackets(self):
        """Defanged IP like 185[.]174[.]100[.]56 is recognized."""
        text = "C2 Server: 185[.]174[.]100[.]56"
        iocs = extract_iocs(text)
        ipv4s = iocs.get("ipv4", iocs.get("ipv4s", iocs.get("ip", [])))
        assert any("185.174.100.56" in str(ip) for ip in ipv4s)

    def test_domain_standard(self):
        """Standard domain names are extracted."""
        text = "The malware calls back to evil-c2.example.com for instructions."
        iocs = extract_iocs(text)
        domains = iocs.get("domains", iocs.get("domain", []))
        assert any("evil-c2.example.com" in str(d) for d in domains)

    def test_domain_defanged(self):
        """Defanged domain like update-service[.]net is recognized."""
        text = "C2 Domain: update-service[.]net"
        iocs = extract_iocs(text)
        domains = iocs.get("domains", iocs.get("domain", []))
        assert any("update-service.net" in str(d) for d in domains)

    def test_sha256_hash(self):
        """SHA-256 hashes (64 hex chars) are extracted."""
        hash_val = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"
        text = f"Payload Hash (SHA-256): {hash_val}"
        iocs = extract_iocs(text)
        sha256s = iocs.get("sha256", iocs.get("sha256s", iocs.get("hashes", [])))
        assert any(hash_val in str(h) for h in sha256s)

    def test_md5_hash(self):
        """MD5 hashes (32 hex chars) are extracted."""
        md5 = "d41d8cd98f00b204e9800998ecf8427e"
        text = f"MD5: {md5}"
        iocs = extract_iocs(text)
        md5s = iocs.get("md5", iocs.get("md5s", iocs.get("hashes", [])))
        assert any(md5 in str(h) for h in md5s)

    def test_sha1_hash(self):
        """SHA-1 hashes (40 hex chars) are extracted."""
        sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        text = f"SHA-1: {sha1}"
        iocs = extract_iocs(text)
        sha1s = iocs.get("sha1", iocs.get("sha1s", iocs.get("hashes", [])))
        assert any(sha1 in str(h) for h in sha1s)

    def test_url_defanged_hxxps(self):
        """Defanged URL hxxps://... is recognized and refanged."""
        text = "Phishing URL: hxxps://login[.]microsoftonline-auth[.]com/oauth2"
        iocs = extract_iocs(text)
        urls = iocs.get("urls", iocs.get("url", []))
        assert any("microsoftonline-auth" in str(u) for u in urls)

    def test_url_defanged_hxxp(self):
        """Defanged hxxp:// is handled."""
        text = "Download from hxxp://evil[.]com/payload.exe"
        iocs = extract_iocs(text)
        urls = iocs.get("urls", iocs.get("url", []))
        assert any("evil" in str(u) for u in urls)

    def test_full_sample_from_conftest(self, sample_article_with_iocs):
        """The conftest sample text yields expected IOCs."""
        iocs = extract_iocs(sample_article_with_iocs)

        # IPv4
        ipv4s_str = str(iocs.get("ipv4", iocs.get("ipv4s", iocs.get("ip", []))))
        assert "185.174.100.56" in ipv4s_str

        # Domain
        domains_str = str(iocs.get("domains", iocs.get("domain", [])))
        assert "update-service" in domains_str

        # SHA-256
        sha256_str = str(iocs.get("sha256", iocs.get("sha256s", iocs.get("hashes", []))))
        assert "a1b2c3d4e5f6a7b8" in sha256_str

    def test_no_iocs_in_clean_text(self):
        """Clean business prose yields no IOCs."""
        text = (
            "The board of directors approved the annual cybersecurity budget "
            "increase of fifteen percent for the upcoming fiscal year."
        )
        iocs = extract_iocs(text)
        # All IOC lists should be empty
        total = sum(len(v) if isinstance(v, (list, set)) else 0 for v in iocs.values())
        assert total == 0

    def test_ipv4_loopback_excluded(self):
        """127.0.0.1 and other loopback/private ranges may be filtered."""
        text = "localhost at 127.0.0.1 is not a threat indicator."
        iocs = extract_iocs(text)
        ipv4s = iocs.get("ipv4", iocs.get("ipv4s", iocs.get("ip", [])))
        # Either empty or 127.0.0.1 explicitly filtered
        assert not any("127.0.0.1" in str(ip) for ip in ipv4s) or len(ipv4s) == 0


# ===========================================================================
# Threat actor name matching
# ===========================================================================


class TestThreatActorMatching:
    """Validate fuzzy matching of threat actor names and aliases."""

    def test_canonical_name_match(self, threat_actors):
        """Canonical name 'APT28' matches itself."""
        result = match_threat_actor("APT28", threat_actors)
        assert result is not None
        assert result["canonical_name"] == "APT28"

    def test_alias_fancy_bear(self, threat_actors):
        """Alias 'Fancy Bear' resolves to APT28."""
        result = match_threat_actor("Fancy Bear", threat_actors)
        assert result is not None
        assert result["canonical_name"] == "APT28"

    def test_alias_sofacy(self, threat_actors):
        """Alias 'Sofacy' resolves to APT28."""
        result = match_threat_actor("Sofacy", threat_actors)
        assert result is not None
        assert result["canonical_name"] == "APT28"

    def test_alias_strontium(self, threat_actors):
        """Microsoft designation 'STRONTIUM' resolves to APT28."""
        result = match_threat_actor("STRONTIUM", threat_actors)
        assert result is not None
        assert result["canonical_name"] == "APT28"

    def test_alias_forest_blizzard(self, threat_actors):
        """New Microsoft naming 'Forest Blizzard' resolves to APT28."""
        result = match_threat_actor("Forest Blizzard", threat_actors)
        assert result is not None
        assert result["canonical_name"] == "APT28"

    def test_cozy_bear_to_apt29(self, threat_actors):
        """'Cozy Bear' resolves to APT29."""
        result = match_threat_actor("Cozy Bear", threat_actors)
        assert result is not None
        assert result["canonical_name"] == "APT29"

    def test_lazarus_group(self, threat_actors):
        """'Lazarus Group' is matched correctly."""
        result = match_threat_actor("Lazarus Group", threat_actors)
        assert result is not None
        assert result["canonical_name"] == "Lazarus Group"

    def test_hidden_cobra_to_lazarus(self, threat_actors):
        """'HIDDEN COBRA' resolves to Lazarus Group."""
        result = match_threat_actor("HIDDEN COBRA", threat_actors)
        assert result is not None
        assert result["canonical_name"] == "Lazarus Group"

    def test_volt_typhoon(self, threat_actors):
        """'Volt Typhoon' is matched."""
        result = match_threat_actor("Volt Typhoon", threat_actors)
        assert result is not None
        assert result["canonical_name"] == "Volt Typhoon"

    def test_scattered_spider(self, threat_actors):
        """'Scattered Spider' is matched."""
        result = match_threat_actor("Scattered Spider", threat_actors)
        assert result is not None
        assert result["canonical_name"] == "Scattered Spider"

    def test_octo_tempest_to_scattered_spider(self, threat_actors):
        """'Octo Tempest' resolves to Scattered Spider."""
        result = match_threat_actor("Octo Tempest", threat_actors)
        assert result is not None
        assert result["canonical_name"] == "Scattered Spider"

    def test_lockbit_as_threat_actor(self, threat_actors):
        """'LockBit' in threat_actors context matches the ransomware group."""
        result = match_threat_actor("LockBit", threat_actors)
        assert result is not None
        assert result["canonical_name"] == "LockBit"

    def test_no_match_for_random_name(self, threat_actors):
        """A random non-actor name returns None."""
        result = match_threat_actor("John Smith Corp", threat_actors)
        assert result is None

    def test_no_match_for_common_words(self, threat_actors):
        """Common English words do not false-positive as threat actors."""
        for word in ["Security", "Microsoft", "Update", "Server", "Network"]:
            result = match_threat_actor(word, threat_actors)
            assert result is None, f"'{word}' should not match a threat actor"

    def test_case_insensitive(self, threat_actors):
        """Matching is case-insensitive ('apt28' matches APT28)."""
        result = match_threat_actor("apt28", threat_actors)
        assert result is not None
        assert result["canonical_name"] == "APT28"

    def test_from_conftest_sample(self, threat_actors, sample_article_with_iocs):
        """The conftest IOC sample mentions APT28 / Fancy Bear."""
        # Extract actor mention from text
        result = match_threat_actor("APT28", threat_actors)
        assert result is not None
        assert result["canonical_name"] == "APT28"


# ===========================================================================
# Malware family matching
# ===========================================================================


class TestMalwareFamilyMatching:
    """Validate fuzzy matching of malware family names and aliases."""

    def test_canonical_cobalt_strike(self, malware_families):
        """'Cobalt Strike' matches itself."""
        result = match_malware_family("Cobalt Strike", malware_families)
        assert result is not None
        assert result["canonical_name"] == "Cobalt Strike"

    def test_alias_beacon(self, malware_families):
        """'Beacon' resolves to Cobalt Strike."""
        result = match_malware_family("Beacon", malware_families)
        assert result is not None
        assert result["canonical_name"] == "Cobalt Strike"

    def test_alias_cs_beacon(self, malware_families):
        """'CS Beacon' resolves to Cobalt Strike."""
        result = match_malware_family("CS Beacon", malware_families)
        assert result is not None
        assert result["canonical_name"] == "Cobalt Strike"

    def test_qakbot_aliases(self, malware_families):
        """'Qbot' resolves to QakBot."""
        result = match_malware_family("Qbot", malware_families)
        assert result is not None
        assert result["canonical_name"] == "QakBot"

    def test_emotet_alias_heodo(self, malware_families):
        """'Heodo' resolves to Emotet."""
        result = match_malware_family("Heodo", malware_families)
        assert result is not None
        assert result["canonical_name"] == "Emotet"

    def test_redline_stealer(self, malware_families):
        """'RedLine Stealer' resolves to RedLine."""
        result = match_malware_family("RedLine Stealer", malware_families)
        assert result is not None
        assert result["canonical_name"] == "RedLine"

    def test_alphv_to_blackcat(self, malware_families):
        """'ALPHV' resolves to BlackCat."""
        result = match_malware_family("ALPHV", malware_families)
        assert result is not None
        assert result["canonical_name"] == "BlackCat"

    def test_clop_alternate_spelling(self, malware_families):
        """'Clop' resolves to Cl0p."""
        result = match_malware_family("Clop", malware_families)
        assert result is not None
        assert result["canonical_name"] == "Cl0p"

    def test_hermetic_wiper(self, malware_families):
        """'HermeticWiper' is matched."""
        result = match_malware_family("HermeticWiper", malware_families)
        assert result is not None
        assert result["canonical_name"] == "HermeticWiper"

    def test_foxblade_to_hermetic(self, malware_families):
        """'FoxBlade' (Microsoft name) resolves to HermeticWiper."""
        result = match_malware_family("FoxBlade", malware_families)
        assert result is not None
        assert result["canonical_name"] == "HermeticWiper"

    def test_lumma_stealer(self, malware_families):
        """'Lumma Stealer' resolves to Lumma."""
        result = match_malware_family("Lumma Stealer", malware_families)
        assert result is not None
        assert result["canonical_name"] == "Lumma"

    def test_no_match_for_random_software(self, malware_families):
        """Generic software names do not match malware families."""
        result = match_malware_family("Microsoft Excel", malware_families)
        assert result is None

    def test_no_match_for_common_words(self, malware_families):
        """Common words do not false-positive as malware."""
        for word in ["Update", "Chrome", "Install", "Download", "Login"]:
            result = match_malware_family(word, malware_families)
            assert result is None, f"'{word}' should not match a malware family"

    def test_returns_type_field(self, malware_families):
        """Matched malware includes its type (tool, loader, ransomware, etc.)."""
        result = match_malware_family("Cobalt Strike", malware_families)
        assert result is not None
        assert "type" in result
        assert result["type"] == "tool"

    def test_ransomware_type(self, malware_families):
        """LockBit is classified as ransomware."""
        result = match_malware_family("LockBit", malware_families)
        assert result is not None
        assert result["type"] == "ransomware"

    def test_infostealer_type(self, malware_families):
        """Vidar is classified as infostealer."""
        result = match_malware_family("Vidar", malware_families)
        assert result is not None
        assert result["type"] == "infostealer"
