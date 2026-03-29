"""DailyCTI test configuration and shared fixtures."""

import json
from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def sample_rss_entry() -> dict:
    """A sample RSS entry as parsed by feedparser."""
    return {
        "title": "Critical RCE Vulnerability in Apache Struts (CVE-2024-53677)",
        "link": "https://www.bleepingcomputer.com/news/security/apache-struts-rce-flaw/",
        "summary": (
            "A critical remote code execution vulnerability (CVE-2024-53677) has been discovered "
            "in Apache Struts, affecting versions 2.0.0 through 6.3.0.2. The flaw, with a CVSS "
            "score of 9.8, allows unauthenticated attackers to execute arbitrary code on affected "
            "servers. CISA has added this to the Known Exploited Vulnerabilities catalog. "
            "Administrators should upgrade to Struts 6.4.0 or later immediately."
        ),
        "published": "2024-12-15T14:30:00Z",
        "author": "Lawrence Abrams",
        "tags": [{"term": "vulnerability"}, {"term": "apache"}],
    }


@pytest.fixture
def sample_nvd_cve() -> dict:
    """A sample NVD API CVE response."""
    return {
        "cve": {
            "id": "CVE-2024-53677",
            "descriptions": [
                {
                    "lang": "en",
                    "value": (
                        "Apache Struts 2.0.0 through 6.3.0.2 contains a file upload vulnerability "
                        "that allows remote code execution via crafted file upload parameters."
                    ),
                }
            ],
            "metrics": {
                "cvssMetricV31": [
                    {
                        "cvssData": {
                            "baseScore": 9.8,
                            "baseSeverity": "CRITICAL",
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        }
                    }
                ]
            },
            "weaknesses": [{"description": [{"value": "CWE-502"}]}],
            "references": [
                {"url": "https://struts.apache.org/announce-2024", "source": "vendor"}
            ],
        }
    }


@pytest.fixture
def sample_article_with_iocs() -> str:
    """Sample article text containing defanged IOCs."""
    return (
        "The threat actor APT28 (Fancy Bear) has been observed deploying a new variant of "
        "their Sednit malware. The campaign targets government organizations in Eastern Europe. "
        "\n\n"
        "Indicators of Compromise:\n"
        "- C2 Server: 185[.]174[.]100[.]56\n"
        "- C2 Domain: update-service[.]net\n"
        "- Payload Hash (SHA-256): "
        "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2\n"
        "- Phishing URL: hxxps://login[.]microsoftonline-auth[.]com/oauth2\n"
        "\n"
        "The attack leverages CVE-2024-38178 (Windows Scripting Engine RCE) for initial access, "
        "followed by lateral movement using Mimikatz and Cobalt Strike beacons. "
        "The MITRE ATT&CK techniques observed include T1566.001 (Spearphishing Attachment), "
        "T1059.001 (PowerShell), and T1003 (Credential Dumping)."
    )


@pytest.fixture
def sample_cisa_kev_entry() -> dict:
    """A sample CISA KEV catalog entry."""
    return {
        "cveID": "CVE-2024-53677",
        "vendorProject": "Apache",
        "product": "Struts",
        "vulnerabilityName": "Apache Struts File Upload Vulnerability",
        "dateAdded": "2024-12-16",
        "shortDescription": (
            "Apache Struts contains a file upload vulnerability that allows "
            "remote code execution."
        ),
        "requiredAction": "Apply mitigations per vendor instructions or upgrade to Struts 6.4.0+.",
        "dueDate": "2025-01-06",
        "knownRansomwareCampaignUse": "Unknown",
    }
