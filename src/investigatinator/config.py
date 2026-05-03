"""Configuration helpers for Investigatinator."""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

DEFAULT_TIMEOUT_SECONDS = 15.0
DEFAULT_ATTACK_STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)
DEFAULT_CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
DEFAULT_LOLBAS_URL = "https://lolbas-project.github.io/api/lolbas.json"
DEFAULT_D3FEND_TECHNIQUES_URL = "https://d3fend.mitre.org/api/technique/all.json"
DEFAULT_D3FEND_TACTICS_URL = "https://d3fend.mitre.org/api/tactic/all.json"
DEFAULT_D3FEND_MAPPINGS_URL = (
    "https://d3fend.mitre.org/api/ontology/inference/d3fend-full-mappings.json"
)
DEFAULT_NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_ABUSEIPDB_BASE_URL = "https://api.abuseipdb.com/api/v2"
DEFAULT_GREYNOISE_BASE_URL = "https://api.greynoise.io/v3/community"
DEFAULT_VIRUSTOTAL_BASE_URL = "https://www.virustotal.com/api/v3"
DEFAULT_SHODAN_BASE_URL = "https://api.shodan.io"
DEFAULT_SECURITYTRAILS_BASE_URL = "https://api.securitytrails.com/v1"
DEFAULT_IPGEOLOCATION_BASE_URL = "https://api.ipgeolocation.io"
DEFAULT_ALIENVAULT_BASE_URL = "https://otx.alienvault.com/api/v1"
DEFAULT_GOOGLE_SAFEBROWSING_BASE_URL = "https://safebrowsing.googleapis.com"
DEFAULT_RESEARCH_FEEDS = (
    "https://www.bleepingcomputer.com/feed/,"
    "https://cloud.google.com/blog/topics/threat-intelligence/rss"
)
DEFAULT_RESEARCH_USER_AGENT = "Investigatinator/1.0"

load_dotenv()


def get_timeout_seconds() -> float:
    """Return the network timeout configured for enrichment lookups."""
    raw_value = os.getenv("INVESTIGATINATOR_TIMEOUT_SECONDS")
    if raw_value is None:
        return DEFAULT_TIMEOUT_SECONDS

    try:
        timeout = float(raw_value)
    except ValueError:
        return DEFAULT_TIMEOUT_SECONDS

    if timeout <= 0:
        return DEFAULT_TIMEOUT_SECONDS

    return timeout


def get_attack_stix_path() -> Path:
    """Return the local ATT&CK Enterprise STIX cache path."""
    return _knowledge_path(
        "INVESTIGATINATOR_ATTACK_STIX_PATH",
        "attack",
        "enterprise-attack.json",
    )


def get_attack_stix_url() -> str:
    """Return the ATT&CK Enterprise STIX download URL."""
    return os.getenv("INVESTIGATINATOR_ATTACK_STIX_URL", DEFAULT_ATTACK_STIX_URL).strip()


def get_cisa_kev_path() -> Path:
    """Return the local CISA KEV cache path."""
    return _knowledge_path(
        "INVESTIGATINATOR_CISA_KEV_PATH",
        "cisa",
        "known_exploited_vulnerabilities.json",
    )


def get_cisa_kev_url() -> str:
    """Return the CISA KEV download URL."""
    return os.getenv("INVESTIGATINATOR_CISA_KEV_URL", DEFAULT_CISA_KEV_URL).strip()


def get_lolbas_path() -> Path:
    """Return the local LOLBAS cache path."""
    return _knowledge_path("INVESTIGATINATOR_LOLBAS_PATH", "lolbas", "lolbas.json")


def get_lolbas_url() -> str:
    """Return the LOLBAS JSON download URL."""
    return os.getenv("INVESTIGATINATOR_LOLBAS_URL", DEFAULT_LOLBAS_URL).strip()


def get_d3fend_path() -> Path:
    """Return the local D3FEND cache path."""
    return _knowledge_path("INVESTIGATINATOR_D3FEND_PATH", "d3fend", "d3fend.json")


def get_d3fend_techniques_url() -> str:
    """Return the D3FEND defensive techniques download URL."""
    return os.getenv(
        "INVESTIGATINATOR_D3FEND_TECHNIQUES_URL",
        DEFAULT_D3FEND_TECHNIQUES_URL,
    ).strip()


def get_d3fend_tactics_url() -> str:
    """Return the D3FEND defensive tactics download URL."""
    return os.getenv(
        "INVESTIGATINATOR_D3FEND_TACTICS_URL",
        DEFAULT_D3FEND_TACTICS_URL,
    ).strip()


def get_d3fend_mappings_url() -> str:
    """Return the D3FEND inferred mappings download URL."""
    return os.getenv(
        "INVESTIGATINATOR_D3FEND_MAPPINGS_URL",
        DEFAULT_D3FEND_MAPPINGS_URL,
    ).strip()


def get_nvd_base_url() -> str:
    """Return the NVD CVE API base URL."""
    return os.getenv("INVESTIGATINATOR_NVD_BASE_URL", DEFAULT_NVD_BASE_URL).rstrip("/")


def get_api_key(name: str) -> str | None:
    """Return an API key from the environment when configured."""
    value = os.getenv(name)
    if value is None:
        return None

    cleaned_value = value.strip()
    return cleaned_value or None


def get_abuseipdb_base_url() -> str:
    """Return the AbuseIPDB API base URL."""
    return os.getenv("INVESTIGATINATOR_ABUSEIPDB_BASE_URL", DEFAULT_ABUSEIPDB_BASE_URL).rstrip("/")


def get_greynoise_base_url() -> str:
    """Return the GreyNoise Community API base URL."""
    return os.getenv("INVESTIGATINATOR_GREYNOISE_BASE_URL", DEFAULT_GREYNOISE_BASE_URL).rstrip("/")


def get_virustotal_base_url() -> str:
    """Return the VirusTotal API base URL."""
    return os.getenv(
        "INVESTIGATINATOR_VIRUSTOTAL_BASE_URL",
        DEFAULT_VIRUSTOTAL_BASE_URL,
    ).rstrip("/")


def get_shodan_base_url() -> str:
    """Return the Shodan API base URL."""
    return os.getenv("INVESTIGATINATOR_SHODAN_BASE_URL", DEFAULT_SHODAN_BASE_URL).rstrip("/")


def get_securitytrails_base_url() -> str:
    """Return the SecurityTrails API base URL."""
    return os.getenv(
        "INVESTIGATINATOR_SECURITYTRAILS_BASE_URL",
        DEFAULT_SECURITYTRAILS_BASE_URL,
    ).rstrip("/")


def get_ipgeolocation_base_url() -> str:
    """Return the IPGeolocation.io API base URL."""
    return os.getenv(
        "INVESTIGATINATOR_IPGEOLOCATION_BASE_URL",
        DEFAULT_IPGEOLOCATION_BASE_URL,
    ).rstrip("/")


def get_alienvault_base_url() -> str:
    """Return the AlienVault OTX API base URL."""
    return os.getenv("INVESTIGATINATOR_ALIENVAULT_BASE_URL", DEFAULT_ALIENVAULT_BASE_URL).rstrip(
        "/"
    )


def get_google_safebrowsing_base_url() -> str:
    """Return the Google Safe Browsing API base URL."""
    return os.getenv(
        "INVESTIGATINATOR_GOOGLE_SAFEBROWSING_BASE_URL",
        DEFAULT_GOOGLE_SAFEBROWSING_BASE_URL,
    ).rstrip("/")


def get_research_feeds() -> list[str]:
    """Return configured research RSS feed URLs."""
    raw_value = os.getenv("INVESTIGATINATOR_RESEARCH_FEEDS", DEFAULT_RESEARCH_FEEDS)
    return [item.strip() for item in raw_value.split(",") if item.strip()]


def get_research_user_agent() -> str:
    """Return the user agent used for public research fetches."""
    value = os.getenv("INVESTIGATINATOR_RESEARCH_USER_AGENT", DEFAULT_RESEARCH_USER_AGENT).strip()
    return value or DEFAULT_RESEARCH_USER_AGENT


def knowledge_update_command(source: str) -> str:
    """Return the console command for refreshing one knowledge snapshot."""
    return f"investigatinator knowledge-update {source}"


def _knowledge_path(env_name: str, *relative_parts: str) -> Path:
    raw_value = os.getenv(env_name)
    if raw_value:
        return Path(raw_value)
    return Path.home().joinpath(".investigatinator", "knowledge", *relative_parts)
