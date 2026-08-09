"""Configuration helpers for ThreatSyft."""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import find_dotenv, load_dotenv

DEFAULT_TIMEOUT_SECONDS = 15.0
DEFAULT_ATTACK_STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)
DEFAULT_CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
DEFAULT_LOLBAS_URL = "https://lolbas-project.github.io/api/lolbas.json"
DEFAULT_NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_ABUSEIPDB_BASE_URL = "https://api.abuseipdb.com/api/v2"
DEFAULT_GREYNOISE_BASE_URL = "https://api.greynoise.io/v3/community"
DEFAULT_VIRUSTOTAL_BASE_URL = "https://www.virustotal.com/api/v3"
DEFAULT_SHODAN_BASE_URL = "https://api.shodan.io"
DEFAULT_SECURITYTRAILS_BASE_URL = "https://api.securitytrails.com/v1"
DEFAULT_IPGEOLOCATION_BASE_URL = "https://api.ipgeolocation.io"
DEFAULT_ALIENVAULT_BASE_URL = "https://otx.alienvault.com/api/v1"
DEFAULT_GOOGLE_SAFEBROWSING_BASE_URL = "https://safebrowsing.googleapis.com"


def _load_environment() -> None:
    """Load ``.env`` from the working directory and from a fixed home location.

    The previous ``load_dotenv()`` call found nothing when an MCP host launched
    the server, so every keyed tool reported a missing API key. A bare call
    resolves its search root by inspecting the *calling frame*, meaning it walks
    up from wherever this module happens to live: the repository for an editable
    install, site-packages otherwise. It looked like it worked because local
    development is the editable case. None of the documented host configurations
    set ``cwd``, and none of them install editable.

    Two explicit locations replace that guesswork. ``find_dotenv(usecwd=True)``
    really does search the working directory, so a project-local file keeps
    working during development, and ``~/.threatsyft/.env`` is a fixed path that
    resolves the same no matter where the host starts the process.

    ``load_dotenv`` never overwrites a variable that is already set, so
    precedence runs: real process environment, then a ``.env`` at or above the
    working directory, then ``~/.threatsyft/.env``.
    """
    working_directory_env = find_dotenv(usecwd=True)
    if working_directory_env:
        load_dotenv(working_directory_env)
    load_dotenv(Path.home().joinpath(".threatsyft", ".env"))


_load_environment()


def get_timeout_seconds() -> float:
    """Return the network timeout configured for enrichment lookups."""
    raw_value = os.getenv("THREATSYFT_TIMEOUT_SECONDS")
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
        "THREATSYFT_ATTACK_STIX_PATH",
        "attack",
        "enterprise-attack.json",
    )


def get_attack_stix_url() -> str:
    """Return the ATT&CK Enterprise STIX download URL."""
    return os.getenv("THREATSYFT_ATTACK_STIX_URL", DEFAULT_ATTACK_STIX_URL).strip()


def get_cisa_kev_path() -> Path:
    """Return the local CISA KEV cache path."""
    return _knowledge_path(
        "THREATSYFT_CISA_KEV_PATH",
        "cisa",
        "known_exploited_vulnerabilities.json",
    )


def get_cisa_kev_url() -> str:
    """Return the CISA KEV download URL."""
    return os.getenv("THREATSYFT_CISA_KEV_URL", DEFAULT_CISA_KEV_URL).strip()


def get_lolbas_path() -> Path:
    """Return the local LOLBAS cache path."""
    return _knowledge_path("THREATSYFT_LOLBAS_PATH", "lolbas", "lolbas.json")


def get_lolbas_url() -> str:
    """Return the LOLBAS JSON download URL."""
    return os.getenv("THREATSYFT_LOLBAS_URL", DEFAULT_LOLBAS_URL).strip()


def get_nvd_base_url() -> str:
    """Return the NVD CVE API base URL."""
    return os.getenv("THREATSYFT_NVD_BASE_URL", DEFAULT_NVD_BASE_URL).rstrip("/")


def get_api_key(name: str) -> str | None:
    """Return an API key from the environment when configured."""
    value = os.getenv(name)
    if value is None:
        return None

    cleaned_value = value.strip()
    return cleaned_value or None


def get_abuseipdb_base_url() -> str:
    """Return the AbuseIPDB API base URL."""
    return os.getenv("THREATSYFT_ABUSEIPDB_BASE_URL", DEFAULT_ABUSEIPDB_BASE_URL).rstrip("/")


def get_greynoise_base_url() -> str:
    """Return the GreyNoise Community API base URL."""
    return os.getenv("THREATSYFT_GREYNOISE_BASE_URL", DEFAULT_GREYNOISE_BASE_URL).rstrip("/")


def get_virustotal_base_url() -> str:
    """Return the VirusTotal API base URL."""
    return os.getenv(
        "THREATSYFT_VIRUSTOTAL_BASE_URL",
        DEFAULT_VIRUSTOTAL_BASE_URL,
    ).rstrip("/")


def get_shodan_base_url() -> str:
    """Return the Shodan API base URL."""
    return os.getenv("THREATSYFT_SHODAN_BASE_URL", DEFAULT_SHODAN_BASE_URL).rstrip("/")


def get_securitytrails_base_url() -> str:
    """Return the SecurityTrails API base URL."""
    return os.getenv(
        "THREATSYFT_SECURITYTRAILS_BASE_URL",
        DEFAULT_SECURITYTRAILS_BASE_URL,
    ).rstrip("/")


def get_ipgeolocation_base_url() -> str:
    """Return the IPGeolocation.io API base URL."""
    return os.getenv(
        "THREATSYFT_IPGEOLOCATION_BASE_URL",
        DEFAULT_IPGEOLOCATION_BASE_URL,
    ).rstrip("/")


def get_alienvault_base_url() -> str:
    """Return the AlienVault OTX API base URL."""
    return os.getenv("THREATSYFT_ALIENVAULT_BASE_URL", DEFAULT_ALIENVAULT_BASE_URL).rstrip("/")


def get_google_safebrowsing_base_url() -> str:
    """Return the Google Safe Browsing API base URL."""
    return os.getenv(
        "THREATSYFT_GOOGLE_SAFEBROWSING_BASE_URL",
        DEFAULT_GOOGLE_SAFEBROWSING_BASE_URL,
    ).rstrip("/")


def knowledge_update_command(source: str) -> str:
    """Return the console command for refreshing one knowledge snapshot."""
    return f"threatsyft knowledge-update {source}"


def _knowledge_path(env_name: str, *relative_parts: str) -> Path:
    raw_value = os.getenv(env_name)
    if raw_value:
        return Path(raw_value)
    return Path.home().joinpath(".threatsyft", "knowledge", *relative_parts)
