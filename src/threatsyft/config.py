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
DEFAULT_RDAP_BASE_URL = "https://rdap.org"
DEFAULT_ABUSEIPDB_BASE_URL = "https://api.abuseipdb.com/api/v2"
DEFAULT_GREYNOISE_BASE_URL = "https://api.greynoise.io/v3/community"
DEFAULT_VIRUSTOTAL_BASE_URL = "https://www.virustotal.com/api/v3"
DEFAULT_SHODAN_BASE_URL = "https://api.shodan.io"
DEFAULT_SECURITYTRAILS_BASE_URL = "https://api.securitytrails.com/v1"
DEFAULT_ALIENVAULT_BASE_URL = "https://otx.alienvault.com/api/v1"
DEFAULT_GOOGLE_SAFEBROWSING_BASE_URL = "https://safebrowsing.googleapis.com"
DEFAULT_SENTINEL_BASE_URL = "https://maskbreak.com/v1"
DEFAULT_CENSYS_BASE_URL = "https://api.platform.censys.io/v3"
DEFAULT_URLSCAN_BASE_URL = "https://urlscan.io/api/v1"
# No "www.": that host answers 301 to this one, and the API key travels in a
# custom header, which httpx does not strip when following a cross-host redirect
# the way it strips `auth=`. Chasing the redirect would hand the key to whatever
# the Location names, so the canonical host is used directly instead.
DEFAULT_HYBRID_ANALYSIS_BASE_URL = "https://hybrid-analysis.com/api/v2"
# The current download host. The older
# download.maxmind.com/app/geoip_download?license_key=... endpoint is deprecated
# and now fails; this one takes the account ID and license key as basic auth.
DEFAULT_MAXMIND_BASE_URL = "https://download.maxmind.com/geoip/databases"


def _load_environment() -> None:
    """Load ``.env`` from the working directory and from a fixed home location.

    Both locations are explicit on purpose. A bare ``load_dotenv()`` resolves
    its search root from the *calling frame*, so it walks up from wherever this
    module lives: the repository under an editable install, site-packages
    otherwise. That works during local development and silently finds nothing
    when an MCP host launches the server, because hosts set neither ``cwd`` nor
    an editable install, and every keyed tool then reports a missing API key.

    ``find_dotenv(usecwd=True)`` really does search the working directory, so a
    project-local file works during development, and ``~/.threatsyft/.env`` is a
    fixed path that resolves the same wherever the host starts the process.

    ``load_dotenv`` never overwrites an already-set variable, so precedence runs:
    process environment, then a ``.env`` at or above the working directory, then
    ``~/.threatsyft/.env``.
    """
    working_directory_env = find_dotenv(usecwd=True)
    if working_directory_env:
        load_dotenv(working_directory_env)
    load_dotenv(Path.home().joinpath(".threatsyft", ".env"))


_load_environment()


def _setting(name: str, default: str) -> str:
    """Return an environment override, treating blank as unset.

    ``os.getenv(name, default)`` returns "" for a variable that is set but
    empty, so the default never applies and the setting is silently blanked. A
    ``.env`` listing optional settings with empty values is an easy way to hit
    that, so blank is treated as absent here.
    """
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip() or default


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
    return _setting("THREATSYFT_ATTACK_STIX_URL", DEFAULT_ATTACK_STIX_URL).strip()


def get_cisa_kev_path() -> Path:
    """Return the local CISA KEV cache path."""
    return _knowledge_path(
        "THREATSYFT_CISA_KEV_PATH",
        "cisa",
        "known_exploited_vulnerabilities.json",
    )


def get_cisa_kev_url() -> str:
    """Return the CISA KEV download URL."""
    return _setting("THREATSYFT_CISA_KEV_URL", DEFAULT_CISA_KEV_URL).strip()


def get_lolbas_path() -> Path:
    """Return the local LOLBAS cache path."""
    return _knowledge_path("THREATSYFT_LOLBAS_PATH", "lolbas", "lolbas.json")


def get_lolbas_url() -> str:
    """Return the LOLBAS JSON download URL."""
    return _setting("THREATSYFT_LOLBAS_URL", DEFAULT_LOLBAS_URL).strip()


def get_nvd_base_url() -> str:
    """Return the NVD CVE API base URL."""
    return _setting("THREATSYFT_NVD_BASE_URL", DEFAULT_NVD_BASE_URL).rstrip("/")


def get_api_key(name: str) -> str | None:
    """Return an API key from the environment when configured."""
    value = os.getenv(name)
    if value is None:
        return None

    cleaned_value = value.strip()
    return cleaned_value or None


def get_rdap_base_url() -> str:
    """Return the RDAP bootstrap base URL."""
    return _setting("THREATSYFT_RDAP_BASE_URL", DEFAULT_RDAP_BASE_URL).rstrip("/")


def get_abuseipdb_base_url() -> str:
    """Return the AbuseIPDB API base URL."""
    return _setting("THREATSYFT_ABUSEIPDB_BASE_URL", DEFAULT_ABUSEIPDB_BASE_URL).rstrip("/")


def get_greynoise_base_url() -> str:
    """Return the GreyNoise Community API base URL."""
    return _setting("THREATSYFT_GREYNOISE_BASE_URL", DEFAULT_GREYNOISE_BASE_URL).rstrip("/")


def get_censys_base_url() -> str:
    """Return the Censys Platform API base URL."""
    return _setting("THREATSYFT_CENSYS_BASE_URL", DEFAULT_CENSYS_BASE_URL).rstrip("/")


def get_sentinel_base_url() -> str:
    """Return the Sentinel API base URL."""
    return _setting("THREATSYFT_SENTINEL_BASE_URL", DEFAULT_SENTINEL_BASE_URL).rstrip("/")


def get_virustotal_base_url() -> str:
    """Return the VirusTotal API base URL."""
    return _setting("THREATSYFT_VIRUSTOTAL_BASE_URL", DEFAULT_VIRUSTOTAL_BASE_URL).rstrip("/")


def get_shodan_base_url() -> str:
    """Return the Shodan API base URL."""
    return _setting("THREATSYFT_SHODAN_BASE_URL", DEFAULT_SHODAN_BASE_URL).rstrip("/")


def get_securitytrails_base_url() -> str:
    """Return the SecurityTrails API base URL."""
    return _setting("THREATSYFT_SECURITYTRAILS_BASE_URL", DEFAULT_SECURITYTRAILS_BASE_URL).rstrip(
        "/"
    )


def get_alienvault_base_url() -> str:
    """Return the AlienVault OTX API base URL."""
    return _setting("THREATSYFT_ALIENVAULT_BASE_URL", DEFAULT_ALIENVAULT_BASE_URL).rstrip("/")


def get_google_safebrowsing_base_url() -> str:
    """Return the Google Safe Browsing API base URL."""
    return _setting(
        "THREATSYFT_GOOGLE_SAFEBROWSING_BASE_URL", DEFAULT_GOOGLE_SAFEBROWSING_BASE_URL
    ).rstrip("/")


def get_urlscan_base_url() -> str:
    """Return the urlscan.io API base URL."""
    return _setting("THREATSYFT_URLSCAN_BASE_URL", DEFAULT_URLSCAN_BASE_URL).rstrip("/")


def get_hybrid_analysis_base_url() -> str:
    """Return the Hybrid Analysis (Falcon Sandbox) API base URL."""
    return _setting("THREATSYFT_HYBRID_ANALYSIS_BASE_URL", DEFAULT_HYBRID_ANALYSIS_BASE_URL).rstrip(
        "/"
    )


def get_maxmind_base_url() -> str:
    """Return the MaxMind database download base URL."""
    return _setting("THREATSYFT_MAXMIND_BASE_URL", DEFAULT_MAXMIND_BASE_URL).rstrip("/")


def get_maxmind_city_path() -> Path:
    """Return the local GeoLite2 City database path."""
    return _knowledge_path("THREATSYFT_MAXMIND_CITY_PATH", "maxmind", "GeoLite2-City.mmdb")


def get_maxmind_asn_path() -> Path:
    """Return the local GeoLite2 ASN database path."""
    return _knowledge_path("THREATSYFT_MAXMIND_ASN_PATH", "maxmind", "GeoLite2-ASN.mmdb")


def get_maxmind_account_id() -> str | None:
    """Return the MaxMind account ID used as the basic-auth username."""
    return get_api_key("MAXMIND_ACCOUNT_ID")


def knowledge_update_command(source: str) -> str:
    """Return the console command for refreshing one knowledge snapshot.

    This string is handed to a caller whose snapshot is missing, so it has to
    name a console script that exists. ``test_packaging`` asserts that pairing
    against ``pyproject``.
    """
    return f"threatsyft-update {source}"


def _knowledge_path(env_name: str, *relative_parts: str) -> Path:
    raw_value = os.getenv(env_name)
    if raw_value:
        return Path(raw_value)
    return Path.home().joinpath(".threatsyft", "knowledge", *relative_parts)
