from threatsyft.enrichment.enrich import DISPATCH
from threatsyft.enrichment.providers import PROVIDERS
from threatsyft.enrichment.status import enrichment_status


def test_enrichment_status_reports_key_presence_without_secret_values(monkeypatch) -> None:
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "super-secret")
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)

    result = enrichment_status()

    assert result["ok"] is True
    assert result["data"]["local_only"] is True
    assert result["data"]["network_checked"] is False
    assert result["data"]["secret_values_returned"] is False
    assert result["data"]["providers"]["virustotal"]["api_keys"] == {"VIRUSTOTAL_API_KEY": True}
    assert result["data"]["providers"]["abuseipdb"]["api_keys"] == {"ABUSEIPDB_API_KEY": False}
    assert "super-secret" not in str(result)


def test_enrichment_status_no_longer_reports_fact_packs(monkeypatch) -> None:
    """The aggregate tools are gone, so the block describing their key requirements is too."""
    result = enrichment_status()

    assert "fact_packs" not in result["data"]


def test_enrichment_status_key_lists_cover_every_provider(monkeypatch) -> None:
    """Configured/missing are computed across all providers, not a fact-pack subset."""
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "set")
    monkeypatch.delenv("SHODAN_API_KEY", raising=False)

    data = enrichment_status()["data"]
    every_key = {name for metadata in PROVIDERS.values() for name in metadata["api_keys"]}

    assert set(data["configured_api_keys"]) | set(data["missing_api_keys"]) == every_key
    assert not set(data["configured_api_keys"]) & set(data["missing_api_keys"])
    assert "VIRUSTOTAL_API_KEY" in data["configured_api_keys"]
    assert "SHODAN_API_KEY" in data["missing_api_keys"]


def test_every_keyed_enrich_source_has_provider_metadata() -> None:
    """A source named in DISPATCH must be resolvable to its API-key status.

    enrich() reports failures per source; enrichment_status reports keys per
    provider. If the two used different names for the same provider, a caller
    could not tell a missing key from a broken provider.
    """
    keyless = {"dns", "rdap", "whois"}
    named = {name for sources in DISPATCH.values() for name, _ in sources}

    assert named - keyless <= set(PROVIDERS)
