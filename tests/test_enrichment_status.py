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
