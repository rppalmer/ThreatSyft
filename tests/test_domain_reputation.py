from typing import Any

from threatsyft.enrichment import domain_reputation


def test_domain_reputation_rejects_url() -> None:
    result = domain_reputation.domain_reputation("https://example.com")

    assert result["ok"] is False
    assert result["error"]["code"] == "invalid_input"


def test_domain_reputation_all_providers_benign(monkeypatch) -> None:
    monkeypatch.setattr(
        domain_reputation,
        "PROVIDERS",
        (
            ("dns", _provider_success({"records": {"A": ["93.184.216.34"], "MX": []}})),
            (
                "rdap",
                _provider_success({"status": ["active"], "entities": ["Example Registrar"]}),
            ),
            (
                "whois",
                _provider_success(
                    {
                        "registrar": "Example Registrar",
                        "creation_date": "1995-08-14T04:00:00+00:00",
                    }
                ),
            ),
            (
                "virustotal",
                _provider_success(
                    {
                        "verdict": "benign",
                        "reputation": 12,
                        "last_analysis_stats": {"malicious": 0, "suspicious": 0},
                    }
                ),
            ),
            (
                "securitytrails",
                _provider_success(
                    {"current_dns": {"a": [{"value": "93.184.216.34"}]}, "alexa_rank": 12345}
                ),
            ),
        ),
    )

    result = domain_reputation.domain_reputation("Example.COM.")

    assert result["ok"] is True
    assert result["data"]["domain"] == "example.com"
    assert result["data"]["overall_verdict"] == "benign"
    assert result["data"]["confidence"] == "high"
    assert result["data"]["provider_errors"] == []
    assert set(result["data"]["provider_results"]) == {
        "dns",
        "rdap",
        "whois",
        "virustotal",
        "securitytrails",
    }


def test_domain_reputation_virustotal_malicious_wins(monkeypatch) -> None:
    monkeypatch.setattr(
        domain_reputation,
        "PROVIDERS",
        (
            ("dns", _provider_success({"records": {"A": ["93.184.216.34"]}})),
            (
                "virustotal",
                _provider_success(
                    {
                        "verdict": "malicious",
                        "last_analysis_stats": {"malicious": 2, "suspicious": 1},
                    }
                ),
            ),
        ),
    )

    result = domain_reputation.domain_reputation("example.com")

    assert result["ok"] is True
    assert result["data"]["overall_verdict"] == "malicious"
    assert result["data"]["confidence"] == "medium"


def test_domain_reputation_partial_failure_still_succeeds(monkeypatch) -> None:
    monkeypatch.setattr(
        domain_reputation,
        "PROVIDERS",
        (
            ("dns", _provider_success({"records": {"A": ["93.184.216.34"]}})),
            ("virustotal", _provider_error("rate_limited", "VirusTotal rate limit was reached.")),
        ),
    )

    result = domain_reputation.domain_reputation("example.com")

    assert result["ok"] is True
    assert result["data"]["overall_verdict"] == "unknown"
    assert result["data"]["confidence"] == "low"
    assert result["data"]["provider_errors"] == [
        {
            "provider": "virustotal",
            "code": "rate_limited",
            "message": "VirusTotal rate limit was reached.",
        }
    ]


def test_domain_reputation_all_providers_fail_with_mocked_providers(monkeypatch) -> None:
    monkeypatch.setattr(
        domain_reputation,
        "PROVIDERS",
        (
            ("dns", _provider_error("network_error", "DNS failed.")),
            ("virustotal", _provider_error("missing_api_key", "Missing key.")),
        ),
    )

    result = domain_reputation.domain_reputation("example.com")

    assert result["ok"] is False
    assert result["error"]["code"] == "upstream_error"
    assert len(result["error"]["details"]["provider_errors"]) == 2


def _provider_success(data: dict[str, Any]):
    def provider(domain: str) -> dict[str, Any]:
        return {
            "ok": True,
            "tool": "fake_provider",
            "query": {"domain": domain},
            "data": {"domain": domain, **data},
            "error": None,
        }

    return provider


def _provider_error(code: str, message: str):
    def provider(domain: str) -> dict[str, Any]:
        return {
            "ok": False,
            "tool": "fake_provider",
            "query": {"domain": domain},
            "data": None,
            "error": {"code": code, "message": message, "details": None},
        }

    return provider
