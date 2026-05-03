from typing import Any

from investigatinator.enrichment import ip_reputation


def test_ip_reputation_rejects_invalid_ip() -> None:
    result = ip_reputation.ip_reputation("example.com")

    assert result["ok"] is False
    assert result["error"]["code"] == "invalid_input"


def test_ip_reputation_all_providers_benign(monkeypatch) -> None:
    monkeypatch.setattr(
        ip_reputation,
        "PROVIDERS",
        (
            ("abuseipdb", _provider_success({"verdict": "benign", "abuse_confidence_score": 0})),
            ("greynoise", _provider_success({"verdict": "benign", "riot": True})),
            (
                "virustotal",
                _provider_success(
                    {
                        "verdict": "benign",
                        "last_analysis_stats": {"malicious": 0, "suspicious": 0},
                    }
                ),
            ),
            ("shodan", _provider_success({"verdict": "observed", "ports": [53, 443]})),
        ),
    )

    result = ip_reputation.ip_reputation("8.8.8.8")

    assert result["ok"] is True
    assert result["data"]["overall_verdict"] == "benign"
    assert result["data"]["confidence"] == "high"
    assert result["data"]["provider_errors"] == []
    assert set(result["data"]["provider_results"]) == {
        "abuseipdb",
        "greynoise",
        "virustotal",
        "shodan",
    }


def test_ip_reputation_provider_malicious_wins(monkeypatch) -> None:
    monkeypatch.setattr(
        ip_reputation,
        "PROVIDERS",
        (
            ("abuseipdb", _provider_success({"verdict": "benign"})),
            (
                "virustotal",
                _provider_success(
                    {
                        "verdict": "malicious",
                        "last_analysis_stats": {"malicious": 3, "suspicious": 0},
                    }
                ),
            ),
        ),
    )

    result = ip_reputation.ip_reputation("8.8.8.8")

    assert result["ok"] is True
    assert result["data"]["overall_verdict"] == "malicious"
    assert result["data"]["confidence"] == "medium"


def test_ip_reputation_shodan_vulnerability_is_suspicious(monkeypatch) -> None:
    monkeypatch.setattr(
        ip_reputation,
        "PROVIDERS",
        (
            ("abuseipdb", _provider_success({"verdict": "benign"})),
            ("shodan", _provider_success({"verdict": "observed", "vulnerabilities": ["CVE-1"]})),
        ),
    )

    result = ip_reputation.ip_reputation("8.8.8.8")

    assert result["ok"] is True
    assert result["data"]["overall_verdict"] == "suspicious"
    assert any("CVE-1" in signal for signal in result["data"]["key_signals"])


def test_ip_reputation_partial_failure_still_succeeds(monkeypatch) -> None:
    monkeypatch.setattr(
        ip_reputation,
        "PROVIDERS",
        (
            ("abuseipdb", _provider_success({"verdict": "benign", "abuse_confidence_score": 0})),
            ("shodan", _provider_error("rate_limited", "Shodan rate limit was reached.")),
        ),
    )

    result = ip_reputation.ip_reputation("8.8.8.8")

    assert result["ok"] is True
    assert result["data"]["overall_verdict"] == "benign"
    assert result["data"]["confidence"] == "low"
    assert result["data"]["provider_errors"] == [
        {
            "provider": "shodan",
            "code": "rate_limited",
            "message": "Shodan rate limit was reached.",
        }
    ]


def test_ip_reputation_all_providers_fail_with_mocked_providers(monkeypatch) -> None:
    monkeypatch.setattr(
        ip_reputation,
        "PROVIDERS",
        (
            ("abuseipdb", _provider_error("missing_api_key", "Missing key.")),
            ("greynoise", _provider_error("missing_api_key", "Missing key.")),
        ),
    )

    result = ip_reputation.ip_reputation("8.8.8.8")

    assert result["ok"] is False
    assert result["error"]["code"] == "upstream_error"
    assert len(result["error"]["details"]["provider_errors"]) == 2


def _provider_success(data: dict[str, Any]):
    def provider(ip: str) -> dict[str, Any]:
        return {
            "ok": True,
            "tool": "fake_provider",
            "query": {"ip": ip},
            "data": {"ip": ip, **data},
            "error": None,
        }

    return provider


def _provider_error(code: str, message: str):
    def provider(ip: str) -> dict[str, Any]:
        return {
            "ok": False,
            "tool": "fake_provider",
            "query": {"ip": ip},
            "data": None,
            "error": {"code": code, "message": message, "details": None},
        }

    return provider
