from typing import Any

from investigatinator.enrichment import url_reputation


def test_url_reputation_rejects_domain_only() -> None:
    result = url_reputation.url_reputation("example.com")

    assert result["ok"] is False
    assert result["error"]["code"] == "invalid_input"


def test_url_reputation_benign_with_two_benign_providers(monkeypatch) -> None:
    monkeypatch.setattr(
        url_reputation,
        "PROVIDERS",
        (
            (
                "google_safebrowsing",
                _provider_success({"matched": False, "verdict": "benign"}),
            ),
            (
                "virustotal",
                _provider_success(
                    {
                        "verdict": "benign",
                        "reputation": 10,
                        "last_analysis_stats": {"malicious": 0, "suspicious": 0},
                    }
                ),
            ),
            ("alienvault", _provider_success({"pulse_count": 0, "verdict": "unknown"})),
        ),
    )

    result = url_reputation.url_reputation("https://example.com/")

    assert result["ok"] is True
    assert result["data"]["url"] == "https://example.com/"
    assert result["data"]["overall_verdict"] == "benign"
    assert result["data"]["confidence"] == "high"
    assert result["data"]["provider_errors"] == []


def test_url_reputation_malicious_wins(monkeypatch) -> None:
    monkeypatch.setattr(
        url_reputation,
        "PROVIDERS",
        (
            ("google_safebrowsing", _provider_success({"matched": True, "verdict": "malicious"})),
            (
                "virustotal",
                _provider_success(
                    {
                        "verdict": "benign",
                        "last_analysis_stats": {"malicious": 0, "suspicious": 0},
                    }
                ),
            ),
        ),
    )

    result = url_reputation.url_reputation("https://bad.example/")

    assert result["ok"] is True
    assert result["data"]["overall_verdict"] == "malicious"
    assert result["data"]["confidence"] == "medium"
    assert "Google Safe Browsing found" in result["data"]["key_signals"][0]


def test_url_reputation_partial_failure_still_succeeds(monkeypatch) -> None:
    monkeypatch.setattr(
        url_reputation,
        "PROVIDERS",
        (
            ("google_safebrowsing", _provider_success({"matched": False, "verdict": "benign"})),
            ("virustotal", _provider_error("rate_limited", "VirusTotal rate limit was reached.")),
        ),
    )

    result = url_reputation.url_reputation("https://example.com/")

    assert result["ok"] is True
    assert result["data"]["overall_verdict"] == "benign"
    assert result["data"]["confidence"] == "low"
    assert result["data"]["provider_errors"] == [
        {
            "provider": "virustotal",
            "code": "rate_limited",
            "message": "VirusTotal rate limit was reached.",
        }
    ]


def test_url_reputation_all_providers_fail(monkeypatch) -> None:
    monkeypatch.setattr(
        url_reputation,
        "PROVIDERS",
        (
            ("google_safebrowsing", _provider_error("network_error", "Safe Browsing failed.")),
            ("virustotal", _provider_error("missing_api_key", "Missing key.")),
        ),
    )

    result = url_reputation.url_reputation("https://example.com/")

    assert result["ok"] is False
    assert result["error"]["code"] == "upstream_error"
    assert len(result["error"]["details"]["provider_errors"]) == 2


def _provider_success(data: dict[str, Any]):
    def provider(url: str) -> dict[str, Any]:
        return {
            "ok": True,
            "tool": "fake_provider",
            "query": {"url": url},
            "data": {"url": url, **data},
            "error": None,
        }

    return provider


def _provider_error(code: str, message: str):
    def provider(url: str) -> dict[str, Any]:
        return {
            "ok": False,
            "tool": "fake_provider",
            "query": {"url": url},
            "data": None,
            "error": {"code": code, "message": message, "details": None},
        }

    return provider
