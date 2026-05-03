from typing import Any

from investigatinator.enrichment import file_reputation


def test_file_reputation_rejects_invalid_hash() -> None:
    result = file_reputation.file_reputation("not-a-hash")

    assert result["ok"] is False
    assert result["error"]["code"] == "invalid_input"


def test_file_reputation_malicious_wins(monkeypatch) -> None:
    monkeypatch.setattr(
        file_reputation,
        "PROVIDERS",
        (
            (
                "virustotal",
                _provider_success(
                    {
                        "verdict": "malicious",
                        "meaningful_name": "bad.exe",
                        "last_analysis_stats": {"malicious": 12, "suspicious": 1},
                    }
                ),
            ),
            ("alienvault", _provider_success({"pulse_count": 2, "verdict": "unknown"})),
        ),
    )

    result = file_reputation.file_reputation("A" * 64)

    assert result["ok"] is True
    assert result["data"]["hash"] == "a" * 64
    assert result["data"]["hash_type"] == "sha256"
    assert result["data"]["overall_verdict"] == "malicious"
    assert result["data"]["confidence"] == "high"
    assert "VirusTotal meaningful file name is bad.exe." in result["data"]["key_signals"]
    assert "AlienVault OTX pulse count is 2." in result["data"]["key_signals"]


def test_file_reputation_partial_failure_still_succeeds(monkeypatch) -> None:
    monkeypatch.setattr(
        file_reputation,
        "PROVIDERS",
        (
            ("virustotal", _provider_error("rate_limited", "VirusTotal rate limit was reached.")),
            ("alienvault", _provider_success({"pulse_count": 0, "verdict": "unknown"})),
        ),
    )

    result = file_reputation.file_reputation("d41d8cd98f00b204e9800998ecf8427e")

    assert result["ok"] is True
    assert result["data"]["hash_type"] == "md5"
    assert result["data"]["overall_verdict"] == "unknown"
    assert result["data"]["provider_errors"] == [
        {
            "provider": "virustotal",
            "code": "rate_limited",
            "message": "VirusTotal rate limit was reached.",
        }
    ]


def test_file_reputation_all_providers_fail(monkeypatch) -> None:
    monkeypatch.setattr(
        file_reputation,
        "PROVIDERS",
        (
            ("virustotal", _provider_error("missing_api_key", "Missing key.")),
            ("alienvault", _provider_error("network_error", "OTX failed.")),
        ),
    )

    result = file_reputation.file_reputation("A" * 40)

    assert result["ok"] is False
    assert result["error"]["code"] == "upstream_error"
    assert len(result["error"]["details"]["provider_errors"]) == 2


def _provider_success(data: dict[str, Any]):
    def provider(file_hash: str) -> dict[str, Any]:
        return {
            "ok": True,
            "tool": "fake_provider",
            "query": {"hash": file_hash},
            "data": {"hash": file_hash, **data},
            "error": None,
        }

    return provider


def _provider_error(code: str, message: str):
    def provider(file_hash: str) -> dict[str, Any]:
        return {
            "ok": False,
            "tool": "fake_provider",
            "query": {"hash": file_hash},
            "data": None,
            "error": {"code": code, "message": message, "details": None},
        }

    return provider
