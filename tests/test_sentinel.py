import httpx

from threatsyft.enrichment import sentinel

PAYLOAD = {
    "ip": "185.220.101.34",
    "known": True,
    "verdict": "allow",
    "risk_score": 90,
    "signals": {"vpn": False, "proxied": False, "tor": True, "dch": False, "anon": True},
    "network": {"asn": 205100, "org": "F3 Netze", "country": "DE", "city": None},
    "latency_ms": 4,
}


def test_sentinel_ip_lookup_missing_api_key(monkeypatch) -> None:
    monkeypatch.delenv("SENTINEL_API_KEY", raising=False)

    result = sentinel.sentinel_ip_lookup("8.8.8.8")

    assert result["ok"] is False
    assert result["error"]["code"] == "missing_api_key"


def test_sentinel_ip_lookup_rejects_invalid_ip() -> None:
    result = sentinel.sentinel_ip_lookup("example.com")

    assert result["ok"] is False
    assert result["error"]["code"] == "invalid_input"


def test_sentinel_ip_lookup_success(monkeypatch) -> None:
    monkeypatch.setenv("SENTINEL_API_KEY", "sk_live_test")

    def fake_get(url: str, headers: dict[str, str], timeout: float) -> httpx.Response:
        assert url == "https://maskbreak.com/v1/lookup/185.220.101.34"
        assert headers["Authorization"] == "Bearer sk_live_test"
        assert timeout > 0
        return httpx.Response(200, request=httpx.Request("GET", url), json=PAYLOAD)

    monkeypatch.setattr(httpx, "get", fake_get)

    result = sentinel.sentinel_ip_lookup("185.220.101.34")

    assert result["ok"] is True
    assert result["data"]["signals"]["tor"] is True
    assert result["data"]["network"]["org"] == "F3 Netze"
    assert result["data"]["source"] == "sentinel"


def test_sentinel_passes_provider_judgement_through_unchanged(monkeypatch) -> None:
    """`verdict` and `risk_score` are Sentinel's, not ThreatSyft's.

    The project computes no verdict of its own; a provider that ships one has it
    carried under its own source name rather than dropped or reinterpreted.
    """
    monkeypatch.setenv("SENTINEL_API_KEY", "sk_live_test")
    monkeypatch.setattr(
        httpx,
        "get",
        lambda url, headers, timeout: httpx.Response(
            200, request=httpx.Request("GET", url), json=PAYLOAD
        ),
    )

    data = sentinel.sentinel_ip_lookup("185.220.101.34")["data"]

    assert data["verdict"] == "allow"
    assert data["risk_score"] == 90


def test_sentinel_ip_lookup_reports_an_unauthorized_key(monkeypatch) -> None:
    monkeypatch.setenv("SENTINEL_API_KEY", "sk_live_bad")
    monkeypatch.setattr(
        httpx,
        "get",
        lambda url, headers, timeout: httpx.Response(
            401, request=httpx.Request("GET", url), json={"error": "unauthorized"}
        ),
    )

    result = sentinel.sentinel_ip_lookup("8.8.8.8")

    assert result["ok"] is False
    assert result["error"]["code"] == "authentication_error"


def test_sentinel_ip_lookup_reports_rate_limiting(monkeypatch) -> None:
    monkeypatch.setenv("SENTINEL_API_KEY", "sk_live_test")
    monkeypatch.setattr(
        httpx,
        "get",
        lambda url, headers, timeout: httpx.Response(
            429, request=httpx.Request("GET", url), headers={"Retry-After": "60"}
        ),
    )

    result = sentinel.sentinel_ip_lookup("8.8.8.8")

    assert result["ok"] is False
    assert result["error"]["code"] == "rate_limited"
