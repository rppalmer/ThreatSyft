import httpx

from investigatinator.enrichment import greynoise


def test_greynoise_ip_context_missing_api_key(monkeypatch) -> None:
    monkeypatch.delenv("GREYNOISE_API_KEY", raising=False)

    result = greynoise.greynoise_ip_context("8.8.8.8")

    assert result["ok"] is False
    assert result["error"]["code"] == "missing_api_key"


def test_greynoise_ip_context_rejects_invalid_ip() -> None:
    result = greynoise.greynoise_ip_context("example.com")

    assert result["ok"] is False
    assert result["error"]["code"] == "invalid_input"


def test_greynoise_ip_context_success(monkeypatch) -> None:
    monkeypatch.setenv("GREYNOISE_API_KEY", "test-key")

    def fake_get(url: str, headers: dict[str, str], timeout: float) -> httpx.Response:
        assert url == "https://api.greynoise.io/v3/community/8.8.8.8"
        assert headers["key"] == "test-key"
        assert timeout > 0
        return httpx.Response(
            200,
            request=httpx.Request("GET", url),
            json={
                "ip": "8.8.8.8",
                "noise": False,
                "riot": True,
                "classification": "benign",
                "name": "Google Public DNS",
                "link": "https://viz.greynoise.io/riot/8.8.8.8",
                "last_seen": "2021-03-26",
                "message": "Success",
            },
        )

    monkeypatch.setattr(greynoise.httpx, "get", fake_get)

    result = greynoise.greynoise_ip_context("8.8.8.8")

    assert result["ok"] is True
    assert result["data"]["riot"] is True
    assert result["data"]["verdict"] == "benign"


def test_greynoise_ip_context_not_observed(monkeypatch) -> None:
    monkeypatch.setenv("GREYNOISE_API_KEY", "test-key")

    def fake_get(url: str, headers: dict[str, str], timeout: float) -> httpx.Response:
        return httpx.Response(
            404,
            request=httpx.Request("GET", url),
            json={
                "ip": "8.8.4.4",
                "noise": False,
                "riot": False,
                "message": "IP not observed scanning the internet or contained in RIOT data set.",
            },
        )

    monkeypatch.setattr(greynoise.httpx, "get", fake_get)

    result = greynoise.greynoise_ip_context("8.8.4.4")

    assert result["ok"] is True
    assert result["data"]["noise"] is False
    assert result["data"]["verdict"] == "unknown"


def test_greynoise_ip_context_authentication_error(monkeypatch) -> None:
    monkeypatch.setenv("GREYNOISE_API_KEY", "bad-key")

    def fake_get(url: str, headers: dict[str, str], timeout: float) -> httpx.Response:
        return httpx.Response(401, request=httpx.Request("GET", url))

    monkeypatch.setattr(greynoise.httpx, "get", fake_get)

    result = greynoise.greynoise_ip_context("8.8.8.8")

    assert result["ok"] is False
    assert result["error"]["code"] == "authentication_error"


def test_greynoise_ip_context_rate_limited(monkeypatch) -> None:
    monkeypatch.setenv("GREYNOISE_API_KEY", "test-key")

    def fake_get(url: str, headers: dict[str, str], timeout: float) -> httpx.Response:
        return httpx.Response(429, request=httpx.Request("GET", url))

    monkeypatch.setattr(greynoise.httpx, "get", fake_get)

    result = greynoise.greynoise_ip_context("8.8.8.8")

    assert result["ok"] is False
    assert result["error"]["code"] == "rate_limited"


def test_greynoise_ip_context_timeout(monkeypatch) -> None:
    monkeypatch.setenv("GREYNOISE_API_KEY", "test-key")

    def fake_get(url: str, headers: dict[str, str], timeout: float) -> httpx.Response:
        raise httpx.TimeoutException("timeout")

    monkeypatch.setattr(greynoise.httpx, "get", fake_get)

    result = greynoise.greynoise_ip_context("8.8.8.8")

    assert result["ok"] is False
    assert result["error"]["code"] == "timeout"


def test_greynoise_ip_context_malformed_response(monkeypatch) -> None:
    monkeypatch.setenv("GREYNOISE_API_KEY", "test-key")

    def fake_get(url: str, headers: dict[str, str], timeout: float) -> httpx.Response:
        return httpx.Response(200, request=httpx.Request("GET", url), content=b"not-json")

    monkeypatch.setattr(greynoise.httpx, "get", fake_get)

    result = greynoise.greynoise_ip_context("8.8.8.8")

    assert result["ok"] is False
    assert result["error"]["code"] == "parse_error"
