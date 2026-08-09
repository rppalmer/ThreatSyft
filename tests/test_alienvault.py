import httpx

from threatsyft.enrichment import alienvault


def test_alienvault_indicator_lookup_missing_api_key(monkeypatch) -> None:
    monkeypatch.delenv("ALIENVAULT_API_KEY", raising=False)

    result = alienvault.alienvault_indicator_lookup("8.8.8.8")

    assert result["ok"] is False
    assert result["error"]["code"] == "missing_api_key"


def test_alienvault_indicator_lookup_rejects_invalid_indicator() -> None:
    result = alienvault.alienvault_indicator_lookup("not a useful indicator")

    assert result["ok"] is False
    assert result["error"]["code"] == "invalid_input"


def test_alienvault_indicator_lookup_success(monkeypatch) -> None:
    monkeypatch.setenv("ALIENVAULT_API_KEY", "test-key")

    def fake_get(url: str, headers: dict[str, str], timeout: float) -> httpx.Response:
        assert url == "https://otx.alienvault.com/api/v1/indicators/IPv4/8.8.8.8/general"
        assert headers["X-OTX-API-KEY"] == "test-key"
        assert timeout > 0
        return httpx.Response(
            200,
            request=httpx.Request("GET", url),
            json={
                "reputation": 0,
                "sections": ["general", "malware"],
                "validation": {"source": "otx"},
                "pulse_info": {
                    "count": 2,
                    "pulses": [
                        {
                            "id": "pulse-1",
                            "name": "Example pulse",
                            "created": "2026-04-01T00:00:00",
                            "modified": "2026-04-02T00:00:00",
                            "TLP": "white",
                            "tags": ["botnet", "dns"],
                        }
                    ],
                },
            },
        )

    monkeypatch.setattr(alienvault.httpx, "get", fake_get)

    result = alienvault.alienvault_indicator_lookup("8.8.8.8")

    assert result["ok"] is True
    assert result["data"]["indicator_type"] == "IPv4"
    assert result["data"]["pulse_count"] == 2
    assert result["data"]["pulses"][0]["name"] == "Example pulse"
    assert result["data"]["pulses"][0]["tags"] == ["botnet", "dns"]
    assert result["data"]["sections"] == ["general", "malware"]
    assert result["data"]["verdict"] == "suspicious"


def test_alienvault_indicator_lookup_url_indicator_is_quoted(monkeypatch) -> None:
    monkeypatch.setenv("ALIENVAULT_API_KEY", "test-key")

    def fake_get(url: str, headers: dict[str, str], timeout: float) -> httpx.Response:
        assert (
            url == "https://otx.alienvault.com/api/v1/indicators/url/"
            "https%3A%2F%2Fexample.com%2Fpath/general"
        )
        return httpx.Response(
            200,
            request=httpx.Request("GET", url),
            json={"pulse_info": {"count": 0, "pulses": []}},
        )

    monkeypatch.setattr(alienvault.httpx, "get", fake_get)

    result = alienvault.alienvault_indicator_lookup("https://example.com/path")

    assert result["ok"] is True
    assert result["data"]["indicator_type"] == "url"
    assert result["data"]["verdict"] == "unknown"


def test_alienvault_indicator_lookup_hash_indicator(monkeypatch) -> None:
    monkeypatch.setenv("ALIENVAULT_API_KEY", "test-key")

    def fake_get(url: str, headers: dict[str, str], timeout: float) -> httpx.Response:
        assert url.endswith("/indicators/file/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/general")
        return httpx.Response(
            200,
            request=httpx.Request("GET", url),
            json={"pulse_info": {"count": 0, "pulses": []}},
        )

    monkeypatch.setattr(alienvault.httpx, "get", fake_get)

    result = alienvault.alienvault_indicator_lookup("A" * 32)

    assert result["ok"] is True
    assert result["query"]["indicator_type"] == "file"
    assert result["query"]["indicator"] == "a" * 32


def test_alienvault_indicator_lookup_authentication_error(monkeypatch) -> None:
    monkeypatch.setenv("ALIENVAULT_API_KEY", "bad-key")

    def fake_get(url: str, headers: dict[str, str], timeout: float) -> httpx.Response:
        return httpx.Response(403, request=httpx.Request("GET", url))

    monkeypatch.setattr(alienvault.httpx, "get", fake_get)

    result = alienvault.alienvault_indicator_lookup("example.com")

    assert result["ok"] is False
    assert result["error"]["code"] == "authentication_error"


def test_alienvault_indicator_lookup_rate_limited(monkeypatch) -> None:
    monkeypatch.setenv("ALIENVAULT_API_KEY", "test-key")

    def fake_get(url: str, headers: dict[str, str], timeout: float) -> httpx.Response:
        return httpx.Response(429, request=httpx.Request("GET", url))

    monkeypatch.setattr(alienvault.httpx, "get", fake_get)

    result = alienvault.alienvault_indicator_lookup("example.com")

    assert result["ok"] is False
    assert result["error"]["code"] == "rate_limited"


def test_alienvault_indicator_lookup_not_found(monkeypatch) -> None:
    monkeypatch.setenv("ALIENVAULT_API_KEY", "test-key")

    def fake_get(url: str, headers: dict[str, str], timeout: float) -> httpx.Response:
        return httpx.Response(404, request=httpx.Request("GET", url))

    monkeypatch.setattr(alienvault.httpx, "get", fake_get)

    result = alienvault.alienvault_indicator_lookup("example.com")

    assert result["ok"] is False
    assert result["error"]["code"] == "not_found"


def test_alienvault_indicator_lookup_timeout(monkeypatch) -> None:
    monkeypatch.setenv("ALIENVAULT_API_KEY", "test-key")

    def fake_get(url: str, headers: dict[str, str], timeout: float) -> httpx.Response:
        raise httpx.TimeoutException("timeout")

    monkeypatch.setattr(alienvault.httpx, "get", fake_get)

    result = alienvault.alienvault_indicator_lookup("example.com")

    assert result["ok"] is False
    assert result["error"]["code"] == "timeout"


def test_alienvault_indicator_lookup_malformed_response(monkeypatch) -> None:
    monkeypatch.setenv("ALIENVAULT_API_KEY", "test-key")

    def fake_get(url: str, headers: dict[str, str], timeout: float) -> httpx.Response:
        return httpx.Response(200, request=httpx.Request("GET", url), content=b"not-json")

    monkeypatch.setattr(alienvault.httpx, "get", fake_get)

    result = alienvault.alienvault_indicator_lookup("example.com")

    assert result["ok"] is False
    assert result["error"]["code"] == "parse_error"


def test_alienvault_indicator_lookup_unexpected_json_shape(monkeypatch) -> None:
    monkeypatch.setenv("ALIENVAULT_API_KEY", "test-key")

    def fake_get(url: str, headers: dict[str, str], timeout: float) -> httpx.Response:
        return httpx.Response(200, request=httpx.Request("GET", url), json=[])

    monkeypatch.setattr(alienvault.httpx, "get", fake_get)

    result = alienvault.alienvault_indicator_lookup("example.com")

    assert result["ok"] is False
    assert result["error"]["code"] == "parse_error"


def test_pulse_tags_are_capped_with_the_total_reported(monkeypatch) -> None:
    """OTX tags are community-submitted and unbounded; some pulses carry hundreds."""
    monkeypatch.setenv("ALIENVAULT_API_KEY", "test-key")
    payload = {
        "pulse_info": {
            "count": 1,
            "pulses": [
                {
                    "id": "p1",
                    "name": "Noisy pulse",
                    "tags": [f"tag-{index:03d}" for index in range(250)],
                }
            ],
        }
    }
    monkeypatch.setattr(
        alienvault.httpx,
        "get",
        lambda *a, **k: httpx.Response(
            200, request=httpx.Request("GET", "https://otx.test"), json=payload
        ),
    )

    pulse = alienvault.alienvault_indicator_lookup("example.com")["data"]["pulses"][0]

    assert len(pulse["tags"]) == alienvault.MAX_TAGS_PER_PULSE
    assert pulse["tag_count"] == 250


def test_pulses_are_capped(monkeypatch) -> None:
    monkeypatch.setenv("ALIENVAULT_API_KEY", "test-key")
    payload = {
        "pulse_info": {
            "count": 99,
            "pulses": [{"id": f"p{index}", "name": "x"} for index in range(40)],
        }
    }
    monkeypatch.setattr(
        alienvault.httpx,
        "get",
        lambda *a, **k: httpx.Response(
            200, request=httpx.Request("GET", "https://otx.test"), json=payload
        ),
    )

    data = alienvault.alienvault_indicator_lookup("example.com")["data"]

    assert len(data["pulses"]) == alienvault.MAX_PULSES
    assert data["pulse_count"] == 99, "the true total must survive the cap"
