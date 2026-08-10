import httpx

from threatsyft.enrichment import safebrowsing


def test_google_safebrowsing_check_url_missing_api_key(monkeypatch) -> None:
    monkeypatch.delenv("GOOGLE_SAFEBROWSING_API_KEY", raising=False)

    result = safebrowsing.google_safebrowsing_check_url("https://example.com")

    assert result["ok"] is False
    assert result["error"]["code"] == "missing_api_key"


def test_google_safebrowsing_check_url_rejects_domain_only() -> None:
    result = safebrowsing.google_safebrowsing_check_url("example.com")

    assert result["ok"] is False
    assert result["error"]["code"] == "invalid_input"


def test_google_safebrowsing_check_url_no_match(monkeypatch) -> None:
    monkeypatch.setenv("GOOGLE_SAFEBROWSING_API_KEY", "test-key")

    def fake_post(
        url: str,
        params: dict[str, str],
        json: dict[str, object],
        timeout: float,
    ) -> httpx.Response:
        assert url == "https://safebrowsing.googleapis.com/v4/threatMatches:find"
        assert params == {"key": "test-key"}
        assert json["client"] == {"clientId": "threatsyft", "clientVersion": "1.0"}
        assert timeout > 0
        return httpx.Response(200, request=httpx.Request("POST", url), json={})

    monkeypatch.setattr(safebrowsing.httpx, "post", fake_post)

    result = safebrowsing.google_safebrowsing_check_url("https://example.com")

    assert result["ok"] is True
    assert result["data"]["matched"] is False
    assert result["data"]["matches"] == []
    # `matched` is Google's answer. A second field restating it as a verdict
    # only invites reading "no match" as "safe", which the note denies.
    assert "verdict" not in result["data"]


def test_google_safebrowsing_check_url_match(monkeypatch) -> None:
    monkeypatch.setenv("GOOGLE_SAFEBROWSING_API_KEY", "test-key")

    def fake_post(
        url: str,
        params: dict[str, str],
        json: dict[str, object],
        timeout: float,
    ) -> httpx.Response:
        return httpx.Response(
            200,
            request=httpx.Request("POST", url),
            json={
                "matches": [
                    {
                        "threatType": "MALWARE",
                        "platformType": "ANY_PLATFORM",
                        "threatEntryType": "URL",
                        "threat": {"url": "https://bad.example"},
                        "cacheDuration": "300s",
                        "threatEntryMetadata": {
                            "entries": [{"key": "malware_threat_type", "value": "landing"}]
                        },
                    }
                ]
            },
        )

    monkeypatch.setattr(safebrowsing.httpx, "post", fake_post)

    result = safebrowsing.google_safebrowsing_check_url("https://bad.example")

    assert result["ok"] is True
    assert result["data"]["matched"] is True
    assert result["data"]["matches"][0]["threat_type"] == "MALWARE"
    assert result["data"]["matches"][0]["metadata"] == {"malware_threat_type": "landing"}
    assert "verdict" not in result["data"]


def test_google_safebrowsing_check_url_authentication_error(monkeypatch) -> None:
    monkeypatch.setenv("GOOGLE_SAFEBROWSING_API_KEY", "bad-key")

    def fake_post(
        url: str,
        params: dict[str, str],
        json: dict[str, object],
        timeout: float,
    ) -> httpx.Response:
        return httpx.Response(401, request=httpx.Request("POST", url))

    monkeypatch.setattr(safebrowsing.httpx, "post", fake_post)

    result = safebrowsing.google_safebrowsing_check_url("https://example.com")

    assert result["ok"] is False
    assert result["error"]["code"] == "authentication_error"


def test_google_safebrowsing_check_url_rate_limited(monkeypatch) -> None:
    monkeypatch.setenv("GOOGLE_SAFEBROWSING_API_KEY", "test-key")

    def fake_post(
        url: str,
        params: dict[str, str],
        json: dict[str, object],
        timeout: float,
    ) -> httpx.Response:
        return httpx.Response(429, request=httpx.Request("POST", url))

    monkeypatch.setattr(safebrowsing.httpx, "post", fake_post)

    result = safebrowsing.google_safebrowsing_check_url("https://example.com")

    assert result["ok"] is False
    assert result["error"]["code"] == "rate_limited"


def test_google_safebrowsing_check_url_timeout(monkeypatch) -> None:
    monkeypatch.setenv("GOOGLE_SAFEBROWSING_API_KEY", "test-key")

    def fake_post(
        url: str,
        params: dict[str, str],
        json: dict[str, object],
        timeout: float,
    ) -> httpx.Response:
        raise httpx.TimeoutException("timeout")

    monkeypatch.setattr(safebrowsing.httpx, "post", fake_post)

    result = safebrowsing.google_safebrowsing_check_url("https://example.com")

    assert result["ok"] is False
    assert result["error"]["code"] == "timeout"


def test_google_safebrowsing_check_url_malformed_response(monkeypatch) -> None:
    monkeypatch.setenv("GOOGLE_SAFEBROWSING_API_KEY", "test-key")

    def fake_post(
        url: str,
        params: dict[str, str],
        json: dict[str, object],
        timeout: float,
    ) -> httpx.Response:
        return httpx.Response(200, request=httpx.Request("POST", url), content=b"not-json")

    monkeypatch.setattr(safebrowsing.httpx, "post", fake_post)

    result = safebrowsing.google_safebrowsing_check_url("https://example.com")

    assert result["ok"] is False
    assert result["error"]["code"] == "parse_error"


def test_google_safebrowsing_check_url_unexpected_json_shape(monkeypatch) -> None:
    monkeypatch.setenv("GOOGLE_SAFEBROWSING_API_KEY", "test-key")

    def fake_post(
        url: str,
        params: dict[str, str],
        json: dict[str, object],
        timeout: float,
    ) -> httpx.Response:
        return httpx.Response(200, request=httpx.Request("POST", url), json=[])

    monkeypatch.setattr(safebrowsing.httpx, "post", fake_post)

    result = safebrowsing.google_safebrowsing_check_url("https://example.com")

    assert result["ok"] is False
    assert result["error"]["code"] == "parse_error"


def test_google_safebrowsing_check_url_unexpected_matches_shape(monkeypatch) -> None:
    monkeypatch.setenv("GOOGLE_SAFEBROWSING_API_KEY", "test-key")

    def fake_post(
        url: str,
        params: dict[str, str],
        json: dict[str, object],
        timeout: float,
    ) -> httpx.Response:
        return httpx.Response(200, request=httpx.Request("POST", url), json={"matches": {}})

    monkeypatch.setattr(safebrowsing.httpx, "post", fake_post)

    result = safebrowsing.google_safebrowsing_check_url("https://example.com")

    assert result["ok"] is False
    assert result["error"]["code"] == "parse_error"
