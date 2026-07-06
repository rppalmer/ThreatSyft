import httpx

from threatsyft.enrichment import securitytrails


def test_securitytrails_domain_lookup_missing_api_key(monkeypatch) -> None:
    monkeypatch.delenv("SECURITYTRAILS_API_KEY", raising=False)

    result = securitytrails.securitytrails_domain_lookup("example.com")

    assert result["ok"] is False
    assert result["error"]["code"] == "missing_api_key"


def test_securitytrails_domain_lookup_rejects_url() -> None:
    result = securitytrails.securitytrails_domain_lookup("https://example.com")

    assert result["ok"] is False
    assert result["error"]["code"] == "invalid_input"


def test_securitytrails_domain_lookup_success(monkeypatch) -> None:
    monkeypatch.setenv("SECURITYTRAILS_API_KEY", "test-key")

    def fake_get(url: str, headers: dict[str, str], timeout: float) -> httpx.Response:
        assert url == "https://api.securitytrails.com/v1/domain/example.com"
        assert headers["APIKEY"] == "test-key"
        assert timeout > 0
        return httpx.Response(
            200,
            request=httpx.Request("GET", url),
            json={
                "hostname": "example.com",
                "apex_domain": "example.com",
                "alexa_rank": 12345,
                "current_dns": {
                    "a": {
                        "values": [
                            {"ip": "93.184.216.34", "ttl": 300},
                        ]
                    },
                    "mx": {
                        "values": [
                            {"hostname": "mail.example.com", "priority": 10},
                        ]
                    },
                    "txt": {
                        "values": [
                            {"value": "v=spf1 -all"},
                        ]
                    },
                },
                "whois": {
                    "registrar": "Example Registrar",
                    "createdDate": "1995-08-14T04:00:00Z",
                    "updatedDate": "2026-01-16T18:26:50Z",
                    "expiresDate": "2026-08-13T04:00:00Z",
                },
            },
        )

    monkeypatch.setattr(securitytrails.httpx, "get", fake_get)

    result = securitytrails.securitytrails_domain_lookup("Example.COM.")

    assert result["ok"] is True
    assert result["data"]["domain"] == "example.com"
    assert result["data"]["hostname"] == "example.com"
    assert result["data"]["current_dns"]["a"] == [{"value": "93.184.216.34", "ttl": 300}]
    assert result["data"]["current_dns"]["mx"] == [{"value": "mail.example.com", "priority": 10}]
    assert result["data"]["whois"]["registrar"] == "Example Registrar"


def test_securitytrails_domain_lookup_authentication_error(monkeypatch) -> None:
    monkeypatch.setenv("SECURITYTRAILS_API_KEY", "bad-key")

    def fake_get(url: str, headers: dict[str, str], timeout: float) -> httpx.Response:
        return httpx.Response(401, request=httpx.Request("GET", url))

    monkeypatch.setattr(securitytrails.httpx, "get", fake_get)

    result = securitytrails.securitytrails_domain_lookup("example.com")

    assert result["ok"] is False
    assert result["error"]["code"] == "authentication_error"


def test_securitytrails_domain_lookup_rate_limited(monkeypatch) -> None:
    monkeypatch.setenv("SECURITYTRAILS_API_KEY", "test-key")

    def fake_get(url: str, headers: dict[str, str], timeout: float) -> httpx.Response:
        return httpx.Response(429, request=httpx.Request("GET", url))

    monkeypatch.setattr(securitytrails.httpx, "get", fake_get)

    result = securitytrails.securitytrails_domain_lookup("example.com")

    assert result["ok"] is False
    assert result["error"]["code"] == "rate_limited"


def test_securitytrails_domain_lookup_not_found(monkeypatch) -> None:
    monkeypatch.setenv("SECURITYTRAILS_API_KEY", "test-key")

    def fake_get(url: str, headers: dict[str, str], timeout: float) -> httpx.Response:
        return httpx.Response(404, request=httpx.Request("GET", url))

    monkeypatch.setattr(securitytrails.httpx, "get", fake_get)

    result = securitytrails.securitytrails_domain_lookup("example.com")

    assert result["ok"] is False
    assert result["error"]["code"] == "not_found"


def test_securitytrails_domain_lookup_timeout(monkeypatch) -> None:
    monkeypatch.setenv("SECURITYTRAILS_API_KEY", "test-key")

    def fake_get(url: str, headers: dict[str, str], timeout: float) -> httpx.Response:
        raise httpx.TimeoutException("timeout")

    monkeypatch.setattr(securitytrails.httpx, "get", fake_get)

    result = securitytrails.securitytrails_domain_lookup("example.com")

    assert result["ok"] is False
    assert result["error"]["code"] == "timeout"


def test_securitytrails_domain_lookup_malformed_response(monkeypatch) -> None:
    monkeypatch.setenv("SECURITYTRAILS_API_KEY", "test-key")

    def fake_get(url: str, headers: dict[str, str], timeout: float) -> httpx.Response:
        return httpx.Response(200, request=httpx.Request("GET", url), content=b"not-json")

    monkeypatch.setattr(securitytrails.httpx, "get", fake_get)

    result = securitytrails.securitytrails_domain_lookup("example.com")

    assert result["ok"] is False
    assert result["error"]["code"] == "parse_error"


def test_securitytrails_domain_lookup_unexpected_json_shape(monkeypatch) -> None:
    monkeypatch.setenv("SECURITYTRAILS_API_KEY", "test-key")

    def fake_get(url: str, headers: dict[str, str], timeout: float) -> httpx.Response:
        return httpx.Response(200, request=httpx.Request("GET", url), json=[])

    monkeypatch.setattr(securitytrails.httpx, "get", fake_get)

    result = securitytrails.securitytrails_domain_lookup("example.com")

    assert result["ok"] is False
    assert result["error"]["code"] == "parse_error"
