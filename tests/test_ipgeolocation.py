import httpx

from threatsyft.enrichment import ipgeolocation


def test_ipgeolocation_lookup_missing_api_key(monkeypatch) -> None:
    monkeypatch.delenv("IPGEOLOCATION_API_KEY", raising=False)

    result = ipgeolocation.ipgeolocation_lookup("8.8.8.8")

    assert result["ok"] is False
    assert result["error"]["code"] == "missing_api_key"


def test_ipgeolocation_lookup_rejects_invalid_ip() -> None:
    result = ipgeolocation.ipgeolocation_lookup("example.com")

    assert result["ok"] is False
    assert result["error"]["code"] == "invalid_input"


def test_ipgeolocation_lookup_success(monkeypatch) -> None:
    monkeypatch.setenv("IPGEOLOCATION_API_KEY", "test-key")

    def fake_get(url: str, params: dict[str, str], timeout: float) -> httpx.Response:
        assert url == "https://api.ipgeolocation.io/v3/ipgeo"
        assert params == {"apiKey": "test-key", "ip": "8.8.8.8"}
        assert timeout > 0
        return httpx.Response(
            200,
            request=httpx.Request("GET", url),
            json={
                "ip": "8.8.8.8",
                "location": {
                    "country_name": "United States",
                    "country_code2": "US",
                    "state_prov": "California",
                    "city": "Mountain View",
                    "zipcode": "94035",
                    "latitude": "37.40599",
                    "longitude": "-122.078514",
                },
                "time_zone": {"name": "America/Los_Angeles"},
                "asn": {"as_number": "AS15169", "organization": "Google LLC"},
                "company": {"name": "Google LLC"},
            },
        )

    monkeypatch.setattr(ipgeolocation.httpx, "get", fake_get)

    result = ipgeolocation.ipgeolocation_lookup("8.8.8.8")

    assert result["ok"] is True
    assert result["data"]["country_code"] == "US"
    assert result["data"]["region"] == "California"
    assert result["data"]["city"] == "Mountain View"
    assert result["data"]["asn"] == "AS15169"
    assert result["data"]["organization"] == "Google LLC"
    assert result["data"]["source"] == "ipgeolocation"


def test_ipgeolocation_lookup_authentication_error(monkeypatch) -> None:
    monkeypatch.setenv("IPGEOLOCATION_API_KEY", "bad-key")

    def fake_get(url: str, params: dict[str, str], timeout: float) -> httpx.Response:
        return httpx.Response(401, request=httpx.Request("GET", url))

    monkeypatch.setattr(ipgeolocation.httpx, "get", fake_get)

    result = ipgeolocation.ipgeolocation_lookup("8.8.8.8")

    assert result["ok"] is False
    assert result["error"]["code"] == "authentication_error"


def test_ipgeolocation_lookup_rate_limited(monkeypatch) -> None:
    monkeypatch.setenv("IPGEOLOCATION_API_KEY", "test-key")

    def fake_get(url: str, params: dict[str, str], timeout: float) -> httpx.Response:
        return httpx.Response(429, request=httpx.Request("GET", url))

    monkeypatch.setattr(ipgeolocation.httpx, "get", fake_get)

    result = ipgeolocation.ipgeolocation_lookup("8.8.8.8")

    assert result["ok"] is False
    assert result["error"]["code"] == "rate_limited"


def test_ipgeolocation_lookup_not_found(monkeypatch) -> None:
    monkeypatch.setenv("IPGEOLOCATION_API_KEY", "test-key")

    def fake_get(url: str, params: dict[str, str], timeout: float) -> httpx.Response:
        return httpx.Response(404, request=httpx.Request("GET", url))

    monkeypatch.setattr(ipgeolocation.httpx, "get", fake_get)

    result = ipgeolocation.ipgeolocation_lookup("8.8.8.8")

    assert result["ok"] is False
    assert result["error"]["code"] == "not_found"


def test_ipgeolocation_lookup_timeout(monkeypatch) -> None:
    monkeypatch.setenv("IPGEOLOCATION_API_KEY", "test-key")

    def fake_get(url: str, params: dict[str, str], timeout: float) -> httpx.Response:
        raise httpx.TimeoutException("timeout")

    monkeypatch.setattr(ipgeolocation.httpx, "get", fake_get)

    result = ipgeolocation.ipgeolocation_lookup("8.8.8.8")

    assert result["ok"] is False
    assert result["error"]["code"] == "timeout"


def test_ipgeolocation_lookup_malformed_response(monkeypatch) -> None:
    monkeypatch.setenv("IPGEOLOCATION_API_KEY", "test-key")

    def fake_get(url: str, params: dict[str, str], timeout: float) -> httpx.Response:
        return httpx.Response(200, request=httpx.Request("GET", url), content=b"not-json")

    monkeypatch.setattr(ipgeolocation.httpx, "get", fake_get)

    result = ipgeolocation.ipgeolocation_lookup("8.8.8.8")

    assert result["ok"] is False
    assert result["error"]["code"] == "parse_error"


def test_ipgeolocation_lookup_unexpected_json_shape(monkeypatch) -> None:
    monkeypatch.setenv("IPGEOLOCATION_API_KEY", "test-key")

    def fake_get(url: str, params: dict[str, str], timeout: float) -> httpx.Response:
        return httpx.Response(200, request=httpx.Request("GET", url), json=[])

    monkeypatch.setattr(ipgeolocation.httpx, "get", fake_get)

    result = ipgeolocation.ipgeolocation_lookup("8.8.8.8")

    assert result["ok"] is False
    assert result["error"]["code"] == "parse_error"
