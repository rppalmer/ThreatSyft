import httpx

from threatsyft.enrichment import shodan


def test_shodan_host_lookup_missing_api_key(monkeypatch) -> None:
    monkeypatch.delenv("SHODAN_API_KEY", raising=False)

    result = shodan.shodan_host_lookup("8.8.8.8")

    assert result["ok"] is False
    assert result["error"]["code"] == "missing_api_key"


def test_shodan_host_lookup_rejects_invalid_ip() -> None:
    result = shodan.shodan_host_lookup("example.com")

    assert result["ok"] is False
    assert result["error"]["code"] == "invalid_input"


def test_shodan_host_lookup_success_with_vulnerabilities(monkeypatch) -> None:
    monkeypatch.setenv("SHODAN_API_KEY", "test-key")

    def fake_get(url: str, params: dict[str, object], timeout: float) -> httpx.Response:
        assert url == "https://api.shodan.io/shodan/host/8.8.8.8"
        assert params == {"key": "test-key", "history": "false", "minify": "false"}
        assert timeout > 0
        return httpx.Response(
            200,
            request=httpx.Request("GET", url),
            json={
                "ip_str": "8.8.8.8",
                "org": "Google LLC",
                "isp": "Google LLC",
                "asn": "AS15169",
                "country_code": "US",
                "country_name": "United States",
                "city": "Mountain View",
                "region_code": "CA",
                "hostnames": ["dns.google"],
                "domains": ["google.com"],
                "ports": [443, 53],
                "tags": ["cloud"],
                "last_update": "2026-04-12T14:30:00.000000",
                "vulns": {"CVE-2020-0001": {}, "CVE-2021-0002": {}},
                "data": [
                    {
                        "port": 443,
                        "transport": "tcp",
                        "product": "Google Frontend",
                        "version": None,
                        "timestamp": "2026-04-12T14:30:00.000000",
                        "_shodan": {"module": "https"},
                        "ssl": {},
                    },
                    {
                        "port": 53,
                        "transport": "udp",
                        "product": "DNS",
                        "version": "unknown",
                        "timestamp": "2026-04-12T14:20:00.000000",
                        "_shodan": {"module": "dns-udp"},
                    },
                ],
            },
        )

    monkeypatch.setattr(shodan.httpx, "get", fake_get)

    result = shodan.shodan_host_lookup("8.8.8.8")

    assert result["ok"] is True
    assert result["data"]["organization"] == "Google LLC"
    assert result["data"]["ports"] == [53, 443]
    assert result["data"]["services"][0]["port"] == 53
    assert result["data"]["services"][1]["ssl"] is True
    assert result["data"]["vulnerabilities"] == ["CVE-2020-0001", "CVE-2021-0002"]
    assert result["data"]["verdict"] == "suspicious"


def test_shodan_host_lookup_sparse_success(monkeypatch) -> None:
    monkeypatch.setenv("SHODAN_API_KEY", "test-key")

    def fake_get(url: str, params: dict[str, object], timeout: float) -> httpx.Response:
        return httpx.Response(
            200,
            request=httpx.Request("GET", url),
            json={"ip_str": "8.8.8.8", "data": [], "ports": []},
        )

    monkeypatch.setattr(shodan.httpx, "get", fake_get)

    result = shodan.shodan_host_lookup("8.8.8.8")

    assert result["ok"] is True
    assert result["data"]["services"] == []
    assert result["data"]["ports"] == []
    assert result["data"]["verdict"] == "unknown"


def test_shodan_host_lookup_observed_without_vulnerabilities(monkeypatch) -> None:
    monkeypatch.setenv("SHODAN_API_KEY", "test-key")

    def fake_get(url: str, params: dict[str, object], timeout: float) -> httpx.Response:
        return httpx.Response(
            200,
            request=httpx.Request("GET", url),
            json={
                "ip_str": "8.8.8.8",
                "data": [{"port": 443, "transport": "tcp"}],
            },
        )

    monkeypatch.setattr(shodan.httpx, "get", fake_get)

    result = shodan.shodan_host_lookup("8.8.8.8")

    assert result["ok"] is True
    assert result["data"]["verdict"] == "observed"


def test_shodan_host_lookup_authentication_error(monkeypatch) -> None:
    monkeypatch.setenv("SHODAN_API_KEY", "bad-key")

    def fake_get(url: str, params: dict[str, object], timeout: float) -> httpx.Response:
        return httpx.Response(401, request=httpx.Request("GET", url))

    monkeypatch.setattr(shodan.httpx, "get", fake_get)

    result = shodan.shodan_host_lookup("8.8.8.8")

    assert result["ok"] is False
    assert result["error"]["code"] == "authentication_error"


def test_shodan_host_lookup_rate_limited(monkeypatch) -> None:
    monkeypatch.setenv("SHODAN_API_KEY", "test-key")

    def fake_get(url: str, params: dict[str, object], timeout: float) -> httpx.Response:
        return httpx.Response(429, request=httpx.Request("GET", url))

    monkeypatch.setattr(shodan.httpx, "get", fake_get)

    result = shodan.shodan_host_lookup("8.8.8.8")

    assert result["ok"] is False
    assert result["error"]["code"] == "rate_limited"


def test_shodan_host_lookup_not_found(monkeypatch) -> None:
    monkeypatch.setenv("SHODAN_API_KEY", "test-key")

    def fake_get(url: str, params: dict[str, object], timeout: float) -> httpx.Response:
        return httpx.Response(404, request=httpx.Request("GET", url))

    monkeypatch.setattr(shodan.httpx, "get", fake_get)

    result = shodan.shodan_host_lookup("8.8.8.8")

    assert result["ok"] is False
    assert result["error"]["code"] == "not_found"


def test_shodan_host_lookup_timeout(monkeypatch) -> None:
    monkeypatch.setenv("SHODAN_API_KEY", "test-key")

    def fake_get(url: str, params: dict[str, object], timeout: float) -> httpx.Response:
        raise httpx.TimeoutException("timeout")

    monkeypatch.setattr(shodan.httpx, "get", fake_get)

    result = shodan.shodan_host_lookup("8.8.8.8")

    assert result["ok"] is False
    assert result["error"]["code"] == "timeout"


def test_shodan_host_lookup_malformed_response(monkeypatch) -> None:
    monkeypatch.setenv("SHODAN_API_KEY", "test-key")

    def fake_get(url: str, params: dict[str, object], timeout: float) -> httpx.Response:
        return httpx.Response(200, request=httpx.Request("GET", url), content=b"not-json")

    monkeypatch.setattr(shodan.httpx, "get", fake_get)

    result = shodan.shodan_host_lookup("8.8.8.8")

    assert result["ok"] is False
    assert result["error"]["code"] == "parse_error"


def test_shodan_host_lookup_unexpected_json_shape(monkeypatch) -> None:
    monkeypatch.setenv("SHODAN_API_KEY", "test-key")

    def fake_get(url: str, params: dict[str, object], timeout: float) -> httpx.Response:
        return httpx.Response(200, request=httpx.Request("GET", url), json=[])

    monkeypatch.setattr(shodan.httpx, "get", fake_get)

    result = shodan.shodan_host_lookup("8.8.8.8")

    assert result["ok"] is False
    assert result["error"]["code"] == "parse_error"
