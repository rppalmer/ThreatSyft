import httpx

from threatsyft.enrichment import abuseipdb


def test_abuseipdb_check_ip_missing_api_key(monkeypatch) -> None:
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)

    result = abuseipdb.abuseipdb_check_ip("8.8.8.8")

    assert result["ok"] is False
    assert result["error"]["code"] == "missing_api_key"


def test_abuseipdb_check_ip_rejects_invalid_ip() -> None:
    result = abuseipdb.abuseipdb_check_ip("example.com")

    assert result["ok"] is False
    assert result["error"]["code"] == "invalid_input"


def test_abuseipdb_check_ip_rejects_invalid_max_age(monkeypatch) -> None:
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-key")

    result = abuseipdb.abuseipdb_check_ip("8.8.8.8", max_age_days=366)

    assert result["ok"] is False
    assert result["error"]["code"] == "invalid_input"


def test_abuseipdb_check_ip_success(monkeypatch) -> None:
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-key")

    def fake_get(
        url: str,
        headers: dict[str, str],
        params: dict[str, object],
        timeout: float,
    ) -> httpx.Response:
        assert url == "https://api.abuseipdb.com/api/v2/check"
        assert headers["Key"] == "test-key"
        assert params == {"ipAddress": "8.8.8.8", "maxAgeInDays": 90}
        assert timeout > 0
        return httpx.Response(
            200,
            request=httpx.Request("GET", url),
            json={
                "data": {
                    "ipAddress": "8.8.8.8",
                    "isPublic": True,
                    "ipVersion": 4,
                    "isWhitelisted": False,
                    "abuseConfidenceScore": 0,
                    "countryCode": "US",
                    "countryName": "United States",
                    "usageType": "Content Delivery Network",
                    "isp": "Google LLC",
                    "domain": "google.com",
                    "isTor": False,
                    "totalReports": 0,
                    "numDistinctUsers": 0,
                    "lastReportedAt": None,
                }
            },
        )

    monkeypatch.setattr(abuseipdb.httpx, "get", fake_get)

    result = abuseipdb.abuseipdb_check_ip("8.8.8.8")

    assert result["ok"] is True
    assert result["data"]["abuse_confidence_score"] == 0
    assert result["data"]["verdict"] == "benign"


def test_abuseipdb_check_ip_whitelisted_zero_score_is_benign(monkeypatch) -> None:
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-key")

    def fake_get(
        url: str,
        headers: dict[str, str],
        params: dict[str, object],
        timeout: float,
    ) -> httpx.Response:
        return httpx.Response(
            200,
            request=httpx.Request("GET", url),
            json={
                "data": {
                    "ipAddress": "8.8.8.8",
                    "isPublic": True,
                    "ipVersion": 4,
                    "isWhitelisted": True,
                    "abuseConfidenceScore": 0,
                    "totalReports": 35,
                    "numDistinctUsers": 26,
                }
            },
        )

    monkeypatch.setattr(abuseipdb.httpx, "get", fake_get)

    result = abuseipdb.abuseipdb_check_ip("8.8.8.8")

    assert result["ok"] is True
    assert result["data"]["is_whitelisted"] is True
    assert result["data"]["verdict"] == "benign"


def test_abuseipdb_check_ip_authentication_error(monkeypatch) -> None:
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "bad-key")

    def fake_get(
        url: str,
        headers: dict[str, str],
        params: dict[str, object],
        timeout: float,
    ) -> httpx.Response:
        return httpx.Response(401, request=httpx.Request("GET", url))

    monkeypatch.setattr(abuseipdb.httpx, "get", fake_get)

    result = abuseipdb.abuseipdb_check_ip("8.8.8.8")

    assert result["ok"] is False
    assert result["error"]["code"] == "authentication_error"


def test_abuseipdb_check_ip_rate_limited(monkeypatch) -> None:
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-key")

    def fake_get(
        url: str,
        headers: dict[str, str],
        params: dict[str, object],
        timeout: float,
    ) -> httpx.Response:
        return httpx.Response(429, request=httpx.Request("GET", url))

    monkeypatch.setattr(abuseipdb.httpx, "get", fake_get)

    result = abuseipdb.abuseipdb_check_ip("8.8.8.8")

    assert result["ok"] is False
    assert result["error"]["code"] == "rate_limited"


def test_abuseipdb_check_ip_timeout(monkeypatch) -> None:
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-key")

    def fake_get(
        url: str,
        headers: dict[str, str],
        params: dict[str, object],
        timeout: float,
    ) -> httpx.Response:
        raise httpx.TimeoutException("timeout")

    monkeypatch.setattr(abuseipdb.httpx, "get", fake_get)

    result = abuseipdb.abuseipdb_check_ip("8.8.8.8")

    assert result["ok"] is False
    assert result["error"]["code"] == "timeout"


def test_abuseipdb_check_ip_malformed_response(monkeypatch) -> None:
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-key")

    def fake_get(
        url: str,
        headers: dict[str, str],
        params: dict[str, object],
        timeout: float,
    ) -> httpx.Response:
        return httpx.Response(200, request=httpx.Request("GET", url), content=b"not-json")

    monkeypatch.setattr(abuseipdb.httpx, "get", fake_get)

    result = abuseipdb.abuseipdb_check_ip("8.8.8.8")

    assert result["ok"] is False
    assert result["error"]["code"] == "parse_error"
