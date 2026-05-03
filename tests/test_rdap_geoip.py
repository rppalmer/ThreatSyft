import httpx

from investigatinator.enrichment import rdap


def test_rdap_lookup_success(monkeypatch) -> None:
    def fake_get(url: str, timeout: float, follow_redirects: bool) -> httpx.Response:
        assert url == "https://rdap.org/domain/example.com"
        assert follow_redirects is True
        request = httpx.Request("GET", url)
        return httpx.Response(
            200,
            request=request,
            json={
                "handle": "EXAMPLE-HANDLE",
                "ldhName": "example.com",
                "country": "US",
                "status": ["active"],
                "entities": [{"vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar"]]]}],
                "nameservers": [{"ldhName": "NS1.EXAMPLE.COM."}],
                "events": [{"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"}],
            },
        )

    monkeypatch.setattr(rdap.httpx, "get", fake_get)

    result = rdap.rdap_lookup("example.com")

    assert result["ok"] is True
    assert result["data"]["target_type"] == "domain"
    assert result["data"]["entities"] == ["Example Registrar"]
    assert result["data"]["nameservers"] == ["ns1.example.com"]


def test_rdap_lookup_not_found(monkeypatch) -> None:
    def fake_get(url: str, timeout: float, follow_redirects: bool) -> httpx.Response:
        assert follow_redirects is True
        return httpx.Response(404, request=httpx.Request("GET", url))

    monkeypatch.setattr(rdap.httpx, "get", fake_get)

    result = rdap.rdap_lookup("example.com")

    assert result["ok"] is False
    assert result["error"]["code"] == "not_found"


def test_rdap_lookup_timeout(monkeypatch) -> None:
    def fake_get(url: str, timeout: float, follow_redirects: bool) -> httpx.Response:
        assert follow_redirects is True
        raise httpx.TimeoutException("timeout")

    monkeypatch.setattr(rdap.httpx, "get", fake_get)

    result = rdap.rdap_lookup("example.com")

    assert result["ok"] is False
    assert result["error"]["code"] == "timeout"


def test_rdap_lookup_malformed_response(monkeypatch) -> None:
    def fake_get(url: str, timeout: float, follow_redirects: bool) -> httpx.Response:
        assert follow_redirects is True
        return httpx.Response(200, request=httpx.Request("GET", url), content=b"not json")

    monkeypatch.setattr(rdap.httpx, "get", fake_get)

    result = rdap.rdap_lookup("example.com")

    assert result["ok"] is False
    assert result["error"]["code"] == "parse_error"
