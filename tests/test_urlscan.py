import httpx

from threatsyft.enrichment import urlscan

RESULT_ROW = {
    "_id": "01234567-89ab-cdef-0123-456789abcdef",
    "task": {
        "url": "http://login-example.test/verify",
        "time": "2026-08-01T10:00:00.000Z",
        "visibility": "public",
        "method": "manual",
        "source": "web",
        "uuid": "not-echoed",
    },
    "page": {
        "url": "https://phish.example/final",
        "domain": "phish.example",
        "ip": "203.0.113.10",
        "asn": "AS64496",
        "asnname": "EXAMPLE-AS",
        "country": "NL",
        "server": "nginx",
        "title": "Sign in to your account",
        "tlsIssuer": "R3",
        "mimeType": "text/html",
        "status": "200",
        "redirected": "noise",
    },
    "stats": {
        "uniqIPs": 4,
        "uniqCountries": 2,
        "dataLength": 51234,
        "requests": 31,
        "malicious": 1,
        "consoleMsgs": 9,
    },
    "brand": [{"name": "Example Bank"}],
    "result": "https://urlscan.io/api/v1/result/01234567-89ab-cdef-0123-456789abcdef/",
    "screenshot": "https://urlscan.io/screenshots/01234567.png",
}


def _respond(status: int, payload: dict | None = None, captured: dict | None = None):
    def fake_get(url: str, params: dict, headers: dict[str, str], timeout: float) -> httpx.Response:
        if captured is not None:
            captured["url"] = url
            captured["params"] = params
            captured["headers"] = headers
        return httpx.Response(status, request=httpx.Request("GET", url), json=payload or {})

    return fake_get


def test_urlscan_search_returns_page_identity(monkeypatch) -> None:
    monkeypatch.delenv("URLSCAN_API_KEY", raising=False)
    monkeypatch.setattr(urlscan.httpx, "get", _respond(200, {"results": [RESULT_ROW], "total": 37}))

    result = urlscan.urlscan_search("http://login-example.test/verify")

    assert result["ok"] is True
    data = result["data"]
    assert data["total"] == 37
    assert data["scan_count"] == 1

    scan = data["scans"][0]
    # The redirect destination, which is the field no other URL source produces.
    assert scan["page"]["url"] == "https://phish.example/final"
    assert scan["page"]["title"] == "Sign in to your account"
    assert scan["result_url"].endswith("/result/01234567-89ab-cdef-0123-456789abcdef/")


def test_urlscan_search_trims_to_declared_fields(monkeypatch) -> None:
    monkeypatch.delenv("URLSCAN_API_KEY", raising=False)
    monkeypatch.setattr(urlscan.httpx, "get", _respond(200, {"results": [RESULT_ROW]}))

    scan = urlscan.urlscan_search("http://login-example.test/verify")["data"]["scans"][0]

    # Bulk fields outside the declared subsets are dropped rather than passed on.
    assert "redirected" not in scan["page"]
    assert "consoleMsgs" not in scan["stats"]
    assert "uuid" not in scan["task"]


def test_urlscan_search_works_without_api_key(monkeypatch) -> None:
    """An absent key is a smaller quota, not a dead source."""
    monkeypatch.delenv("URLSCAN_API_KEY", raising=False)
    captured: dict = {}
    monkeypatch.setattr(urlscan.httpx, "get", _respond(200, {"results": []}, captured))

    result = urlscan.urlscan_search("https://example.test/a")

    assert result["ok"] is True
    assert result["data"]["authenticated"] is False
    assert "API-Key" not in captured["headers"]


def test_urlscan_search_sends_key_when_configured(monkeypatch) -> None:
    monkeypatch.setenv("URLSCAN_API_KEY", "secret-key")
    captured: dict = {}
    monkeypatch.setattr(urlscan.httpx, "get", _respond(200, {"results": []}, captured))

    result = urlscan.urlscan_search("https://example.test/a")

    assert result["data"]["authenticated"] is True
    assert captured["headers"]["API-Key"] == "secret-key"


def test_urlscan_search_escapes_quotes_in_the_query(monkeypatch) -> None:
    """A quote in the URL must not close the phrase and become query syntax."""
    monkeypatch.delenv("URLSCAN_API_KEY", raising=False)
    captured: dict = {}
    monkeypatch.setattr(urlscan.httpx, "get", _respond(200, {"results": []}, captured))

    urlscan.urlscan_search('https://example.test/a"b')

    query = captured["params"]["q"]
    assert query == 'page.url:"https://example.test/a\\"b"'


def test_urlscan_search_rejects_a_non_url(monkeypatch) -> None:
    result = urlscan.urlscan_search("example.test")

    assert result["ok"] is False
    assert result["error"]["code"] == "invalid_input"


def test_urlscan_search_maps_rate_limit(monkeypatch) -> None:
    monkeypatch.delenv("URLSCAN_API_KEY", raising=False)
    monkeypatch.setattr(urlscan.httpx, "get", _respond(429))

    result = urlscan.urlscan_search("https://example.test/a")

    assert result["ok"] is False
    assert result["error"]["code"] == "rate_limited"


def test_urlscan_search_survives_a_non_list_results_field(monkeypatch) -> None:
    monkeypatch.delenv("URLSCAN_API_KEY", raising=False)
    monkeypatch.setattr(urlscan.httpx, "get", _respond(200, {"results": None}))

    result = urlscan.urlscan_search("https://example.test/a")

    assert result["ok"] is True
    assert result["data"]["scans"] == []


def test_urlscan_module_cannot_submit_a_scan() -> None:
    """The submit endpoint is an active, publicly-visible action.

    Guarding it here rather than in review because the cost of a regression is
    tipping off an adversary, which nothing downstream would notice.
    """
    source = (urlscan.__file__,)
    with open(source[0], encoding="utf-8") as handle:
        body = handle.read()

    assert "httpx.post" not in body
    assert "/scan/" not in body
