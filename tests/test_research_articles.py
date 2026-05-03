import httpx

from investigatinator.research import articles

ARTICLE_HTML = """
<html>
  <head>
    <title>Fallback title</title>
    <meta property="og:title" content="Campaign uses fake updates" />
    <meta name="description" content="Researchers found a campaign using fake updates." />
    <meta property="article:published_time" content="2037-04-14T12:00:00Z" />
  </head>
  <body>
    <script>http://ignore.example/script.js</script>
    <p>Researchers observed hxxp://malicious[.]example/payload in a phishing campaign.</p>
    <p>The infrastructure included 156.240.110.244 and bad-domain[.]example.</p>
    <p>Related references include CVE-2024-3400 and d41d8cd98f00b204e9800998ecf8427e.</p>
    <p>
      This paragraph is intentionally long enough to be treated as visible article text
      by the parser.
    </p>
  </body>
</html>
"""


def test_research_article_summary_extracts_metadata_and_snippets(monkeypatch) -> None:
    def fake_get(url: str, headers: dict[str, str], timeout: float) -> httpx.Response:
        assert url == "https://example.com/report"
        assert headers["User-Agent"]
        assert timeout > 0
        return httpx.Response(200, request=httpx.Request("GET", url), text=ARTICLE_HTML)

    monkeypatch.setattr(articles.httpx, "get", fake_get)

    result = articles.research_article_summary("https://example.com/report")

    assert result["ok"] is True
    assert result["data"]["title"] == "Campaign uses fake updates"
    assert result["data"]["description"] == "Researchers found a campaign using fake updates."
    assert result["data"]["published"] == "2037-04-14T12:00:00Z"
    assert result["data"]["snippet_count"] == 4
    assert result["data"]["full_text_returned"] is False
    assert "text" not in result["data"]


def test_research_article_summary_rejects_unsafe_urls() -> None:
    for url in [
        "ftp://example.com/report",
        "http://localhost/report",
        "http://127.0.0.1/report",
        "http://10.0.0.1/report",
    ]:
        result = articles.research_article_summary(url)
        assert result["ok"] is False
        assert result["error"]["code"] == "invalid_input"


def test_research_article_summary_timeout(monkeypatch) -> None:
    def fake_get(url: str, headers: dict[str, str], timeout: float) -> httpx.Response:
        raise httpx.TimeoutException("timeout")

    monkeypatch.setattr(articles.httpx, "get", fake_get)

    result = articles.research_article_summary("https://example.com/report")

    assert result["ok"] is False
    assert result["error"]["code"] == "timeout"


def test_research_article_iocs_extracts_normalized_iocs(monkeypatch) -> None:
    def fake_get(url: str, headers: dict[str, str], timeout: float) -> httpx.Response:
        return httpx.Response(200, request=httpx.Request("GET", url), text=ARTICLE_HTML)

    monkeypatch.setattr(articles.httpx, "get", fake_get)

    result = articles.research_article_iocs("https://example.com/report")

    assert result["ok"] is True
    iocs = result["data"]["iocs"]
    assert {"value": "156.240.110.244", "contexts": iocs["ips"][0]["contexts"]} in iocs["ips"]
    assert "http://malicious.example/payload" in {item["value"] for item in iocs["urls"]}
    assert "bad-domain.example" in {item["value"] for item in iocs["domains"]}
    assert "CVE-2024-3400" in {item["value"] for item in iocs["cves"]}
    assert "d41d8cd98f00b204e9800998ecf8427e" in {item["value"] for item in iocs["hashes"]}
    assert result["data"]["full_text_returned"] is False


def test_research_article_iocs_http_failure(monkeypatch) -> None:
    def fake_get(url: str, headers: dict[str, str], timeout: float) -> httpx.Response:
        return httpx.Response(404, request=httpx.Request("GET", url))

    monkeypatch.setattr(articles.httpx, "get", fake_get)

    result = articles.research_article_iocs("https://example.com/missing")

    assert result["ok"] is False
    assert result["error"]["code"] == "upstream_error"
    assert result["error"]["details"]["status_code"] == 404
