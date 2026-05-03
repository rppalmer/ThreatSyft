import httpx

from investigatinator.research import feeds

RSS_FIXTURE = """<?xml version="1.0"?>
<rss version="2.0">
  <channel>
    <title>Example Security News</title>
    <item>
      <title>Ransomware crew targets edge devices</title>
      <link>https://example.com/ransomware-edge</link>
      <description>Researchers published indicators for a new ransomware campaign.</description>
      <pubDate>Tue, 14 Apr 2037 12:00:00 GMT</pubDate>
    </item>
    <item>
      <title>Patch Tuesday notes</title>
      <link>https://example.com/patches</link>
      <description>Several vendors released updates.</description>
      <pubDate>Mon, 13 Apr 2037 12:00:00 GMT</pubDate>
    </item>
  </channel>
</rss>
"""

ATOM_FIXTURE = """<?xml version="1.0"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>Atom Threat Feed</title>
  <entry>
    <title>Cloud intrusion write-up</title>
    <link href="https://example.com/cloud-intrusion" />
    <summary>Attackers used stolen tokens in a cloud environment.</summary>
    <updated>2037-04-14T13:00:00Z</updated>
  </entry>
</feed>
"""


def test_research_feed_search_rss_success(monkeypatch) -> None:
    monkeypatch.setenv("INVESTIGATINATOR_RESEARCH_FEEDS", "https://example.com/rss.xml")

    def fake_get(url: str, headers: dict[str, str], timeout: float) -> httpx.Response:
        assert url == "https://example.com/rss.xml"
        assert headers["User-Agent"]
        assert timeout > 0
        return httpx.Response(200, request=httpx.Request("GET", url), text=RSS_FIXTURE)

    monkeypatch.setattr(feeds.httpx, "get", fake_get)

    result = feeds.research_feed_search("ransomware", limit=10, days=365)

    assert result["ok"] is True
    assert result["data"]["result_count"] == 1
    assert result["data"]["entries"][0]["title"] == "Ransomware crew targets edge devices"
    assert result["data"]["entries"][0]["source"] == "Example Security News"


def test_research_feed_search_atom_success(monkeypatch) -> None:
    monkeypatch.setenv("INVESTIGATINATOR_RESEARCH_FEEDS", "https://example.com/atom.xml")

    def fake_get(url: str, headers: dict[str, str], timeout: float) -> httpx.Response:
        return httpx.Response(200, request=httpx.Request("GET", url), text=ATOM_FIXTURE)

    monkeypatch.setattr(feeds.httpx, "get", fake_get)

    result = feeds.research_feed_search("tokens", limit=10, days=365)

    assert result["ok"] is True
    assert result["data"]["entries"][0]["url"] == "https://example.com/cloud-intrusion"
    assert "tokens" in result["data"]["entries"][0]["matched_context"].lower()


def test_research_feed_search_empty_query_returns_latest(monkeypatch) -> None:
    monkeypatch.setenv("INVESTIGATINATOR_RESEARCH_FEEDS", "https://example.com/rss.xml")

    def fake_get(url: str, headers: dict[str, str], timeout: float) -> httpx.Response:
        return httpx.Response(200, request=httpx.Request("GET", url), text=RSS_FIXTURE)

    monkeypatch.setattr(feeds.httpx, "get", fake_get)

    result = feeds.research_feed_search("", limit=2, days=365)

    assert result["ok"] is True
    assert [entry["title"] for entry in result["data"]["entries"]] == [
        "Ransomware crew targets edge devices",
        "Patch Tuesday notes",
    ]


def test_research_feed_search_validates_limit_and_days() -> None:
    limit_result = feeds.research_feed_search("", limit=0, days=14)
    days_result = feeds.research_feed_search("", limit=10, days=0)

    assert limit_result["ok"] is False
    assert limit_result["error"]["code"] == "invalid_input"
    assert days_result["ok"] is False
    assert days_result["error"]["code"] == "invalid_input"


def test_research_feed_search_partial_feed_failure(monkeypatch) -> None:
    monkeypatch.setenv(
        "INVESTIGATINATOR_RESEARCH_FEEDS",
        "https://bad.example/rss.xml,https://good.example/rss.xml",
    )

    def fake_get(url: str, headers: dict[str, str], timeout: float) -> httpx.Response:
        if "bad.example" in url:
            raise httpx.TimeoutException("timeout")
        return httpx.Response(200, request=httpx.Request("GET", url), text=RSS_FIXTURE)

    monkeypatch.setattr(feeds.httpx, "get", fake_get)

    result = feeds.research_feed_search("ransomware", limit=10, days=365)

    assert result["ok"] is True
    assert result["data"]["source_error_count"] == 1
    assert result["data"]["source_errors"][0]["code"] == "timeout"
    assert result["data"]["result_count"] == 1


def test_research_feed_search_all_feeds_failing(monkeypatch) -> None:
    monkeypatch.setenv("INVESTIGATINATOR_RESEARCH_FEEDS", "https://bad.example/rss.xml")

    def fake_get(url: str, headers: dict[str, str], timeout: float) -> httpx.Response:
        return httpx.Response(500, request=httpx.Request("GET", url))

    monkeypatch.setattr(feeds.httpx, "get", fake_get)

    result = feeds.research_feed_search("ransomware", limit=10, days=365)

    assert result["ok"] is False
    assert result["error"]["code"] == "upstream_error"
    assert result["error"]["details"]["source_errors"][0]["code"] == "upstream_error"


def test_research_feed_search_malformed_xml(monkeypatch) -> None:
    monkeypatch.setenv("INVESTIGATINATOR_RESEARCH_FEEDS", "https://example.com/rss.xml")

    def fake_get(url: str, headers: dict[str, str], timeout: float) -> httpx.Response:
        return httpx.Response(200, request=httpx.Request("GET", url), text="<rss>")

    monkeypatch.setattr(feeds.httpx, "get", fake_get)

    result = feeds.research_feed_search("anything", limit=10, days=365)

    assert result["ok"] is False
    assert result["error"]["details"]["source_errors"][0]["code"] == "parse_error"


def test_research_feed_search_ignores_malformed_items(monkeypatch) -> None:
    monkeypatch.setenv("INVESTIGATINATOR_RESEARCH_FEEDS", "https://example.com/rss.xml")
    payload = (
        "<rss><channel><title>Feed</title><item><description>No title or link</description>"
        "</item></channel></rss>"
    )

    def fake_get(url: str, headers: dict[str, str], timeout: float) -> httpx.Response:
        return httpx.Response(200, request=httpx.Request("GET", url), text=payload)

    monkeypatch.setattr(feeds.httpx, "get", fake_get)

    result = feeds.research_feed_search("", limit=10, days=365)

    assert result["ok"] is True
    assert result["data"]["entries"] == []
