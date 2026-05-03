from investigatinator.research import briefs


def test_research_brief_invalid_url() -> None:
    result = briefs.research_brief("ftp://example.com/report")

    assert result["ok"] is False
    assert result["error"]["code"] == "invalid_input"


def test_research_brief_summary_and_iocs_success(monkeypatch) -> None:
    monkeypatch.setattr(briefs, "run_article_summary", _summary_success)
    monkeypatch.setattr(briefs, "run_article_iocs", _iocs_success)

    result = briefs.research_brief("https://example.com/report")

    assert result["ok"] is True
    assert result["tool"] == "research_brief"
    assert result["data"]["title"] == "Emerging phishing campaign"
    assert result["data"]["description"] == "Campaign context."
    assert result["data"]["published"] == "2037-04-14T12:00:00Z"
    assert result["data"]["snippets"] == ["Threat actors used hxxp links."]
    assert result["data"]["ioc_counts"]["urls"] == 1
    assert result["data"]["source_results"] == {
        "article_summary": "ok",
        "article_iocs": "ok",
    }
    assert result["data"]["source_errors"] == []
    assert result["data"]["full_text_returned"] is False
    assert "text" not in result["data"]
    assert result["data"]["workflow_guidance"]["brief_complete"] is True
    assert "research_article_iocs" in result["data"]["workflow_guidance"]["already_performed"]
    assert "research_brief" in result["data"]["workflow_guidance"]["do_not_repeat_for_same_url"]


def test_research_brief_summary_success_iocs_failure(monkeypatch) -> None:
    monkeypatch.setattr(briefs, "run_article_summary", _summary_success)
    monkeypatch.setattr(briefs, "run_article_iocs", _source_failure)

    result = briefs.research_brief("https://example.com/report")

    assert result["ok"] is True
    assert result["data"]["title"] == "Emerging phishing campaign"
    assert result["data"]["iocs"] == {
        "ips": [],
        "domains": [],
        "urls": [],
        "hashes": [],
        "cves": [],
    }
    assert result["data"]["source_results"] == {
        "article_summary": "ok",
        "article_iocs": "error",
    }
    assert result["data"]["source_errors"][0]["source"] == "article_iocs"


def test_research_brief_iocs_success_summary_failure(monkeypatch) -> None:
    monkeypatch.setattr(briefs, "run_article_summary", _source_failure)
    monkeypatch.setattr(briefs, "run_article_iocs", _iocs_success)

    result = briefs.research_brief("https://example.com/report")

    assert result["ok"] is True
    assert result["data"]["title"] == "Emerging phishing campaign"
    assert result["data"]["published"] == "2037-04-14T12:00:00Z"
    assert result["data"]["ioc_counts"]["cves"] == 1
    assert result["data"]["source_results"] == {
        "article_summary": "error",
        "article_iocs": "ok",
    }
    assert result["data"]["source_errors"][0]["source"] == "article_summary"


def test_research_brief_both_sources_fail(monkeypatch) -> None:
    monkeypatch.setattr(briefs, "run_article_summary", _source_failure)
    monkeypatch.setattr(briefs, "run_article_iocs", _source_failure)

    result = briefs.research_brief("https://example.com/report")

    assert result["ok"] is False
    assert result["error"]["code"] == "upstream_error"
    assert result["error"]["details"]["source_results"] == {
        "article_summary": "error",
        "article_iocs": "error",
    }


def test_research_brief_suggested_pivots(monkeypatch) -> None:
    monkeypatch.setattr(briefs, "run_article_summary", _summary_success)
    monkeypatch.setattr(briefs, "run_article_iocs", _iocs_success)

    result = briefs.research_brief("https://example.com/report")

    pivots = result["data"]["suggested_next_pivots"]
    assert {"url": "https://bad.example/login"} in [pivot["input"] for pivot in pivots]
    assert {"domain": "bad.example"} in [pivot["input"] for pivot in pivots]
    assert {"ip": "156.240.110.244"} in [pivot["input"] for pivot in pivots]
    assert {"file_hash": "d41d8cd98f00b204e9800998ecf8427e"} in [pivot["input"] for pivot in pivots]
    assert {"cve_id": "CVE-2024-3400"} in [pivot["input"] for pivot in pivots]
    assert {pivot["tool"] for pivot in pivots} == {
        "url_reputation",
        "domain_reputation",
        "ip_reputation",
        "file_reputation",
        "vulnerability_brief",
    }


def _summary_success(url: str) -> dict:
    return {
        "ok": True,
        "tool": "research_article_summary",
        "query": {"url": url},
        "data": {
            "live_network": True,
            "url": url,
            "title": "Emerging phishing campaign",
            "description": "Campaign context.",
            "published": "2037-04-14T12:00:00Z",
            "snippets": ["Threat actors used hxxp links."],
            "snippet_count": 1,
            "full_text_returned": False,
        },
        "error": None,
    }


def _iocs_success(url: str) -> dict:
    return {
        "ok": True,
        "tool": "research_article_iocs",
        "query": {"url": url},
        "data": {
            "live_network": True,
            "url": url,
            "title": "Emerging phishing campaign",
            "published": "2037-04-14T12:00:00Z",
            "ioc_counts": {
                "ips": 1,
                "domains": 1,
                "urls": 1,
                "hashes": 1,
                "cves": 1,
            },
            "iocs": {
                "ips": [{"value": "156.240.110.244", "contexts": ["ip context"]}],
                "domains": [{"value": "bad.example", "contexts": ["domain context"]}],
                "urls": [{"value": "https://bad.example/login", "contexts": ["url context"]}],
                "hashes": [
                    {
                        "value": "d41d8cd98f00b204e9800998ecf8427e",
                        "contexts": ["hash context"],
                    }
                ],
                "cves": [{"value": "CVE-2024-3400", "contexts": ["cve context"]}],
            },
            "full_text_returned": False,
        },
        "error": None,
    }


def _source_failure(url: str) -> dict:
    return {
        "ok": False,
        "tool": "research_article_summary",
        "query": {"url": url},
        "data": None,
        "error": {
            "code": "timeout",
            "message": "Article fetch timed out.",
            "details": None,
        },
    }
