import httpx
import pytest

from threatsyft.enrichment import hybrid_analysis

SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
MD5 = "44d88612fea8a8f36de82e1278abb02f"

# The shape /search/hash really returns: an object with lean per-environment
# stubs, carrying no behaviour at all.
SEARCH_PAYLOAD = {
    "sha256s": [SHA256],
    "reports": [
        {
            "id": "err01",
            "environment_id": 140,
            "environment_description": "Windows 11 64 bit",
            "state": "ERROR",
            "error_type": "FILE_TYPE_BAD_ERROR",
            "verdict": None,
        },
        {
            "id": "job42",
            "environment_id": 110,
            "environment_description": "Windows 7 64 bit",
            "state": "SUCCESS",
            "verdict": "malicious",
        },
    ],
}

# The shape /report/{id}/summary really returns, where the behaviour lives.
SUMMARY_PAYLOAD = {
    "job_id": "job42",
    "environment_id": 110,
    "environment_description": "Windows 7 64 bit",
    "state": "SUCCESS",
    "verdict": "malicious",
    "threat_score": 100,
    "av_detect": 84,
    "vx_family": "Trojan.Emotet",
    "classification_tags": ["ransomware"],
    "size": 68,
    "total_processes": 7,
    "mitre_attcks": [
        {
            "attck_id": "T1204.002",
            "tactic": "Execution",
            "technique": "Malicious File",
            "attck_id_wiki": "https://attack.mitre.org/techniques/T1204/002",
            "malicious_identifiers": ["bulk", "evidence"],
            "informative_identifiers_count": 3,
        },
        {"attck_id": "T1027", "tactic": "Defense Evasion", "technique": "Obfuscated Files"},
        {"attck_id": "T1027", "tactic": "Defense Evasion", "technique": "Obfuscated Files"},
    ],
    "domains": [f"d{index}.example" for index in range(40)],
    "hosts": ["203.0.113.5"],
    "compromised_hosts": [],
    "processes": [{"huge": "tree"}, {"more": "tree"}],
    "signatures": [{"a": 1}, {"b": 2}, {"c": 3}],
    "extracted_files": [{"bulk": True}],
}


@pytest.fixture
def api_key(monkeypatch):
    monkeypatch.setenv("HYBRID_ANALYSIS_API_KEY", "secret")


def _wire(
    monkeypatch, *, search=None, summary=None, search_status=200, summary_status=200, captured=None
):
    """Route /search/hash and /report/.../summary to canned responses."""

    def fake_get(url, params=None, headers=None, timeout=None):
        if captured is not None:
            captured.setdefault("calls", []).append(
                {"url": url, "params": params, "headers": headers}
            )
        if "/search/hash" in url:
            body = SEARCH_PAYLOAD if search is None else search
            status = search_status
        else:
            body = SUMMARY_PAYLOAD if summary is None else summary
            status = summary_status
        return httpx.Response(status, request=httpx.Request("GET", url), json=body)

    monkeypatch.setattr(hybrid_analysis.httpx, "get", fake_get)


def test_missing_api_key(monkeypatch) -> None:
    monkeypatch.delenv("HYBRID_ANALYSIS_API_KEY", raising=False)

    result = hybrid_analysis.hybrid_analysis_hash_lookup(SHA256)

    assert result["ok"] is False
    assert result["error"]["code"] == "missing_api_key"


def test_lookup_returns_behaviour_from_the_summary(monkeypatch, api_key) -> None:
    _wire(monkeypatch)

    result = hybrid_analysis.hybrid_analysis_hash_lookup(MD5)

    assert result["ok"] is True
    data = result["data"]
    assert data["sha256"] == SHA256
    assert data["report_count"] == 2
    assert data["completed_report_count"] == 1

    report = data["report"]
    assert report["verdict"] == "malicious"
    assert report["threat_score"] == 100
    assert report["av_detect"] == 84
    assert report["vx_family"] == "Trojan.Emotet"


def test_attack_ids_are_lifted_deduplicated_and_sorted(monkeypatch, api_key) -> None:
    """The IDs feed `lookup`, so a caller must not have to walk the mappings."""
    _wire(monkeypatch)

    data = hybrid_analysis.hybrid_analysis_hash_lookup(SHA256)["data"]

    assert data["attack_technique_ids"] == ["T1027", "T1204.002"]


def test_attack_mappings_drop_their_evidence_lists(monkeypatch, api_key) -> None:
    _wire(monkeypatch)

    mapping = hybrid_analysis.hybrid_analysis_hash_lookup(SHA256)["data"]["report"]["mitre_attcks"][
        0
    ]

    assert mapping == {
        "attck_id": "T1204.002",
        "tactic": "Execution",
        "technique": "Malicious File",
    }


def test_the_summary_is_only_fetched_for_a_completed_run(monkeypatch, api_key) -> None:
    """An ERROR run has no behaviour, so it must not be the one fetched."""
    captured: dict = {}
    _wire(monkeypatch, captured=captured)

    hybrid_analysis.hybrid_analysis_hash_lookup(SHA256)

    urls = [call["url"] for call in captured["calls"]]
    assert len(urls) == 2
    assert urls[0].endswith("/search/hash")
    # job42 is the SUCCESS stub; err01 is the ERROR one listed before it.
    assert urls[1].endswith("/report/job42/summary")


def test_no_completed_run_still_returns_the_environments(monkeypatch, api_key) -> None:
    """Knowing a sample ran and failed everywhere is worth more than an error."""
    only_errors = {
        "sha256s": [SHA256],
        "reports": [{"id": "e1", "state": "ERROR", "environment_id": 140}],
    }
    captured: dict = {}
    _wire(monkeypatch, search=only_errors, captured=captured)

    result = hybrid_analysis.hybrid_analysis_hash_lookup(SHA256)

    assert result["ok"] is True
    data = result["data"]
    assert data["report_count"] == 1
    assert data["completed_report_count"] == 0
    assert data["report"] is None
    assert data["attack_technique_ids"] == []
    assert "No sandbox run completed" in data["report_unavailable"]
    # The second request is not worth spending on a run with no behaviour.
    assert len(captured["calls"]) == 1


def test_a_failed_summary_does_not_lose_the_environment_list(monkeypatch, api_key) -> None:
    _wire(monkeypatch, summary_status=500)

    data = hybrid_analysis.hybrid_analysis_hash_lookup(SHA256)["data"]

    assert data["report_count"] == 2
    assert data["environments"][1]["verdict"] == "malicious"
    assert data["report"] is None
    assert "upstream_error" in data["report_unavailable"]


def test_environment_list_is_bounded_with_the_true_total(monkeypatch, api_key) -> None:
    """EICAR really returns over 600 stubs."""
    many = {
        "sha256s": [SHA256],
        "reports": [{"id": f"j{i}", "state": "ERROR", "environment_id": i} for i in range(600)],
    }
    _wire(monkeypatch, search=many)

    data = hybrid_analysis.hybrid_analysis_hash_lookup(SHA256)["data"]

    assert data["report_count"] == 600
    assert len(data["environments"]) == hybrid_analysis.MAX_ENVIRONMENTS


def test_network_lists_are_bounded_with_true_counts(monkeypatch, api_key) -> None:
    _wire(monkeypatch)

    network = hybrid_analysis.hybrid_analysis_hash_lookup(SHA256)["data"]["report"]["network"]

    assert len(network["domains"]) == hybrid_analysis.MAX_NETWORK_ENTRIES
    assert network["domains_count"] == 40
    # An empty observable list is omitted rather than reported as empty.
    assert "compromised_hosts" not in network


def test_bulk_lists_become_counts(monkeypatch, api_key) -> None:
    _wire(monkeypatch)

    report = hybrid_analysis.hybrid_analysis_hash_lookup(SHA256)["data"]["report"]

    assert report["processes_count"] == 2
    assert report["signatures_count"] == 3
    assert "processes" not in report
    assert "signatures" not in report


def test_required_headers_are_sent(monkeypatch, api_key) -> None:
    """Falcon Sandbox rejects requests without its fixed User-Agent."""
    captured: dict = {}
    _wire(monkeypatch, captured=captured)

    hybrid_analysis.hybrid_analysis_hash_lookup(SHA256)

    headers = captured["calls"][0]["headers"]
    assert headers["User-Agent"] == "Falcon Sandbox"
    assert headers["api-key"] == "secret"
    assert captured["calls"][0]["params"] == {"hash": SHA256}


def test_unknown_hash_is_zero_reports_not_an_error(monkeypatch, api_key) -> None:
    """No report is the common case, not a failure and not proof of safety."""
    _wire(monkeypatch, search={}, search_status=404)

    result = hybrid_analysis.hybrid_analysis_hash_lookup(SHA256)

    assert result["ok"] is True
    assert result["data"]["report_count"] == 0
    assert result["data"]["attack_technique_ids"] == []
    # Nothing was unavailable: there was simply nothing to fetch.
    assert "report_unavailable" not in result["data"]


def test_rate_limit_is_mapped(monkeypatch, api_key) -> None:
    _wire(monkeypatch, search_status=429)

    result = hybrid_analysis.hybrid_analysis_hash_lookup(SHA256)

    assert result["ok"] is False
    assert result["error"]["code"] == "rate_limited"


def test_array_response_is_a_parse_error(monkeypatch, api_key) -> None:
    """The endpoint returns an object; a bare array is not the contract."""
    _wire(monkeypatch, search=[{"not": "an object"}])

    result = hybrid_analysis.hybrid_analysis_hash_lookup(SHA256)

    assert result["ok"] is False
    assert result["error"]["code"] == "parse_error"


def test_invalid_hash_is_rejected_before_any_request(monkeypatch, api_key) -> None:
    def explode(*args, **kwargs):
        raise AssertionError("no request should be made for an invalid hash")

    monkeypatch.setattr(hybrid_analysis.httpx, "get", explode)

    result = hybrid_analysis.hybrid_analysis_hash_lookup("not-a-hash")

    assert result["ok"] is False
    assert result["error"]["code"] == "invalid_input"


def test_module_cannot_submit_a_sample() -> None:
    """Submission detonates a sample; enrich must never take that action."""
    with open(hybrid_analysis.__file__, encoding="utf-8") as handle:
        body = handle.read()

    assert "httpx.post" not in body
    assert "/submit" not in body


def test_module_never_follows_redirects() -> None:
    """The api-key rides in a custom header, which httpx does not strip on a
    cross-host redirect the way it strips `auth=`."""
    with open(hybrid_analysis.__file__, encoding="utf-8") as handle:
        body = handle.read()

    assert "follow_redirects=True" not in body
