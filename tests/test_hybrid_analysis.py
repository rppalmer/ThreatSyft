import httpx

from threatsyft.enrichment import hybrid_analysis

SHA256 = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"

REPORT = {
    "job_id": "abc123",
    "environment_id": 120,
    "environment_description": "Windows 7 64 bit",
    "submit_name": "invoice.doc",
    "type": "Rich Text Format",
    "size": 51234,
    "verdict": "malicious",
    "threat_score": 98,
    "threat_level": 2,
    "av_detect": 61,
    "vx_family": "Trojan.Emotet",
    "classification_tags": ["ransomware"],
    "tags": ["doc"],
    "total_processes": 7,
    "total_network_connections": 12,
    "total_signatures": 44,
    "mitre_attcks": [
        {
            "attck_id": "T1059.001",
            "tactic": "Execution",
            "technique": "PowerShell",
            "malicious_identifiers": ["bulk", "evidence", "noise"],
            "parent": {"deep": "object"},
        },
        {
            "attck_id": "T1055",
            "tactic": "Defense Evasion",
            "technique": "Process Injection",
        },
    ],
    "domains": [f"d{index}.example" for index in range(40)],
    "hosts": ["203.0.113.5"],
    "compromised_hosts": [],
    "processes": [{"huge": "tree"}],
    "extracted_files": [{"more": "bulk"}],
}


def _respond(status: int, payload=None, captured: dict | None = None):
    def fake_get(url: str, params: dict, headers: dict[str, str], timeout: float) -> httpx.Response:
        if captured is not None:
            captured["url"] = url
            captured["params"] = params
            captured["headers"] = headers
        response = httpx.Response(status, request=httpx.Request("GET", url), json=payload)
        return response

    return fake_get


def test_hash_lookup_missing_api_key(monkeypatch) -> None:
    monkeypatch.delenv("HYBRID_ANALYSIS_API_KEY", raising=False)

    result = hybrid_analysis.hybrid_analysis_hash_lookup(SHA256)

    assert result["ok"] is False
    assert result["error"]["code"] == "missing_api_key"


def test_hash_lookup_returns_behaviour_and_attack_ids(monkeypatch) -> None:
    monkeypatch.setenv("HYBRID_ANALYSIS_API_KEY", "k")
    monkeypatch.setattr(hybrid_analysis.httpx, "get", _respond(200, [REPORT]))

    result = hybrid_analysis.hybrid_analysis_hash_lookup(SHA256)

    assert result["ok"] is True
    data = result["data"]
    assert data["report_count"] == 1

    report = data["reports"][0]
    assert report["vx_family"] == "Trojan.Emotet"
    assert report["total_processes"] == 7
    # Provider's own verdict field, passed through rather than recomputed.
    assert report["verdict"] == "malicious"


def test_attack_ids_are_lifted_deduplicated_and_sorted(monkeypatch) -> None:
    """The IDs feed `lookup`, so a caller must not have to walk every report."""
    monkeypatch.setenv("HYBRID_ANALYSIS_API_KEY", "k")
    second = {**REPORT, "environment_id": 100}
    monkeypatch.setattr(hybrid_analysis.httpx, "get", _respond(200, [REPORT, second]))

    data = hybrid_analysis.hybrid_analysis_hash_lookup(SHA256)["data"]

    assert data["attack_technique_ids"] == ["T1055", "T1059.001"]


def test_attack_mappings_drop_their_evidence_lists(monkeypatch) -> None:
    monkeypatch.setenv("HYBRID_ANALYSIS_API_KEY", "k")
    monkeypatch.setattr(hybrid_analysis.httpx, "get", _respond(200, [REPORT]))

    mapping = hybrid_analysis.hybrid_analysis_hash_lookup(SHA256)["data"]["reports"][0][
        "mitre_attcks"
    ][0]

    assert mapping == {
        "attck_id": "T1059.001",
        "tactic": "Execution",
        "technique": "PowerShell",
    }


def test_network_lists_are_bounded_with_true_counts(monkeypatch) -> None:
    monkeypatch.setenv("HYBRID_ANALYSIS_API_KEY", "k")
    monkeypatch.setattr(hybrid_analysis.httpx, "get", _respond(200, [REPORT]))

    network = hybrid_analysis.hybrid_analysis_hash_lookup(SHA256)["data"]["reports"][0]["network"]

    assert len(network["domains"]) == hybrid_analysis.MAX_NETWORK_ENTRIES
    # The untruncated total, so a caller can see it has a slice.
    assert network["domains_count"] == 40
    # An empty observable list is omitted rather than reported as empty.
    assert "compromised_hosts" not in network


def test_bulk_report_fields_are_dropped(monkeypatch) -> None:
    monkeypatch.setenv("HYBRID_ANALYSIS_API_KEY", "k")
    monkeypatch.setattr(hybrid_analysis.httpx, "get", _respond(200, [REPORT]))

    report = hybrid_analysis.hybrid_analysis_hash_lookup(SHA256)["data"]["reports"][0]

    assert "processes" not in report
    assert "extracted_files" not in report


def test_required_headers_are_sent(monkeypatch) -> None:
    """Falcon Sandbox rejects requests without its fixed User-Agent."""
    monkeypatch.setenv("HYBRID_ANALYSIS_API_KEY", "secret")
    captured: dict = {}
    monkeypatch.setattr(hybrid_analysis.httpx, "get", _respond(200, [], captured))

    hybrid_analysis.hybrid_analysis_hash_lookup(SHA256)

    assert captured["headers"]["User-Agent"] == "Falcon Sandbox"
    assert captured["headers"]["api-key"] == "secret"
    assert captured["params"] == {"hash": SHA256}


def test_unknown_hash_is_zero_reports_not_an_error(monkeypatch) -> None:
    """No report is the common case, not a failure and not proof of safety."""
    monkeypatch.setenv("HYBRID_ANALYSIS_API_KEY", "k")
    monkeypatch.setattr(hybrid_analysis.httpx, "get", _respond(404, None))

    result = hybrid_analysis.hybrid_analysis_hash_lookup(SHA256)

    assert result["ok"] is True
    assert result["data"]["report_count"] == 0
    assert result["data"]["attack_technique_ids"] == []


def test_empty_array_is_zero_reports(monkeypatch) -> None:
    monkeypatch.setenv("HYBRID_ANALYSIS_API_KEY", "k")
    monkeypatch.setattr(hybrid_analysis.httpx, "get", _respond(200, []))

    result = hybrid_analysis.hybrid_analysis_hash_lookup(SHA256)

    assert result["ok"] is True
    assert result["data"]["report_count"] == 0


def test_rate_limit_is_mapped(monkeypatch) -> None:
    monkeypatch.setenv("HYBRID_ANALYSIS_API_KEY", "k")
    monkeypatch.setattr(hybrid_analysis.httpx, "get", _respond(429, {}))

    result = hybrid_analysis.hybrid_analysis_hash_lookup(SHA256)

    assert result["ok"] is False
    assert result["error"]["code"] == "rate_limited"


def test_object_response_is_a_parse_error(monkeypatch) -> None:
    monkeypatch.setenv("HYBRID_ANALYSIS_API_KEY", "k")
    monkeypatch.setattr(hybrid_analysis.httpx, "get", _respond(200, {"not": "an array"}))

    result = hybrid_analysis.hybrid_analysis_hash_lookup(SHA256)

    assert result["ok"] is False
    assert result["error"]["code"] == "parse_error"


def test_invalid_hash_is_rejected_before_any_request(monkeypatch) -> None:
    monkeypatch.setenv("HYBRID_ANALYSIS_API_KEY", "k")

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
