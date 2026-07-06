from threatsyft.knowledge import briefs


def test_technique_brief_success(monkeypatch) -> None:
    monkeypatch.setattr(briefs, "run_attack_lookup", _attack_success)
    monkeypatch.setattr(briefs, "run_defense_mapping", _defense_success)
    monkeypatch.setattr(briefs, "run_lolbas_search", _lolbas_success)

    result = briefs.technique_brief("t1059")

    assert result["ok"] is True
    assert result["tool"] == "technique_brief"
    assert result["query"]["technique_id"] == "T1059"
    assert result["data"]["technique"]["name"] == "Command and Scripting Interpreter"
    assert result["data"]["defensive_mappings"][0]["name"] == "Process Analysis"
    assert result["data"]["related_lolbas"][0]["name"] == "Certutil.exe"
    assert result["data"]["source_results"] == {
        "attack": "ok",
        "d3fend": "ok",
        "lolbas": "ok",
    }
    assert result["data"]["source_errors"] == []


def test_technique_brief_invalid_id() -> None:
    result = briefs.technique_brief("1059")

    assert result["ok"] is False
    assert result["error"]["code"] == "invalid_input"


def test_technique_brief_primary_attack_failure(monkeypatch) -> None:
    monkeypatch.setattr(briefs, "run_attack_lookup", _attack_error)

    result = briefs.technique_brief("T1234")

    assert result["ok"] is False
    assert result["error"]["code"] == "not_found"


def test_technique_brief_allows_optional_source_not_found(monkeypatch) -> None:
    monkeypatch.setattr(briefs, "run_attack_lookup", _attack_success)
    monkeypatch.setattr(briefs, "run_defense_mapping", _not_found)
    monkeypatch.setattr(briefs, "run_lolbas_search", _not_found)

    result = briefs.technique_brief("T1059")

    assert result["ok"] is True
    assert result["data"]["defensive_mappings"] == []
    assert result["data"]["related_lolbas"] == []
    assert result["data"]["source_results"] == {
        "attack": "ok",
        "d3fend": "not_found",
        "lolbas": "not_found",
    }


def test_technique_brief_records_optional_source_errors(monkeypatch) -> None:
    monkeypatch.setattr(briefs, "run_attack_lookup", _attack_success)
    monkeypatch.setattr(briefs, "run_defense_mapping", _optional_error)
    monkeypatch.setattr(briefs, "run_lolbas_search", _lolbas_success)

    result = briefs.technique_brief("T1059")

    assert result["ok"] is True
    assert result["data"]["source_results"]["d3fend"] == "error"
    assert result["data"]["source_errors"][0]["source"] == "d3fend"
    assert result["data"]["source_errors"][0]["code"] == "parse_error"


def test_vulnerability_brief_invalid_cve() -> None:
    result = briefs.vulnerability_brief("2024-3400")

    assert result["ok"] is False
    assert result["error"]["code"] == "invalid_input"


def test_vulnerability_brief_nvd_and_kev_success(monkeypatch) -> None:
    monkeypatch.setattr(briefs, "run_cve_lookup", _cve_success)
    monkeypatch.setattr(briefs, "run_kev_lookup", _kev_success)

    result = briefs.vulnerability_brief("cve-2024-3400")

    assert result["ok"] is True
    assert result["tool"] == "vulnerability_brief"
    assert result["query"]["cve_id"] == "CVE-2024-3400"
    assert result["data"]["cve_id"] == "CVE-2024-3400"
    assert result["data"]["nvd"]["cvss"]["base_severity"] == "CRITICAL"
    assert result["data"]["kev"]["vulnerability_name"] == "PAN-OS Command Injection"
    assert result["data"]["in_kev"] is True
    assert result["data"]["source_results"] == {"nvd": "ok", "kev": "ok"}
    assert result["data"]["source_errors"] == []


def test_vulnerability_brief_nvd_success_kev_not_found(monkeypatch) -> None:
    monkeypatch.setattr(briefs, "run_cve_lookup", _cve_success)
    monkeypatch.setattr(briefs, "run_kev_lookup", _not_found)

    result = briefs.vulnerability_brief("CVE-2024-3400")

    assert result["ok"] is True
    assert result["data"]["nvd"]["cve_id"] == "CVE-2024-3400"
    assert result["data"]["kev"] is None
    assert result["data"]["in_kev"] is False
    assert result["data"]["source_results"] == {"nvd": "ok", "kev": "not_found"}


def test_vulnerability_brief_nvd_failure_kev_success(monkeypatch) -> None:
    monkeypatch.setattr(briefs, "run_cve_lookup", _optional_error)
    monkeypatch.setattr(briefs, "run_kev_lookup", _kev_success)

    result = briefs.vulnerability_brief("CVE-2024-3400")

    assert result["ok"] is True
    assert result["data"]["nvd"] is None
    assert result["data"]["kev"]["vulnerability_name"] == "PAN-OS Command Injection"
    assert result["data"]["in_kev"] is True
    assert result["data"]["source_results"] == {"nvd": "error", "kev": "ok"}
    assert result["data"]["source_errors"][0]["source"] == "nvd"


def test_vulnerability_brief_both_sources_fail(monkeypatch) -> None:
    monkeypatch.setattr(briefs, "run_cve_lookup", _optional_error)
    monkeypatch.setattr(briefs, "run_kev_lookup", _not_found)

    result = briefs.vulnerability_brief("CVE-1999-0001")

    assert result["ok"] is False
    assert result["error"]["code"] == "upstream_error"
    assert result["error"]["details"]["source_results"] == {
        "nvd": "error",
        "kev": "not_found",
    }


def test_vulnerability_brief_records_rate_limit(monkeypatch) -> None:
    monkeypatch.setattr(briefs, "run_cve_lookup", _rate_limited)
    monkeypatch.setattr(briefs, "run_kev_lookup", _kev_success)

    result = briefs.vulnerability_brief("CVE-2024-3400")

    assert result["ok"] is True
    assert result["data"]["source_errors"][0]["code"] == "rate_limited"


def _attack_success(technique_id: str) -> dict:
    return {
        "ok": True,
        "tool": "attack_technique_lookup",
        "query": {"technique_id": technique_id},
        "data": {
            "technique_id": "T1059",
            "name": "Command and Scripting Interpreter",
            "tactics": [{"name": "Execution", "short_name": "execution"}],
        },
        "error": None,
    }


def _defense_success(technique_id: str) -> dict:
    return {
        "ok": True,
        "tool": "attack_defense_mapping",
        "query": {"technique_id": technique_id},
        "data": {
            "defensive_techniques": [
                {"d3fend_id": "D3-PA", "name": "Process Analysis"},
            ]
        },
        "error": None,
    }


def _lolbas_success(query: str, limit: int = 10) -> dict:
    return {
        "ok": True,
        "tool": "lolbas_search",
        "query": {"query": query, "limit": limit},
        "data": {"matches": [{"name": "Certutil.exe", "mitre_ids": ["T1059"]}]},
        "error": None,
    }


def _attack_error(technique_id: str) -> dict:
    return {
        "ok": False,
        "tool": "attack_technique_lookup",
        "query": {"technique_id": technique_id},
        "data": None,
        "error": {"code": "not_found", "message": "Not found.", "details": None},
    }


def _not_found(*args, **kwargs) -> dict:
    return {
        "ok": False,
        "tool": "optional",
        "query": {},
        "data": None,
        "error": {"code": "not_found", "message": "Not found.", "details": None},
    }


def _optional_error(*args, **kwargs) -> dict:
    return {
        "ok": False,
        "tool": "optional",
        "query": {},
        "data": None,
        "error": {"code": "parse_error", "message": "Bad snapshot.", "details": None},
    }


def _rate_limited(*args, **kwargs) -> dict:
    return {
        "ok": False,
        "tool": "optional",
        "query": {},
        "data": None,
        "error": {"code": "rate_limited", "message": "Rate limited.", "details": None},
    }


def _cve_success(cve_id: str) -> dict:
    return {
        "ok": True,
        "tool": "cve_lookup",
        "query": {"cve_id": cve_id},
        "data": {
            "cve_id": "CVE-2024-3400",
            "published": "2024-04-12T08:15:06.230",
            "last_modified": "2025-11-04T16:49:20.907",
            "vuln_status": "Analyzed",
            "description": "Command injection.",
            "cvss": {"base_score": 10.0, "base_severity": "CRITICAL"},
            "weaknesses": ["CWE-77"],
            "references": [{"url": "https://example.com"}],
            "affected_cpes": ["cpe:2.3:o:paloaltonetworks:pan-os:*:*:*:*:*:*:*:*"],
        },
        "error": None,
    }


def _kev_success(cve_id: str) -> dict:
    return {
        "ok": True,
        "tool": "kev_lookup",
        "query": {"cve_id": cve_id},
        "data": {
            "in_kev": True,
            "vulnerability": {
                "cve_id": "CVE-2024-3400",
                "vendor_project": "Palo Alto Networks",
                "product": "PAN-OS",
                "vulnerability_name": "PAN-OS Command Injection",
                "date_added": "2024-04-12",
                "required_action": "Apply mitigations.",
                "due_date": "2024-04-19",
                "known_ransomware_campaign_use": "Unknown",
            },
        },
        "error": None,
    }
