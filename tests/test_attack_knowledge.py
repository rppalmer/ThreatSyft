from pathlib import Path

from threatsyft.knowledge import attack

FIXTURE_PATH = Path("tests/fixtures/attack-enterprise-mini.json")


def test_load_attack_knowledge_valid_fixture() -> None:
    knowledge = attack.load_attack_knowledge(FIXTURE_PATH)

    assert "T1059" in knowledge.techniques_by_id
    assert "T1059.001" in knowledge.techniques_by_id
    assert "initial-access" in knowledge.tactics_by_short_name
    assert knowledge.techniques_by_id["T1059"].subtechnique_ids == ["T1059.001"]
    assert knowledge.techniques_by_id["T1059.001"].parent_id == "T1059"
    assert knowledge.techniques_by_id["T1059"].mitigations[0]["mitigation_id"] == "M1038"


def test_load_attack_knowledge_missing_snapshot() -> None:
    try:
        attack.load_attack_knowledge(Path("tests/fixtures/missing-attack.json"))
    except attack.KnowledgeLoadError as exc:
        assert exc.code == "not_found"
        assert exc.details["setup_command"] == "threatsyft knowledge-update attack"
    else:
        raise AssertionError("Expected KnowledgeLoadError")


def test_load_attack_knowledge_malformed_json(tmp_path) -> None:
    snapshot = tmp_path / "bad.json"
    snapshot.write_text("not-json", encoding="utf-8")

    try:
        attack.load_attack_knowledge(snapshot)
    except attack.KnowledgeLoadError as exc:
        assert exc.code == "parse_error"
    else:
        raise AssertionError("Expected KnowledgeLoadError")


def test_attack_technique_lookup_success(monkeypatch) -> None:
    monkeypatch.setenv("THREATSYFT_ATTACK_STIX_PATH", str(FIXTURE_PATH))

    result = attack.attack_technique_lookup("t1059")

    assert result["ok"] is True
    assert result["tool"] == "attack_technique_lookup"
    assert result["query"]["technique_id"] == "T1059"
    assert result["data"]["technique_id"] == "T1059"
    assert result["data"]["name"] == "Command and Scripting Interpreter"
    assert result["data"]["tactics"][0]["short_name"] == "execution"
    assert result["data"]["data_sources"] == [
        "Command: Command Execution",
        "Process: Process Creation",
    ]
    assert result["data"]["mitigations"][0]["mitigation_id"] == "M1038"
    assert result["data"]["subtechniques"][0]["technique_id"] == "T1059.001"


def test_attack_technique_lookup_subtechnique(monkeypatch) -> None:
    monkeypatch.setenv("THREATSYFT_ATTACK_STIX_PATH", str(FIXTURE_PATH))

    result = attack.attack_technique_lookup("T1059.001")

    assert result["ok"] is True
    assert result["data"]["is_subtechnique"] is True
    assert result["data"]["parent"]["technique_id"] == "T1059"


def test_attack_technique_lookup_flags_deprecated(monkeypatch) -> None:
    monkeypatch.setenv("THREATSYFT_ATTACK_STIX_PATH", str(FIXTURE_PATH))

    result = attack.attack_technique_lookup("T9999")

    assert result["ok"] is True
    assert result["data"]["deprecated"] is True


def test_attack_technique_lookup_invalid_id() -> None:
    result = attack.attack_technique_lookup("1059")

    assert result["ok"] is False
    assert result["error"]["code"] == "invalid_input"


def test_attack_technique_lookup_not_found(monkeypatch) -> None:
    monkeypatch.setenv("THREATSYFT_ATTACK_STIX_PATH", str(FIXTURE_PATH))

    result = attack.attack_technique_lookup("T1234")

    assert result["ok"] is False
    assert result["error"]["code"] == "not_found"


def test_attack_search_returns_ranked_matches(monkeypatch) -> None:
    monkeypatch.setenv("THREATSYFT_ATTACK_STIX_PATH", str(FIXTURE_PATH))

    result = attack.attack_search("powershell", limit=5)

    assert result["ok"] is True
    assert result["data"]["match_count"] >= 1
    assert result["data"]["matches"][0]["technique_id"] == "T1059.001"
    assert "PowerShell" in result["data"]["matches"][0]["matched_context"]


def test_attack_search_limit_validation(monkeypatch) -> None:
    monkeypatch.setenv("THREATSYFT_ATTACK_STIX_PATH", str(FIXTURE_PATH))

    result = attack.attack_search("powershell", limit=26)

    assert result["ok"] is False
    assert result["error"]["code"] == "invalid_input"


def test_attack_tactic_lookup_by_short_name(monkeypatch) -> None:
    monkeypatch.setenv("THREATSYFT_ATTACK_STIX_PATH", str(FIXTURE_PATH))

    result = attack.attack_tactic_lookup("initial-access")

    assert result["ok"] is True
    assert result["data"]["tactic"]["name"] == "Initial Access"
    assert result["data"]["techniques"][0]["technique_id"] == "T1189"


def test_attack_tactic_lookup_by_display_name(monkeypatch) -> None:
    monkeypatch.setenv("THREATSYFT_ATTACK_STIX_PATH", str(FIXTURE_PATH))

    result = attack.attack_tactic_lookup("Initial Access")

    assert result["ok"] is True
    assert result["query"]["tactic"] == "initial-access"


def test_attack_tactic_lookup_not_found(monkeypatch) -> None:
    monkeypatch.setenv("THREATSYFT_ATTACK_STIX_PATH", str(FIXTURE_PATH))

    result = attack.attack_tactic_lookup("impact")

    assert result["ok"] is False
    assert result["error"]["code"] == "not_found"
