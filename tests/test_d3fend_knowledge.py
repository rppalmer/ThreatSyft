from pathlib import Path

from investigatinator.knowledge import d3fend

FIXTURE_PATH = Path("tests/fixtures/d3fend-mini.json")


def test_load_d3fend_catalog_valid_fixture() -> None:
    catalog = d3fend.load_d3fend_catalog(FIXTURE_PATH)

    assert "D3-FA" in catalog.techniques_by_id
    assert "file-analysis" in catalog.techniques_by_name
    assert catalog.techniques_by_id["D3-FA"].tactics == ["Detect"]
    assert catalog.techniques_by_id["D3-FA"].related_attack_techniques[0]["attack_id"] == "T1059"


def test_load_d3fend_catalog_missing_snapshot() -> None:
    try:
        d3fend.load_d3fend_catalog(Path("tests/fixtures/missing-d3fend.json"))
    except d3fend.KnowledgeLoadError as exc:
        assert exc.code == "not_found"
        assert exc.details["setup_command"] == "investigatinator knowledge-update d3fend"
    else:
        raise AssertionError("Expected KnowledgeLoadError")


def test_load_d3fend_catalog_malformed_json(tmp_path) -> None:
    snapshot = tmp_path / "bad.json"
    snapshot.write_text("not-json", encoding="utf-8")

    try:
        d3fend.load_d3fend_catalog(snapshot)
    except d3fend.KnowledgeLoadError as exc:
        assert exc.code == "parse_error"
    else:
        raise AssertionError("Expected KnowledgeLoadError")


def test_d3fend_lookup_by_id(monkeypatch) -> None:
    monkeypatch.setenv("INVESTIGATINATOR_D3FEND_PATH", str(FIXTURE_PATH))

    result = d3fend.d3fend_lookup("d3-fa")

    assert result["ok"] is True
    assert result["tool"] == "d3fend_lookup"
    assert result["query"]["defense_id_or_name"] == "D3-FA"
    assert result["data"]["technique"]["name"] == "File Analysis"
    assert result["data"]["technique"]["artifacts"] == ["File"]


def test_d3fend_lookup_by_name(monkeypatch) -> None:
    monkeypatch.setenv("INVESTIGATINATOR_D3FEND_PATH", str(FIXTURE_PATH))

    result = d3fend.d3fend_lookup("File Inspection")

    assert result["ok"] is True
    assert result["data"]["technique"]["d3fend_id"] == "D3-FA"


def test_d3fend_lookup_not_found(monkeypatch) -> None:
    monkeypatch.setenv("INVESTIGATINATOR_D3FEND_PATH", str(FIXTURE_PATH))

    result = d3fend.d3fend_lookup("No Such Defense")

    assert result["ok"] is False
    assert result["error"]["code"] == "not_found"


def test_d3fend_search_returns_matches(monkeypatch) -> None:
    monkeypatch.setenv("INVESTIGATINATOR_D3FEND_PATH", str(FIXTURE_PATH))

    result = d3fend.d3fend_search("process", limit=5)

    assert result["ok"] is True
    assert result["data"]["match_count"] == 1
    assert result["data"]["matches"][0]["name"] == "Process Analysis"


def test_d3fend_search_limit_validation(monkeypatch) -> None:
    monkeypatch.setenv("INVESTIGATINATOR_D3FEND_PATH", str(FIXTURE_PATH))

    result = d3fend.d3fend_search("process", limit=26)

    assert result["ok"] is False
    assert result["error"]["code"] == "invalid_input"


def test_attack_defense_mapping_success(monkeypatch) -> None:
    monkeypatch.setenv("INVESTIGATINATOR_D3FEND_PATH", str(FIXTURE_PATH))

    result = d3fend.attack_defense_mapping("t1059")

    assert result["ok"] is True
    assert result["query"]["technique_id"] == "T1059"
    assert result["data"]["attack_technique_name"] == "Command and Scripting Interpreter"
    assert result["data"]["defensive_technique_count"] == 2
    assert {item["d3fend_id"] for item in result["data"]["defensive_techniques"]} == {
        "D3-FA",
        "D3-PA",
    }


def test_attack_defense_mapping_invalid_id() -> None:
    result = d3fend.attack_defense_mapping("1059")

    assert result["ok"] is False
    assert result["error"]["code"] == "invalid_input"


def test_attack_defense_mapping_not_found(monkeypatch) -> None:
    monkeypatch.setenv("INVESTIGATINATOR_D3FEND_PATH", str(FIXTURE_PATH))

    result = d3fend.attack_defense_mapping("T1234")

    assert result["ok"] is False
    assert result["error"]["code"] == "not_found"
