from pathlib import Path

from threatsyft.knowledge import lolbas

FIXTURE_PATH = Path("tests/fixtures/lolbas-mini.json")


def test_load_lolbas_catalog_valid_fixture() -> None:
    catalog = lolbas.load_lolbas_catalog(FIXTURE_PATH)

    assert catalog.count == 2
    assert "certutil.exe" in catalog.entries_by_name
    assert catalog.entries_by_name["certutil.exe"].command_count == 2


def test_load_lolbas_catalog_missing_snapshot() -> None:
    try:
        lolbas.load_lolbas_catalog(Path("tests/fixtures/missing-lolbas.json"))
    except lolbas.KnowledgeLoadError as exc:
        assert exc.code == "not_found"
        assert exc.details["setup_command"] == "threatsyft-update lolbas"
    else:
        raise AssertionError("Expected KnowledgeLoadError")


def test_load_lolbas_catalog_malformed_json(tmp_path) -> None:
    snapshot = tmp_path / "bad.json"
    snapshot.write_text("not-json", encoding="utf-8")

    try:
        lolbas.load_lolbas_catalog(snapshot)
    except lolbas.KnowledgeLoadError as exc:
        assert exc.code == "parse_error"
    else:
        raise AssertionError("Expected KnowledgeLoadError")


def test_lolbas_lookup_success(monkeypatch) -> None:
    monkeypatch.setenv("THREATSYFT_LOLBAS_PATH", str(FIXTURE_PATH))

    result = lolbas.lolbas_lookup("certutil.exe")

    assert result["ok"] is True
    assert result["tool"] == "lolbas_lookup"
    assert result["data"]["entry"]["name"] == "Certutil.exe"
    assert result["data"]["entry"]["categories"] == ["Decode", "Download"]
    assert result["data"]["entry"]["mitre_ids"] == ["T1105", "T1140"]
    assert result["data"]["entry"]["command_count"] == 2
    assert result["data"]["entry"]["command_examples_omitted"] is True
    assert "Command" not in result["data"]["entry"]


def test_lolbas_lookup_invalid_name() -> None:
    result = lolbas.lolbas_lookup(" ")

    assert result["ok"] is False
    assert result["error"]["code"] == "invalid_input"


def test_lolbas_lookup_not_found(monkeypatch) -> None:
    monkeypatch.setenv("THREATSYFT_LOLBAS_PATH", str(FIXTURE_PATH))

    result = lolbas.lolbas_lookup("notepad.exe")

    assert result["ok"] is False
    assert result["error"]["code"] == "not_found"


def test_lolbas_search_returns_matches(monkeypatch) -> None:
    monkeypatch.setenv("THREATSYFT_LOLBAS_PATH", str(FIXTURE_PATH))

    result = lolbas.lolbas_search("certutil", limit=5)

    assert result["ok"] is True
    assert result["data"]["match_count"] == 1
    assert result["data"]["matches"][0]["name"] == "Certutil.exe"
    assert "certutil" in result["data"]["matches"][0]["matched_context"].lower()


def test_lolbas_search_limit_validation(monkeypatch) -> None:
    monkeypatch.setenv("THREATSYFT_LOLBAS_PATH", str(FIXTURE_PATH))

    result = lolbas.lolbas_search("download", limit=26)

    assert result["ok"] is False
    assert result["error"]["code"] == "invalid_input"
