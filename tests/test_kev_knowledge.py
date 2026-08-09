from pathlib import Path

from threatsyft.knowledge import kev

FIXTURE_PATH = Path("tests/fixtures/cisa-kev-mini.json")


def test_load_kev_catalog_valid_fixture() -> None:
    catalog = kev.load_kev_catalog(FIXTURE_PATH)

    assert catalog.title == "CISA Known Exploited Vulnerabilities Catalog"
    assert catalog.count == 2
    assert "CVE-2023-34362" in catalog.vulnerabilities_by_cve


def test_load_kev_catalog_missing_snapshot() -> None:
    try:
        kev.load_kev_catalog(Path("tests/fixtures/missing-kev.json"))
    except kev.KnowledgeLoadError as exc:
        assert exc.code == "not_found"
        assert exc.details["setup_command"] == "threatsyft-update kev"
    else:
        raise AssertionError("Expected KnowledgeLoadError")


def test_load_kev_catalog_malformed_json(tmp_path) -> None:
    snapshot = tmp_path / "bad.json"
    snapshot.write_text("not-json", encoding="utf-8")

    try:
        kev.load_kev_catalog(snapshot)
    except kev.KnowledgeLoadError as exc:
        assert exc.code == "parse_error"
    else:
        raise AssertionError("Expected KnowledgeLoadError")


def test_kev_lookup_success(monkeypatch) -> None:
    monkeypatch.setenv("THREATSYFT_CISA_KEV_PATH", str(FIXTURE_PATH))

    result = kev.kev_lookup("cve-2023-34362")

    assert result["ok"] is True
    assert result["tool"] == "kev_lookup"
    assert result["query"]["cve_id"] == "CVE-2023-34362"
    assert result["data"]["in_kev"] is True
    assert result["data"]["vulnerability"]["vendor_project"] == "Progress"
    assert result["data"]["vulnerability"]["cwes"] == ["CWE-89"]


def test_kev_lookup_invalid_cve() -> None:
    result = kev.kev_lookup("2023-34362")

    assert result["ok"] is False
    assert result["error"]["code"] == "invalid_input"


def test_kev_lookup_not_found(monkeypatch) -> None:
    monkeypatch.setenv("THREATSYFT_CISA_KEV_PATH", str(FIXTURE_PATH))

    result = kev.kev_lookup("CVE-1999-0001")

    assert result["ok"] is False
    assert result["error"]["code"] == "not_found"


def test_kev_search_returns_matches(monkeypatch) -> None:
    monkeypatch.setenv("THREATSYFT_CISA_KEV_PATH", str(FIXTURE_PATH))

    result = kev.kev_search("MOVEit", limit=5)

    assert result["ok"] is True
    assert result["data"]["match_count"] == 1
    assert result["data"]["matches"][0]["cve_id"] == "CVE-2023-34362"
    assert "MOVEit" in result["data"]["matches"][0]["matched_context"]


def test_kev_search_limit_validation(monkeypatch) -> None:
    monkeypatch.setenv("THREATSYFT_CISA_KEV_PATH", str(FIXTURE_PATH))

    result = kev.kev_search("MOVEit", limit=0)

    assert result["ok"] is False
    assert result["error"]["code"] == "invalid_input"
