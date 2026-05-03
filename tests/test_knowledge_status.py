from pathlib import Path

from investigatinator.knowledge import status

ATTACK_FIXTURE = Path("tests/fixtures/attack-enterprise-mini.json")
D3FEND_FIXTURE = Path("tests/fixtures/d3fend-mini.json")
KEV_FIXTURE = Path("tests/fixtures/cisa-kev-mini.json")
LOLBAS_FIXTURE = Path("tests/fixtures/lolbas-mini.json")


def test_knowledge_status_all_snapshots_available(monkeypatch) -> None:
    monkeypatch.setenv("INVESTIGATINATOR_ATTACK_STIX_PATH", str(ATTACK_FIXTURE))
    monkeypatch.setenv("INVESTIGATINATOR_D3FEND_PATH", str(D3FEND_FIXTURE))
    monkeypatch.setenv("INVESTIGATINATOR_CISA_KEV_PATH", str(KEV_FIXTURE))
    monkeypatch.setenv("INVESTIGATINATOR_LOLBAS_PATH", str(LOLBAS_FIXTURE))
    monkeypatch.setenv("NVD_API_KEY", "test-key")

    result = status.knowledge_status()

    assert result["ok"] is True
    assert result["tool"] == "knowledge_status"
    assert result["data"]["local_only"] is True
    assert result["data"]["network_checked"] is False
    assert result["data"]["ready"] is True
    assert result["data"]["unavailable_snapshots"] == []
    assert result["data"]["snapshots"]["attack"]["counts"]["techniques"] == 4
    assert result["data"]["snapshots"]["attack"]["file_modified_at"] is not None
    assert result["data"]["snapshots"]["attack"]["source_updated_at"] is None
    assert result["data"]["snapshots"]["d3fend"]["counts"]["mappings"] == 2
    assert result["data"]["snapshots"]["d3fend"]["file_modified_at"] is not None
    assert result["data"]["snapshots"]["d3fend"]["source_updated_at"] is None
    assert result["data"]["snapshots"]["kev"]["counts"]["vulnerabilities"] == 2
    assert result["data"]["snapshots"]["kev"]["file_modified_at"] is not None
    assert result["data"]["snapshots"]["kev"]["source_updated_at"] == "2026-04-13T00:00:00.0000Z"
    assert result["data"]["snapshots"]["lolbas"]["counts"]["entries"] == 2
    assert result["data"]["snapshots"]["lolbas"]["file_modified_at"] is not None
    assert result["data"]["snapshots"]["lolbas"]["source_updated_at"] is None
    assert result["data"]["live_tools"]["cve_lookup"]["api_key_configured"] is True
    assert "test-key" not in str(result)


def test_knowledge_status_reports_missing_snapshot(monkeypatch) -> None:
    monkeypatch.setenv("INVESTIGATINATOR_ATTACK_STIX_PATH", "tests/fixtures/missing-attack.json")
    monkeypatch.setenv("INVESTIGATINATOR_D3FEND_PATH", str(D3FEND_FIXTURE))
    monkeypatch.setenv("INVESTIGATINATOR_CISA_KEV_PATH", str(KEV_FIXTURE))
    monkeypatch.setenv("INVESTIGATINATOR_LOLBAS_PATH", str(LOLBAS_FIXTURE))

    result = status.knowledge_status()

    assert result["ok"] is True
    assert result["data"]["ready"] is False
    assert result["data"]["unavailable_snapshots"] == ["attack"]
    assert result["data"]["snapshots"]["attack"]["ok"] is False
    assert result["data"]["snapshots"]["attack"]["status"] == "not_found"
    assert result["data"]["snapshots"]["attack"]["file_modified_at"] is None
    assert result["data"]["snapshots"]["attack"]["setup_command"] == (
        "investigatinator knowledge-update attack"
    )


def test_knowledge_status_reports_parse_error(monkeypatch, tmp_path) -> None:
    malformed = tmp_path / "bad-kev.json"
    malformed.write_text("not-json", encoding="utf-8")
    monkeypatch.setenv("INVESTIGATINATOR_ATTACK_STIX_PATH", str(ATTACK_FIXTURE))
    monkeypatch.setenv("INVESTIGATINATOR_D3FEND_PATH", str(D3FEND_FIXTURE))
    monkeypatch.setenv("INVESTIGATINATOR_CISA_KEV_PATH", str(malformed))
    monkeypatch.setenv("INVESTIGATINATOR_LOLBAS_PATH", str(LOLBAS_FIXTURE))

    result = status.knowledge_status()

    assert result["ok"] is True
    assert result["data"]["ready"] is False
    assert result["data"]["unavailable_snapshots"] == ["kev"]
    assert result["data"]["snapshots"]["kev"]["status"] == "parse_error"
    assert result["data"]["snapshots"]["kev"]["error"]["code"] == "parse_error"


def test_knowledge_status_does_not_require_nvd_key(monkeypatch) -> None:
    monkeypatch.setenv("INVESTIGATINATOR_ATTACK_STIX_PATH", str(ATTACK_FIXTURE))
    monkeypatch.setenv("INVESTIGATINATOR_D3FEND_PATH", str(D3FEND_FIXTURE))
    monkeypatch.setenv("INVESTIGATINATOR_CISA_KEV_PATH", str(KEV_FIXTURE))
    monkeypatch.setenv("INVESTIGATINATOR_LOLBAS_PATH", str(LOLBAS_FIXTURE))
    monkeypatch.delenv("NVD_API_KEY", raising=False)

    result = status.knowledge_status()

    assert result["ok"] is True
    assert result["data"]["ready"] is True
    assert result["data"]["live_tools"]["cve_lookup"]["api_key_configured"] is False
