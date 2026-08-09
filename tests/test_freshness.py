import os
import time
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from threatsyft.knowledge.freshness import STALE_AFTER_DAYS, snapshot_freshness
from threatsyft.knowledge.lookup import lookup, search

KEV_FIXTURE = Path("tests/fixtures/cisa-kev-mini.json")
LOLBAS_FIXTURE = Path("tests/fixtures/lolbas-mini.json")
ATTACK_FIXTURE = Path("tests/fixtures/attack-enterprise-mini.json")


def _aged_copy(tmp_path: Path, source: Path, days_old: float) -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    copy = tmp_path / source.name
    copy.write_bytes(source.read_bytes())
    old = time.time() - days_old * 86400
    os.utime(copy, (old, old))
    return copy


@pytest.fixture(autouse=True)
def local_snapshots(monkeypatch):
    monkeypatch.setenv("THREATSYFT_ATTACK_STIX_PATH", str(ATTACK_FIXTURE))
    monkeypatch.setenv("THREATSYFT_CISA_KEV_PATH", str(KEV_FIXTURE))
    monkeypatch.setenv("THREATSYFT_LOLBAS_PATH", str(LOLBAS_FIXTURE))


def test_thresholds_differ_per_source() -> None:
    """One global threshold would be wrong: KEV changes weekly, ATT&CK a few times a year."""
    assert STALE_AFTER_DAYS["kev"] < STALE_AFTER_DAYS["attack"]


def test_a_fresh_snapshot_is_not_stale(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("THREATSYFT_CISA_KEV_PATH", str(_aged_copy(tmp_path, KEV_FIXTURE, 1)))

    freshness = snapshot_freshness("kev")

    assert freshness["stale"] is False
    assert freshness["age_days"] == 1
    assert freshness["snapshot_present"] is True


def test_a_snapshot_past_its_threshold_is_stale(monkeypatch, tmp_path) -> None:
    days = STALE_AFTER_DAYS["kev"] + 5
    monkeypatch.setenv("THREATSYFT_CISA_KEV_PATH", str(_aged_copy(tmp_path, KEV_FIXTURE, days)))

    freshness = snapshot_freshness("kev")

    assert freshness["stale"] is True
    assert freshness["age_days"] == days


def test_the_same_age_is_stale_for_kev_but_not_for_attack(monkeypatch, tmp_path) -> None:
    """The point of per-source thresholds, asserted directly."""
    days = 30
    monkeypatch.setenv("THREATSYFT_CISA_KEV_PATH", str(_aged_copy(tmp_path, KEV_FIXTURE, days)))
    monkeypatch.setenv(
        "THREATSYFT_ATTACK_STIX_PATH", str(_aged_copy(tmp_path / "a", ATTACK_FIXTURE, days))
    )

    assert snapshot_freshness("kev")["stale"] is True
    assert snapshot_freshness("attack")["stale"] is False


def test_a_missing_snapshot_reports_unknown_age_rather_than_guessing(monkeypatch) -> None:
    monkeypatch.setenv("THREATSYFT_CISA_KEV_PATH", "/nonexistent/kev.json")

    freshness = snapshot_freshness("kev")

    assert freshness["snapshot_present"] is False
    assert freshness["as_of"] is None
    assert freshness["stale"] is None


def test_a_live_source_has_no_snapshot_freshness() -> None:
    assert snapshot_freshness("nvd") is None


def test_lookup_reports_freshness_on_the_failure_path(monkeypatch, tmp_path) -> None:
    """The sharp case: 'not in KEV' means nothing without the age of the catalog."""
    days = STALE_AFTER_DAYS["kev"] + 40
    monkeypatch.setenv("THREATSYFT_CISA_KEV_PATH", str(_aged_copy(tmp_path, KEV_FIXTURE, days)))

    entry = lookup("CVE-2021-44228")["data"]["sources"]["kev"]

    assert entry["ok"] is False
    assert entry["code"] == "not_found"
    assert entry["freshness"]["stale"] is True
    assert entry["freshness"]["age_days"] == days


def test_lookup_reports_freshness_on_the_success_path() -> None:
    entry = lookup("T1059")["data"]["sources"]["attack"]

    assert entry["ok"] is True
    assert entry["freshness"]["snapshot_present"] is True


def test_search_reports_freshness_for_every_snapshot_source() -> None:
    sources = search("cert")["data"]["sources"]

    for name in ["attack", "kev", "lolbas"]:
        assert "freshness" in sources[name], name


def test_freshness_never_refuses_to_answer(monkeypatch, tmp_path) -> None:
    """Refusing past a threshold would break the offline case the snapshots exist for."""
    monkeypatch.setenv("THREATSYFT_CISA_KEV_PATH", str(_aged_copy(tmp_path, KEV_FIXTURE, 3650)))

    result = search("cert", source="kev")

    assert result["ok"] is True
    assert result["data"]["sources"]["kev"]["ok"] is True
    assert result["data"]["sources"]["kev"]["freshness"]["stale"] is True


def test_as_of_is_a_parseable_timestamp() -> None:
    as_of = snapshot_freshness("attack")["as_of"]

    assert datetime.fromisoformat(as_of) < datetime.now(
        datetime.now().astimezone().tzinfo
    ) + timedelta(seconds=1)
