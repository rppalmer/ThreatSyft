"""Stale snapshots must be visible at the top of a response, not one level down."""

import time

from threatsyft.enrichment import maxmind
from threatsyft.enrichment.enrich import DISPATCH, enrich
from threatsyft.knowledge.freshness import staleness_warnings


def _entry(source_freshness):
    return {"ok": True, "data": {}, "freshness": source_freshness}


def _fresh(age_days=2, threshold=14):
    return {
        "as_of": "2026-08-09T00:00:00+00:00",
        "age_days": age_days,
        "stale": False,
        "stale_after_days": threshold,
        "snapshot_present": True,
    }


def _stale(age_days=45, threshold=14):
    return {**_fresh(age_days, threshold), "stale": True}


# --- knowledge side -----------------------------------------------------------


def test_nothing_stale_produces_no_warnings() -> None:
    """A healthy install must stay silent, or the warning becomes noise."""
    assert staleness_warnings({"kev": _entry(_fresh())}) == []


def test_a_stale_snapshot_names_its_age_and_its_fix() -> None:
    warnings = staleness_warnings({"kev": _entry(_stale(45))})

    assert len(warnings) == 1
    assert "45 days old" in warnings[0]
    assert "stale after 14" in warnings[0]
    assert "threatsyft-update kev" in warnings[0]


def test_sources_sharing_a_snapshot_warn_once() -> None:
    """A bare-name lookup asks three ATT&CK catalogs; they are one file."""
    stale = _stale(400, 180)
    warnings = staleness_warnings(
        {
            "attack_technique": _entry(stale),
            "attack_tactic": _entry(stale),
            "attack_actor": _entry(stale),
        }
    )

    assert len(warnings) == 1
    assert "attack snapshot" in warnings[0]
    assert "threatsyft-update attack" in warnings[0]


def test_each_stale_snapshot_gets_its_own_warning() -> None:
    warnings = staleness_warnings({"kev": _entry(_stale(45)), "lolbas": _entry(_stale(400, 180))})

    assert len(warnings) == 2
    assert any("threatsyft-update kev" in text for text in warnings)
    assert any("threatsyft-update lolbas" in text for text in warnings)


def test_a_source_without_freshness_is_not_warned_about() -> None:
    """NVD is live, not snapshot-backed, so it has no age to be stale."""
    assert staleness_warnings({"nvd": {"ok": True, "data": {}}}) == []


def test_a_failed_source_still_warns_when_its_snapshot_is_stale() -> None:
    """ "Not in KEV" from a stale catalog is exactly the case this exists for."""
    entry = {"ok": False, "code": "not_found", "message": "x", "freshness": _stale(45)}

    assert len(staleness_warnings({"kev": entry})) == 1


# --- enrichment side ----------------------------------------------------------


def _stub_maxmind(monkeypatch, tmp_path, build_epoch):
    city = tmp_path / "GeoLite2-City.mmdb"
    city.write_bytes(b"x")
    monkeypatch.setattr(maxmind, "get_maxmind_city_path", lambda: city)
    monkeypatch.setattr(maxmind, "get_maxmind_asn_path", lambda: tmp_path / "absent.mmdb")

    class _Reader:
        def get(self, _ip):
            return {"country": {"iso_code": "US", "names": {"en": "United States"}}}

        def metadata(self):
            return type("M", (), {"build_epoch": build_epoch})()

        def close(self):
            pass

    monkeypatch.setattr(maxmind, "_readers", {})
    monkeypatch.setattr(maxmind.maxminddb, "open_database", lambda _p: _Reader())


def test_a_fresh_geolite_database_warns_about_nothing(monkeypatch, tmp_path) -> None:
    _stub_maxmind(monkeypatch, tmp_path, int(time.time()))

    data = maxmind.maxmind_ip_lookup("8.8.8.8")["data"]

    assert "staleness_warning" not in data


def test_a_stale_geolite_database_declares_a_warning(monkeypatch, tmp_path) -> None:
    _stub_maxmind(monkeypatch, tmp_path, int(time.time()) - (90 * 86400))

    data = maxmind.maxmind_ip_lookup("8.8.8.8")["data"]

    assert "threatsyft-update maxmind" in data["staleness_warning"]
    assert "90 days old" in data["staleness_warning"]


def test_enrich_lifts_a_source_warning_to_the_top(monkeypatch) -> None:
    """The whole point: a reader must not have to open a source to see it."""
    monkeypatch.setitem(
        DISPATCH,
        "ip",
        (
            (
                "maxmind",
                lambda _ip: {
                    "ok": True,
                    "tool": "stub",
                    "query": {},
                    "error": None,
                    "data": {"staleness_warning": "The GeoLite2 database is 90 days old."},
                },
            ),
        ),
    )

    data = enrich("8.8.8.8")["data"]

    assert data["warnings"] == ["The GeoLite2 database is 90 days old."]


def test_enrich_warnings_are_empty_when_no_source_declares_one(monkeypatch) -> None:
    monkeypatch.setitem(
        DISPATCH,
        "ip",
        (
            (
                "abuseipdb",
                lambda _ip: {
                    "ok": True,
                    "tool": "s",
                    "query": {},
                    "error": None,
                    "data": {"score": 0},
                },
            ),
        ),
    )

    assert enrich("8.8.8.8")["data"]["warnings"] == []


def test_enrich_ignores_a_non_string_warning(monkeypatch) -> None:
    """A malformed provider payload must not break the response."""
    monkeypatch.setitem(
        DISPATCH,
        "ip",
        (
            (
                "maxmind",
                lambda _ip: {
                    "ok": True,
                    "tool": "s",
                    "query": {},
                    "error": None,
                    "data": {"staleness_warning": {"not": "a string"}},
                },
            ),
        ),
    )

    assert enrich("8.8.8.8")["data"]["warnings"] == []
