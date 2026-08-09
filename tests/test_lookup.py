from pathlib import Path

import pytest

from threatsyft.knowledge import lookup as lookup_module
from threatsyft.knowledge.lookup import SEARCH_SOURCES, lookup, search

ATTACK_FIXTURE = Path("tests/fixtures/attack-enterprise-mini.json")
KEV_FIXTURE = Path("tests/fixtures/cisa-kev-mini.json")
LOLBAS_FIXTURE = Path("tests/fixtures/lolbas-mini.json")


@pytest.fixture(autouse=True)
def local_snapshots(monkeypatch):
    monkeypatch.setenv("THREATSYFT_ATTACK_STIX_PATH", str(ATTACK_FIXTURE))
    monkeypatch.setenv("THREATSYFT_CISA_KEV_PATH", str(KEV_FIXTURE))
    monkeypatch.setenv("THREATSYFT_LOLBAS_PATH", str(LOLBAS_FIXTURE))


# --- classification and dispatch ---------------------------------------------


def test_lookup_routes_a_technique_to_attack_and_lolbas() -> None:
    data = lookup("T1059")["data"]

    assert data["reference_type"] == "attack_technique"
    assert list(data["sources"]) == ["attack", "lolbas"]


def test_lookup_routes_an_unrecognized_name_to_lolbas() -> None:
    data = lookup("Certutil.exe")["data"]

    assert data["reference_type"] == "lolbas_name"
    assert list(data["sources"]) == ["lolbas"]


def test_lookup_normalizes_the_reference_it_echoes_back() -> None:
    result = lookup("  t1059  ")

    assert result["data"]["reference"] == "T1059"
    assert result["query"]["reference"] == "T1059"


def test_search_sources_are_all_callable() -> None:
    assert set(SEARCH_SOURCES) == {"attack", "kev", "lolbas"}
    for name, function in SEARCH_SOURCES.items():
        assert callable(function), name


# --- shared sources shape (§3.2), identical to enrich -------------------------


def test_lookup_and_search_share_the_enrich_sources_shape() -> None:
    for data in [lookup("T1059")["data"], search("cert")["data"]]:
        assert set(data["source_summary"]) == {"ok", "failed"}
        for entry in data["sources"].values():
            assert isinstance(entry["ok"], bool)
            if not entry["ok"]:
                assert set(entry) >= {"ok", "code", "message"}


def test_lookup_summary_counts_match_the_sources_map() -> None:
    data = lookup("T1059")["data"]
    summary = data["source_summary"]

    assert summary["ok"] == sum(1 for e in data["sources"].values() if e["ok"])
    assert summary["ok"] + summary["failed"] == len(data["sources"])


# --- ok semantics (§3.3) ------------------------------------------------------


@pytest.mark.parametrize("value", ["", "   "])
def test_empty_reference_is_a_tool_failure(value) -> None:
    result = lookup(value)

    assert result["ok"] is False
    assert result["error"]["code"] == "invalid_input"


@pytest.mark.parametrize(
    ("value", "detected_type"),
    [
        ("8.8.8.8", "ip"),
        ("https://example.com/a", "url"),
        ("d41d8cd98f00b204e9800998ecf8427e", "hash"),
    ],
)
def test_lookup_redirects_an_enrichable_indicator_to_enrich(value, detected_type) -> None:
    """§3.4 symmetry: the mirror of enrich() redirecting a CVE to the reference tools."""
    result = lookup(value)

    assert result["ok"] is False
    assert result["error"]["code"] == "invalid_input"
    assert result["error"]["details"] == {
        "detected_type": detected_type,
        "suggested_tool": "enrich",
    }


def test_a_reference_no_source_knows_is_still_a_successful_call() -> None:
    """Absence of data is a result, not a tool error; retrying will not fix it."""
    result = lookup("NoSuchBinary.exe")

    assert result["ok"] is True
    assert result["error"] is None
    assert result["data"]["source_summary"]["ok"] == 0


def test_search_rejects_an_unknown_source() -> None:
    result = search("cert", source="nope")

    assert result["ok"] is False
    assert result["error"]["code"] == "invalid_input"
    assert "all" in result["error"]["details"]["valid_sources"]


def test_search_rejects_an_empty_query() -> None:
    assert search("   ")["error"]["code"] == "invalid_input"


# --- search grouping (§3.5) ---------------------------------------------------


def test_search_all_queries_every_source_and_never_merges_them() -> None:
    data = search("cert")["data"]

    assert list(data["sources"]) == ["attack", "kev", "lolbas"]
    assert "matches" not in data, "results must stay grouped by source, never merge-ranked"


def test_search_one_source_queries_only_that_source() -> None:
    data = search("cert", source="lolbas")["data"]

    assert list(data["sources"]) == ["lolbas"]


def test_search_limit_applies_per_source_not_across_them(monkeypatch) -> None:
    seen = {}

    def record(name):
        def call(query, limit):
            seen[name] = limit
            return {"ok": True, "tool": name, "query": {}, "data": {"matches": []}, "error": None}

        return call

    monkeypatch.setitem(SEARCH_SOURCES, "attack", record("attack"))
    monkeypatch.setitem(SEARCH_SOURCES, "kev", record("kev"))
    monkeypatch.setitem(SEARCH_SOURCES, "lolbas", record("lolbas"))

    search("cert", limit=7)

    assert seen == {"attack": 7, "kev": 7, "lolbas": 7}


def test_search_reports_total_matches_alongside_returned_rows(monkeypatch) -> None:
    """M8: a caller must be able to tell 1-of-1 from 1-of-400."""
    monkeypatch.setitem(
        SEARCH_SOURCES,
        "lolbas",
        lambda query, limit: {
            "ok": True,
            "tool": "lolbas_search",
            "query": {},
            "data": {"match_count": 400, "returned": 1, "matches": [{"name": "a"}]},
            "error": None,
        },
    )

    entry = search("cert", source="lolbas")["data"]["sources"]["lolbas"]

    assert entry["match_count"] == 400
    assert entry["returned"] == 1
    assert len(entry["matches"]) == 1


def test_search_attributes_a_failing_source_without_failing_the_call(monkeypatch) -> None:
    monkeypatch.setitem(
        SEARCH_SOURCES,
        "kev",
        lambda query, limit: {
            "ok": False,
            "tool": "kev_search",
            "query": {},
            "data": None,
            "error": {"code": "not_found", "message": "Snapshot missing.", "details": None},
        },
    )

    result = search("cert")

    assert result["ok"] is True
    assert result["data"]["sources"]["kev"] == {
        "ok": False,
        "code": "not_found",
        "message": "Snapshot missing.",
    }
    assert result["data"]["source_summary"]["failed"] >= 1


def test_search_does_not_score_across_sources() -> None:
    assert not [name for name in dir(lookup_module) if "rank" in name or "merge" in name]
