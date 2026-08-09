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
    assert list(data["sources"]) == ["attack_technique", "lolbas"]


def test_lookup_routes_a_tactic_id_to_attack() -> None:
    data = lookup("TA0002")["data"]

    assert data["reference_type"] == "attack_tactic"
    assert list(data["sources"]) == ["attack_tactic"]
    assert data["sources"]["attack_tactic"]["ok"] is True


def test_lookup_asks_every_catalog_for_a_bare_name() -> None:
    """A bare name could be a binary, a tactic or a threat actor, so ask all three."""
    data = lookup("Certutil.exe")["data"]

    assert data["reference_type"] == "name"
    assert list(data["sources"]) == ["lolbas", "attack_tactic", "attack_actor"]
    assert data["sources"]["lolbas"]["ok"] is True


def test_lookup_finds_a_tactic_by_name_through_the_same_path() -> None:
    data = lookup("execution")["data"]

    assert data["reference_type"] == "name"
    assert data["sources"]["attack_tactic"]["ok"] is True


@pytest.mark.parametrize("value", ["TA0002", "ta0002", "  TA0002  "])
def test_tactic_ids_are_case_and_whitespace_insensitive(value) -> None:
    assert lookup(value)["data"]["sources"]["attack_tactic"]["ok"] is True


def test_lookup_covers_every_reference_type_it_classifies() -> None:
    """Each reference type reaches at least one source that can answer it."""
    for reference in ["T1059", "TA0002", "Certutil.exe", "execution", "G9001", "Fixture Bear"]:
        data = lookup(reference)["data"]
        assert data["source_summary"]["ok"] >= 1, reference


def test_lookup_normalizes_the_reference_it_echoes_back() -> None:
    result = lookup("  t1059  ")

    assert result["data"]["reference"] == "T1059"
    assert result["query"]["reference"] == "T1059"


def test_search_sources_are_all_callable() -> None:
    assert set(SEARCH_SOURCES) == {"attack", "actors", "kev", "lolbas"}
    for name, function in SEARCH_SOURCES.items():
        assert callable(function), name


# --- shared sources shape (§3.2), identical to enrich -------------------------


def test_lookup_and_search_share_the_enrich_sources_shape() -> None:
    for data in [lookup("T1059")["data"], search("cert")["data"]]:
        assert set(data["source_summary"]) == {"ok", "failed"}
        for name, entry in data["sources"].items():
            assert isinstance(entry["ok"], bool)
            if not entry["ok"]:
                assert set(entry) >= {"ok", "code", "message"}
            # Snapshot-backed sources also carry their age; live ones do not.
            assert "freshness" in entry or name == "nvd"


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

    assert list(data["sources"]) == ["attack", "actors", "kev", "lolbas"]
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

    for name in SEARCH_SOURCES:
        monkeypatch.setitem(SEARCH_SOURCES, name, record(name))

    search("cert", limit=7)

    assert seen == dict.fromkeys(SEARCH_SOURCES, 7)


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
    entry = result["data"]["sources"]["kev"]
    assert entry["ok"] is False
    assert entry["code"] == "not_found"
    assert entry["message"] == "Snapshot missing."
    assert result["data"]["source_summary"]["failed"] >= 1


def test_search_does_not_score_across_sources() -> None:
    assert not [name for name in dir(lookup_module) if "rank" in name or "merge" in name]


# --- threat actors ------------------------------------------------------------


def test_lookup_routes_a_group_id_to_the_actor_catalog() -> None:
    data = lookup("G9001")["data"]

    assert data["reference_type"] == "attack_actor"
    assert list(data["sources"]) == ["attack_actor"]
    assert data["sources"]["attack_actor"]["data"]["name"] == "Fixture Bear"


def test_lookup_finds_an_actor_by_name_or_alias() -> None:
    for name in ["Fixture Bear", "FIXTUREBEAR", "Test Panda"]:
        data = lookup(name)["data"]
        assert data["sources"]["attack_actor"]["ok"] is True, name
        assert data["sources"]["attack_actor"]["data"]["actor_id"] == "G9001", name


def test_an_actor_carries_the_techniques_it_uses_as_identities() -> None:
    """Same trimming rule as everywhere else: identity here, detail via lookup."""
    data = lookup("G9001")["data"]["sources"]["attack_actor"]["data"]

    assert data["technique_count"] >= 1
    for technique in data["techniques"]:
        assert set(technique) == {"technique_id", "name"}


def test_search_includes_actors_as_its_own_group() -> None:
    entry = search("Fixture", source="actors")["data"]["sources"]["actors"]

    assert entry["ok"] is True
    assert entry["match_count"] >= 1
    assert any(match["actor_id"] == "G9001" for match in entry["matches"])


def test_actor_search_matches_aliases_not_just_names() -> None:
    entry = search("Test Panda", source="actors")["data"]["sources"]["actors"]

    assert any(match["actor_id"] == "G9001" for match in entry["matches"])
