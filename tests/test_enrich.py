import importlib
import pkgutil

import pytest

from threatsyft.core import ErrorCode
from threatsyft.enrichment.enrich import DISPATCH, enrich
from threatsyft.enrichment.models import InputValidationError, classify_indicator

EXPECTED_DISPATCH = {
    "ip": [
        "abuseipdb",
        "greynoise",
        "sentinel",
        "virustotal",
        "shodan",
        "censys",
        "maxmind",
        "mnemonic",
        "alienvault",
        "rdap",
        "whois",
    ],
    "domain": ["dns", "rdap", "whois", "virustotal", "securitytrails", "alienvault"],
    "url": ["google_safebrowsing", "virustotal", "urlscan", "alienvault"],
    "hash": ["virustotal", "hybrid_analysis", "alienvault"],
}


def _stub_dispatch(monkeypatch, indicator_type, outcomes):
    """Replace one dispatch row with stubs returning canned envelopes."""

    def make(result):
        return lambda _target: result

    monkeypatch.setitem(
        DISPATCH,
        indicator_type,
        tuple((name, make(result)) for name, result in outcomes),
    )


def _ok(data):
    return {"ok": True, "tool": "stub", "query": {}, "data": data, "error": None}


def _failed(code, message):
    return {
        "ok": False,
        "tool": "stub",
        "query": {},
        "data": None,
        "error": {"code": code, "message": message, "details": None},
    }


# --- the dispatch table is pure data, so assert it directly -------------------


def test_dispatch_covers_exactly_the_four_indicator_types() -> None:
    assert set(DISPATCH) == {"ip", "domain", "url", "hash"}


@pytest.mark.parametrize(("indicator_type", "expected"), EXPECTED_DISPATCH.items())
def test_dispatch_row_matches_expected_sources(indicator_type, expected) -> None:
    assert [name for name, _ in DISPATCH[indicator_type]] == expected


def test_every_dispatch_entry_is_callable() -> None:
    for sources in DISPATCH.values():
        for name, function in sources:
            assert callable(function), name


def test_every_indicator_type_has_at_least_one_source() -> None:
    for indicator_type, sources in DISPATCH.items():
        assert sources, indicator_type


def test_source_names_are_unique_within_a_row() -> None:
    for indicator_type, sources in DISPATCH.items():
        names = [name for name, _ in sources]
        assert len(names) == len(set(names)), indicator_type


def test_every_classifiable_type_has_a_dispatch_row() -> None:
    for value in ["8.8.8.8", "example.com", "https://example.com/a", "d41d8cd9" * 4]:
        indicator_type, _ = classify_indicator(value)
        assert indicator_type in DISPATCH


# --- classification -----------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected_type", "expected_value"),
    [
        ("8.8.8.8", "ip", "8.8.8.8"),
        ("2001:4860:4860::8888", "ip", "2001:4860:4860::8888"),
        ("https://Example.com/path", "url", "https://Example.com/path"),
        ("D41D8CD98F00B204E9800998ECF8427E", "hash", "d41d8cd98f00b204e9800998ecf8427e"),
        ("Example.COM", "domain", "example.com"),
    ],
)
def test_classify_indicator_covers_all_four_types(value, expected_type, expected_value) -> None:
    assert classify_indicator(value) == (expected_type, expected_value)


@pytest.mark.parametrize("value", ["", "   ", "not a valid indicator", "!!!"])
def test_classify_indicator_rejects_unclassifiable_input(value) -> None:
    with pytest.raises(InputValidationError):
        classify_indicator(value)


# --- envelope shape (§3.2) ----------------------------------------------------


def test_enrich_returns_one_sources_map_keyed_by_source(monkeypatch) -> None:
    _stub_dispatch(
        monkeypatch,
        "ip",
        [
            ("abuseipdb", _ok({"score": 0})),
            ("greynoise", _ok({"noise": False})),
            ("virustotal", _failed("rate_limited", "VirusTotal rate limit was reached.")),
        ],
    )

    result = enrich("8.8.8.8")
    data = result["data"]

    assert result["ok"] is True
    assert result["tool"] == "enrich"
    assert data["indicator"] == "8.8.8.8"
    assert data["indicator_type"] == "ip"
    assert data["source_summary"] == {"ok": 2, "failed": 1}
    assert data["sources"]["abuseipdb"] == {"ok": True, "data": {"score": 0}}
    assert data["sources"]["virustotal"] == {
        "ok": False,
        "code": "rate_limited",
        "message": "VirusTotal rate limit was reached.",
    }


def test_enrich_source_order_is_fixed_and_independent_of_arrival(monkeypatch) -> None:
    _stub_dispatch(
        monkeypatch,
        "ip",
        [("abuseipdb", _ok({})), ("greynoise", _failed("timeout", "slow")), ("shodan", _ok({}))],
    )

    sources = enrich("8.8.8.8")["data"]["sources"]

    assert list(sources) == ["abuseipdb", "greynoise", "shodan"]


def test_enrich_summary_counts_match_the_sources_map(monkeypatch) -> None:
    _stub_dispatch(
        monkeypatch,
        "domain",
        [("dns", _ok({})), ("rdap", _failed("timeout", "slow")), ("whois", _ok({}))],
    )

    data = enrich("example.com")["data"]
    summary = data["source_summary"]

    assert summary["ok"] == sum(1 for e in data["sources"].values() if e["ok"])
    assert summary["failed"] == sum(1 for e in data["sources"].values() if not e["ok"])
    assert summary["ok"] + summary["failed"] == len(data["sources"])


def test_enrich_normalizes_the_indicator_it_echoes_back(monkeypatch) -> None:
    _stub_dispatch(monkeypatch, "domain", [("dns", _ok({}))])

    result = enrich("  Example.COM  ")

    assert result["query"]["indicator"] == "example.com"
    assert result["data"]["indicator"] == "example.com"


def test_enrich_passes_the_normalized_value_to_every_source(monkeypatch) -> None:
    seen = []
    monkeypatch.setitem(
        DISPATCH, "domain", (("dns", lambda target: seen.append(target) or _ok({})),)
    )

    enrich("  Example.COM  ")

    assert seen == ["example.com"]


# --- ok semantics, one test per §3.3 row --------------------------------------


def test_invalid_input_is_a_tool_failure() -> None:
    result = enrich("not a valid indicator")

    assert result["ok"] is False
    assert result["error"]["code"] == "invalid_input"
    assert result["data"] is None


@pytest.mark.parametrize(
    ("value", "detected_type"),
    [
        ("CVE-2024-1234", "cve"),
        ("T1059", "attack_technique"),
        ("T1059.001", "attack_technique"),
    ],
)
def test_right_input_wrong_tool_redirects(value, detected_type) -> None:
    result = enrich(value)

    assert result["ok"] is False
    assert result["error"]["code"] == "invalid_input"
    assert result["error"]["details"]["detected_type"] == detected_type
    assert result["error"]["details"]["suggested_tool"] == "lookup"


def test_some_sources_failing_is_still_a_successful_call(monkeypatch) -> None:
    _stub_dispatch(
        monkeypatch,
        "ip",
        [("abuseipdb", _ok({})), ("greynoise", _failed("timeout", "slow"))],
    )

    result = enrich("8.8.8.8")

    assert result["ok"] is True
    assert result["error"] is None
    assert result["data"]["source_summary"] == {"ok": 1, "failed": 1}


def test_every_source_failing_is_still_a_successful_call(monkeypatch) -> None:
    """Retrying will not fix "the world had no data", so it is not a tool error."""
    _stub_dispatch(
        monkeypatch,
        "hash",
        [
            ("virustotal", _failed("missing_api_key", "VIRUSTOTAL_API_KEY is not configured.")),
            ("alienvault", _failed("missing_api_key", "ALIENVAULT_API_KEY is not configured.")),
        ],
    )

    result = enrich("d41d8cd98f00b204e9800998ecf8427e")

    assert result["ok"] is True
    assert result["error"] is None
    assert result["data"]["source_summary"] == {"ok": 0, "failed": 2}
    assert all(entry["ok"] is False for entry in result["data"]["sources"].values())


def test_no_sources_for_a_type_is_still_a_successful_call(monkeypatch) -> None:
    monkeypatch.setitem(DISPATCH, "url", ())

    result = enrich("https://example.com/a")

    assert result["ok"] is True
    assert result["data"]["sources"] == {}
    assert result["data"]["source_summary"] == {"ok": 0, "failed": 0}


# --- error codes stay inside the shared vocabulary ----------------------------


def test_redirect_uses_a_declared_error_code() -> None:
    assert enrich("CVE-2024-1234")["error"]["code"] in ErrorCode.__args__


def test_enrich_aggregates_nothing_across_sources(monkeypatch) -> None:
    """H7: no scalar judgement anywhere. The caller is the reasoning layer."""
    _stub_dispatch(
        monkeypatch,
        "ip",
        [("abuseipdb", _ok({"abuse_confidence_score": 100})), ("greynoise", _ok({"noise": True}))],
    )

    data = enrich("8.8.8.8")["data"]

    assert "overall_verdict" not in data
    assert "confidence" not in data
    assert "key_signals" not in data
    # Each source's own fields arrive untouched; nothing is reduced across them.
    assert data["sources"]["abuseipdb"]["data"] == {"abuse_confidence_score": 100}


def test_no_enrichment_module_computes_a_verdict() -> None:
    """The doctrine is project-wide, not enrich.py-wide.

    Asserting this against enrich.py alone passed for as long as it existed,
    because enrich.py never had a scoring helper. Six providers did: each had
    grown its own threshold table turning provider numbers into malicious /
    suspicious / benign, which is exactly the value that changes meaning when a
    source degrades. Walk the whole package instead of one module.
    """
    package = importlib.import_module("threatsyft.enrichment")

    offenders = []
    for module_info in pkgutil.iter_modules(package.__path__):
        module = importlib.import_module(f"{package.__name__}.{module_info.name}")
        offenders += [
            f"{module_info.name}.{name}"
            for name in vars(module)
            if "verdict" in name.lower() or "confidence" in name.lower()
        ]

    assert offenders == [], f"scoring helpers found: {offenders}"
