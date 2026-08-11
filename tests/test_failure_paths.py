"""Failure paths: corrupt snapshots, provider errors, and secret containment.

These are the cases a user hits when something is broken rather than absent, and
they are the ones least likely to be exercised by hand.
"""

import httpx
import pytest

from threatsyft.enrichment import virustotal
from threatsyft.enrichment.enrich import DISPATCH, enrich
from threatsyft.enrichment.providers import PROVIDERS
from threatsyft.knowledge import attack
from threatsyft.knowledge.lookup import lookup, search

REQUEST = httpx.Request("GET", "https://provider.test/x")


# --- a snapshot that exists but cannot be used -------------------------------


CORRUPT_SNAPSHOTS = {
    "truncated json": '{"objects": [{"type": "attack-pat',
    "valid json, wrong shape": '{"nope": 1}',
    "empty file": "",
    "top level array": "[]",
    "objects not a list": '{"objects": {}}',
    "objects of wrong type": '{"objects": [1, 2, 3]}',
}


@pytest.mark.parametrize(("name", "content"), CORRUPT_SNAPSHOTS.items())
def test_a_corrupt_snapshot_is_a_structured_error_not_a_crash(
    name, content, tmp_path, monkeypatch
) -> None:
    snapshot = tmp_path / "attack.json"
    snapshot.write_text(content)
    monkeypatch.setenv("THREATSYFT_ATTACK_STIX_PATH", str(snapshot))

    result = attack.attack_technique_lookup("T1059")

    assert result["ok"] is False, name
    assert result["error"]["code"] in {"parse_error", "not_found"}, name
    assert result["error"]["details"]["snapshot_path"] == str(snapshot)


def test_a_directory_where_a_snapshot_belongs_is_reported(tmp_path, monkeypatch) -> None:
    directory = tmp_path / "attack.json"
    directory.mkdir()
    monkeypatch.setenv("THREATSYFT_ATTACK_STIX_PATH", str(directory))

    result = attack.attack_technique_lookup("T1059")

    assert result["ok"] is False
    assert result["error"]["code"] == "upstream_error"


def test_lookup_survives_a_corrupt_snapshot_and_attributes_it(tmp_path, monkeypatch) -> None:
    """One unusable source must not fail the whole call."""
    snapshot = tmp_path / "attack.json"
    snapshot.write_text("{ broken")
    monkeypatch.setenv("THREATSYFT_ATTACK_STIX_PATH", str(snapshot))
    monkeypatch.setenv("THREATSYFT_LOLBAS_PATH", "tests/fixtures/lolbas-mini.json")

    result = lookup("T1059")

    assert result["ok"] is True
    assert result["data"]["sources"]["attack_technique"]["ok"] is False
    assert result["data"]["sources"]["attack_technique"]["code"] == "parse_error"
    assert result["data"]["sources"]["lolbas"]["ok"] is True


def test_search_reports_every_source_broken_without_failing(tmp_path, monkeypatch) -> None:
    for var in [
        "THREATSYFT_ATTACK_STIX_PATH",
        "THREATSYFT_CISA_KEV_PATH",
        "THREATSYFT_LOLBAS_PATH",
    ]:
        monkeypatch.setenv(var, str(tmp_path / "missing.json"))

    result = search("anything")

    assert result["ok"] is True
    assert result["data"]["source_summary"]["ok"] == 0
    for entry in result["data"]["sources"].values():
        assert entry["ok"] is False
        assert entry["freshness"]["snapshot_present"] is False


# --- provider HTTP failures map to the shared error vocabulary ---------------


PROVIDER_FAILURES = [
    (
        "401 unauthorized",
        lambda: httpx.Response(401, request=REQUEST, json={}),
        "authentication_error",
    ),
    (
        "403 forbidden",
        lambda: httpx.Response(403, request=REQUEST, json={}),
        "authentication_error",
    ),
    ("429 rate limited", lambda: httpx.Response(429, request=REQUEST, json={}), "rate_limited"),
    ("500 server error", lambda: httpx.Response(500, request=REQUEST, json={}), "upstream_error"),
    ("503 unavailable", lambda: httpx.Response(503, request=REQUEST, json={}), "upstream_error"),
    (
        "body is not json",
        lambda: httpx.Response(200, request=REQUEST, text="<html>"),
        "parse_error",
    ),
]


@pytest.mark.parametrize(("name", "response", "expected"), PROVIDER_FAILURES)
def test_provider_http_failures_map_to_expected_codes(
    name, response, expected, monkeypatch
) -> None:
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-key")
    monkeypatch.setattr(virustotal.httpx, "get", lambda *a, **k: response())

    result = virustotal.virustotal_ip_report("8.8.8.8")

    assert result["ok"] is False, name
    assert result["error"]["code"] == expected, name


@pytest.mark.parametrize(
    ("exception", "expected"),
    [
        (httpx.TimeoutException("slow"), "timeout"),
        (httpx.ConnectError("refused"), "network_error"),
        (httpx.ReadError("reset"), "network_error"),
    ],
)
def test_provider_transport_failures_map_to_expected_codes(
    exception, expected, monkeypatch
) -> None:
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-key")

    def raise_it(*args, **kwargs):
        raise exception

    monkeypatch.setattr(virustotal.httpx, "get", raise_it)

    assert virustotal.virustotal_ip_report("8.8.8.8")["error"]["code"] == expected


def test_enrich_degrades_rather_than_failing_when_providers_break(monkeypatch) -> None:
    """A rate limit on one source is a partial answer, not a failed call."""

    def stub(result):
        return lambda _target: result

    monkeypatch.setitem(
        DISPATCH,
        "ip",
        (
            ("abuseipdb", stub({"ok": True, "tool": "s", "query": {}, "data": {}, "error": None})),
            (
                "virustotal",
                stub(
                    {
                        "ok": False,
                        "tool": "s",
                        "query": {},
                        "data": None,
                        "error": {"code": "rate_limited", "message": "429", "details": None},
                    }
                ),
            ),
        ),
    )

    result = enrich("8.8.8.8")

    assert result["ok"] is True
    assert result["data"]["source_summary"] == {"ok": 1, "failed": 1}
    assert result["data"]["sources"]["virustotal"]["code"] == "rate_limited"


# --- M6: no API key value may appear in any tool response --------------------


ALL_KEY_NAMES = sorted({name for keys in PROVIDERS.values() for name in keys})


def test_no_api_key_value_appears_in_any_tool_response(monkeypatch) -> None:
    """enrichment_status declares secret_values_returned: false; this is the check behind it.

    Every key is set to a distinctive value, every tool is called, and the whole
    response is searched. Covers the error paths too, since a failing provider is
    where a URL or message is most likely to carry a key.
    """
    from threatsyft.enrichment.status import enrichment_status
    from threatsyft.knowledge.iocs import extract_iocs
    from threatsyft.knowledge.status import knowledge_status

    sentinels = {}
    for index, name in enumerate(ALL_KEY_NAMES):
        value = f"SENTINEL-{index}-{name}-VALUE"
        sentinels[name] = value
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("NVD_API_KEY", "SENTINEL-NVD-VALUE")
    sentinels["NVD_API_KEY"] = "SENTINEL-NVD-VALUE"

    def failing_get(*args, **kwargs):
        raise httpx.ConnectError("refused")

    for module_name in [
        "abuseipdb",
        "greynoise",
        "virustotal",
        "securitytrails",
        "shodan",
        "alienvault",
        "safebrowsing",
    ]:
        module = __import__(f"threatsyft.enrichment.{module_name}", fromlist=["httpx"])
        monkeypatch.setattr(module.httpx, "get", failing_get, raising=False)
        monkeypatch.setattr(module.httpx, "post", failing_get, raising=False)

    responses = [
        str(enrichment_status()),
        str(knowledge_status()),
        str(extract_iocs("8.8.8.8 and evil.example")),
        str(enrich("8.8.8.8")),
        str(enrich("example.com")),
        str(enrich("https://example.com/a")),
        str(enrich("d41d8cd98f00b204e9800998ecf8427e")),
        str(lookup("T1059")),
        str(search("cert")),
    ]

    blob = "\n".join(responses)
    leaked = [name for name, value in sentinels.items() if value in blob]
    assert leaked == [], f"API key values leaked into tool responses: {leaked}"
