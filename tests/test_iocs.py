from threatsyft.knowledge.iocs import (
    MAX_CONTEXTS_PER_IOC,
    MAX_ITEMS_PER_TYPE,
    extract_iocs,
    normalize_defanged_text,
)

SAMPLE_TEXT = (
    "The actor staged payloads on hxxp://malicious[.]example/payload and beaconed to "
    "156.240.110.244 over port 443. Related infrastructure included bad-domain[.]example. "
    "The intrusion exploited CVE-2024-3400 and dropped d41d8cd98f00b204e9800998ecf8427e."
)


def _values(items: list[dict[str, str]]) -> set[str]:
    return {item["value"] for item in items}


def test_extract_iocs_returns_all_five_types() -> None:
    result = extract_iocs(SAMPLE_TEXT)
    iocs = result["data"]["iocs"]

    assert result["ok"] is True
    assert result["tool"] == "extract_iocs"
    assert set(iocs) == {"ips", "domains", "urls", "hashes", "cves"}
    assert _values(iocs["ips"]) == {"156.240.110.244"}
    assert "http://malicious.example/payload" in _values(iocs["urls"])
    assert "bad-domain.example" in _values(iocs["domains"])
    assert _values(iocs["cves"]) == {"CVE-2024-3400"}
    assert _values(iocs["hashes"]) == {"d41d8cd98f00b204e9800998ecf8427e"}


def test_extract_iocs_query_carries_length_not_the_untrusted_text() -> None:
    result = extract_iocs(SAMPLE_TEXT)

    assert result["query"] == {"text_length": len(SAMPLE_TEXT)}


def test_extract_iocs_entries_carry_values_only() -> None:
    iocs = extract_iocs(SAMPLE_TEXT)["data"]["iocs"]

    for items in iocs.values():
        for item in items:
            assert set(item) == {"value"}


def test_extract_iocs_keeps_source_text_out_of_the_ioc_values() -> None:
    data = extract_iocs(SAMPLE_TEXT)["data"]

    context = data["untrusted_context"]["156.240.110.244"][0]
    assert "beaconed to" in context
    assert data["iocs"]["ips"] == [{"value": "156.240.110.244"}]

    del data["untrusted_context"]
    assert data["iocs"]["ips"] == [{"value": "156.240.110.244"}]


def test_extract_iocs_counts_match_the_returned_items() -> None:
    data = extract_iocs(SAMPLE_TEXT)["data"]

    assert data["ioc_counts"] == {ioc_type: len(items) for ioc_type, items in data["iocs"].items()}
    assert data["ioc_counts"]["ips"] == 1
    assert data["ioc_counts"]["cves"] == 1


def test_extract_iocs_returns_empty_lists_for_text_without_indicators() -> None:
    data = extract_iocs("No indicators appear anywhere in this sentence.")["data"]

    assert data["iocs"] == {"ips": [], "domains": [], "urls": [], "hashes": [], "cves": []}
    assert data["ioc_counts"] == {"ips": 0, "domains": 0, "urls": 0, "hashes": 0, "cves": 0}
    assert data["untrusted_context"] == {}


def test_extract_iocs_rejects_empty_text() -> None:
    result = extract_iocs("   \n  ")

    assert result["ok"] is False
    assert result["error"]["code"] == "invalid_input"
    assert result["data"] is None


def test_normalize_defanged_text_restores_common_markers() -> None:
    defanged = "hxxp://a[.]test HXXPS://b(.)test c{.}test host[:]8080"

    assert normalize_defanged_text(defanged) == "http://a.test https://b.test c.test host:8080"


def test_extract_iocs_normalizes_case_and_trailing_punctuation() -> None:
    iocs = extract_iocs(
        "Seen at cve-2026-11111, hash D41D8CD98F00B204E9800998ECF8427E, "
        "and https://Example.test/a), plus EVIL.Example."
    )["data"]["iocs"]

    assert _values(iocs["cves"]) == {"CVE-2026-11111"}
    assert _values(iocs["hashes"]) == {"d41d8cd98f00b204e9800998ecf8427e"}
    assert "https://Example.test/a" in _values(iocs["urls"])
    assert "evil.example" in _values(iocs["domains"])


def test_extract_iocs_drops_dotted_quads_that_are_not_valid_addresses() -> None:
    iocs = extract_iocs("Traffic to 999.888.777.666 and to 8.8.8.8 was observed.")["data"]["iocs"]

    assert _values(iocs["ips"]) == {"8.8.8.8"}


def test_extract_iocs_caps_contexts_per_indicator() -> None:
    text = " ".join(f"Sighting {index} involved 8.8.8.8 traffic." for index in range(10))

    contexts = extract_iocs(text)["data"]["untrusted_context"]["8.8.8.8"]

    assert len(contexts) == MAX_CONTEXTS_PER_IOC


def test_extract_iocs_caps_items_per_type() -> None:
    text = " ".join(f"CVE-2024-{1000 + index}" for index in range(MAX_ITEMS_PER_TYPE + 10))

    data = extract_iocs(text)["data"]
    cves = data["iocs"]["cves"]

    assert len(cves) == MAX_ITEMS_PER_TYPE
    assert data["ioc_counts"]["cves"] == MAX_ITEMS_PER_TYPE
    assert cves[0]["value"] == "CVE-2024-1000"
    assert cves[-1]["value"] == f"CVE-2024-{1000 + MAX_ITEMS_PER_TYPE - 1}"
    assert set(data["untrusted_context"]) == _values(cves)


def test_extract_iocs_context_is_a_collapsed_window_not_the_whole_text() -> None:
    text = "x" * 500 + " beacon to 8.8.8.8 seen\n\there " + "y" * 500

    context = extract_iocs(text)["data"]["untrusted_context"]["8.8.8.8"][0]

    assert "8.8.8.8" in context
    assert "seen here" in context
    assert len(context) < len(text)
