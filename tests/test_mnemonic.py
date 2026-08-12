import httpx

from threatsyft.enrichment import mnemonic

# The shape mnemonic really returns, including the two timestamp fields that
# look right and are always zero on the open tier.
ROW = {
    "query": "platelet.rxrx.io",
    "answer": "93.184.216.34",
    "rrtype": "a",
    "rrclass": "in",
    "times": 37,
    "createdTimestamp": 1605713179372,
    "lastUpdatedTimestamp": 1730110849096,
    "firstSeenTimestamp": 0,
    "lastSeenTimestamp": 0,
    "minTtl": 300,
    "maxTtl": 300,
    "tlp": "white",
    "flags": ["partialResult"],
    "customer": None,
}


def _respond(status: int, payload=None, captured: dict | None = None):
    def fake_get(url, params=None, headers=None, timeout=None):
        if captured is not None:
            captured["url"] = url
            captured["params"] = params
        return httpx.Response(
            status, request=httpx.Request("GET", url), json=payload if payload is not None else {}
        )

    return fake_get


def test_records_carry_the_name_and_the_window(monkeypatch) -> None:
    monkeypatch.setattr(mnemonic.httpx, "get", _respond(200, {"data": [ROW], "count": 1}))

    result = mnemonic.mnemonic_pdns_lookup("93.184.216.34")

    assert result["ok"] is True
    record = result["data"]["records"][0]
    assert record["domain"] == "platelet.rxrx.io"
    assert record["rrtype"] == "a"
    assert record["observations"] == 37
    assert record["first_seen"].startswith("2020-11-18")
    assert record["last_seen"].startswith("2024-10-28")


def test_the_zeroed_timestamp_fields_are_not_used(monkeypatch) -> None:
    """firstSeenTimestamp/lastSeenTimestamp exist and are 0; reading them gives 1970."""
    monkeypatch.setattr(mnemonic.httpx, "get", _respond(200, {"data": [ROW]}))

    record = mnemonic.mnemonic_pdns_lookup("93.184.216.34")["data"]["records"][0]

    assert not record["first_seen"].startswith("1970")
    assert not record["last_seen"].startswith("1970")


def test_a_missing_timestamp_is_omitted_rather_than_epoch_zero(monkeypatch) -> None:
    row = {**ROW, "createdTimestamp": 0, "lastUpdatedTimestamp": None}
    monkeypatch.setattr(mnemonic.httpx, "get", _respond(200, {"data": [row]}))

    record = mnemonic.mnemonic_pdns_lookup("93.184.216.34")["data"]["records"][0]

    assert "first_seen" not in record
    assert "last_seen" not in record
    assert record["domain"] == "platelet.rxrx.io"


def test_records_come_back_most_recently_seen_first(monkeypatch) -> None:
    old = {**ROW, "query": "old.example", "lastUpdatedTimestamp": 1500000000000}
    new = {**ROW, "query": "new.example", "lastUpdatedTimestamp": 1800000000000}
    monkeypatch.setattr(mnemonic.httpx, "get", _respond(200, {"data": [old, new]}))

    records = mnemonic.mnemonic_pdns_lookup("93.184.216.34")["data"]["records"]

    assert [record["domain"] for record in records] == ["new.example", "old.example"]


def test_a_capped_count_is_reported_as_capped(monkeypatch) -> None:
    """count stops at 1000, so a result sitting there is a floor, not a total."""
    monkeypatch.setattr(mnemonic.httpx, "get", _respond(200, {"data": [ROW], "count": 1000}))

    data = mnemonic.mnemonic_pdns_lookup("93.184.216.34")["data"]

    assert data["record_count"] == 1000
    assert data["record_count_is_capped"] is True


def test_a_real_count_is_not_reported_as_capped(monkeypatch) -> None:
    monkeypatch.setattr(mnemonic.httpx, "get", _respond(200, {"data": [ROW], "count": 12}))

    data = mnemonic.mnemonic_pdns_lookup("93.184.216.34")["data"]

    assert data["record_count"] == 12
    assert data["record_count_is_capped"] is False


def test_the_returned_rows_are_bounded(monkeypatch) -> None:
    rows = [{**ROW, "query": f"d{index}.example"} for index in range(200)]
    monkeypatch.setattr(mnemonic.httpx, "get", _respond(200, {"data": rows, "count": 1000}))

    data = mnemonic.mnemonic_pdns_lookup("93.184.216.34")["data"]

    assert data["returned"] == mnemonic.MAX_RECORDS


def test_the_page_limit_is_requested(monkeypatch) -> None:
    captured: dict = {}
    monkeypatch.setattr(mnemonic.httpx, "get", _respond(200, {"data": []}, captured))

    mnemonic.mnemonic_pdns_lookup("93.184.216.34")

    assert captured["params"] == {"limit": mnemonic.MAX_RECORDS}
    assert captured["url"].endswith("/93.184.216.34")


def test_an_address_with_no_history_is_not_an_error(monkeypatch) -> None:
    monkeypatch.setattr(mnemonic.httpx, "get", _respond(200, {"data": [], "count": 0}))

    result = mnemonic.mnemonic_pdns_lookup("155.117.189.76")

    assert result["ok"] is True
    assert result["data"]["records"] == []
    assert result["data"]["record_count"] == 0


def test_needs_no_api_key(monkeypatch) -> None:
    """mnemonic serves this anonymously; SecurityTrails charges for the equivalent."""
    captured: dict = {}
    monkeypatch.setattr(mnemonic.httpx, "get", _respond(200, {"data": []}, captured))

    assert mnemonic.mnemonic_pdns_lookup("8.8.8.8")["ok"] is True
    assert not hasattr(mnemonic, "API_KEY_NAME")


def test_an_invalid_ip_is_rejected_before_any_request(monkeypatch) -> None:
    def explode(*args, **kwargs):
        raise AssertionError("no request should be made for an invalid IP")

    monkeypatch.setattr(mnemonic.httpx, "get", explode)

    result = mnemonic.mnemonic_pdns_lookup("example.com")

    assert result["ok"] is False
    assert result["error"]["code"] == "invalid_input"


def test_rate_limit_is_mapped(monkeypatch) -> None:
    monkeypatch.setattr(mnemonic.httpx, "get", _respond(429))

    result = mnemonic.mnemonic_pdns_lookup("8.8.8.8")

    assert result["ok"] is False
    assert result["error"]["code"] == "rate_limited"


def test_a_non_list_data_field_is_survived(monkeypatch) -> None:
    monkeypatch.setattr(mnemonic.httpx, "get", _respond(200, {"data": None}))

    result = mnemonic.mnemonic_pdns_lookup("8.8.8.8")

    assert result["ok"] is True
    assert result["data"]["records"] == []
