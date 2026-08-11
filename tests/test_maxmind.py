import time

import pytest

from threatsyft.enrichment import maxmind

CITY_RECORD = {
    "country": {"iso_code": "DE", "names": {"en": "Germany", "de": "Deutschland"}},
    "city": {"names": {"en": "Frankfurt am Main"}},
    "subdivisions": [{"iso_code": "HE", "names": {"en": "Hesse"}}],
    "postal": {"code": "60313"},
    "location": {"latitude": 50.1188, "longitude": 8.6843, "time_zone": "Europe/Berlin"},
}

ASN_RECORD = {
    "autonomous_system_number": 205100,
    "autonomous_system_organization": "F3 Netze e.V.",
}


class _FakeMetadata:
    def __init__(self, build_epoch: int) -> None:
        self.build_epoch = build_epoch


class _FakeReader:
    """Stands in for maxminddb.Reader; only get/metadata/close are used."""

    def __init__(self, record, build_epoch: int) -> None:
        self._record = record
        self._build_epoch = build_epoch
        self.closed = False

    def get(self, _ip):
        return self._record

    def metadata(self):
        return _FakeMetadata(self._build_epoch)

    def close(self):
        self.closed = True


@pytest.fixture(autouse=True)
def clear_reader_cache():
    maxmind._readers.clear()
    yield
    maxmind._readers.clear()


@pytest.fixture
def databases(tmp_path, monkeypatch):
    """Point config at real files on disk and stub the reader they open."""
    city_path = tmp_path / "GeoLite2-City.mmdb"
    asn_path = tmp_path / "GeoLite2-ASN.mmdb"
    city_path.write_bytes(b"not-really-a-database")
    asn_path.write_bytes(b"not-really-a-database")

    monkeypatch.setattr(maxmind, "get_maxmind_city_path", lambda: city_path)
    monkeypatch.setattr(maxmind, "get_maxmind_asn_path", lambda: asn_path)

    build_epoch = int(time.time())
    readers = {
        str(city_path): _FakeReader(CITY_RECORD, build_epoch),
        str(asn_path): _FakeReader(ASN_RECORD, build_epoch),
    }
    monkeypatch.setattr(maxmind.maxminddb, "open_database", lambda path: readers[str(path)])
    return {"city": city_path, "asn": asn_path, "readers": readers}


def test_lookup_flattens_city_and_asn(databases) -> None:
    result = maxmind.maxmind_ip_lookup("45.83.192.4")

    assert result["ok"] is True
    data = result["data"]
    assert data["country_name"] == "Germany"
    assert data["country_code"] == "DE"
    assert data["region"] == "Hesse"
    assert data["city"] == "Frankfurt am Main"
    assert data["zipcode"] == "60313"
    assert data["latitude"] == 50.1188
    assert data["time_zone"] == "Europe/Berlin"
    assert data["asn"] == 205100
    assert data["organization"] == "F3 Netze e.V."
    assert data["source"] == "maxmind"


def test_lookup_reports_the_databases_own_build_date(databases) -> None:
    """Age comes from MaxMind's build stamp, not this machine's file mtime."""
    freshness = maxmind.maxmind_ip_lookup("45.83.192.4")["data"]["database"]

    assert freshness["age_days"] == 0
    assert freshness["stale"] is False
    assert freshness["stale_after_days"] == maxmind.STALE_AFTER_DAYS


def test_an_old_database_is_flagged_stale(tmp_path, monkeypatch) -> None:
    city_path = tmp_path / "GeoLite2-City.mmdb"
    city_path.write_bytes(b"x")
    monkeypatch.setattr(maxmind, "get_maxmind_city_path", lambda: city_path)
    monkeypatch.setattr(maxmind, "get_maxmind_asn_path", lambda: tmp_path / "missing.mmdb")

    old_epoch = int(time.time()) - (400 * 86400)
    monkeypatch.setattr(
        maxmind.maxminddb, "open_database", lambda _p: _FakeReader(CITY_RECORD, old_epoch)
    )

    freshness = maxmind.maxmind_ip_lookup("45.83.192.4")["data"]["database"]

    assert freshness["age_days"] >= 399
    assert freshness["stale"] is True


def test_missing_city_database_names_the_command_to_run(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(maxmind, "get_maxmind_city_path", lambda: tmp_path / "absent.mmdb")

    result = maxmind.maxmind_ip_lookup("8.8.8.8")

    assert result["ok"] is False
    assert result["error"]["code"] == "not_found"
    assert result["error"]["details"]["setup_command"] == "threatsyft-update maxmind"


def test_missing_asn_database_still_returns_location(tmp_path, monkeypatch) -> None:
    """Half the answer beats none, as long as the gap is named."""
    city_path = tmp_path / "GeoLite2-City.mmdb"
    city_path.write_bytes(b"x")
    monkeypatch.setattr(maxmind, "get_maxmind_city_path", lambda: city_path)
    monkeypatch.setattr(maxmind, "get_maxmind_asn_path", lambda: tmp_path / "absent.mmdb")
    monkeypatch.setattr(
        maxmind.maxminddb, "open_database", lambda _p: _FakeReader(CITY_RECORD, int(time.time()))
    )

    data = maxmind.maxmind_ip_lookup("45.83.192.4")["data"]

    assert data["country_name"] == "Germany"
    assert data["asn"] is None
    assert "ASN database has not been downloaded" in data["asn_unavailable"]


def test_address_absent_from_the_database_is_not_an_error(tmp_path, monkeypatch) -> None:
    city_path = tmp_path / "GeoLite2-City.mmdb"
    city_path.write_bytes(b"x")
    monkeypatch.setattr(maxmind, "get_maxmind_city_path", lambda: city_path)
    monkeypatch.setattr(maxmind, "get_maxmind_asn_path", lambda: tmp_path / "absent.mmdb")
    monkeypatch.setattr(
        maxmind.maxminddb, "open_database", lambda _p: _FakeReader(None, int(time.time()))
    )

    result = maxmind.maxmind_ip_lookup("10.0.0.1")

    assert result["ok"] is True
    assert result["data"]["country_name"] is None
    assert "not present in the GeoLite2 City database" in result["data"]["note"]


def test_corrupt_database_is_a_parse_error(tmp_path, monkeypatch) -> None:
    city_path = tmp_path / "GeoLite2-City.mmdb"
    city_path.write_bytes(b"x")
    monkeypatch.setattr(maxmind, "get_maxmind_city_path", lambda: city_path)

    def explode(_path):
        raise maxmind.maxminddb.InvalidDatabaseError("truncated")

    monkeypatch.setattr(maxmind.maxminddb, "open_database", explode)

    result = maxmind.maxmind_ip_lookup("8.8.8.8")

    assert result["ok"] is False
    assert result["error"]["code"] == "parse_error"


def test_invalid_ip_is_rejected_before_touching_the_database(monkeypatch) -> None:
    def explode(_path):
        raise AssertionError("no database should be opened for an invalid IP")

    monkeypatch.setattr(maxmind.maxminddb, "open_database", explode)

    result = maxmind.maxmind_ip_lookup("example.com")

    assert result["ok"] is False
    assert result["error"]["code"] == "invalid_input"


def test_reader_is_reused_across_lookups(databases) -> None:
    """A long-lived server must not remap the database on every call."""
    opened = []
    original = maxmind.maxminddb.open_database

    def counting_open(path):
        opened.append(str(path))
        return original(path)

    maxmind.maxminddb.open_database = counting_open
    try:
        maxmind.maxmind_ip_lookup("45.83.192.4")
        maxmind.maxmind_ip_lookup("8.8.8.8")
    finally:
        maxmind.maxminddb.open_database = original

    # Two lookups, two databases, one open each.
    assert sorted(opened) == sorted([str(databases["city"]), str(databases["asn"])])


def test_rewritten_database_is_reopened_and_the_old_reader_closed(databases) -> None:
    """An update replaces the file in place; the cache must notice and release it."""
    maxmind.maxmind_ip_lookup("45.83.192.4")
    first_reader = databases["readers"][str(databases["city"])]

    replacement = _FakeReader(
        {"country": {"iso_code": "FR", "names": {"en": "France"}}}, int(time.time())
    )
    databases["readers"][str(databases["city"])] = replacement
    # Bump the mtime the way an update would.
    future = time.time() + 10
    import os

    os.utime(databases["city"], (future, future))

    data = maxmind.maxmind_ip_lookup("45.83.192.4")["data"]

    assert data["country_code"] == "FR"
    assert first_reader.closed is True
