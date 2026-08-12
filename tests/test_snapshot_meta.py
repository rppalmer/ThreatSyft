"""Conditional downloads, and the age semantics that depend on them.

The trap these guard: once an updater can skip a download, file mtime stops
being a usable age. A snapshot that upstream confirms is current would sit at a
frozen mtime and drift toward looking abandoned.
"""

import json
import time
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

import httpx
import pytest

from threatsyft.knowledge import snapshot_fetch, update_kev, update_lolbas
from threatsyft.knowledge.freshness import snapshot_freshness
from threatsyft.snapshot_meta import (
    conditional_headers,
    meta_path,
    parse_timestamp,
    read_meta,
    write_meta,
)

UTC = ZoneInfo("UTC")

KEV_BODY = {
    "title": "KEV",
    "catalogVersion": "2026.08.07",
    "dateReleased": "2026-08-07T16:45:47.0648Z",
    "vulnerabilities": [{"cveID": "CVE-2024-3400"}],
}


@pytest.fixture
def kev_snapshot(tmp_path, monkeypatch):
    path = tmp_path / "kev.json"
    monkeypatch.setenv("THREATSYFT_CISA_KEV_PATH", str(path))
    monkeypatch.setenv("THREATSYFT_CISA_KEV_URL", "https://example.com/kev.json")
    return path


# --- the sidecar itself -------------------------------------------------------


def test_missing_sidecar_reads_as_empty(tmp_path) -> None:
    assert read_meta(tmp_path / "nothing.json") == {}


def test_malformed_sidecar_reads_as_empty(tmp_path) -> None:
    """A corrupt sidecar must degrade to mtime, never raise into a lookup."""
    snapshot = tmp_path / "kev.json"
    meta_path(snapshot).write_text("{not json", encoding="utf-8")

    assert read_meta(snapshot) == {}


def test_write_then_read_round_trips(tmp_path) -> None:
    snapshot = tmp_path / "kev.json"
    write_meta(snapshot, content_date="2026-08-07T00:00:00+00:00", etag='"abc"')

    meta = read_meta(snapshot)
    assert meta["content_date"] == "2026-08-07T00:00:00+00:00"
    assert meta["etag"] == '"abc"'
    assert parse_timestamp(meta["checked_at"]) is not None


def test_both_validators_are_sent_when_known(tmp_path) -> None:
    """GitHub honours the ETag and CISA honours the date; sending both covers all."""
    snapshot = tmp_path / "kev.json"
    write_meta(snapshot, etag='"abc"', last_modified="Tue, 11 Aug 2026 18:59:43 GMT")

    headers = conditional_headers(snapshot)

    assert headers["If-None-Match"] == '"abc"'
    assert headers["If-Modified-Since"] == "Tue, 11 Aug 2026 18:59:43 GMT"


def test_no_validators_means_no_conditional_headers(tmp_path) -> None:
    assert conditional_headers(tmp_path / "kev.json") == {}


def test_http_dates_parse_as_well_as_iso() -> None:
    """LOLBAS has no date of its own, so its content date is an HTTP date."""
    assert parse_timestamp("Fri, 31 Jul 2026 20:01:07 GMT") is not None
    assert parse_timestamp("2026-08-07T16:45:47.0648Z") is not None
    assert parse_timestamp("not a date") is None
    assert parse_timestamp(None) is None


# --- conditional fetching -----------------------------------------------------


def test_first_download_records_the_publish_date(monkeypatch, kev_snapshot) -> None:
    def fake_get(url, headers=None, timeout=None, follow_redirects=None):
        return httpx.Response(
            200,
            request=httpx.Request("GET", url),
            json=KEV_BODY,
            headers={"ETag": '"v1"', "Last-Modified": "Fri, 07 Aug 2026 16:45:47 GMT"},
        )

    monkeypatch.setattr(snapshot_fetch.httpx, "get", fake_get)

    result = update_kev.update_kev_snapshot()

    assert result["data"]["downloaded"] is True
    # CISA's own release date, not the time this machine wrote the file.
    assert read_meta(kev_snapshot)["content_date"] == "2026-08-07T16:45:47.0648Z"
    assert read_meta(kev_snapshot)["etag"] == '"v1"'


def test_second_run_sends_the_validators_it_stored(monkeypatch, kev_snapshot) -> None:
    write_meta(kev_snapshot, etag='"v1"', last_modified="Fri, 07 Aug 2026 16:45:47 GMT")
    seen = []

    def fake_get(url, headers=None, timeout=None, follow_redirects=None):
        seen.append(headers or {})
        return httpx.Response(304, request=httpx.Request("GET", url))

    monkeypatch.setattr(snapshot_fetch.httpx, "get", fake_get)

    update_kev.update_kev_snapshot()

    assert seen[0]["If-None-Match"] == '"v1"'
    assert seen[0]["If-Modified-Since"] == "Fri, 07 Aug 2026 16:45:47 GMT"


def test_304_leaves_the_snapshot_untouched(monkeypatch, kev_snapshot) -> None:
    """The whole point: no rewrite means running servers keep their parse cache."""
    kev_snapshot.write_text(json.dumps(KEV_BODY), encoding="utf-8")
    original_mtime = kev_snapshot.stat().st_mtime
    write_meta(kev_snapshot, content_date=KEV_BODY["dateReleased"], etag='"v1"')
    time.sleep(0.01)

    monkeypatch.setattr(
        snapshot_fetch.httpx,
        "get",
        lambda url, **kw: httpx.Response(304, request=httpx.Request("GET", url)),
    )

    result = update_kev.update_kev_snapshot()

    assert result["ok"] is True
    assert result["data"]["downloaded"] is False
    assert kev_snapshot.stat().st_mtime == original_mtime


def test_304_still_counts_as_a_check(monkeypatch, kev_snapshot) -> None:
    """Without this the conditional fetch would slowly fake a stale snapshot."""
    kev_snapshot.write_text(json.dumps(KEV_BODY), encoding="utf-8")
    stale_check = (datetime.now(UTC) - timedelta(days=90)).isoformat()
    write_meta(kev_snapshot, content_date=KEV_BODY["dateReleased"], checked_at=None, etag='"v1"')
    # Force the recorded check far into the past.
    meta = read_meta(kev_snapshot)
    meta["checked_at"] = stale_check
    meta_path(kev_snapshot).write_text(json.dumps(meta), encoding="utf-8")
    assert snapshot_freshness("kev")["stale"] is True

    monkeypatch.setattr(
        snapshot_fetch.httpx,
        "get",
        lambda url, **kw: httpx.Response(304, request=httpx.Request("GET", url)),
    )

    update_kev.update_kev_snapshot()

    assert snapshot_freshness("kev")["stale"] is False
    # The validators survived the re-stamp, so the next run is still conditional.
    assert read_meta(kev_snapshot)["etag"] == '"v1"'


def test_304_keeps_the_recorded_publish_date(monkeypatch, kev_snapshot) -> None:
    kev_snapshot.write_text(json.dumps(KEV_BODY), encoding="utf-8")
    write_meta(kev_snapshot, content_date="2026-08-07T16:45:47.0648Z", etag='"v1"')

    monkeypatch.setattr(
        snapshot_fetch.httpx,
        "get",
        lambda url, **kw: httpx.Response(304, request=httpx.Request("GET", url)),
    )

    update_kev.update_kev_snapshot()

    assert read_meta(kev_snapshot)["content_date"] == "2026-08-07T16:45:47.0648Z"


def test_lolbas_falls_back_to_the_server_date(monkeypatch, tmp_path) -> None:
    """LOLBAS ships a bare list with nowhere to put a publish date."""
    path = tmp_path / "lolbas.json"
    monkeypatch.setenv("THREATSYFT_LOLBAS_PATH", str(path))
    monkeypatch.setenv("THREATSYFT_LOLBAS_URL", "https://example.com/lolbas.json")

    monkeypatch.setattr(
        snapshot_fetch.httpx,
        "get",
        lambda url, **kw: httpx.Response(
            200,
            request=httpx.Request("GET", url),
            json=[{"Name": "Certutil.exe"}],
            headers={"Last-Modified": "Fri, 31 Jul 2026 20:01:07 GMT"},
        ),
    )

    update_lolbas.update_lolbas_snapshot()

    assert read_meta(path)["content_date"] == "Fri, 31 Jul 2026 20:01:07 GMT"


# --- the age semantics --------------------------------------------------------


def test_age_comes_from_the_publish_date_not_the_write_time(monkeypatch, kev_snapshot) -> None:
    """Reporting the download time understates how old the data really is."""
    kev_snapshot.write_text(json.dumps(KEV_BODY), encoding="utf-8")
    published = (datetime.now(UTC) - timedelta(days=10)).isoformat()
    write_meta(kev_snapshot, content_date=published)

    freshness = snapshot_freshness("kev")

    assert freshness["age_days"] == 10
    # Written just now, so the check is current even though the data is not.
    assert freshness["days_since_checked"] == 0


def test_a_quiet_upstream_does_not_warn(monkeypatch, kev_snapshot) -> None:
    """Old data we verified today is not a problem anyone can act on."""
    kev_snapshot.write_text(json.dumps(KEV_BODY), encoding="utf-8")
    write_meta(kev_snapshot, content_date=(datetime.now(UTC) - timedelta(days=400)).isoformat())

    freshness = snapshot_freshness("kev")

    assert freshness["age_days"] == 400
    assert freshness["stale"] is False


def test_an_updater_that_stopped_running_does_warn(monkeypatch, kev_snapshot) -> None:
    """The actionable failure: nobody has checked in a long time."""
    kev_snapshot.write_text(json.dumps(KEV_BODY), encoding="utf-8")
    write_meta(kev_snapshot, content_date=datetime.now(UTC).isoformat())
    meta = read_meta(kev_snapshot)
    meta["checked_at"] = (datetime.now(UTC) - timedelta(days=45)).isoformat()
    meta_path(kev_snapshot).write_text(json.dumps(meta), encoding="utf-8")

    freshness = snapshot_freshness("kev")

    assert freshness["days_since_checked"] == 45
    assert freshness["stale"] is True


def test_no_sidecar_falls_back_to_mtime(monkeypatch, kev_snapshot) -> None:
    """An install predating the sidecar must behave exactly as it used to."""
    kev_snapshot.write_text(json.dumps(KEV_BODY), encoding="utf-8")
    old = time.time() - 45 * 86400
    import os

    os.utime(kev_snapshot, (old, old))

    freshness = snapshot_freshness("kev")

    assert freshness["age_days"] == 45
    assert freshness["days_since_checked"] == 45
    assert freshness["stale"] is True
