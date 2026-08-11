import io
import tarfile

import httpx
import pytest

from threatsyft.knowledge import update_maxmind

DATABASE_BYTES = b"\x00\xab" * 64
BUILD = "Tue, 11 Aug 2026 02:00:00 GMT"


def _archive(member_name: str = "GeoLite2-City_20260811/GeoLite2-City.mmdb") -> bytes:
    """Build the date-stamped tar.gz shape MaxMind actually serves."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as bundle:
        info = tarfile.TarInfo("GeoLite2-City_20260811/COPYRIGHT.txt")
        info.size = 4
        bundle.addfile(info, io.BytesIO(b"tail"))

        info = tarfile.TarInfo(member_name)
        info.size = len(DATABASE_BYTES)
        bundle.addfile(info, io.BytesIO(DATABASE_BYTES))
    return buffer.getvalue()


@pytest.fixture
def credentials(monkeypatch):
    monkeypatch.setenv("MAXMIND_ACCOUNT_ID", "123456")
    monkeypatch.setenv("MAXMIND_LICENSE_KEY", "license-key")


@pytest.fixture
def paths(tmp_path, monkeypatch):
    city = tmp_path / "GeoLite2-City.mmdb"
    asn = tmp_path / "GeoLite2-ASN.mmdb"
    monkeypatch.setitem(update_maxmind.EDITIONS, "GeoLite2-City", lambda: city)
    monkeypatch.setitem(update_maxmind.EDITIONS, "GeoLite2-ASN", lambda: asn)
    return {"city": city, "asn": asn}


def _wire(monkeypatch, *, head_status=200, get_status=200, body=None, headers=None, captured=None):
    head_headers = headers if headers is not None else {"Last-Modified": BUILD}

    def fake_head(url, params, auth, timeout, follow_redirects):
        if captured is not None:
            captured.setdefault("head", []).append({"url": url, "auth": auth, "params": params})
        return httpx.Response(head_status, request=httpx.Request("HEAD", url), headers=head_headers)

    def fake_get(url, params, auth, timeout, follow_redirects):
        if captured is not None:
            captured.setdefault("get", []).append({"url": url, "auth": auth, "timeout": timeout})
        return httpx.Response(
            get_status,
            request=httpx.Request("GET", url),
            content=_archive() if body is None else body,
            headers=head_headers,
        )

    monkeypatch.setattr(update_maxmind.httpx, "head", fake_head)
    monkeypatch.setattr(update_maxmind.httpx, "get", fake_get)


def test_missing_credentials_fail_before_any_request(monkeypatch, paths) -> None:
    monkeypatch.delenv("MAXMIND_ACCOUNT_ID", raising=False)
    monkeypatch.delenv("MAXMIND_LICENSE_KEY", raising=False)

    def explode(*args, **kwargs):
        raise AssertionError("no request should be made without credentials")

    monkeypatch.setattr(update_maxmind.httpx, "head", explode)

    result = update_maxmind.update_maxmind_snapshot()

    assert result["ok"] is False
    assert result["error"]["code"] == "missing_api_key"


def test_download_extracts_the_mmdb_from_the_archive(monkeypatch, credentials, paths) -> None:
    _wire(monkeypatch)

    result = update_maxmind.update_maxmind_snapshot()

    assert result["ok"] is True
    # The database, not the tarball and not the COPYRIGHT member beside it.
    assert paths["city"].read_bytes() == DATABASE_BYTES
    assert paths["asn"].read_bytes() == DATABASE_BYTES


def test_credentials_are_sent_as_basic_auth(monkeypatch, credentials, paths) -> None:
    captured: dict = {}
    _wire(monkeypatch, captured=captured)

    update_maxmind.update_maxmind_snapshot()

    assert captured["head"][0]["auth"] == ("123456", "license-key")
    assert captured["head"][0]["params"] == {"suffix": "tar.gz"}
    assert "/GeoLite2-City/download" in captured["head"][0]["url"]


def test_matching_build_skips_the_download(monkeypatch, credentials, paths) -> None:
    """The HEAD is free of the download quota; the GET is not."""
    _wire(monkeypatch)
    update_maxmind.update_maxmind_snapshot()

    captured: dict = {}
    _wire(monkeypatch, captured=captured)
    result = update_maxmind.update_maxmind_snapshot()

    assert result["ok"] is True
    assert result["data"]["editions"]["GeoLite2-City"]["data"]["downloaded"] is False
    # HEAD was asked; GET was never issued.
    assert len(captured["head"]) == 2
    assert "get" not in captured


def test_a_newer_build_does_download(monkeypatch, credentials, paths) -> None:
    _wire(monkeypatch)
    update_maxmind.update_maxmind_snapshot()

    newer = {"Last-Modified": "Wed, 19 Aug 2026 02:00:00 GMT"}
    captured: dict = {}
    _wire(monkeypatch, headers=newer, captured=captured)
    result = update_maxmind.update_maxmind_snapshot()

    assert result["data"]["editions"]["GeoLite2-City"]["data"]["downloaded"] is True
    assert len(captured["get"]) == 2


def test_download_uses_a_timeout_above_the_api_default(monkeypatch, credentials, paths) -> None:
    """A tens-of-megabytes archive cannot share the small-JSON timeout."""
    monkeypatch.setenv("THREATSYFT_TIMEOUT_SECONDS", "15")
    captured: dict = {}
    _wire(monkeypatch, captured=captured)

    update_maxmind.update_maxmind_snapshot()

    assert captured["get"][0]["timeout"] == update_maxmind.MINIMUM_DOWNLOAD_TIMEOUT_SECONDS


def test_bad_credentials_are_an_authentication_error(monkeypatch, credentials, paths) -> None:
    _wire(monkeypatch, get_status=401, headers={})

    result = update_maxmind.update_maxmind_snapshot()

    assert result["ok"] is False
    editions = result["error"]["details"]["editions"]
    assert editions["GeoLite2-City"]["error"]["code"] == "authentication_error"


def test_rate_limit_is_reported_as_such(monkeypatch, credentials, paths) -> None:
    _wire(monkeypatch, get_status=429, headers={})

    result = update_maxmind.update_maxmind_snapshot()

    assert (
        result["error"]["details"]["editions"]["GeoLite2-City"]["error"]["code"] == "rate_limited"
    )


def test_archive_without_a_database_is_a_parse_error(monkeypatch, credentials, paths) -> None:
    empty = io.BytesIO()
    with tarfile.open(fileobj=empty, mode="w:gz") as bundle:
        info = tarfile.TarInfo("GeoLite2-City_20260811/COPYRIGHT.txt")
        info.size = 4
        bundle.addfile(info, io.BytesIO(b"tail"))
    _wire(monkeypatch, body=empty.getvalue(), headers={})

    result = update_maxmind.update_maxmind_snapshot()

    error = result["error"]["details"]["editions"]["GeoLite2-City"]["error"]
    assert error["code"] == "parse_error"
    assert "no .mmdb database" in error["message"]


def test_non_archive_body_is_a_parse_error(monkeypatch, credentials, paths) -> None:
    _wire(monkeypatch, body=b"this is not a tarball", headers={})

    result = update_maxmind.update_maxmind_snapshot()

    error = result["error"]["details"]["editions"]["GeoLite2-City"]["error"]
    assert error["code"] == "parse_error"
    assert "readable tar.gz" in error["message"]


def test_a_failed_edition_does_not_hide_the_other(monkeypatch, credentials, paths) -> None:
    """One edition failing must still leave the other one on disk."""

    def fake_head(url, params, auth, timeout, follow_redirects):
        return httpx.Response(200, request=httpx.Request("HEAD", url), headers={})

    def fake_get(url, params, auth, timeout, follow_redirects):
        if "GeoLite2-ASN" in url:
            raise httpx.ConnectError("refused")
        return httpx.Response(
            200, request=httpx.Request("GET", url), content=_archive(), headers={}
        )

    monkeypatch.setattr(update_maxmind.httpx, "head", fake_head)
    monkeypatch.setattr(update_maxmind.httpx, "get", fake_get)

    result = update_maxmind.update_maxmind_snapshot()

    assert result["ok"] is False
    details = result["error"]["details"]
    assert details["failed_editions"] == ["GeoLite2-ASN"]
    assert details["updated_edition_count"] == 1
    assert paths["city"].read_bytes() == DATABASE_BYTES


def test_partial_write_cannot_replace_a_good_database(monkeypatch, credentials, paths) -> None:
    """The temp-file-and-rename guarantee, exercised through the updater."""
    paths["city"].parent.mkdir(parents=True, exist_ok=True)
    paths["city"].write_bytes(b"previous-good-database")

    _wire(monkeypatch, body=b"not a tarball", headers={})
    update_maxmind.update_maxmind_snapshot()

    assert paths["city"].read_bytes() == b"previous-good-database"
