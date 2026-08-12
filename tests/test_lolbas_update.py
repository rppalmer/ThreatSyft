import json

import httpx

from threatsyft.knowledge import snapshot_fetch, update_lolbas


def test_update_lolbas_snapshot_success(monkeypatch, tmp_path) -> None:
    snapshot = tmp_path / "lolbas.json"
    monkeypatch.setenv("THREATSYFT_LOLBAS_PATH", str(snapshot))
    monkeypatch.setenv("THREATSYFT_LOLBAS_URL", "https://example.com/lolbas.json")

    def fake_get(url: str, timeout: float, **kwargs) -> httpx.Response:
        assert url == "https://example.com/lolbas.json"
        assert timeout > 0
        return httpx.Response(
            200,
            request=httpx.Request("GET", url),
            json=[{"Name": "Certutil.exe"}],
        )

    monkeypatch.setattr(snapshot_fetch.httpx, "get", fake_get)

    result = update_lolbas.update_lolbas_snapshot()

    assert result["ok"] is True
    assert result["data"]["entry_count"] == 1
    written_payload = json.loads(snapshot.read_text(encoding="utf-8"))
    assert written_payload[0]["Name"] == "Certutil.exe"


def test_update_lolbas_snapshot_timeout(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("THREATSYFT_LOLBAS_PATH", str(tmp_path / "lolbas.json"))

    def fake_get(url: str, timeout: float, **kwargs) -> httpx.Response:
        raise httpx.TimeoutException("timeout")

    monkeypatch.setattr(snapshot_fetch.httpx, "get", fake_get)

    result = update_lolbas.update_lolbas_snapshot()

    assert result["ok"] is False
    assert result["error"]["code"] == "timeout"


def test_update_lolbas_snapshot_http_failure(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("THREATSYFT_LOLBAS_PATH", str(tmp_path / "lolbas.json"))

    def fake_get(url: str, timeout: float, **kwargs) -> httpx.Response:
        return httpx.Response(500, request=httpx.Request("GET", url))

    monkeypatch.setattr(snapshot_fetch.httpx, "get", fake_get)

    result = update_lolbas.update_lolbas_snapshot()

    assert result["ok"] is False
    assert result["error"]["code"] == "upstream_error"


def test_update_lolbas_snapshot_invalid_json(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("THREATSYFT_LOLBAS_PATH", str(tmp_path / "lolbas.json"))

    def fake_get(url: str, timeout: float, **kwargs) -> httpx.Response:
        return httpx.Response(200, request=httpx.Request("GET", url), content=b"not-json")

    monkeypatch.setattr(snapshot_fetch.httpx, "get", fake_get)

    result = update_lolbas.update_lolbas_snapshot()

    assert result["ok"] is False
    assert result["error"]["code"] == "parse_error"


def test_update_lolbas_snapshot_unexpected_shape(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("THREATSYFT_LOLBAS_PATH", str(tmp_path / "lolbas.json"))

    def fake_get(url: str, timeout: float, **kwargs) -> httpx.Response:
        return httpx.Response(200, request=httpx.Request("GET", url), json={"Name": "Certutil.exe"})

    monkeypatch.setattr(snapshot_fetch.httpx, "get", fake_get)

    result = update_lolbas.update_lolbas_snapshot()

    assert result["ok"] is False
    assert result["error"]["code"] == "parse_error"
