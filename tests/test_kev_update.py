import json

import httpx

from threatsyft.knowledge import update_kev


def test_update_kev_snapshot_success(monkeypatch, tmp_path) -> None:
    snapshot = tmp_path / "known_exploited_vulnerabilities.json"
    monkeypatch.setenv("THREATSYFT_CISA_KEV_PATH", str(snapshot))
    monkeypatch.setenv("THREATSYFT_CISA_KEV_URL", "https://example.com/kev.json")

    def fake_get(url: str, timeout: float) -> httpx.Response:
        assert url == "https://example.com/kev.json"
        assert timeout > 0
        return httpx.Response(
            200,
            request=httpx.Request("GET", url),
            json={"title": "KEV", "vulnerabilities": [{"cveID": "CVE-2024-3400"}]},
        )

    monkeypatch.setattr(update_kev.httpx, "get", fake_get)

    result = update_kev.update_kev_snapshot()

    assert result["ok"] is True
    assert result["data"]["vulnerability_count"] == 1
    written_payload = json.loads(snapshot.read_text(encoding="utf-8"))
    assert written_payload["vulnerabilities"][0]["cveID"] == "CVE-2024-3400"


def test_update_kev_snapshot_timeout(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("THREATSYFT_CISA_KEV_PATH", str(tmp_path / "kev.json"))

    def fake_get(url: str, timeout: float) -> httpx.Response:
        raise httpx.TimeoutException("timeout")

    monkeypatch.setattr(update_kev.httpx, "get", fake_get)

    result = update_kev.update_kev_snapshot()

    assert result["ok"] is False
    assert result["error"]["code"] == "timeout"


def test_update_kev_snapshot_http_failure(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("THREATSYFT_CISA_KEV_PATH", str(tmp_path / "kev.json"))

    def fake_get(url: str, timeout: float) -> httpx.Response:
        return httpx.Response(500, request=httpx.Request("GET", url))

    monkeypatch.setattr(update_kev.httpx, "get", fake_get)

    result = update_kev.update_kev_snapshot()

    assert result["ok"] is False
    assert result["error"]["code"] == "upstream_error"


def test_update_kev_snapshot_invalid_json(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("THREATSYFT_CISA_KEV_PATH", str(tmp_path / "kev.json"))

    def fake_get(url: str, timeout: float) -> httpx.Response:
        return httpx.Response(200, request=httpx.Request("GET", url), content=b"not-json")

    monkeypatch.setattr(update_kev.httpx, "get", fake_get)

    result = update_kev.update_kev_snapshot()

    assert result["ok"] is False
    assert result["error"]["code"] == "parse_error"


def test_update_kev_snapshot_unexpected_shape(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("THREATSYFT_CISA_KEV_PATH", str(tmp_path / "kev.json"))

    def fake_get(url: str, timeout: float) -> httpx.Response:
        return httpx.Response(200, request=httpx.Request("GET", url), json={"title": "KEV"})

    monkeypatch.setattr(update_kev.httpx, "get", fake_get)

    result = update_kev.update_kev_snapshot()

    assert result["ok"] is False
    assert result["error"]["code"] == "parse_error"
