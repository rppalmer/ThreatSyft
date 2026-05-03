import json

import httpx

from investigatinator.knowledge import update_d3fend


def test_update_d3fend_snapshot_success(monkeypatch, tmp_path) -> None:
    snapshot = tmp_path / "d3fend.json"
    monkeypatch.setenv("INVESTIGATINATOR_D3FEND_PATH", str(snapshot))
    monkeypatch.setenv("INVESTIGATINATOR_D3FEND_TECHNIQUES_URL", "https://example.com/tech.json")
    monkeypatch.setenv("INVESTIGATINATOR_D3FEND_TACTICS_URL", "https://example.com/tactic.json")
    monkeypatch.setenv("INVESTIGATINATOR_D3FEND_MAPPINGS_URL", "https://example.com/map.json")

    def fake_get(url: str, timeout: float) -> httpx.Response:
        payloads = {
            "https://example.com/tech.json": {"@graph": [{"rdfs:label": "File Analysis"}]},
            "https://example.com/tactic.json": {"@graph": [{"rdfs:label": "Detect"}]},
            "https://example.com/map.json": {"results": {"bindings": [{"x": {"value": "y"}}]}},
        }
        assert timeout > 0
        return httpx.Response(200, request=httpx.Request("GET", url), json=payloads[url])

    monkeypatch.setattr(update_d3fend.httpx, "get", fake_get)

    result = update_d3fend.update_d3fend_snapshot()

    assert result["ok"] is True
    assert result["data"]["technique_count"] == 1
    written_payload = json.loads(snapshot.read_text(encoding="utf-8"))
    assert set(written_payload) == {"techniques", "tactics", "mappings"}


def test_update_d3fend_snapshot_timeout(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("INVESTIGATINATOR_D3FEND_PATH", str(tmp_path / "d3fend.json"))

    def fake_get(url: str, timeout: float) -> httpx.Response:
        raise httpx.TimeoutException("timeout")

    monkeypatch.setattr(update_d3fend.httpx, "get", fake_get)

    result = update_d3fend.update_d3fend_snapshot()

    assert result["ok"] is False
    assert result["error"]["code"] == "timeout"


def test_update_d3fend_snapshot_http_failure(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("INVESTIGATINATOR_D3FEND_PATH", str(tmp_path / "d3fend.json"))

    def fake_get(url: str, timeout: float) -> httpx.Response:
        return httpx.Response(500, request=httpx.Request("GET", url))

    monkeypatch.setattr(update_d3fend.httpx, "get", fake_get)

    result = update_d3fend.update_d3fend_snapshot()

    assert result["ok"] is False
    assert result["error"]["code"] == "upstream_error"


def test_update_d3fend_snapshot_invalid_json(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("INVESTIGATINATOR_D3FEND_PATH", str(tmp_path / "d3fend.json"))

    def fake_get(url: str, timeout: float) -> httpx.Response:
        return httpx.Response(200, request=httpx.Request("GET", url), content=b"not-json")

    monkeypatch.setattr(update_d3fend.httpx, "get", fake_get)

    result = update_d3fend.update_d3fend_snapshot()

    assert result["ok"] is False
    assert result["error"]["code"] == "parse_error"


def test_update_d3fend_snapshot_unexpected_shape(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("INVESTIGATINATOR_D3FEND_PATH", str(tmp_path / "d3fend.json"))

    def fake_get(url: str, timeout: float) -> httpx.Response:
        return httpx.Response(200, request=httpx.Request("GET", url), json={})

    monkeypatch.setattr(update_d3fend.httpx, "get", fake_get)

    result = update_d3fend.update_d3fend_snapshot()

    assert result["ok"] is False
    assert result["error"]["code"] == "parse_error"
