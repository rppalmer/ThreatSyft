import json

import httpx

from threatsyft.knowledge import snapshot_fetch, update_attack


def test_update_attack_snapshot_success(monkeypatch, tmp_path) -> None:
    snapshot = tmp_path / "enterprise-attack.json"
    monkeypatch.setenv("THREATSYFT_ATTACK_STIX_PATH", str(snapshot))
    monkeypatch.setenv("THREATSYFT_ATTACK_STIX_URL", "https://example.com/attack.json")

    def fake_get(url: str, timeout: float, **kwargs) -> httpx.Response:
        assert url == "https://example.com/attack.json"
        assert timeout > 0
        return httpx.Response(
            200,
            request=httpx.Request("GET", url),
            json={"type": "bundle", "objects": [{"type": "attack-pattern"}]},
        )

    monkeypatch.setattr(snapshot_fetch.httpx, "get", fake_get)

    result = update_attack.update_attack_snapshot()

    assert result["ok"] is True
    assert result["data"]["object_count"] == 1
    written_payload = json.loads(snapshot.read_text(encoding="utf-8"))
    assert written_payload["objects"][0]["type"] == "attack-pattern"


def test_update_attack_snapshot_timeout(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("THREATSYFT_ATTACK_STIX_PATH", str(tmp_path / "attack.json"))

    def fake_get(url: str, timeout: float, **kwargs) -> httpx.Response:
        raise httpx.TimeoutException("timeout")

    monkeypatch.setattr(snapshot_fetch.httpx, "get", fake_get)

    result = update_attack.update_attack_snapshot()

    assert result["ok"] is False
    assert result["error"]["code"] == "timeout"


def test_update_attack_snapshot_http_failure(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("THREATSYFT_ATTACK_STIX_PATH", str(tmp_path / "attack.json"))

    def fake_get(url: str, timeout: float, **kwargs) -> httpx.Response:
        return httpx.Response(500, request=httpx.Request("GET", url))

    monkeypatch.setattr(snapshot_fetch.httpx, "get", fake_get)

    result = update_attack.update_attack_snapshot()

    assert result["ok"] is False
    assert result["error"]["code"] == "upstream_error"


def test_update_attack_snapshot_invalid_json(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("THREATSYFT_ATTACK_STIX_PATH", str(tmp_path / "attack.json"))

    def fake_get(url: str, timeout: float, **kwargs) -> httpx.Response:
        return httpx.Response(200, request=httpx.Request("GET", url), content=b"not-json")

    monkeypatch.setattr(snapshot_fetch.httpx, "get", fake_get)

    result = update_attack.update_attack_snapshot()

    assert result["ok"] is False
    assert result["error"]["code"] == "parse_error"


def test_update_attack_snapshot_unexpected_shape(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("THREATSYFT_ATTACK_STIX_PATH", str(tmp_path / "attack.json"))

    def fake_get(url: str, timeout: float, **kwargs) -> httpx.Response:
        return httpx.Response(
            200,
            request=httpx.Request("GET", url),
            json={"type": "bundle"},
        )

    monkeypatch.setattr(snapshot_fetch.httpx, "get", fake_get)

    result = update_attack.update_attack_snapshot()

    assert result["ok"] is False
    assert result["error"]["code"] == "parse_error"
