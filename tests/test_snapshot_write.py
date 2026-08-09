import json

import pytest

from threatsyft.knowledge.snapshot_cache import write_snapshot


def test_write_snapshot_creates_parent_directories(tmp_path) -> None:
    target = tmp_path / "nested" / "deeper" / "snapshot.json"

    write_snapshot(target, {"vulnerabilities": []})

    assert json.loads(target.read_text(encoding="utf-8")) == {"vulnerabilities": []}


def test_write_snapshot_leaves_no_temporary_file(tmp_path) -> None:
    target = tmp_path / "snapshot.json"

    write_snapshot(target, {"objects": [1, 2, 3]})

    assert [item.name for item in tmp_path.iterdir()] == ["snapshot.json"]


def test_failed_write_leaves_the_previous_snapshot_intact(tmp_path, monkeypatch) -> None:
    """The whole point of the atomic write: a crash must not destroy good data."""
    target = tmp_path / "snapshot.json"
    write_snapshot(target, {"objects": ["original"]})

    def explode(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr("threatsyft.knowledge.snapshot_cache.os.replace", explode)

    with pytest.raises(OSError):
        write_snapshot(target, {"objects": ["replacement"]})

    assert json.loads(target.read_text(encoding="utf-8")) == {"objects": ["original"]}
