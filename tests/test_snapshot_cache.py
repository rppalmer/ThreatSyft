"""Caching behaviour of the parsed snapshots.

The expensive case is a cold cache under fan-out: `lookup` asks several ATT&CK
catalogs concurrently and they all resolve against the same 47 MB file.
"""

import threading
from pathlib import Path

import pytest

from threatsyft.knowledge import attack
from threatsyft.knowledge.lookup import lookup
from threatsyft.knowledge.snapshot_cache import load_cached

ATTACK_FIXTURE = Path("tests/fixtures/attack-enterprise-mini.json")
LOLBAS_FIXTURE = Path("tests/fixtures/lolbas-mini.json")
KEV_FIXTURE = Path("tests/fixtures/cisa-kev-mini.json")


@pytest.fixture
def snapshot(tmp_path):
    path = tmp_path / "snapshot.json"
    path.write_text("{}")
    return path


def test_a_second_call_reuses_the_parse(snapshot) -> None:
    cache = {}
    parses = []

    def parse():
        parses.append(1)
        return "parsed"

    assert load_cached(cache, snapshot, parse) == "parsed"
    assert load_cached(cache, snapshot, parse) == "parsed"
    assert len(parses) == 1


def test_a_rewritten_snapshot_is_reparsed(snapshot) -> None:
    """threatsyft-update must take effect without restarting the server."""
    cache = {}
    parses = []

    def parse():
        parses.append(1)
        return len(parses)

    assert load_cached(cache, snapshot, parse) == 1
    import os

    stat = snapshot.stat()
    os.utime(snapshot, (stat.st_atime + 10, stat.st_mtime + 10))

    assert load_cached(cache, snapshot, parse) == 2


def test_a_failed_parse_is_not_cached(snapshot) -> None:
    cache = {}
    attempts = []

    def parse():
        attempts.append(1)
        raise ValueError("malformed")

    for _ in range(2):
        with pytest.raises(ValueError):
            load_cached(cache, snapshot, parse)

    assert len(attempts) == 2


def test_a_missing_file_still_reaches_the_parser(tmp_path) -> None:
    """parse() owns the domain-specific "snapshot not found" error, so it must run."""
    called = []

    def parse():
        called.append(1)
        raise FileNotFoundError

    with pytest.raises(FileNotFoundError):
        load_cached({}, tmp_path / "absent.json", parse)

    assert called == [1]


def test_concurrent_misses_on_one_snapshot_parse_once(snapshot) -> None:
    """Both threads reach the miss check before either finishes parsing."""
    cache = {}
    parses = []
    arrived = threading.Barrier(2, timeout=5)

    def parse():
        parses.append(1)
        return "parsed"

    def call():
        arrived.wait()
        load_cached(cache, snapshot, parse)

    threads = [threading.Thread(target=call) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)

    assert len(parses) == 1


def test_different_snapshots_do_not_block_each_other(tmp_path) -> None:
    """A per-path lock, not a global one: a cold KEV parse must not wait on ATT&CK."""
    first, second = tmp_path / "a.json", tmp_path / "b.json"
    first.write_text("{}")
    second.write_text("{}")
    inside_first = threading.Event()
    second_done = threading.Event()

    def parse_first():
        inside_first.set()
        assert second_done.wait(timeout=5), "second snapshot blocked behind the first"
        return "a"

    def parse_second():
        assert inside_first.wait(timeout=5)
        second_done.set()
        return "b"

    cache = {}
    thread = threading.Thread(target=lambda: load_cached(cache, first, parse_first))
    thread.start()
    load_cached(cache, second, parse_second)
    thread.join(timeout=5)

    assert cache[str(first)][1] == "a"


def test_a_bare_name_lookup_parses_the_attack_snapshot_once(monkeypatch) -> None:
    """The fan-out case, end to end.

    lookup("Certutil.exe") asks LOLBAS, ATT&CK tactics and ATT&CK actors
    concurrently; the last two share one file and must not both parse it.
    """
    monkeypatch.setenv("THREATSYFT_ATTACK_STIX_PATH", str(ATTACK_FIXTURE))
    monkeypatch.setenv("THREATSYFT_LOLBAS_PATH", str(LOLBAS_FIXTURE))
    monkeypatch.setenv("THREATSYFT_CISA_KEV_PATH", str(KEV_FIXTURE))

    parses = []
    real_parse = attack._load_attack_knowledge

    def counting(snapshot_path):
        parses.append(snapshot_path)
        return real_parse(snapshot_path)

    monkeypatch.setattr(attack, "_load_attack_knowledge", counting)
    attack._ATTACK_CACHE.clear()

    result = lookup("Certutil.exe")

    assert result["ok"] is True
    assert len(parses) == 1, f"ATT&CK snapshot parsed {len(parses)} times"
