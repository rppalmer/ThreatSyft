"""The two shared collection primitives, tested directly.

Both were previously exercised only through `enrich` and `lookup` with stubs
that always returned a well-formed envelope, so neither the fan-out's behaviour
when a source raises nor `build_sources`' handling of a malformed envelope had
any coverage at all.
"""

import threading

from threatsyft.core import build_sources
from threatsyft.fanout import run_sources


def _ok(data):
    return {"ok": True, "tool": "stub", "query": {}, "data": data, "error": None}


def _failed(code, message, details=None):
    return {
        "ok": False,
        "tool": "stub",
        "query": {},
        "data": None,
        "error": {"code": code, "message": message, "details": details},
    }


# --- run_sources --------------------------------------------------------------


def test_no_sources_is_an_empty_result_not_an_error() -> None:
    assert run_sources([], "8.8.8.8") == []


def test_results_come_back_in_source_order_not_completion_order() -> None:
    """A response must not reorder because one source happened to be slow."""
    started = threading.Event()

    def slow(_target):
        started.wait(timeout=5)
        return _ok({"n": "slow"})

    def fast(_target):
        started.set()
        return _ok({"n": "fast"})

    results = run_sources([("slow", slow), ("fast", fast)], "x")

    assert [name for name, _ in results] == ["slow", "fast"]


def test_every_source_is_called_with_the_target() -> None:
    seen = []
    run_sources([("a", lambda t: seen.append(("a", t)) or _ok({}))], "example.com")

    assert seen == [("a", "example.com")]


def test_sources_run_concurrently_rather_than_serially() -> None:
    """Two sources that each wait on the other only both finish in parallel."""
    first, second = threading.Event(), threading.Event()

    def a(_target):
        first.set()
        assert second.wait(timeout=5), "second source never started"
        return _ok({})

    def b(_target):
        second.set()
        assert first.wait(timeout=5), "first source never started"
        return _ok({})

    results = run_sources([("a", a), ("b", b)], "x")

    assert all(envelope["ok"] for _, envelope in results)


def test_a_source_that_raises_becomes_that_source_s_error(monkeypatch) -> None:
    """The regression this guard exists for: one raising source took the call down."""

    def boom(_target):
        raise RuntimeError("provider returned something unexpected")

    results = dict(run_sources([("good", lambda _t: _ok({"n": 1})), ("boom", boom)], "x"))

    assert results["good"]["ok"] is True
    assert results["boom"]["ok"] is False
    assert results["boom"]["error"]["code"] == "unexpected_error"
    assert "RuntimeError" in results["boom"]["error"]["details"]


def test_a_raising_source_does_not_lose_the_others() -> None:
    def boom(_target):
        raise ValueError("nope")

    sources = [("a", lambda _t: _ok({})), ("boom", boom), ("c", lambda _t: _ok({}))]
    _, summary = build_sources(run_sources(sources, "x"))

    assert summary == {"ok": 2, "failed": 1}


def test_every_source_raising_is_still_a_full_result() -> None:
    def boom(_target):
        raise OSError("disk gone")

    sources, summary = build_sources(run_sources([("a", boom), ("b", boom)], "x"))

    assert summary == {"ok": 0, "failed": 2}
    assert set(sources) == {"a", "b"}


def test_a_source_raising_keyboardinterrupt_is_not_swallowed() -> None:
    """Cancellation must reach the caller, unlike an ordinary provider failure."""

    def interrupted(_target):
        raise KeyboardInterrupt

    try:
        run_sources([("a", interrupted)], "x")
    except KeyboardInterrupt:
        return
    raise AssertionError("KeyboardInterrupt was swallowed")


# --- build_sources ------------------------------------------------------------


def test_success_entries_carry_only_ok_and_data() -> None:
    sources, _ = build_sources([("a", _ok({"n": 1}))])

    assert sources["a"] == {"ok": True, "data": {"n": 1}}


def test_failure_entries_carry_the_code_and_message() -> None:
    sources, _ = build_sources([("a", _failed("rate_limited", "429"))])

    assert sources["a"] == {"ok": False, "code": "rate_limited", "message": "429"}


def test_details_ride_along_when_a_source_provides_them() -> None:
    """setup_command lives here, and is the only part telling a caller how to fix it."""
    sources, _ = build_sources(
        [("a", _failed("not_found", "no snapshot", {"setup_command": "threatsyft-update kev"}))]
    )

    assert sources["a"]["details"] == {"setup_command": "threatsyft-update kev"}


def test_a_success_without_a_data_object_is_treated_as_a_failure() -> None:
    """ok:true with no data cannot be reported as a successful source."""
    sources, summary = build_sources([("a", {"ok": True, "data": None, "error": None})])

    assert sources["a"]["ok"] is False
    assert sources["a"]["code"] == "unexpected_error"
    assert summary == {"ok": 0, "failed": 1}


def test_the_summary_always_matches_the_map() -> None:
    entries = [("a", _ok({})), ("b", _failed("timeout", "slow")), ("c", _ok({}))]
    sources, summary = build_sources(entries)

    assert summary["ok"] == sum(1 for entry in sources.values() if entry["ok"])
    assert summary["ok"] + summary["failed"] == len(sources)
