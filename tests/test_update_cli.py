import pytest

from threatsyft import update_cli


def _ok(tool):
    return {"ok": True, "tool": tool, "query": {}, "data": {"path": "/tmp/x"}, "error": None}


def _failed(tool, message="Download failed."):
    return {
        "ok": False,
        "tool": tool,
        "query": {},
        "data": None,
        "error": {"code": "upstream_error", "message": message, "details": None},
    }


@pytest.fixture
def real_sources():
    """The sources the command actually offers, so a new one is not missed here."""
    return list(update_cli.UPDATE_FUNCTIONS)


@pytest.fixture(autouse=True)
def stub_updaters(monkeypatch, real_sources):
    """No network. Records which snapshots were asked for.

    Stubs are built from the real source table rather than a hand-written list,
    so adding an updater is covered by these tests instead of silently skipped.
    """
    called = []

    def make(name, result=None):
        def update():
            called.append(name)
            return result or _ok(f"{name}_snapshot_update")

        return update

    monkeypatch.setattr(
        update_cli,
        "UPDATE_FUNCTIONS",
        {name: make(name) for name in real_sources},
    )
    return called


def test_all_refreshes_every_snapshot(stub_updaters, real_sources) -> None:
    result = update_cli.knowledge_update("all")

    assert result["ok"] is True
    assert stub_updaters == real_sources
    assert result["data"]["updated_source_count"] == len(real_sources)
    assert result["data"]["failed_sources"] == []


def test_one_source_refreshes_only_that_snapshot(stub_updaters) -> None:
    result = update_cli.knowledge_update("kev")

    assert result["ok"] is True
    assert stub_updaters == ["kev"]
    assert result["data"]["requested_sources"] == ["kev"]


def test_unknown_source_is_rejected_without_downloading(stub_updaters) -> None:
    result = update_cli.knowledge_update("d3fend")

    assert result["ok"] is False
    assert result["error"]["code"] == "invalid_input"
    assert stub_updaters == []


def test_one_failure_fails_the_command_but_still_tries_the_rest(monkeypatch) -> None:
    """A broken source must not stop the others from refreshing."""
    called = []

    def make(name, result):
        def update():
            called.append(name)
            return result

        return update

    monkeypatch.setattr(
        update_cli,
        "UPDATE_FUNCTIONS",
        {
            "attack": make("attack", _ok("attack_snapshot_update")),
            "kev": make("kev", _failed("kev_snapshot_update")),
            "lolbas": make("lolbas", _ok("lolbas_snapshot_update")),
        },
    )

    result = update_cli.knowledge_update("all")

    assert called == ["attack", "kev", "lolbas"]
    assert result["ok"] is False
    assert result["error"]["code"] == "upstream_error"
    assert result["error"]["details"]["failed_sources"] == ["kev"]
    assert result["error"]["details"]["updated_source_count"] == 2


def test_an_updater_raising_is_reported_not_propagated(monkeypatch) -> None:
    def boom():
        raise OSError("disk full")

    monkeypatch.setattr(update_cli, "UPDATE_FUNCTIONS", {"attack": boom})

    result = update_cli.knowledge_update("attack")

    assert result["ok"] is False
    assert result["data"] is None
    assert "OSError" in str(result["error"]["details"]["results"]["attack"]["error"]["message"])


def test_main_exit_code_is_zero_on_success(stub_updaters, capsys) -> None:
    assert update_cli.main(["all"]) == 0
    assert capsys.readouterr().out.strip().startswith("{")


def test_main_exit_code_is_one_on_failure(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        update_cli, "UPDATE_FUNCTIONS", {"kev": lambda: _failed("kev_snapshot_update")}
    )

    assert update_cli.main(["kev"]) == 1


def test_main_rejects_an_unknown_source_at_the_argument_parser(stub_updaters) -> None:
    with pytest.raises(SystemExit):
        update_cli.main(["nope"])
