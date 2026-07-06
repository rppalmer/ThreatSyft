from threatsyft import cli
from threatsyft.tool_catalog import catalog


def test_cli_domain_compact_success(monkeypatch, capsys) -> None:
    monkeypatch.setattr(cli, "domain_reputation", _success_result)
    monkeypatch.setitem(
        cli.COMMANDS,
        "domain",
        (cli.domain_reputation, "Build a domain reputation fact pack."),
    )

    exit_code = cli.main(["--compact", "domain", "example.com"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert '"ok": true' in captured.out
    assert '"verdict": "benign"' in captured.out
    assert '"provider_result_count": 1' in captured.out


def test_cli_returns_error_exit_code(monkeypatch, capsys) -> None:
    monkeypatch.setattr(cli, "domain_reputation", _error_result)
    monkeypatch.setitem(
        cli.COMMANDS,
        "domain",
        (cli.domain_reputation, "Build a domain reputation fact pack."),
    )

    exit_code = cli.main(["domain", "not a domain"])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert '"ok": false' in captured.out
    assert '"invalid_input"' in captured.out


def test_cli_doctor_redacts_api_keys(monkeypatch, capsys) -> None:
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "very-secret")

    exit_code = cli.main(["doctor"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert '"tool": "doctor"' in captured.out
    assert "very-secret" not in captured.out
    assert '"secret_value": "redacted"' in captured.out


def test_cli_doctor_compact(monkeypatch, capsys) -> None:
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "very-secret")

    exit_code = cli.main(["--compact", "doctor"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert '"configured_key_count"' in captured.out
    assert '"missing_key_count"' in captured.out
    assert "very-secret" not in captured.out


def test_cli_tools_includes_expected_tools_without_secrets(monkeypatch, capsys) -> None:
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "very-secret")

    exit_code = cli.main(["tools"])

    captured = capsys.readouterr()
    names = {item["name"] for item in catalog()}
    assert exit_code == 0
    assert "very-secret" not in captured.out
    assert '"tool": "tools"' in captured.out
    assert '"local_only": true' in captured.out
    assert "doctor" in names
    assert "tools" in names
    assert "smoke" in names
    assert '"VIRUSTOTAL_API_KEY"' in captured.out
    assert '"live_network": true' in captured.out
    assert '"live_network": false' in captured.out


def test_cli_tools_compact(capsys) -> None:
    exit_code = cli.main(["--compact", "tools"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert '"tool_count"' in captured.out
    assert '"tools"' in captured.out
    assert '"recommended_use"' not in captured.out


def test_cli_smoke_runs_all_safe_samples(monkeypatch, capsys) -> None:
    calls: list[tuple[str, str]] = []

    for command_name in cli.SMOKE_SAMPLES:
        monkeypatch.setitem(
            cli.COMMANDS,
            command_name,
            (_recording_command(command_name, calls), f"Run {command_name}."),
        )

    exit_code = cli.main(["smoke"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert calls == list(cli.SMOKE_SAMPLES.items())
    assert '"tool": "smoke"' in captured.out
    assert '"sample_count": 4' in captured.out
    assert '"failed_sample_count": 0' in captured.out


def test_cli_smoke_represents_failures(monkeypatch, capsys) -> None:
    for command_name in cli.SMOKE_SAMPLES:
        result_function = _error_result if command_name == "domain" else _success_result
        monkeypatch.setitem(
            cli.COMMANDS,
            command_name,
            (result_function, f"Run {command_name}."),
        )

    exit_code = cli.main(["--compact", "smoke"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert '"failed_sample_count": 1' in captured.out


def test_cli_knowledge_status_returns_structured_json(monkeypatch, capsys) -> None:
    monkeypatch.setattr(cli, "knowledge_status", _knowledge_status_result)

    exit_code = cli.main(["knowledge-status"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert '"tool": "knowledge_status"' in captured.out
    assert '"ready": false' in captured.out
    assert '"attack"' in captured.out


def test_cli_knowledge_status_compact(monkeypatch, capsys) -> None:
    monkeypatch.setattr(cli, "knowledge_status", _knowledge_status_result)

    exit_code = cli.main(["--compact", "knowledge-status"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert '"ready": false' in captured.out
    assert '"snapshot_count": 2' in captured.out
    assert '"unavailable_snapshot_count": 1' in captured.out


def test_cli_knowledge_update_attack_calls_only_attack(monkeypatch, capsys) -> None:
    calls: list[str] = []

    monkeypatch.setitem(
        cli.KNOWLEDGE_UPDATE_FUNCTIONS,
        "attack",
        (_recording_update("attack", calls), "Download ATT&CK."),
    )
    monkeypatch.setitem(
        cli.KNOWLEDGE_UPDATE_FUNCTIONS,
        "d3fend",
        (_recording_update("d3fend", calls), "Download D3FEND."),
    )

    exit_code = cli.main(["knowledge-update", "attack"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert calls == ["attack"]
    assert '"tool": "knowledge_update"' in captured.out
    assert '"source": "attack"' in captured.out
    assert '"live_network": true' in captured.out


def test_cli_knowledge_update_all_calls_all_sources_in_order(monkeypatch, capsys) -> None:
    calls: list[str] = []

    for source in cli.KNOWLEDGE_UPDATE_FUNCTIONS:
        monkeypatch.setitem(
            cli.KNOWLEDGE_UPDATE_FUNCTIONS,
            source,
            (_recording_update(source, calls), f"Download {source}."),
        )

    exit_code = cli.main(["knowledge-update", "all"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert calls == ["attack", "d3fend", "kev", "lolbas"]
    assert '"requested_sources": [' in captured.out
    assert '"updated_source_count": 4' in captured.out


def test_cli_knowledge_update_all_partial_failure_returns_error(monkeypatch, capsys) -> None:
    calls: list[str] = []

    for source in cli.KNOWLEDGE_UPDATE_FUNCTIONS:
        if source == "kev":
            monkeypatch.setitem(
                cli.KNOWLEDGE_UPDATE_FUNCTIONS,
                source,
                (_recording_update(source, calls, ok=False), "Download KEV."),
            )
        else:
            monkeypatch.setitem(
                cli.KNOWLEDGE_UPDATE_FUNCTIONS,
                source,
                (_recording_update(source, calls), f"Download {source}."),
            )

    exit_code = cli.main(["knowledge-update", "all"])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert calls == ["attack", "d3fend", "kev", "lolbas"]
    assert '"ok": false' in captured.out
    assert '"upstream_error"' in captured.out
    assert '"failed_source_count": 1' in captured.out
    assert '"kev"' in captured.out


def _success_result(value: str) -> dict:
    return {
        "ok": True,
        "tool": "domain_reputation",
        "query": {"domain": value},
        "data": {
            "domain": value,
            "overall_verdict": "benign",
            "confidence": "high",
            "key_signals": ["Provider signal."],
            "provider_results": {"provider": {"verdict": "benign"}},
            "provider_errors": [],
        },
        "error": None,
    }


def _error_result(value: str) -> dict:
    return {
        "ok": False,
        "tool": "domain_reputation",
        "query": {"domain": value},
        "data": None,
        "error": {
            "code": "invalid_input",
            "message": "Domain must look like example.com.",
            "details": None,
        },
    }


def _knowledge_status_result() -> dict:
    return {
        "ok": True,
        "tool": "knowledge_status",
        "query": {},
        "data": {
            "local_only": True,
            "network_checked": False,
            "ready": False,
            "unavailable_snapshots": ["kev"],
            "snapshots": {
                "attack": {"ok": True, "counts": {"techniques": 1}},
                "kev": {"ok": False, "counts": {}},
            },
        },
        "error": None,
    }


def _recording_update(source: str, calls: list[str], *, ok: bool = True):
    def update() -> dict:
        calls.append(source)
        if ok:
            return {
                "ok": True,
                "tool": f"{source}_snapshot_update",
                "query": {},
                "data": {"snapshot_path": f"data/{source}.json"},
                "error": None,
            }
        return {
            "ok": False,
            "tool": f"{source}_snapshot_update",
            "query": {},
            "data": None,
            "error": {
                "code": "upstream_error",
                "message": f"{source} update failed.",
                "details": None,
            },
        }

    return update


def _recording_command(command_name: str, calls: list[tuple[str, str]]):
    def command(value: str) -> dict:
        calls.append((command_name, value))
        return _success_result(value)

    return command
