from threatsyft import config


def test_default_knowledge_paths_live_under_user_home(monkeypatch, tmp_path) -> None:
    home = tmp_path / "home"
    cwd = tmp_path / "cwd"
    home.mkdir()
    cwd.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.chdir(cwd)
    monkeypatch.delenv("THREATSYFT_ATTACK_STIX_PATH", raising=False)
    monkeypatch.delenv("THREATSYFT_CISA_KEV_PATH", raising=False)
    monkeypatch.delenv("THREATSYFT_LOLBAS_PATH", raising=False)

    assert config.get_attack_stix_path() == (
        home / ".threatsyft" / "knowledge" / "attack" / "enterprise-attack.json"
    )
    assert config.get_cisa_kev_path() == (
        home / ".threatsyft" / "knowledge" / "cisa" / "known_exploited_vulnerabilities.json"
    )
    assert config.get_lolbas_path() == (
        home / ".threatsyft" / "knowledge" / "lolbas" / "lolbas.json"
    )


def test_knowledge_path_env_override_wins(monkeypatch, tmp_path) -> None:
    override = tmp_path / "custom" / "attack.json"
    monkeypatch.setenv("THREATSYFT_ATTACK_STIX_PATH", str(override))

    assert config.get_attack_stix_path() == override


def test_knowledge_update_command_is_console_friendly() -> None:
    assert config.knowledge_update_command("attack") == "threatsyft knowledge-update attack"
