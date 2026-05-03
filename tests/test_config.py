from investigatinator import config


def test_default_knowledge_paths_live_under_user_home(monkeypatch, tmp_path) -> None:
    home = tmp_path / "home"
    cwd = tmp_path / "cwd"
    home.mkdir()
    cwd.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.chdir(cwd)
    monkeypatch.delenv("INVESTIGATINATOR_ATTACK_STIX_PATH", raising=False)
    monkeypatch.delenv("INVESTIGATINATOR_D3FEND_PATH", raising=False)
    monkeypatch.delenv("INVESTIGATINATOR_CISA_KEV_PATH", raising=False)
    monkeypatch.delenv("INVESTIGATINATOR_LOLBAS_PATH", raising=False)

    assert config.get_attack_stix_path() == (
        home / ".investigatinator" / "knowledge" / "attack" / "enterprise-attack.json"
    )
    assert config.get_d3fend_path() == (
        home / ".investigatinator" / "knowledge" / "d3fend" / "d3fend.json"
    )
    assert config.get_cisa_kev_path() == (
        home / ".investigatinator" / "knowledge" / "cisa" / "known_exploited_vulnerabilities.json"
    )
    assert config.get_lolbas_path() == (
        home / ".investigatinator" / "knowledge" / "lolbas" / "lolbas.json"
    )


def test_knowledge_path_env_override_wins(monkeypatch, tmp_path) -> None:
    override = tmp_path / "custom" / "attack.json"
    monkeypatch.setenv("INVESTIGATINATOR_ATTACK_STIX_PATH", str(override))

    assert config.get_attack_stix_path() == override


def test_knowledge_update_command_is_console_friendly() -> None:
    assert config.knowledge_update_command("attack") == "investigatinator knowledge-update attack"
