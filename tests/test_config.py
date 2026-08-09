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


def test_blank_env_override_falls_back_to_the_default(monkeypatch) -> None:
    """.env.example lists every optional setting empty, so copying it must not blank them.

    os.getenv(name, default) returns "" for a variable that is set but empty, so
    the default never applied. This broke every snapshot download for anyone who
    followed the documented setup.
    """
    monkeypatch.setenv("THREATSYFT_CISA_KEV_URL", "")
    assert config.get_cisa_kev_url() == config.DEFAULT_CISA_KEV_URL

    monkeypatch.setenv("THREATSYFT_CISA_KEV_URL", "   ")
    assert config.get_cisa_kev_url() == config.DEFAULT_CISA_KEV_URL


def test_blank_env_override_falls_back_for_every_url_setting(monkeypatch) -> None:
    getters = {
        "THREATSYFT_ATTACK_STIX_URL": config.get_attack_stix_url,
        "THREATSYFT_CISA_KEV_URL": config.get_cisa_kev_url,
        "THREATSYFT_LOLBAS_URL": config.get_lolbas_url,
        "THREATSYFT_NVD_BASE_URL": config.get_nvd_base_url,
        "THREATSYFT_ABUSEIPDB_BASE_URL": config.get_abuseipdb_base_url,
        "THREATSYFT_GREYNOISE_BASE_URL": config.get_greynoise_base_url,
        "THREATSYFT_VIRUSTOTAL_BASE_URL": config.get_virustotal_base_url,
        "THREATSYFT_SHODAN_BASE_URL": config.get_shodan_base_url,
        "THREATSYFT_SECURITYTRAILS_BASE_URL": config.get_securitytrails_base_url,
        "THREATSYFT_IPGEOLOCATION_BASE_URL": config.get_ipgeolocation_base_url,
        "THREATSYFT_ALIENVAULT_BASE_URL": config.get_alienvault_base_url,
        "THREATSYFT_GOOGLE_SAFEBROWSING_BASE_URL": config.get_google_safebrowsing_base_url,
    }

    for name, getter in getters.items():
        monkeypatch.setenv(name, "")
        assert getter(), f"{name} blanked its setting instead of using the default"


def test_a_real_env_override_still_wins(monkeypatch) -> None:
    monkeypatch.setenv("THREATSYFT_CISA_KEV_URL", "https://example.test/kev.json")
    assert config.get_cisa_kev_url() == "https://example.test/kev.json"
