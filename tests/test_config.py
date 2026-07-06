from threatsyft import config


def test_default_knowledge_paths_live_under_user_home(monkeypatch, tmp_path) -> None:
    home = tmp_path / "home"
    cwd = tmp_path / "cwd"
    home.mkdir()
    cwd.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.chdir(cwd)
    monkeypatch.delenv("THREATSYFT_ATTACK_STIX_PATH", raising=False)
    monkeypatch.delenv("THREATSYFT_D3FEND_PATH", raising=False)
    monkeypatch.delenv("THREATSYFT_CISA_KEV_PATH", raising=False)
    monkeypatch.delenv("THREATSYFT_LOLBAS_PATH", raising=False)

    assert config.get_attack_stix_path() == (
        home / ".threatsyft" / "knowledge" / "attack" / "enterprise-attack.json"
    )
    assert config.get_d3fend_path() == (
        home / ".threatsyft" / "knowledge" / "d3fend" / "d3fend.json"
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


def test_get_research_feeds_uses_defaults(monkeypatch) -> None:
    monkeypatch.delenv("THREATSYFT_RESEARCH_FEEDS", raising=False)

    assert config.get_research_feeds() == [
        "https://www.bleepingcomputer.com/feed/",
        "https://cloud.google.com/blog/topics/threat-intelligence/rss",
    ]
    assert config.research_feeds_source() == "default"


def test_get_research_feeds_supports_comma_separated_env(monkeypatch) -> None:
    monkeypatch.setenv(
        "THREATSYFT_RESEARCH_FEEDS",
        "https://example.com/rss.xml, https://example.org/feed",
    )

    assert config.get_research_feeds() == [
        "https://example.com/rss.xml",
        "https://example.org/feed",
    ]
    assert config.research_feeds_source() == "environment"


def test_get_research_feeds_supports_newline_separated_env(monkeypatch) -> None:
    monkeypatch.setenv(
        "THREATSYFT_RESEARCH_FEEDS",
        "\nhttps://example.com/rss.xml\nhttps://example.org/feed\n",
    )

    assert config.get_research_feeds() == [
        "https://example.com/rss.xml",
        "https://example.org/feed",
    ]


def test_get_research_feeds_supports_mixed_separators_and_blank_entries(monkeypatch) -> None:
    monkeypatch.setenv(
        "THREATSYFT_RESEARCH_FEEDS",
        "\nhttps://example.com/rss.xml,\n\n https://example.org/feed,\n",
    )

    assert config.get_research_feeds() == [
        "https://example.com/rss.xml",
        "https://example.org/feed",
    ]
