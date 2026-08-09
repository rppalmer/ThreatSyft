from threatsyft import config


def test_env_file_is_found_from_a_foreign_working_directory(tmp_path, monkeypatch) -> None:
    """An MCP server inherits the host's working directory, not the project root.

    None of the documented host configurations set ``cwd``, so a bare
    load_dotenv() found nothing and every keyed tool reported a missing API key.
    """
    home = tmp_path / "home"
    home.joinpath(".threatsyft").mkdir(parents=True)
    home.joinpath(".threatsyft", ".env").write_text(
        "THREATSYFT_DOTENV_MARKER=from_home\n", encoding="utf-8"
    )
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()

    monkeypatch.setattr(config.Path, "home", classmethod(lambda cls: home))
    monkeypatch.chdir(elsewhere)
    monkeypatch.delenv("THREATSYFT_DOTENV_MARKER", raising=False)

    config._load_environment()

    assert config.os.getenv("THREATSYFT_DOTENV_MARKER") == "from_home"


def test_process_environment_wins_over_the_env_file(tmp_path, monkeypatch) -> None:
    home = tmp_path / "home"
    home.joinpath(".threatsyft").mkdir(parents=True)
    home.joinpath(".threatsyft", ".env").write_text(
        "THREATSYFT_DOTENV_MARKER=from_home\n", encoding="utf-8"
    )

    monkeypatch.setattr(config.Path, "home", classmethod(lambda cls: home))
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("THREATSYFT_DOTENV_MARKER", "from_process")

    config._load_environment()

    assert config.os.getenv("THREATSYFT_DOTENV_MARKER") == "from_process"


def test_working_directory_env_file_wins_over_home(tmp_path, monkeypatch) -> None:
    """A project-local .env still takes precedence during development."""
    home = tmp_path / "home"
    home.joinpath(".threatsyft").mkdir(parents=True)
    home.joinpath(".threatsyft", ".env").write_text(
        "THREATSYFT_DOTENV_MARKER=from_home\n", encoding="utf-8"
    )
    project = tmp_path / "project"
    project.mkdir()
    project.joinpath(".env").write_text("THREATSYFT_DOTENV_MARKER=from_project\n", encoding="utf-8")

    monkeypatch.setattr(config.Path, "home", classmethod(lambda cls: home))
    monkeypatch.chdir(project)
    monkeypatch.delenv("THREATSYFT_DOTENV_MARKER", raising=False)

    config._load_environment()

    assert config.os.getenv("THREATSYFT_DOTENV_MARKER") == "from_project"
