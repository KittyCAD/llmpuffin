"""Tests for Config env var overrides."""

from llmpuffin.config import Config


def test_defaults_without_toml_or_env(monkeypatch, tmp_path):
    """With no TOML and no env vars, defaults apply."""
    monkeypatch.chdir(tmp_path)
    c = Config.load()
    assert c.runtime == "podman"
    assert c.postgres.url == "postgresql://localhost:5434/llmpuffin"
    assert c.web.port == 8000
    assert c.web.debug is True
    assert c.logging.level == "INFO"


def test_env_overrides_top_level(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("LLMPUFFIN__RUNTIME", "nexecutor")
    monkeypatch.setenv("LLMPUFFIN__NEXECUTOR_URL", "http://nx:9090")
    monkeypatch.setenv("LLMPUFFIN__MICROVM_IMAGE_ARN", "arn:aws:test")
    c = Config.load()
    assert c.runtime == "nexecutor"
    assert c.nexecutor_url == "http://nx:9090"
    assert c.microvm_image_arn == "arn:aws:test"


def test_env_overrides_nested(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("LLMPUFFIN__POSTGRES__URL", "postgresql://other:5432/db")
    monkeypatch.setenv("LLMPUFFIN__WEB__PORT", "9000")
    monkeypatch.setenv("LLMPUFFIN__WEB__DEBUG", "false")
    monkeypatch.setenv("LLMPUFFIN__LOGGING__LEVEL", "DEBUG")
    monkeypatch.setenv("LLMPUFFIN__GITHUB__FINDINGS_REPO", "org/repo")
    monkeypatch.setenv("LLMPUFFIN__AUTH__ENABLED", "true")
    c = Config.load()
    assert c.postgres.url == "postgresql://other:5432/db"
    assert c.web.port == 9000
    assert c.web.debug is False
    assert c.logging.level == "DEBUG"
    assert c.github.findings_repo == "org/repo"
    assert c.auth.enabled is True


def test_env_overrides_toml(monkeypatch, tmp_path):
    """Env vars take precedence over TOML values."""
    toml_file = tmp_path / "llmpuffin.toml"
    toml_file.write_text(
        '[postgres]\nurl = "postgresql://toml-host:5432/db"\n'
        "[web]\nport = 3000\n"
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("LLMPUFFIN__POSTGRES__URL", "postgresql://env-host:5432/db")
    c = Config.load()
    assert c.postgres.url == "postgresql://env-host:5432/db"
    # TOML value not overridden by env should still apply.
    assert c.web.port == 3000


def test_toml_without_env(monkeypatch, tmp_path):
    """TOML values load correctly when no env vars are set."""
    toml_file = tmp_path / "llmpuffin.toml"
    toml_file.write_text(
        'runtime = "microvm"\n'
        "[postgres]\n"
        'url = "postgresql://toml:5432/x"\n'
        "[github]\n"
        "app_id = 999\n"
        'installation_id = "abc"\n'
    )
    monkeypatch.chdir(tmp_path)
    c = Config.load()
    assert c.runtime == "microvm"
    assert c.postgres.url == "postgresql://toml:5432/x"
    assert c.github.app_id == "999"  # int → str coercion
    assert c.github.installation_id == "abc"
