"""Tests for Config env var overrides and Profile parsing."""

import pytest
from pydantic import ValidationError

from llmpuffin.config import Config, Profile


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
    monkeypatch.setenv("LLMPUFFIN__NEXECUTOR__URL", "http://nx:9090")
    monkeypatch.setenv("LLMPUFFIN__MICROVM__IMAGE_ARN", "arn:aws:test")
    c = Config.load()
    assert c.runtime == "nexecutor"
    assert c.nexecutor.url == "http://nx:9090"
    assert c.microvm.image_arn == "arn:aws:test"


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


# -- Profile tests --

_MINIMAL_PROFILE = """\
[audit]
name = "test-audit"
image = "ghcr.io/org/repo:latest"
threat_model_dir = "threat_model/"
"""


class TestProfileFromToml:
    def test_minimal_profile(self):
        p = Profile.from_toml_string(_MINIMAL_PROFILE)
        assert p.name == "test-audit"
        assert p.image == "ghcr.io/org/repo:latest"
        assert p.code_dir == "/src"  # default

    def test_all_fields(self):
        toml = """\
[audit]
name = "full"
image = "img:v1"
threat_model_dir = "tm/"
code_dir = "/app"

[agent]
model = "openai:gpt-4o"
max_iterations = 50
skills = ["audit-context-building"]

[openai]
reasoning_effort = "high"
use_responses_api = false
"""
        p = Profile.from_toml_string(toml)
        assert p.name == "full"
        assert p.code_dir == "/app"
        assert p.agent.model == "openai:gpt-4o"
        assert p.agent.max_iterations == 50
        assert p.agent.skills == ["audit-context-building"]
        assert p.openai.reasoning_effort == "high"
        assert p.openai.use_responses_api is False

    def test_extra_keys_rejected(self):
        toml = _MINIMAL_PROFILE + '\n[agent]\nbogus = "nope"\n'
        with pytest.raises(ValidationError):
            Profile.from_toml_string(toml)

    def test_missing_required_fields(self):
        with pytest.raises((ValidationError, KeyError)):
            Profile.from_toml_string('[audit]\nname = "x"\n')

    def test_repos(self):
        toml = _MINIMAL_PROFILE + """\
[[repo]]
url = "https://github.com/org/repo.git"

[[repo]]
url = "https://github.com/org/other.git"
name = "custom-name"
lfs = true
"""
        p = Profile.from_toml_string(toml)
        assert len(p.repos) == 2
        assert p.repos[0].url == "https://github.com/org/repo.git"
        assert p.repos[1].name == "custom-name"
        assert p.repos[1].lfs is True


class TestProfileProvider:
    def test_anthropic_prefixed(self):
        p = Profile.from_toml_string(_MINIMAL_PROFILE)
        # Default model is anthropic:claude-sonnet-...
        assert p.provider == "anthropic"

    def test_openai_prefixed(self):
        toml = _MINIMAL_PROFILE.rstrip() + '\n\n[agent]\nmodel = "openai:gpt-4o"\n'
        p = Profile.from_toml_string(toml)
        assert p.provider == "openai"

    def test_bare_claude(self):
        toml = _MINIMAL_PROFILE.rstrip() + '\n\n[agent]\nmodel = "claude-sonnet-4-20250514"\n'
        p = Profile.from_toml_string(toml)
        assert p.provider == "anthropic"

    def test_bare_gpt(self):
        toml = _MINIMAL_PROFILE.rstrip() + '\n\n[agent]\nmodel = "gpt-4o"\n'
        p = Profile.from_toml_string(toml)
        assert p.provider == "openai"

    def test_bare_o3(self):
        toml = _MINIMAL_PROFILE.rstrip() + '\n\n[agent]\nmodel = "o3"\n'
        p = Profile.from_toml_string(toml)
        assert p.provider == "openai"

    def test_bare_o4(self):
        toml = _MINIMAL_PROFILE.rstrip() + '\n\n[agent]\nmodel = "o4-mini"\n'
        p = Profile.from_toml_string(toml)
        assert p.provider == "openai"

    def test_unknown_model(self):
        toml = _MINIMAL_PROFILE.rstrip() + '\n\n[agent]\nmodel = "gemini-pro"\n'
        p = Profile.from_toml_string(toml)
        assert p.provider == "unknown"
