"""Tests for feature flag resolution."""

import pytest

from llmpuffin.config import Profile
from llmpuffin.features import FeatureFlags, Flag, ProfileFeatureOverrides, resolve_features


_MINIMAL_PROFILE = """\
[audit]
name = "test"
image = "test"
threat_model = "test"
"""


class TestFeatureFlags:
    def test_defaults(self):
        f = FeatureFlags()
        assert not f.enabled(Flag.FORK_RUNNING_THREADS)
        assert f.enabled(Flag.DUPLICATE_DETECTION)

    def test_individual_override(self):
        f = FeatureFlags(fork_running_threads=True, duplicate_detection=False)
        assert f.enabled(Flag.FORK_RUNNING_THREADS)
        assert not f.enabled(Flag.DUPLICATE_DETECTION)

    def test_enum_values_match_field_names(self):
        """Every Flag enum member must correspond to a FeatureFlags field."""
        for flag in Flag:
            assert flag.value in FeatureFlags.model_fields, f"Flag.{flag.name} has no matching field"


class TestProfileFeatureOverrides:
    def test_defaults_are_none(self):
        o = ProfileFeatureOverrides()
        assert o.fork_running_threads is None
        assert o.duplicate_detection is None

    def test_partial_override(self):
        o = ProfileFeatureOverrides(duplicate_detection=False)
        assert o.duplicate_detection is False
        assert o.fork_running_threads is None

    def test_overrides_cover_all_flags(self):
        """Every Flag enum member must have a corresponding override field."""
        for flag in Flag:
            assert flag.value in ProfileFeatureOverrides.model_fields, (
                f"Flag.{flag.name} has no override field"
            )


class TestResolveFeatures:
    def test_no_overrides_returns_global(self):
        g = FeatureFlags(fork_running_threads=True)
        result = resolve_features(g)
        assert result is g

    def test_none_overrides_returns_global(self):
        g = FeatureFlags()
        result = resolve_features(g, None)
        assert result is g

    def test_empty_overrides_inherits_all(self):
        g = FeatureFlags(fork_running_threads=True, duplicate_detection=False)
        result = resolve_features(g, ProfileFeatureOverrides())
        assert result.enabled(Flag.FORK_RUNNING_THREADS)
        assert not result.enabled(Flag.DUPLICATE_DETECTION)

    def test_override_wins(self):
        g = FeatureFlags(duplicate_detection=True)
        o = ProfileFeatureOverrides(duplicate_detection=False)
        result = resolve_features(g, o)
        assert not result.enabled(Flag.DUPLICATE_DETECTION)

    def test_override_enables(self):
        g = FeatureFlags(fork_running_threads=False)
        o = ProfileFeatureOverrides(fork_running_threads=True)
        result = resolve_features(g, o)
        assert result.enabled(Flag.FORK_RUNNING_THREADS)

    def test_unset_override_inherits_global(self):
        g = FeatureFlags(fork_running_threads=True)
        o = ProfileFeatureOverrides(duplicate_detection=True)
        result = resolve_features(g, o)
        assert result.enabled(Flag.DUPLICATE_DETECTION)
        assert result.enabled(Flag.FORK_RUNNING_THREADS)

    def test_multiple_overrides(self):
        g = FeatureFlags(fork_running_threads=False, duplicate_detection=True)
        o = ProfileFeatureOverrides(fork_running_threads=True, duplicate_detection=False)
        result = resolve_features(g, o)
        assert result.enabled(Flag.FORK_RUNNING_THREADS)
        assert not result.enabled(Flag.DUPLICATE_DETECTION)


class TestProfileTomlFeatures:
    def test_no_features_section(self):
        p = Profile.from_toml_string(_MINIMAL_PROFILE)
        assert p.features.duplicate_detection is None
        assert p.features.fork_running_threads is None

    def test_partial_features_section(self):
        toml = _MINIMAL_PROFILE + "\n[features]\nduplicate_detection = false\n"
        p = Profile.from_toml_string(toml)
        assert p.features.duplicate_detection is False
        assert p.features.fork_running_threads is None

    def test_full_features_section(self):
        toml = _MINIMAL_PROFILE + (
            "\n[features]\n"
            "fork_running_threads = true\n"
            "duplicate_detection = false\n"
        )
        p = Profile.from_toml_string(toml)
        assert p.features.fork_running_threads is True
        assert p.features.duplicate_detection is False

    def test_roundtrip_with_resolve(self):
        """Profile features resolve correctly against global config."""
        toml = _MINIMAL_PROFILE + "\n[features]\nduplicate_detection = false\n"
        p = Profile.from_toml_string(toml)
        g = FeatureFlags(duplicate_detection=True, fork_running_threads=True)
        result = resolve_features(g, p.features)
        assert not result.enabled(Flag.DUPLICATE_DETECTION)  # profile override
        assert result.enabled(Flag.FORK_RUNNING_THREADS)  # inherited
