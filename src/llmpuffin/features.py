"""Feature flags for experimental or in-progress features."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel


class Flag(StrEnum):
    """Known feature flags."""

    FORK_RUNNING_THREADS = "fork_running_threads"
    DUPLICATE_DETECTION = "duplicate_detection"


class FeatureFlags(BaseModel):
    """Feature flags for experimental or in-progress features.

    Used as global defaults in ``Config.features``.
    """

    fork_running_threads: bool = False
    """Allow forking from threads that are still running (reads last checkpoint)."""
    duplicate_detection: bool = True
    """Check for duplicate findings before recording."""

    def enabled(self, flag: Flag) -> bool:
        """Check if a flag is enabled."""
        return getattr(self, flag.value, False)


class ProfileFeatureOverrides(BaseModel):
    """Per-profile feature flag overrides.

    ``None`` means inherit from global ``Config.features``.
    """

    fork_running_threads: bool | None = None
    duplicate_detection: bool | None = None


def resolve_features(
    global_flags: FeatureFlags,
    overrides: ProfileFeatureOverrides | None = None,
) -> FeatureFlags:
    """Merge profile overrides on top of global defaults.

    For each flag, the profile override wins if set (not None),
    otherwise the global value is used.
    """
    if overrides is None:
        return global_flags

    merged = {}
    for field in ProfileFeatureOverrides.model_fields:
        override = getattr(overrides, field)
        if override is not None:
            merged[field] = override
        else:
            merged[field] = global_flags.enabled(Flag(field))

    return FeatureFlags(**merged)
