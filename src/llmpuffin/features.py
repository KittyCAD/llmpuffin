"""Feature flags for experimental or in-progress features."""

from pydantic import BaseModel


class FeatureFlags(BaseModel):
    """Feature flags for experimental or in-progress features."""

    all: bool = False
    """Enable all feature flags at once."""
    fork_running_threads: bool = False
    """Allow forking from threads that are still running (reads last checkpoint)."""

    def enabled(self, flag: str) -> bool:
        """Check if a flag is enabled (explicitly or via ``all``)."""
        return self.all or getattr(self, flag, False)
