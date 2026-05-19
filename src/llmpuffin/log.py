"""Central logger for llmpuffin. Import `log` from here."""

from __future__ import annotations

import logging

log = logging.getLogger("llmpuffin")


def setup(verbose: bool = False, level: str | None = None) -> None:
    """Configure the `llmpuffin` logger.

    Idempotent: re-calling will not stack handlers. Plays well with uvicorn,
    which installs its own handlers on the root logger — we attach to the
    `llmpuffin` logger directly and disable propagation so our format is used.
    """
    if verbose:
        resolved = logging.DEBUG
    elif level:
        resolved = logging.getLevelNamesMapping().get(level.upper(), logging.INFO)
    else:
        resolved = logging.INFO

    log.setLevel(resolved)

    # Avoid stacking handlers on hot reload / repeated setup() calls.
    if not any(getattr(h, "_llmpuffin", False) for h in log.handlers):
        handler = logging.StreamHandler()
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)s %(name)s | %(message)s",
                              datefmt="%H:%M:%S")
        )
        handler._llmpuffin = True  # type: ignore[attr-defined]
        log.addHandler(handler)

    # We have our own handler; don't double-log via root (uvicorn's handlers).
    log.propagate = False
