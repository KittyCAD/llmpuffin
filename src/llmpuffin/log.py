"""Central logger for llmpuffin. Import `log` from here."""

import logging

log = logging.getLogger("llmpuffin")


def setup(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(message)s"))
    log.setLevel(level)
    log.addHandler(handler)
