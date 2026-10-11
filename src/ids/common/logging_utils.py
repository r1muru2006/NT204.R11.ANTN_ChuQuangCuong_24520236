"""Logging helpers used across the IDS pipeline."""

from __future__ import annotations

import logging

_CONFIGURED = False


def configure_logging(level: str = "INFO") -> None:
    """Configure root logging once, using a compact, consistent format."""
    global _CONFIGURED
    if _CONFIGURED:
        logging.getLogger("ids").setLevel(level.upper())
        return
    logging.basicConfig(
        level=level.upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    """Return a child logger under the ``ids`` namespace."""
    if not name.startswith("ids"):
        name = f"ids.{name}"
    return logging.getLogger(name)
