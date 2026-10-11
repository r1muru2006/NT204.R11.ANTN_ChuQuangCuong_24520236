"""Runtime configuration for the IDS processing pipeline.

All tunable policies live here so that operators can change behaviour without
touching implementation code. ``PipelineConfig`` can be built from a JSON file
(see ``config/ids.example.json``) or from CLI arguments.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, fields
from pathlib import Path
from typing import Any, Mapping

# Policies for malformed / unsupported events.
INVALID_POLICIES = ("mark", "retain", "skip")
UNSUPPORTED_POLICIES = ("mark", "retain", "skip")

# Decode statuses.
DECODE_DECODED = "decoded"
DECODE_UNCHANGED = "unchanged"
DECODE_PARTIAL = "partial"
DECODE_ERROR = "error"
DECODE_NOT_APPLICABLE = "not_applicable"

# Preprocess statuses.
PREPROCESS_VALID = "valid"
PREPROCESS_PARTIAL = "partial"
PREPROCESS_INVALID = "invalid"

# Processing actions.
ACTION_ACCEPT = "accept"
ACTION_MARK = "mark"
ACTION_SKIP = "skip"


@dataclass
class PipelineConfig:
    """Configurable runtime policies for the IDS pipeline."""

    # --- Decoder ---
    enable_decoder: bool = True
    max_decode_size: int = 1_000_000
    decode_recursive: bool = False
    html_entity_decoding: bool = True

    # --- Preprocessor ---
    enable_preprocessor: bool = True
    invalid_event_policy: str = "mark"
    unsupported_protocol_policy: str = "mark"

    # --- Flow / connection tracker ---
    enable_flow_tracker: bool = True
    tcp_idle_timeout: float = 300.0
    udp_idle_timeout: float = 60.0

    # --- Logging ---
    log_level: str = "INFO"

    def __post_init__(self) -> None:
        if self.invalid_event_policy not in INVALID_POLICIES:
            raise ValueError(
                f"invalid_event_policy must be one of {INVALID_POLICIES}, "
                f"got {self.invalid_event_policy!r}"
            )
        if self.unsupported_protocol_policy not in UNSUPPORTED_POLICIES:
            raise ValueError(
                f"unsupported_protocol_policy must be one of "
                f"{UNSUPPORTED_POLICIES}, got {self.unsupported_protocol_policy!r}"
            )
        if self.max_decode_size <= 0:
            raise ValueError("max_decode_size must be > 0")
        if self.tcp_idle_timeout <= 0 or self.udp_idle_timeout <= 0:
            raise ValueError("idle timeouts must be > 0")

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any] | None) -> "PipelineConfig":
        """Build a config from a mapping, ignoring unknown keys safely."""
        if not data:
            return cls()
        known = {f.name for f in fields(cls)}
        unknown = set(data) - known
        if unknown:
            raise ValueError(f"unknown configuration keys: {sorted(unknown)}")
        return cls(**dict(data))

    @classmethod
    def from_json_file(cls, path: str | Path) -> "PipelineConfig":
        import json

        with Path(path).open("r", encoding="utf-8") as fp:
            return cls.from_mapping(json.load(fp))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
