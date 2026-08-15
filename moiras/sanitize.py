"""Recursive sanitization for anything that might leave Moiras.

Two responsibilities live here:

1. ``validate_id`` — the strict charset used for every identifier that
   appears in a Moiras contract (execution_id, attempt_id, profile,
   reviewer_id, model_id, ...).
2. ``sanitize_value`` — a recursive guard for arbitrary structures that are
   not part of an allowlisted contract's ``to_dict``. It rejects forbidden
   keys and secret-shaped or path-shaped strings outright.

Nothing here redacts. A rejected value raises ``SanitizationError``; it is
never silently stripped, masked, or truncated, and no rationale beyond the
raised message is produced.
"""

from __future__ import annotations

import math
import re
from collections.abc import Mapping
from typing import Any

__all__ = [
    "SanitizationError",
    "ID_PATTERN",
    "MAX_ID_LENGTH",
    "FORBIDDEN_KEYS",
    "SECRET_PREFIXES",
    "validate_id",
    "sanitize_value",
]


class SanitizationError(ValueError):
    """Raised when a value or key is rejected by sanitization checks."""


ID_PATTERN = re.compile(r"^[A-Za-z0-9._:-]+$")
MAX_ID_LENGTH = 128

# Keys that must never appear anywhere in data that leaves Moiras. They are
# matched as exact normalized keys or complete separator-delimited tokens.
# Serialized contract fields use the explicit allowlist below.
FORBIDDEN_KEYS = frozenset(
    {
        "prompt",
        "output",
        "response",
        "command",
        "path",
        "host",
        "user",
        "username",
        "password",
        "token",
        "secret",
        "credential",
        "authorization",
        "api_key",
        "env",
        "pid",
    }
)

# Exact serialized contract keys are safe by construction. Some contain a
# forbidden word as part of a *status name* (for example
# waiting_for_authorization) or a domain label (environment); allowing these
# exact names avoids confusing a boolean/status field with credential content.
ALLOWED_CONTRACT_KEYS = frozenset(
    {
        "schema_version",
        "execution_id",
        "attempt_id",
        "profile",
        "lifecycle_state",
        "captured_at_utc",
        "monotonic_offset_s",
        "progress_counter",
        "activity_counter",
        "artifact_revision",
        "waiting_for_authorization",
        "waiting_for_credential",
        "external_block",
        "terminal",
        "action_type",
        "environment",
        "reversibility",
        "scope",
        "sensitive_data",
        "external_side_effect",
        "score",
        "dimension_scores",
        "reason_codes",
        "bypass_council",
        "classification",
        "evidence_codes",
        "reviewer_id",
        "model_id",
        "role",
        "capability_class",
        "risk_score",
        "confidence",
        "veto",
        "mitigation_codes",
        "verdict",
        "final_score",
        "council_bypassed",
        "executed",
        "mode",
        "REVERSIBILITY",
        "SCOPE",
        "ENVIRONMENT",
        "SENSITIVE_DATA",
        "EXTERNAL_EXPOSURE",
        "recommendation_code",
        "counterfactual_code",
        "risk_assessment",
        "sentinel_result",
        "council_decision",
        "timestamp_utc",
        "level",
        "sentinel_class",
        "human_outcome",
        "outcome_source",
        "capability_id",
        "issued_at_monotonic",
        "expires_at_monotonic",
        "ttl_s",
        "synthetic",
        "authorizes_real_action",
        "status",
        "coverage",
        "candidate_count",
        "labeled_candidates",
        "ambiguous_candidates",
        "unsafe_candidate_count",
        "unsafe_candidate_rate",
        "python_version",
        "platform_family",
        "passed",
        "failed",
        "total",
        "success",
        "scenarios",
        "scenario",
    }
)

SECRET_PREFIXES = (
    "sk-",
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "github_pat_",
    "xox",
    "AKIA",
    "AIza",
    "Bearer ",
    "-----BEGIN",
)

SENSITIVE_ID_MARKERS = (
    "token",
    "secret",
    "password",
    "credential",
    "authorization",
    "bearer",
    "api_key",
    "apikey",
    "user",
    "username",
    "path",
    "host",
)

_NON_ALNUM = re.compile(r"[^a-z0-9]+")


def _normalize_key(text: str) -> str:
    return _NON_ALNUM.sub("", text.lower())


_FORBIDDEN_NORMALIZED = frozenset(_normalize_key(k) for k in FORBIDDEN_KEYS)


def validate_id(value: str, *, field_name: str = "id") -> str:
    """Validate a Moiras identifier: ``[A-Za-z0-9._:-]+``, length-bounded.

    Raises SanitizationError on anything else. Returns the value unchanged.
    """

    if not isinstance(value, str):
        raise SanitizationError(f"{field_name} must be a string")
    if not value:
        raise SanitizationError(f"{field_name} must not be empty")
    if len(value) > MAX_ID_LENGTH:
        raise SanitizationError(f"{field_name} exceeds max length {MAX_ID_LENGTH}")
    if not ID_PATTERN.match(value):
        raise SanitizationError(f"{field_name} contains disallowed characters: {value!r}")
    lowered = value.lower()
    normalized = _normalize_key(value)
    normalized_markers = (_normalize_key(marker) for marker in SENSITIVE_ID_MARKERS)
    if any(marker in normalized for marker in normalized_markers):
        raise SanitizationError(f"{field_name} contains a sensitive marker")
    if any(lowered.startswith(prefix.lower()) for prefix in SECRET_PREFIXES):
        raise SanitizationError(f"{field_name} looks like a credential")
    return value


def _looks_like_absolute_path(value: str) -> bool:
    if value.startswith("/") or value.startswith("\\\\"):
        return True
    if len(value) >= 3 and value[1] == ":" and value[2] in ("\\", "/"):
        return True
    if value.startswith("~"):
        return True
    return False


def _check_key(key: Any) -> None:
    if not isinstance(key, str):
        raise SanitizationError(f"non-string key not allowed: {key!r}")
    if key in ALLOWED_CONTRACT_KEYS:
        return
    normalized = _normalize_key(key)
    tokens = frozenset(part for part in _NON_ALNUM.split(key.lower()) if part)
    if normalized in _FORBIDDEN_NORMALIZED or tokens.intersection(FORBIDDEN_KEYS):
        raise SanitizationError(f"forbidden key: {key!r}")
    if "apikey" in normalized:
        raise SanitizationError(f"forbidden key: {key!r}")


def _check_string_value(value: str) -> None:
    candidate = value.lstrip()
    lowered = value.lower()
    for prefix in SECRET_PREFIXES:
        if prefix.lower() in lowered:
            raise SanitizationError(f"value looks like a secret (prefix {prefix!r})")
    if _looks_like_absolute_path(candidate):
        raise SanitizationError(f"value looks like an absolute path: {value!r}")
    if re.search(
        r"(?:^|\s)/(?!/)[A-Za-z0-9._~-]+(?:/[A-Za-z0-9._~-]+)*(?=$|[\s,.;:)])",
        candidate,
    ):
        raise SanitizationError("value contains an absolute path")
    if re.search(r"(?:^|\s)[A-Za-z]:[\\/]", candidate):
        raise SanitizationError("value contains an absolute Windows path")
    if re.search(r"(?:^|\s)\\\\[^\s\\]+\\[^\s\\]+", candidate):
        raise SanitizationError("value contains an absolute UNC path")


def sanitize_value(value: Any) -> Any:
    """Recursively validate a structure, raising on the first violation.

    Accepts mappings, lists, tuples, strings, bools, ints, floats, and
    ``None``. Mapping keys are checked against ``FORBIDDEN_KEYS``; string
    values are checked against ``SECRET_PREFIXES`` and absolute-path shapes.
    Returns the value unchanged when it passes -- this function validates,
    it does not transform or redact.
    """

    if isinstance(value, Mapping):
        result = {}
        for key, sub_value in value.items():
            _check_key(key)
            result[key] = sanitize_value(sub_value)
        return result
    if isinstance(value, (list, tuple)):
        return type(value)(sanitize_value(item) for item in value)
    if isinstance(value, str):
        _check_string_value(value)
        return value
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, float) and not math.isfinite(value):
        raise SanitizationError("non-finite floats are not JSON-safe")
    if isinstance(value, (int, float)):
        return value
    raise SanitizationError(f"unsupported value type: {type(value)!r}")
