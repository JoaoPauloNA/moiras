"""Typed contracts for Moiras shadow-mode supervision.

Every structure here is a frozen dataclass or enum with an explicit,
allowlisted ``to_dict``. Nothing in this module accepts or emits arbitrary
dictionaries: fields are validated in ``__post_init__`` and rejected loudly
(``ContractValidationError``) rather than coerced or silently dropped.

Moiras is advisory-only. Nothing defined here represents, triggers, or
records an executed action.
"""

from __future__ import annotations

import math
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from types import MappingProxyType

from .sanitize import validate_id

__all__ = [
    "SCHEMA_VERSION",
    "ContractValidationError",
    "LifecycleState",
    "ExecutionSnapshot",
    "ActionType",
    "Environment",
    "Reversibility",
    "Scope",
    "ActionRequest",
    "RiskDimension",
    "ReasonCode",
    "MitigationCode",
    "RiskAssessment",
    "SentinelClass",
    "EvidenceCode",
    "SentinelResult",
    "CouncilRole",
    "ModelCapabilityClass",
    "CouncilOpinion",
    "Verdict",
    "CouncilDecision",
]

SCHEMA_VERSION = "1.0"


class ContractValidationError(ValueError):
    """Raised when a Moiras contract dataclass receives invalid data."""


def _require_bool(value: object, field_name: str) -> None:
    if not isinstance(value, bool):
        raise ContractValidationError(f"{field_name} must be a bool")


def _require_nonneg_int(value: object, field_name: str) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ContractValidationError(f"{field_name} must be a non-negative int")


def _require_finite_range(value: object, field_name: str, lo: float, hi: float) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ContractValidationError(f"{field_name} must be a number")
    if not math.isfinite(value):
        raise ContractValidationError(f"{field_name} must be finite")
    if not (lo <= value <= hi):
        raise ContractValidationError(f"{field_name} must be in [{lo}, {hi}]")


def _materialize_enum_codes(value: object, enum_type: type[Enum], field_name: str) -> tuple:
    """Materialize an iterable once, then validate and retain that same tuple."""

    try:
        codes = tuple(value)
    except TypeError as exc:
        raise ContractValidationError(f"{field_name} must be an iterable") from exc
    if any(not isinstance(code, enum_type) for code in codes):
        raise ContractValidationError(f"{field_name} must be {enum_type.__name__} values")
    return codes


# ---------------------------------------------------------------------------
# Temporal snapshot (Sentinel input)
# ---------------------------------------------------------------------------


class LifecycleState(Enum):
    QUEUED = "QUEUED"
    STARTING = "STARTING"
    RUNNING = "RUNNING"
    CANCELLATION_REQUESTED = "CANCELLATION_REQUESTED"
    TERMINATING = "TERMINATING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    TIMED_OUT = "TIMED_OUT"
    TERMINATION_UNCONFIRMED = "TERMINATION_UNCONFIRMED"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class ExecutionSnapshot:
    """A single point-in-time, non-identifying view of an execution.

    Deliberately excludes anything that could leak content or identity:
    no prompt, output, command, path, host, user, or pid. Only counters,
    flags, and timestamps that let the Sentinel reason about progress.
    """

    execution_id: str
    attempt_id: str
    profile: str
    lifecycle_state: LifecycleState
    captured_at_utc: datetime
    monotonic_offset_s: float
    progress_counter: int
    activity_counter: int
    artifact_revision: int
    waiting_for_authorization: bool
    waiting_for_credential: bool
    external_block: bool
    terminal: bool
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        validate_id(self.execution_id, field_name="execution_id")
        validate_id(self.attempt_id, field_name="attempt_id")
        validate_id(self.profile, field_name="profile")

        if not isinstance(self.lifecycle_state, LifecycleState):
            raise ContractValidationError("lifecycle_state must be a LifecycleState")

        if not isinstance(self.captured_at_utc, datetime):
            raise ContractValidationError("captured_at_utc must be a datetime")
        if self.captured_at_utc.tzinfo is None or self.captured_at_utc.utcoffset() != timedelta(0):
            raise ContractValidationError("captured_at_utc must be timezone-aware UTC")

        if isinstance(self.monotonic_offset_s, bool) or not isinstance(
            self.monotonic_offset_s, (int, float)
        ):
            raise ContractValidationError("monotonic_offset_s must be a number")
        if not math.isfinite(self.monotonic_offset_s) or self.monotonic_offset_s < 0:
            raise ContractValidationError("monotonic_offset_s must be finite and >= 0")

        _require_nonneg_int(self.progress_counter, "progress_counter")
        _require_nonneg_int(self.activity_counter, "activity_counter")
        _require_nonneg_int(self.artifact_revision, "artifact_revision")

        _require_bool(self.waiting_for_authorization, "waiting_for_authorization")
        _require_bool(self.waiting_for_credential, "waiting_for_credential")
        _require_bool(self.external_block, "external_block")
        _require_bool(self.terminal, "terminal")

        if self.schema_version != SCHEMA_VERSION:
            raise ContractValidationError(f"unsupported schema_version: {self.schema_version!r}")

    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "execution_id": self.execution_id,
            "attempt_id": self.attempt_id,
            "profile": self.profile,
            "lifecycle_state": self.lifecycle_state.value,
            "captured_at_utc": self.captured_at_utc.isoformat(),
            "monotonic_offset_s": self.monotonic_offset_s,
            "progress_counter": self.progress_counter,
            "activity_counter": self.activity_counter,
            "artifact_revision": self.artifact_revision,
            "waiting_for_authorization": self.waiting_for_authorization,
            "waiting_for_credential": self.waiting_for_credential,
            "external_block": self.external_block,
            "terminal": self.terminal,
        }


# ---------------------------------------------------------------------------
# Action request (Risk input)
# ---------------------------------------------------------------------------


class ActionType(Enum):
    PUBLIC_WEB_READ = "PUBLIC_WEB_READ"
    CREATE_TEMP_FILE = "CREATE_TEMP_FILE"
    EDIT_DOCUMENTATION = "EDIT_DOCUMENTATION"
    CREATE_SENSITIVE_CONFIG = "CREATE_SENSITIVE_CONFIG"
    EDIT_CODE = "EDIT_CODE"
    EDIT_AUTH = "EDIT_AUTH"
    DELETE_REPRODUCIBLE_CACHE = "DELETE_REPRODUCIBLE_CACHE"
    DELETE_UNIQUE_FILE = "DELETE_UNIQUE_FILE"
    DELETE_BROAD_PATH = "DELETE_BROAD_PATH"
    DATABASE_DELETE = "DATABASE_DELETE"
    DATABASE_DROP = "DATABASE_DROP"
    REQUEST_SUDO = "REQUEST_SUDO"
    REQUEST_CREDENTIAL = "REQUEST_CREDENTIAL"
    EXTERNAL_SEND = "EXTERNAL_SEND"
    CREATE_PRIVILEGED_USER = "CREATE_PRIVILEGED_USER"
    AMBIGUOUS = "AMBIGUOUS"


class Environment(Enum):
    DISPOSABLE = "DISPOSABLE"
    DEVELOPMENT = "DEVELOPMENT"
    PRODUCTION = "PRODUCTION"
    UNKNOWN = "UNKNOWN"


class Reversibility(Enum):
    REVERSIBLE = "REVERSIBLE"
    PARTIAL = "PARTIAL"
    IRREVERSIBLE = "IRREVERSIBLE"
    UNKNOWN = "UNKNOWN"


class Scope(Enum):
    SINGLE = "SINGLE"
    LIMITED = "LIMITED"
    BROAD = "BROAD"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class ActionRequest:
    action_type: ActionType
    environment: Environment
    reversibility: Reversibility
    scope: Scope
    sensitive_data: bool
    external_side_effect: bool
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        if not isinstance(self.action_type, ActionType):
            raise ContractValidationError("action_type must be an ActionType")
        if not isinstance(self.environment, Environment):
            raise ContractValidationError("environment must be an Environment")
        if not isinstance(self.reversibility, Reversibility):
            raise ContractValidationError("reversibility must be a Reversibility")
        if not isinstance(self.scope, Scope):
            raise ContractValidationError("scope must be a Scope")
        _require_bool(self.sensitive_data, "sensitive_data")
        _require_bool(self.external_side_effect, "external_side_effect")
        if self.schema_version != SCHEMA_VERSION:
            raise ContractValidationError(f"unsupported schema_version: {self.schema_version!r}")

    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "action_type": self.action_type.value,
            "environment": self.environment.value,
            "reversibility": self.reversibility.value,
            "scope": self.scope.value,
            "sensitive_data": self.sensitive_data,
            "external_side_effect": self.external_side_effect,
        }


# ---------------------------------------------------------------------------
# Risk assessment
# ---------------------------------------------------------------------------


class RiskDimension(Enum):
    REVERSIBILITY = "REVERSIBILITY"
    SCOPE = "SCOPE"
    ENVIRONMENT = "ENVIRONMENT"
    SENSITIVE_DATA = "SENSITIVE_DATA"
    EXTERNAL_EXPOSURE = "EXTERNAL_EXPOSURE"


class ReasonCode(Enum):
    HARD_STOP_ACTION = "HARD_STOP_ACTION"
    HIGH_SEVERITY_ACTION_TYPE = "HIGH_SEVERITY_ACTION_TYPE"
    ZERO_RISK_EXEMPTION = "ZERO_RISK_EXEMPTION"
    IRREVERSIBLE_OR_PARTIAL = "IRREVERSIBLE_OR_PARTIAL"
    BROAD_OR_UNKNOWN_SCOPE = "BROAD_OR_UNKNOWN_SCOPE"
    PRODUCTION_OR_UNKNOWN_ENVIRONMENT = "PRODUCTION_OR_UNKNOWN_ENVIRONMENT"
    SENSITIVE_DATA_INVOLVED = "SENSITIVE_DATA_INVOLVED"
    EXTERNAL_SIDE_EFFECT = "EXTERNAL_SIDE_EFFECT"
    SCORE_TEN = "SCORE_TEN"
    COUNCIL_INCOMPLETE = "COUNCIL_INCOMPLETE"
    COUNCIL_DUPLICATE_ROLE = "COUNCIL_DUPLICATE_ROLE"
    COUNCIL_INELIGIBLE_MODEL = "COUNCIL_INELIGIBLE_MODEL"
    COUNCIL_VETO = "COUNCIL_VETO"
    COUNCIL_DIVERGENCE = "COUNCIL_DIVERGENCE"
    RISK_BAND_HUMAN = "RISK_BAND_HUMAN"
    RISK_BAND_MITIGATE = "RISK_BAND_MITIGATE"
    NON_DISPOSABLE_ENVIRONMENT = "NON_DISPOSABLE_ENVIRONMENT"
    SHADOW_CANDIDATE_ONLY = "SHADOW_CANDIDATE_ONLY"


class MitigationCode(Enum):
    NONE = "NONE"
    REQUIRE_HUMAN_APPROVAL = "REQUIRE_HUMAN_APPROVAL"
    REQUIRE_BACKUP_BEFORE_ACTION = "REQUIRE_BACKUP_BEFORE_ACTION"
    REQUIRE_DRY_RUN = "REQUIRE_DRY_RUN"
    NARROW_SCOPE = "NARROW_SCOPE"
    REQUIRE_ADDITIONAL_REVIEW = "REQUIRE_ADDITIONAL_REVIEW"


@dataclass(frozen=True)
class RiskAssessment:
    score: float
    dimension_scores: Mapping[RiskDimension, float]
    reason_codes: tuple
    bypass_council: bool
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        _require_finite_range(self.score, "score", 0, 10)

        if not isinstance(self.dimension_scores, Mapping):
            raise ContractValidationError("dimension_scores must be a mapping")
        normalized_dims = {}
        for dim, value in self.dimension_scores.items():
            if not isinstance(dim, RiskDimension):
                raise ContractValidationError("dimension_scores keys must be RiskDimension")
            _require_finite_range(value, f"dimension_scores[{dim}]", 0, 10)
            normalized_dims[dim] = float(value)
        object.__setattr__(self, "dimension_scores", MappingProxyType(normalized_dims))

        reason_codes = _materialize_enum_codes(
            self.reason_codes,
            ReasonCode,
            "reason_codes",
        )
        object.__setattr__(self, "reason_codes", reason_codes)

        _require_bool(self.bypass_council, "bypass_council")
        if self.schema_version != SCHEMA_VERSION:
            raise ContractValidationError(f"unsupported schema_version: {self.schema_version!r}")

    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "score": self.score,
            "dimension_scores": {dim.value: value for dim, value in self.dimension_scores.items()},
            "reason_codes": [code.value for code in self.reason_codes],
            "bypass_council": self.bypass_council,
        }


# ---------------------------------------------------------------------------
# Sentinel result
# ---------------------------------------------------------------------------


class SentinelClass(Enum):
    REAL_PROGRESS = "REAL_PROGRESS"
    ACTIVITY_WITHOUT_PROGRESS = "ACTIVITY_WITHOUT_PROGRESS"
    PROBABLE_INACTIVITY = "PROBABLE_INACTIVITY"
    LEGITIMATE_WAIT = "LEGITIMATE_WAIT"
    EXTERNAL_BLOCK = "EXTERNAL_BLOCK"
    INDETERMINATE = "INDETERMINATE"


class EvidenceCode(Enum):
    PROGRESS_COUNTER_INCREASED = "PROGRESS_COUNTER_INCREASED"
    ARTIFACT_REVISION_INCREASED = "ARTIFACT_REVISION_INCREASED"
    BECAME_TERMINAL = "BECAME_TERMINAL"
    ACTIVITY_COUNTER_INCREASED = "ACTIVITY_COUNTER_INCREASED"
    NO_PROGRESS_NO_ACTIVITY = "NO_PROGRESS_NO_ACTIVITY"
    IDLE_THRESHOLD_EXCEEDED = "IDLE_THRESHOLD_EXCEEDED"
    IDLE_THRESHOLD_NOT_EXCEEDED = "IDLE_THRESHOLD_NOT_EXCEEDED"
    WAITING_FOR_AUTHORIZATION = "WAITING_FOR_AUTHORIZATION"
    WAITING_FOR_CREDENTIAL = "WAITING_FOR_CREDENTIAL"
    EXTERNAL_BLOCK_FLAG = "EXTERNAL_BLOCK_FLAG"


@dataclass(frozen=True)
class SentinelResult:
    classification: SentinelClass
    evidence_codes: tuple
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        if not isinstance(self.classification, SentinelClass):
            raise ContractValidationError("classification must be a SentinelClass")
        evidence_codes = _materialize_enum_codes(
            self.evidence_codes,
            EvidenceCode,
            "evidence_codes",
        )
        object.__setattr__(self, "evidence_codes", evidence_codes)
        if self.schema_version != SCHEMA_VERSION:
            raise ContractValidationError(f"unsupported schema_version: {self.schema_version!r}")

    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "classification": self.classification.value,
            "evidence_codes": [code.value for code in self.evidence_codes],
        }


# ---------------------------------------------------------------------------
# Council
# ---------------------------------------------------------------------------


class CouncilRole(Enum):
    SECURITY = "SECURITY"
    INTEGRITY = "INTEGRITY"
    GOVERNANCE = "GOVERNANCE"
    OPERATIONS = "OPERATIONS"


class ModelCapabilityClass(Enum):
    FRONTIER = "FRONTIER"
    CAPABLE_GENERAL = "CAPABLE_GENERAL"
    EDGE = "EDGE"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class CouncilOpinion:
    reviewer_id: str
    model_id: str
    role: CouncilRole
    capability_class: ModelCapabilityClass
    risk_score: float
    confidence: float
    veto: bool
    dimension_scores: Mapping[RiskDimension, float]
    reason_codes: tuple
    mitigation_codes: tuple
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        validate_id(self.reviewer_id, field_name="reviewer_id")
        validate_id(self.model_id, field_name="model_id")

        if not isinstance(self.role, CouncilRole):
            raise ContractValidationError("role must be a CouncilRole")
        if not isinstance(self.capability_class, ModelCapabilityClass):
            raise ContractValidationError("capability_class must be a ModelCapabilityClass")

        _require_finite_range(self.risk_score, "risk_score", 0, 10)
        _require_finite_range(self.confidence, "confidence", 0, 1)
        _require_bool(self.veto, "veto")

        if not isinstance(self.dimension_scores, Mapping):
            raise ContractValidationError("dimension_scores must be a mapping")
        normalized_dims = {}
        for dim, value in self.dimension_scores.items():
            if not isinstance(dim, RiskDimension):
                raise ContractValidationError("dimension_scores keys must be RiskDimension")
            _require_finite_range(value, f"dimension_scores[{dim}]", 0, 10)
            normalized_dims[dim] = float(value)
        object.__setattr__(self, "dimension_scores", MappingProxyType(normalized_dims))

        reason_codes = _materialize_enum_codes(
            self.reason_codes,
            ReasonCode,
            "reason_codes",
        )
        object.__setattr__(self, "reason_codes", reason_codes)

        mitigation_codes = _materialize_enum_codes(
            self.mitigation_codes,
            MitigationCode,
            "mitigation_codes",
        )
        object.__setattr__(self, "mitigation_codes", mitigation_codes)

        if self.schema_version != SCHEMA_VERSION:
            raise ContractValidationError(f"unsupported schema_version: {self.schema_version!r}")

    @property
    def eligible(self) -> bool:
        return self.capability_class in (
            ModelCapabilityClass.FRONTIER,
            ModelCapabilityClass.CAPABLE_GENERAL,
        )

    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "reviewer_id": self.reviewer_id,
            "model_id": self.model_id,
            "role": self.role.value,
            "capability_class": self.capability_class.value,
            "risk_score": self.risk_score,
            "confidence": self.confidence,
            "veto": self.veto,
            "dimension_scores": {dim.value: value for dim, value in self.dimension_scores.items()},
            "reason_codes": [code.value for code in self.reason_codes],
            "mitigation_codes": [code.value for code in self.mitigation_codes],
        }


class Verdict(Enum):
    STOP_AND_HUMAN = "STOP_AND_HUMAN"
    HUMAN_REQUIRED = "HUMAN_REQUIRED"
    MITIGATE_AND_REASSESS = "MITIGATE_AND_REASSESS"
    SHADOW_AUTOAPPROVE_CANDIDATE = "SHADOW_AUTOAPPROVE_CANDIDATE"


@dataclass(frozen=True)
class CouncilDecision:
    verdict: Verdict
    final_score: float
    council_bypassed: bool
    reason_codes: tuple
    executed: bool = False
    mode: str = "shadow"
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        if not isinstance(self.verdict, Verdict):
            raise ContractValidationError("verdict must be a Verdict")
        _require_finite_range(self.final_score, "final_score", 0, 10)
        _require_bool(self.council_bypassed, "council_bypassed")
        reason_codes = _materialize_enum_codes(
            self.reason_codes,
            ReasonCode,
            "reason_codes",
        )
        object.__setattr__(self, "reason_codes", reason_codes)
        if self.executed is not False:
            raise ContractValidationError("executed must always be False in shadow mode")
        if self.mode != "shadow":
            raise ContractValidationError("mode must always be 'shadow' in v1")
        if self.schema_version != SCHEMA_VERSION:
            raise ContractValidationError(f"unsupported schema_version: {self.schema_version!r}")

    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "verdict": self.verdict.value,
            "final_score": self.final_score,
            "council_bypassed": self.council_bypassed,
            "reason_codes": [code.value for code in self.reason_codes],
            "executed": self.executed,
            "mode": self.mode,
        }
