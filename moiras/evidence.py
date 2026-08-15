"""Sanitized, human-label-aware evidence for shadow-mode research.

The recorder is intentionally local and single-process. It persists only
allowlisted categorical records; it never stores prompts, responses, commands,
paths, hosts, users, model identities, reviewer identities, or credentials.
Recommendations are predictions, never labels. Only a later HUMAN_OUTCOME with
source HUMAN_REVIEW is eligible for descriptive metrics.
"""

from __future__ import annotations

import json
import math
import os
import threading
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path

from .contracts import (
    SCHEMA_VERSION,
    ActionType,
    ContractValidationError,
    SentinelClass,
)
from .sanitize import sanitize_value, validate_id
from .supervisor import RecommendationCode

__all__ = [
    "EvidenceLevel",
    "OutcomeSource",
    "HumanOutcome",
    "EvidenceRecord",
    "EvidenceRecorder",
    "EvidenceMetrics",
]


class EvidenceLevel(Enum):
    OBSERVATION = "OBSERVATION"
    RECOMMENDATION = "RECOMMENDATION"
    HUMAN_OUTCOME = "HUMAN_OUTCOME"


class OutcomeSource(Enum):
    HUMAN_REVIEW = "HUMAN_REVIEW"


class HumanOutcome(Enum):
    SAFE = "SAFE"
    UNSAFE = "UNSAFE"
    INDETERMINATE = "INDETERMINATE"


def _require_utc(value: object) -> None:
    if not isinstance(value, datetime):
        raise ContractValidationError("timestamp_utc must be a datetime")
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ContractValidationError("timestamp_utc must be timezone-aware UTC")


@dataclass(frozen=True)
class EvidenceRecord:
    """One allowlisted record at exactly one of three evidence levels."""

    execution_id: str
    attempt_id: str
    timestamp_utc: datetime
    level: EvidenceLevel
    sentinel_class: SentinelClass | None = None
    action_type: ActionType | None = None
    risk_score: float | None = None
    recommendation_code: RecommendationCode | None = None
    human_outcome: HumanOutcome | None = None
    outcome_source: OutcomeSource | None = None
    executed: bool = False
    mode: str = "shadow"
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        validate_id(self.execution_id, field_name="execution_id")
        validate_id(self.attempt_id, field_name="attempt_id")
        _require_utc(self.timestamp_utc)
        if not isinstance(self.level, EvidenceLevel):
            raise ContractValidationError("level must be an EvidenceLevel")
        if self.executed is not False:
            raise ContractValidationError("executed must always be False")
        if self.mode != "shadow":
            raise ContractValidationError("mode must always be 'shadow'")
        if self.schema_version != SCHEMA_VERSION:
            raise ContractValidationError(f"unsupported schema_version: {self.schema_version!r}")
        self._validate_level_fields()

    def _validate_level_fields(self) -> None:
        if self.level == EvidenceLevel.OBSERVATION:
            if not isinstance(self.sentinel_class, SentinelClass):
                raise ContractValidationError("OBSERVATION requires sentinel_class")
            if any(
                value is not None
                for value in (
                    self.action_type,
                    self.risk_score,
                    self.recommendation_code,
                    self.human_outcome,
                    self.outcome_source,
                )
            ):
                raise ContractValidationError("OBSERVATION accepts only sentinel_class")
            return

        if self.level == EvidenceLevel.RECOMMENDATION:
            if not isinstance(self.action_type, ActionType):
                raise ContractValidationError("RECOMMENDATION requires action_type")
            if isinstance(self.risk_score, bool) or not isinstance(self.risk_score, (int, float)):
                raise ContractValidationError("RECOMMENDATION requires numeric risk_score")
            if not math.isfinite(self.risk_score) or not 0 <= self.risk_score <= 10:
                raise ContractValidationError("risk_score must be finite in [0, 10]")
            if not isinstance(self.recommendation_code, RecommendationCode):
                raise ContractValidationError("RECOMMENDATION requires recommendation_code")
            if any(
                value is not None
                for value in (
                    self.sentinel_class,
                    self.human_outcome,
                    self.outcome_source,
                )
            ):
                raise ContractValidationError(
                    "RECOMMENDATION cannot contain observation or outcome fields"
                )
            return

        if not isinstance(self.human_outcome, HumanOutcome):
            raise ContractValidationError("HUMAN_OUTCOME requires human_outcome")
        if self.outcome_source != OutcomeSource.HUMAN_REVIEW:
            raise ContractValidationError("HUMAN_OUTCOME requires source HUMAN_REVIEW")
        if any(
            value is not None
            for value in (
                self.sentinel_class,
                self.action_type,
                self.risk_score,
                self.recommendation_code,
            )
        ):
            raise ContractValidationError(
                "HUMAN_OUTCOME cannot contain observation or recommendation fields"
            )

    def to_dict(self) -> dict:
        payload = {
            "schema_version": self.schema_version,
            "execution_id": self.execution_id,
            "attempt_id": self.attempt_id,
            "timestamp_utc": self.timestamp_utc.isoformat(),
            "level": self.level.value,
            "executed": self.executed,
            "mode": self.mode,
        }
        if self.level == EvidenceLevel.OBSERVATION:
            payload["sentinel_class"] = self.sentinel_class.value
        elif self.level == EvidenceLevel.RECOMMENDATION:
            payload.update(
                {
                    "action_type": self.action_type.value,
                    "risk_score": float(self.risk_score),
                    "recommendation_code": self.recommendation_code.value,
                }
            )
        else:
            payload.update(
                {
                    "human_outcome": self.human_outcome.value,
                    "outcome_source": self.outcome_source.value,
                }
            )
        return payload


class EvidenceRecorder:
    """Append-only JSONL recorder protected only within this Python process."""

    def __init__(self, destination: str | os.PathLike[str]) -> None:
        if not isinstance(destination, (str, os.PathLike)):
            raise TypeError("destination must be path-like")
        self._destination = Path(destination)
        self._lock = threading.Lock()

    def record(self, record: EvidenceRecord) -> None:
        if not isinstance(record, EvidenceRecord):
            raise TypeError("record must be an EvidenceRecord")
        payload = sanitize_value(record.to_dict())
        line = json.dumps(
            payload,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        with self._lock:
            with self._destination.open("a", encoding="utf-8", newline="\n") as stream:
                stream.write(line + "\n")


@dataclass(frozen=True)
class EvidenceMetrics:
    """Descriptive correlation metrics, not a benchmark or accuracy claim.

    A candidate is labeled only when at least one strictly later human outcome
    exists and all later decisive labels agree. INDETERMINATE or conflicting
    labels make that candidate ambiguous and exclude it from the unsafe-rate
    denominator. Input iteration order does not affect the result.
    """

    candidate_count: int
    labeled_candidates: int
    ambiguous_candidates: int
    unsafe_candidate_count: int
    coverage: float | None
    unsafe_candidate_rate: float | None

    @classmethod
    def compute(cls, records: Iterable[EvidenceRecord]) -> EvidenceMetrics:
        recommendations: dict[tuple[str, str], list[tuple[datetime, RecommendationCode]]] = {}
        outcomes: dict[tuple[str, str], list[tuple[datetime, HumanOutcome]]] = {}

        for record in records:
            if not isinstance(record, EvidenceRecord):
                raise TypeError("records must contain EvidenceRecord instances")
            key = (record.execution_id, record.attempt_id)
            if (
                record.level == EvidenceLevel.RECOMMENDATION
                and record.recommendation_code == RecommendationCode.RECOMMEND_SHADOW_CANDIDATE_ONLY
            ):
                recommendations.setdefault(key, []).append(
                    (record.timestamp_utc, record.recommendation_code)
                )
            elif record.level == EvidenceLevel.RECOMMENDATION:
                recommendations.setdefault(key, []).append(
                    (record.timestamp_utc, record.recommendation_code)
                )
            elif record.level == EvidenceLevel.HUMAN_OUTCOME:
                outcomes.setdefault(key, []).append((record.timestamp_utc, record.human_outcome))

        candidates: dict[tuple[str, str], datetime] = {}
        for key, events in recommendations.items():
            latest_time = max(timestamp for timestamp, _code in events)
            latest_codes = {code for timestamp, code in events if timestamp == latest_time}
            if latest_codes == {RecommendationCode.RECOMMEND_SHADOW_CANDIDATE_ONLY}:
                candidates[key] = latest_time

        labeled = 0
        ambiguous = 0
        unsafe = 0
        for key, recommendation_time in candidates.items():
            later_labels = {
                label
                for timestamp, label in outcomes.get(key, ())
                if timestamp > recommendation_time
            }
            if not later_labels:
                continue
            if HumanOutcome.INDETERMINATE in later_labels or len(later_labels) != 1:
                ambiguous += 1
                continue
            label = next(iter(later_labels))
            labeled += 1
            if label == HumanOutcome.UNSAFE:
                unsafe += 1

        candidate_count = len(candidates)
        coverage = labeled / candidate_count if candidate_count else None
        unsafe_rate = unsafe / labeled if labeled else None
        return cls(
            candidate_count=candidate_count,
            labeled_candidates=labeled,
            ambiguous_candidates=ambiguous,
            unsafe_candidate_count=unsafe,
            coverage=coverage,
            unsafe_candidate_rate=unsafe_rate,
        )

    def to_dict(self) -> dict:
        return {
            "candidate_count": self.candidate_count,
            "labeled_candidates": self.labeled_candidates,
            "ambiguous_candidates": self.ambiguous_candidates,
            "unsafe_candidate_count": self.unsafe_candidate_count,
            "coverage": self.coverage,
            "unsafe_candidate_rate": self.unsafe_candidate_rate,
        }
