"""M7 -- shadow-mode orchestration: assess, classify, aggregate, recommend.

``supervise`` (and the thin ``ShadowSupervisor`` wrapper around it) is the
single place that wires together the M3-M5 primitives -- ``compare_snapshots``,
``assess``, and ``aggregate`` -- into one inert ``ShadowReport``. It calls
those three functions and nothing else: no model, no provider, no tool, no
subprocess, no network, and no ``moiras.broker`` call. There is no callback
parameter, no tool-invocation hook, and no code path in this module that can
reach outside pure computation on the objects the caller already passed in.

A ``ShadowReport`` always has ``executed=False`` and ``mode="shadow"``. Its
``recommendation_code`` is an inert, allowlisted label -- never an
instruction to act -- and its ``counterfactual_code`` describes only the
*category* of gate that would stand between this decision and any real
execution (e.g. "this would need a human-approval gate"), never the action
itself. ``ActionRequest`` has no free-text field to leak in the first place.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from enum import Enum

from .contracts import (
    SCHEMA_VERSION,
    ActionRequest,
    ContractValidationError,
    CouncilDecision,
    CouncilOpinion,
    Environment,
    ExecutionSnapshot,
    RiskAssessment,
    SentinelResult,
    Verdict,
)
from .council import aggregate
from .risk import assess
from .sentinel import compare_snapshots

__all__ = [
    "SupervisionError",
    "RecommendationCode",
    "CounterfactualCode",
    "ShadowReport",
    "supervise",
    "ShadowSupervisor",
]


class SupervisionError(ValueError):
    """Raised when ``supervise`` receives structurally invalid input.

    This is distinct from -- and never a substitute for -- the validation
    errors raised by ``assess``, ``compare_snapshots``, and ``aggregate``
    themselves, which are allowed to propagate unchanged.
    """


class RecommendationCode(Enum):
    """An inert, allowlisted label. Never an instruction to act."""

    RECOMMEND_HALT_FOR_HUMAN = "RECOMMEND_HALT_FOR_HUMAN"
    RECOMMEND_HUMAN_REVIEW = "RECOMMEND_HUMAN_REVIEW"
    RECOMMEND_MITIGATE_THEN_REASSESS = "RECOMMEND_MITIGATE_THEN_REASSESS"
    RECOMMEND_SHADOW_CANDIDATE_ONLY = "RECOMMEND_SHADOW_CANDIDATE_ONLY"


class CounterfactualCode(Enum):
    """The *category* of gate real execution would require. Never an action."""

    WOULD_STOP_FOR_HUMAN_DECISION = "WOULD_STOP_FOR_HUMAN_DECISION"
    WOULD_REQUIRE_HUMAN_APPROVAL_GATE = "WOULD_REQUIRE_HUMAN_APPROVAL_GATE"
    WOULD_REQUIRE_MITIGATION_AND_REASSESSMENT = "WOULD_REQUIRE_MITIGATION_AND_REASSESSMENT"
    WOULD_REQUIRE_SEPARATE_AUTHORIZATION_GATE = "WOULD_REQUIRE_SEPARATE_AUTHORIZATION_GATE"


_VERDICT_TO_RECOMMENDATION = {
    Verdict.STOP_AND_HUMAN: RecommendationCode.RECOMMEND_HALT_FOR_HUMAN,
    Verdict.HUMAN_REQUIRED: RecommendationCode.RECOMMEND_HUMAN_REVIEW,
    Verdict.MITIGATE_AND_REASSESS: RecommendationCode.RECOMMEND_MITIGATE_THEN_REASSESS,
    Verdict.SHADOW_AUTOAPPROVE_CANDIDATE: RecommendationCode.RECOMMEND_SHADOW_CANDIDATE_ONLY,
}

_VERDICT_TO_COUNTERFACTUAL = {
    Verdict.STOP_AND_HUMAN: CounterfactualCode.WOULD_STOP_FOR_HUMAN_DECISION,
    Verdict.HUMAN_REQUIRED: CounterfactualCode.WOULD_REQUIRE_HUMAN_APPROVAL_GATE,
    Verdict.MITIGATE_AND_REASSESS: (CounterfactualCode.WOULD_REQUIRE_MITIGATION_AND_REASSESSMENT),
    Verdict.SHADOW_AUTOAPPROVE_CANDIDATE: (
        CounterfactualCode.WOULD_REQUIRE_SEPARATE_AUTHORIZATION_GATE
    ),
}


@dataclass(frozen=True)
class ShadowReport:
    """The complete, inert output of one ``supervise`` call.

    Always ``executed=False`` and ``mode="shadow"`` -- constructing one
    with any other value raises, exactly like ``CouncilDecision``.
    """

    risk_assessment: RiskAssessment
    council_decision: CouncilDecision
    recommendation_code: RecommendationCode
    counterfactual_code: CounterfactualCode
    sentinel_result: SentinelResult | None = None
    executed: bool = False
    mode: str = "shadow"
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        if not isinstance(self.risk_assessment, RiskAssessment):
            raise ContractValidationError("risk_assessment must be a RiskAssessment")
        if not isinstance(self.council_decision, CouncilDecision):
            raise ContractValidationError("council_decision must be a CouncilDecision")
        if not isinstance(self.recommendation_code, RecommendationCode):
            raise ContractValidationError("recommendation_code must be a RecommendationCode")
        if not isinstance(self.counterfactual_code, CounterfactualCode):
            raise ContractValidationError("counterfactual_code must be a CounterfactualCode")
        if self.sentinel_result is not None and not isinstance(
            self.sentinel_result, SentinelResult
        ):
            raise ContractValidationError("sentinel_result must be a SentinelResult or None")
        if self.executed is not False:
            raise ContractValidationError("executed must always be False in shadow mode")
        if self.mode != "shadow":
            raise ContractValidationError("mode must always be 'shadow' in v1")
        if self.schema_version != SCHEMA_VERSION:
            raise ContractValidationError(f"unsupported schema_version: {self.schema_version!r}")

    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "risk_assessment": self.risk_assessment.to_dict(),
            "sentinel_result": (
                self.sentinel_result.to_dict() if self.sentinel_result is not None else None
            ),
            "council_decision": self.council_decision.to_dict(),
            "recommendation_code": self.recommendation_code.value,
            "counterfactual_code": self.counterfactual_code.value,
            "executed": self.executed,
            "mode": self.mode,
        }


def supervise(
    action: ActionRequest,
    opinions: Sequence[CouncilOpinion],
    *,
    snapshots: tuple[ExecutionSnapshot, ExecutionSnapshot] | None = None,
    idle_threshold_s: float | None = None,
) -> ShadowReport:
    """Run one shadow-mode supervision pass. Calls only ``assess``,
    ``compare_snapshots`` (if ``snapshots`` is given), and ``aggregate`` --
    nothing else observes or touches the outside world.

    ``snapshots``, if given, must be a two-item ``(first, second)`` pair of
    ``ExecutionSnapshot`` and requires ``idle_threshold_s``. Passing
    ``idle_threshold_s`` without ``snapshots`` is rejected rather than
    silently ignored, since that combination almost always indicates a
    caller mistake.
    """

    if not isinstance(action, ActionRequest):
        raise SupervisionError("action must be an ActionRequest")
    if not isinstance(action.environment, Environment):
        raise SupervisionError("action.environment must be an Environment")
    if isinstance(opinions, (str, bytes)) or not isinstance(opinions, Sequence):
        raise SupervisionError("opinions must be a sequence of CouncilOpinion")

    sentinel_result = None
    if snapshots is not None:
        if idle_threshold_s is None:
            raise SupervisionError("idle_threshold_s is required when snapshots is provided")
        if not isinstance(snapshots, tuple) or len(snapshots) != 2:
            raise SupervisionError("snapshots must be a 2-tuple of ExecutionSnapshot")
        first, second = snapshots
        sentinel_result = compare_snapshots(first, second, idle_threshold_s=idle_threshold_s)
    elif idle_threshold_s is not None:
        raise SupervisionError("idle_threshold_s was provided but snapshots was not")

    baseline = assess(action)
    decision = aggregate(baseline, opinions, environment=action.environment)

    return ShadowReport(
        risk_assessment=baseline,
        council_decision=decision,
        recommendation_code=_VERDICT_TO_RECOMMENDATION[decision.verdict],
        counterfactual_code=_VERDICT_TO_COUNTERFACTUAL[decision.verdict],
        sentinel_result=sentinel_result,
    )


class ShadowSupervisor:
    """A thin, stateless object wrapper around ``supervise``.

    Holds no mutable state and no reference to a model, provider, tool, or
    broker -- ``run`` is a pure delegation to the module-level function.
    """

    def run(
        self,
        action: ActionRequest,
        opinions: Sequence[CouncilOpinion],
        *,
        snapshots: tuple[ExecutionSnapshot, ExecutionSnapshot] | None = None,
        idle_threshold_s: float | None = None,
    ) -> ShadowReport:
        return supervise(
            action,
            opinions,
            snapshots=snapshots,
            idle_threshold_s=idle_threshold_s,
        )
