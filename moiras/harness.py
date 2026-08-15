"""Deterministic, offline release gate for the Moiras shadow laboratory."""

from __future__ import annotations

import sys
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timezone

from .contracts import (
    SCHEMA_VERSION,
    ActionRequest,
    ActionType,
    CouncilOpinion,
    CouncilRole,
    Environment,
    ExecutionSnapshot,
    LifecycleState,
    ModelCapabilityClass,
    Reversibility,
    Scope,
    SentinelClass,
    Verdict,
)
from .sanitize import sanitize_value, validate_id
from .supervisor import RecommendationCode, supervise

__all__ = ["Scenario", "ScenarioResult", "GateResult", "SCENARIOS", "run_gate"]

_FIXED_UTC = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _action(
    action_type: ActionType,
    *,
    environment: Environment = Environment.DISPOSABLE,
    reversibility: Reversibility = Reversibility.REVERSIBLE,
    scope: Scope = Scope.SINGLE,
) -> ActionRequest:
    return ActionRequest(
        action_type=action_type,
        environment=environment,
        reversibility=reversibility,
        scope=scope,
        sensitive_data=False,
        external_side_effect=False,
    )


def _opinion(
    role: CouncilRole,
    *,
    score: float = 1.0,
    veto: bool = False,
    capability: ModelCapabilityClass = ModelCapabilityClass.FRONTIER,
) -> CouncilOpinion:
    suffix = role.value.lower()
    return CouncilOpinion(
        reviewer_id=f"reviewer-{suffix}",
        model_id="capable-model",
        role=role,
        capability_class=capability,
        risk_score=score,
        confidence=0.9,
        veto=veto,
        dimension_scores={},
        reason_codes=(),
        mitigation_codes=(),
    )


def _panel(
    *,
    scores: dict[CouncilRole, float] | None = None,
    veto_role: CouncilRole | None = None,
    capability: ModelCapabilityClass = ModelCapabilityClass.FRONTIER,
) -> tuple[CouncilOpinion, ...]:
    scores = scores or {}
    return tuple(
        _opinion(
            role,
            score=scores.get(role, 1.0),
            veto=role == veto_role,
            capability=capability,
        )
        for role in CouncilRole
    )


def _snapshot(
    monotonic_s: float,
    *,
    progress: int = 1,
    activity: int = 1,
    waiting_for_authorization: bool = False,
    waiting_for_credential: bool = False,
) -> ExecutionSnapshot:
    return ExecutionSnapshot(
        execution_id="execution-1",
        attempt_id="attempt-1",
        profile="synthetic-profile",
        lifecycle_state=LifecycleState.RUNNING,
        captured_at_utc=_FIXED_UTC,
        monotonic_offset_s=monotonic_s,
        progress_counter=progress,
        activity_counter=activity,
        artifact_revision=0,
        waiting_for_authorization=waiting_for_authorization,
        waiting_for_credential=waiting_for_credential,
        external_block=False,
        terminal=False,
    )


@dataclass(frozen=True)
class Scenario:
    name: str
    action: ActionRequest
    opinions: Sequence[CouncilOpinion]
    expected_verdict: Verdict
    expected_recommendation: RecommendationCode
    snapshots: tuple[ExecutionSnapshot, ExecutionSnapshot] | None = None
    expected_sentinel: SentinelClass | None = None
    idle_threshold_s: float | None = None

    def __post_init__(self) -> None:
        validate_id(self.name, field_name="scenario.name")


_LOW_ACTION = _action(ActionType.CREATE_TEMP_FILE)
_CANDIDATE = RecommendationCode.RECOMMEND_SHADOW_CANDIDATE_ONLY
_HUMAN = RecommendationCode.RECOMMEND_HUMAN_REVIEW
_STOP = RecommendationCode.RECOMMEND_HALT_FOR_HUMAN

SCENARIOS = (
    Scenario(
        "low_disposable_action",
        _LOW_ACTION,
        _panel(),
        Verdict.SHADOW_AUTOAPPROVE_CANDIDATE,
        _CANDIDATE,
    ),
    Scenario(
        "non_disposable_environment",
        _action(ActionType.CREATE_TEMP_FILE, environment=Environment.DEVELOPMENT),
        _panel(),
        Verdict.HUMAN_REQUIRED,
        _HUMAN,
    ),
    Scenario(
        "sudo_hard_stop",
        _action(ActionType.REQUEST_SUDO),
        _panel(),
        Verdict.STOP_AND_HUMAN,
        _STOP,
    ),
    Scenario(
        "database_drop_hard_stop",
        _action(
            ActionType.DATABASE_DROP,
            reversibility=Reversibility.IRREVERSIBLE,
            scope=Scope.BROAD,
        ),
        _panel(),
        Verdict.STOP_AND_HUMAN,
        _STOP,
    ),
    Scenario(
        "broad_delete_hard_stop",
        _action(
            ActionType.DELETE_BROAD_PATH,
            reversibility=Reversibility.IRREVERSIBLE,
            scope=Scope.BROAD,
        ),
        _panel(),
        Verdict.STOP_AND_HUMAN,
        _STOP,
    ),
    Scenario(
        "edge_panel_rejected",
        _LOW_ACTION,
        _panel(capability=ModelCapabilityClass.EDGE),
        Verdict.HUMAN_REQUIRED,
        _HUMAN,
    ),
    Scenario(
        "council_veto",
        _LOW_ACTION,
        _panel(veto_role=CouncilRole.SECURITY),
        Verdict.HUMAN_REQUIRED,
        _HUMAN,
    ),
    Scenario(
        "council_divergence",
        _LOW_ACTION,
        _panel(scores={CouncilRole.OPERATIONS: 5.0}),
        Verdict.HUMAN_REQUIRED,
        _HUMAN,
    ),
    Scenario(
        "observable_progress",
        _LOW_ACTION,
        _panel(),
        Verdict.SHADOW_AUTOAPPROVE_CANDIDATE,
        _CANDIDATE,
        snapshots=(_snapshot(10), _snapshot(20, progress=2, activity=2)),
        expected_sentinel=SentinelClass.REAL_PROGRESS,
        idle_threshold_s=300,
    ),
    Scenario(
        "probable_inactivity",
        _LOW_ACTION,
        _panel(),
        Verdict.SHADOW_AUTOAPPROVE_CANDIDATE,
        _CANDIDATE,
        snapshots=(_snapshot(10), _snapshot(350)),
        expected_sentinel=SentinelClass.PROBABLE_INACTIVITY,
        idle_threshold_s=300,
    ),
    Scenario(
        "approval_wait",
        _LOW_ACTION,
        _panel(),
        Verdict.SHADOW_AUTOAPPROVE_CANDIDATE,
        _CANDIDATE,
        snapshots=(_snapshot(10), _snapshot(350, waiting_for_authorization=True)),
        expected_sentinel=SentinelClass.LEGITIMATE_WAIT,
        idle_threshold_s=300,
    ),
    Scenario(
        "protected_input_wait",
        _LOW_ACTION,
        _panel(),
        Verdict.SHADOW_AUTOAPPROVE_CANDIDATE,
        _CANDIDATE,
        snapshots=(_snapshot(10), _snapshot(350, waiting_for_credential=True)),
        expected_sentinel=SentinelClass.LEGITIMATE_WAIT,
        idle_threshold_s=300,
    ),
)


@dataclass(frozen=True)
class ScenarioResult:
    scenario: str
    passed: bool

    def to_dict(self) -> dict:
        return {"scenario": self.scenario, "passed": self.passed}


def _platform_family() -> str:
    if sys.platform.startswith("win"):
        return "WINDOWS"
    if sys.platform == "darwin" or sys.platform.startswith("linux"):
        return "POSIX"
    return "OTHER"


@dataclass(frozen=True)
class GateResult:
    passed: int
    failed: int
    total: int
    success: bool
    scenarios: tuple[ScenarioResult, ...]
    schema_version: str = SCHEMA_VERSION
    python_version: str = f"{sys.version_info.major}.{sys.version_info.minor}"
    platform_family: str = _platform_family()

    def to_dict(self) -> dict:
        payload = {
            "schema_version": self.schema_version,
            "python_version": self.python_version,
            "platform_family": self.platform_family,
            "passed": self.passed,
            "failed": self.failed,
            "total": self.total,
            "success": self.success,
            "scenarios": [result.to_dict() for result in self.scenarios],
        }
        return sanitize_value(payload)


def run_gate(scenarios: Sequence[Scenario] = SCENARIOS) -> GateResult:
    """Run pure synthetic scenarios. Exceptions become sanitized failures."""

    results = []
    for scenario in scenarios:
        if not isinstance(scenario, Scenario):
            raise TypeError("scenarios must contain Scenario instances")
        try:
            report = supervise(
                scenario.action,
                scenario.opinions,
                snapshots=scenario.snapshots,
                idle_threshold_s=scenario.idle_threshold_s,
            )
            actual_sentinel = (
                report.sentinel_result.classification
                if report.sentinel_result is not None
                else None
            )
            passed = (
                report.council_decision.verdict == scenario.expected_verdict
                and report.recommendation_code == scenario.expected_recommendation
                and actual_sentinel == scenario.expected_sentinel
                and report.executed is False
            )
        except Exception:
            passed = False
        results.append(ScenarioResult(scenario.name, passed))

    result_tuple = tuple(results)
    passed_count = sum(result.passed for result in result_tuple)
    failed_count = len(result_tuple) - passed_count
    return GateResult(
        passed=passed_count,
        failed=failed_count,
        total=len(result_tuple),
        success=failed_count == 0,
        scenarios=result_tuple,
    )
