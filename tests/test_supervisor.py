import inspect
from datetime import datetime, timezone

import pytest

from moiras.contracts import (
    ActionRequest,
    ActionType,
    ContractValidationError,
    CouncilOpinion,
    CouncilRole,
    Environment,
    ExecutionSnapshot,
    LifecycleState,
    ModelCapabilityClass,
    Reversibility,
    Scope,
    Verdict,
)
from moiras.sanitize import sanitize_value
from moiras.supervisor import (
    CounterfactualCode,
    RecommendationCode,
    ShadowReport,
    ShadowSupervisor,
    SupervisionError,
    supervise,
)


def make_action(**overrides):
    fields = dict(
        action_type=ActionType.CREATE_TEMP_FILE,
        environment=Environment.DISPOSABLE,
        reversibility=Reversibility.REVERSIBLE,
        scope=Scope.SINGLE,
        sensitive_data=False,
        external_side_effect=False,
    )
    fields.update(overrides)
    return ActionRequest(**fields)


def make_opinion(role, **overrides):
    fields = dict(
        reviewer_id=f"reviewer-{role.value.lower()}",
        model_id="capable-model",
        role=role,
        capability_class=ModelCapabilityClass.FRONTIER,
        risk_score=1.0,
        confidence=0.9,
        veto=False,
        dimension_scores={},
        reason_codes=(),
        mitigation_codes=(),
    )
    fields.update(overrides)
    return CouncilOpinion(**fields)


def panel(role_overrides=None):
    role_overrides = role_overrides or {}
    return [make_opinion(role, **role_overrides.get(role, {})) for role in CouncilRole]


@pytest.mark.parametrize(
    ("action", "opinions", "verdict", "recommendation", "counterfactual"),
    [
        (
            make_action(),
            panel(),
            Verdict.SHADOW_AUTOAPPROVE_CANDIDATE,
            RecommendationCode.RECOMMEND_SHADOW_CANDIDATE_ONLY,
            CounterfactualCode.WOULD_REQUIRE_SEPARATE_AUTHORIZATION_GATE,
        ),
        (
            make_action(),
            panel({CouncilRole.SECURITY: {"veto": True}}),
            Verdict.HUMAN_REQUIRED,
            RecommendationCode.RECOMMEND_HUMAN_REVIEW,
            CounterfactualCode.WOULD_REQUIRE_HUMAN_APPROVAL_GATE,
        ),
        (
            make_action(),
            panel({role: {"risk_score": 5.0} for role in CouncilRole}),
            Verdict.MITIGATE_AND_REASSESS,
            RecommendationCode.RECOMMEND_MITIGATE_THEN_REASSESS,
            CounterfactualCode.WOULD_REQUIRE_MITIGATION_AND_REASSESSMENT,
        ),
        (
            make_action(action_type=ActionType.REQUEST_SUDO),
            panel(),
            Verdict.STOP_AND_HUMAN,
            RecommendationCode.RECOMMEND_HALT_FOR_HUMAN,
            CounterfactualCode.WOULD_STOP_FOR_HUMAN_DECISION,
        ),
    ],
)
def test_maps_all_verdicts(action, opinions, verdict, recommendation, counterfactual):
    report = supervise(action, opinions)
    assert report.council_decision.verdict == verdict
    assert report.recommendation_code == recommendation
    assert report.counterfactual_code == counterfactual
    assert report.executed is False
    assert report.mode == "shadow"
    assert sanitize_value(report.to_dict()) == report.to_dict()


def make_snapshot(monotonic, progress):
    return ExecutionSnapshot(
        execution_id="execution-1",
        attempt_id="attempt-1",
        profile="synthetic-profile",
        lifecycle_state=LifecycleState.RUNNING,
        captured_at_utc=datetime(2026, 8, 14, tzinfo=timezone.utc),
        monotonic_offset_s=monotonic,
        progress_counter=progress,
        activity_counter=progress,
        artifact_revision=0,
        waiting_for_authorization=False,
        waiting_for_credential=False,
        external_block=False,
        terminal=False,
    )


def test_optional_sentinel_is_included():
    report = supervise(
        make_action(),
        panel(),
        snapshots=(make_snapshot(1, 1), make_snapshot(2, 2)),
        idle_threshold_s=10,
    )
    assert report.sentinel_result is not None
    assert report.sentinel_result.classification.value == "REAL_PROGRESS"


def test_snapshot_parameter_combinations_fail_closed():
    snapshot = make_snapshot(1, 1)
    with pytest.raises(SupervisionError):
        supervise(make_action(), panel(), snapshots=(snapshot, snapshot))
    with pytest.raises(SupervisionError):
        supervise(make_action(), panel(), idle_threshold_s=10)
    with pytest.raises(SupervisionError):
        supervise(make_action(), panel(), snapshots=(snapshot,), idle_threshold_s=10)


def test_rejects_non_sequence_opinions():
    with pytest.raises(SupervisionError):
        supervise(make_action(), "not-opinions")


def test_public_api_has_no_executor_callback_tool_or_broker_parameter():
    parameters = set(inspect.signature(supervise).parameters)
    assert parameters == {"action", "opinions", "snapshots", "idle_threshold_s"}
    assert vars(ShadowSupervisor()) == {}


def test_shadow_report_cannot_claim_execution():
    valid = supervise(make_action(), panel())
    with pytest.raises(ContractValidationError):
        ShadowReport(
            risk_assessment=valid.risk_assessment,
            council_decision=valid.council_decision,
            recommendation_code=valid.recommendation_code,
            counterfactual_code=valid.counterfactual_code,
            executed=True,
        )


def test_shadow_report_cannot_claim_non_shadow_mode():
    valid = supervise(make_action(), panel())
    with pytest.raises(ContractValidationError):
        ShadowReport(
            risk_assessment=valid.risk_assessment,
            council_decision=valid.council_decision,
            recommendation_code=valid.recommendation_code,
            counterfactual_code=valid.counterfactual_code,
            mode="live",
        )
