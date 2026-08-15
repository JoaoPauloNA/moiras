from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone

import pytest

from moiras.contracts import (
    SCHEMA_VERSION,
    ActionRequest,
    ActionType,
    ContractValidationError,
    CouncilDecision,
    CouncilOpinion,
    CouncilRole,
    Environment,
    EvidenceCode,
    ExecutionSnapshot,
    LifecycleState,
    MitigationCode,
    ModelCapabilityClass,
    ReasonCode,
    Reversibility,
    RiskAssessment,
    RiskDimension,
    Scope,
    SentinelClass,
    SentinelResult,
    Verdict,
)
from moiras.sanitize import SanitizationError

UTC_NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def make_snapshot(**overrides):
    fields = dict(
        execution_id="exec-1",
        attempt_id="att-1",
        profile="dev",
        lifecycle_state=LifecycleState.RUNNING,
        captured_at_utc=UTC_NOW,
        monotonic_offset_s=0.0,
        progress_counter=0,
        activity_counter=0,
        artifact_revision=0,
        waiting_for_authorization=False,
        waiting_for_credential=False,
        external_block=False,
        terminal=False,
    )
    fields.update(overrides)
    return ExecutionSnapshot(**fields)


def make_action(**overrides):
    fields = dict(
        action_type=ActionType.EDIT_CODE,
        environment=Environment.DEVELOPMENT,
        reversibility=Reversibility.REVERSIBLE,
        scope=Scope.SINGLE,
        sensitive_data=False,
        external_side_effect=False,
    )
    fields.update(overrides)
    return ActionRequest(**fields)


def make_opinion(**overrides):
    fields = dict(
        reviewer_id="rev-1",
        model_id="model-1",
        role=CouncilRole.SECURITY,
        capability_class=ModelCapabilityClass.FRONTIER,
        risk_score=2.0,
        confidence=0.8,
        veto=False,
        dimension_scores={RiskDimension.SCOPE: 1.0},
        reason_codes=(ReasonCode.SENSITIVE_DATA_INVOLVED,),
        mitigation_codes=(MitigationCode.NONE,),
    )
    fields.update(overrides)
    return CouncilOpinion(**fields)


class TestExecutionSnapshotIds:
    def test_valid_snapshot_constructs(self):
        snap = make_snapshot()
        assert snap.execution_id == "exec-1"
        assert snap.schema_version == SCHEMA_VERSION

    @pytest.mark.parametrize("field", ["execution_id", "attempt_id", "profile"])
    def test_rejects_bad_id_charset(self, field):
        with pytest.raises(SanitizationError):
            make_snapshot(**{field: "bad id with spaces"})

    def test_rejects_naive_datetime(self):
        with pytest.raises(ContractValidationError):
            make_snapshot(captured_at_utc=datetime(2026, 1, 1))

    def test_rejects_non_utc_datetime(self):
        tz = timezone(timedelta(hours=-3))
        with pytest.raises(ContractValidationError):
            make_snapshot(captured_at_utc=datetime(2026, 1, 1, tzinfo=tz))

    def test_rejects_negative_monotonic_offset(self):
        with pytest.raises(ContractValidationError):
            make_snapshot(monotonic_offset_s=-1.0)

    def test_rejects_non_finite_monotonic_offset(self):
        with pytest.raises(ContractValidationError):
            make_snapshot(monotonic_offset_s=float("inf"))

    @pytest.mark.parametrize("field", ["progress_counter", "activity_counter", "artifact_revision"])
    def test_rejects_negative_counters(self, field):
        with pytest.raises(ContractValidationError):
            make_snapshot(**{field: -1})

    @pytest.mark.parametrize("field", ["progress_counter", "activity_counter", "artifact_revision"])
    def test_rejects_non_int_counters(self, field):
        with pytest.raises(ContractValidationError):
            make_snapshot(**{field: 1.5})

    @pytest.mark.parametrize(
        "field",
        [
            "waiting_for_authorization",
            "waiting_for_credential",
            "external_block",
            "terminal",
        ],
    )
    def test_rejects_non_bool_flags(self, field):
        with pytest.raises(ContractValidationError):
            make_snapshot(**{field: "yes"})

    def test_rejects_wrong_lifecycle_state_type(self):
        with pytest.raises(ContractValidationError):
            make_snapshot(lifecycle_state="RUNNING")

    def test_rejects_bad_schema_version(self):
        with pytest.raises(ContractValidationError):
            make_snapshot(schema_version="2.0")

    def test_to_dict_is_allowlisted_and_serializable(self):
        snap = make_snapshot(progress_counter=3, artifact_revision=2)
        d = snap.to_dict()
        assert set(d.keys()) == {
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
        }
        assert d["lifecycle_state"] == "RUNNING"
        assert d["progress_counter"] == 3
        assert isinstance(d["captured_at_utc"], str)

    def test_to_dict_never_contains_forbidden_fields(self):
        snap = make_snapshot()
        d = snap.to_dict()
        forbidden_substrings = (
            "prompt",
            "output",
            "command",
            "path",
            "host",
            "pid",
        )
        for key in d.keys():
            for forbidden in forbidden_substrings:
                assert forbidden not in key.lower()

    def test_is_frozen(self):
        snap = make_snapshot()
        with pytest.raises(FrozenInstanceError):
            snap.progress_counter = 5


class TestActionRequest:
    def test_valid_action_constructs(self):
        action = make_action()
        assert action.action_type == ActionType.EDIT_CODE

    def test_rejects_wrong_enum_types(self):
        with pytest.raises(ContractValidationError):
            make_action(action_type="EDIT_CODE")

    def test_rejects_non_bool_sensitive_data(self):
        with pytest.raises(ContractValidationError):
            make_action(sensitive_data="yes")

    def test_to_dict_allowlisted(self):
        action = make_action(sensitive_data=True)
        d = action.to_dict()
        assert d["sensitive_data"] is True
        assert d["action_type"] == "EDIT_CODE"


class TestRiskAssessment:
    def test_rejects_score_out_of_range(self):
        with pytest.raises(ContractValidationError):
            RiskAssessment(
                score=11.0,
                dimension_scores={},
                reason_codes=(),
                bypass_council=False,
            )

    def test_rejects_non_finite_score(self):
        with pytest.raises(ContractValidationError):
            RiskAssessment(
                score=float("nan"),
                dimension_scores={},
                reason_codes=(),
                bypass_council=False,
            )

    def test_rejects_non_risk_dimension_key(self):
        with pytest.raises(ContractValidationError):
            RiskAssessment(
                score=1.0,
                dimension_scores={"scope": 1.0},
                reason_codes=(),
                bypass_council=False,
            )

    def test_rejects_dimension_value_out_of_range(self):
        with pytest.raises(ContractValidationError):
            RiskAssessment(
                score=1.0,
                dimension_scores={RiskDimension.SCOPE: 11.0},
                reason_codes=(),
                bypass_council=False,
            )

    def test_rejects_bad_reason_code(self):
        with pytest.raises(ContractValidationError):
            RiskAssessment(
                score=1.0,
                dimension_scores={},
                reason_codes=("NOT_A_CODE",),
                bypass_council=False,
            )

    def test_materializes_reason_code_generator_once(self):
        assessment = RiskAssessment(
            score=10.0,
            dimension_scores={},
            reason_codes=(code for code in (ReasonCode.HARD_STOP_ACTION,)),
            bypass_council=True,
        )

        assert assessment.reason_codes == (ReasonCode.HARD_STOP_ACTION,)

    def test_dimension_scores_immutable(self):
        assessment = RiskAssessment(
            score=1.0,
            dimension_scores={RiskDimension.SCOPE: 1.0},
            reason_codes=(),
            bypass_council=False,
        )
        with pytest.raises(TypeError):
            assessment.dimension_scores[RiskDimension.SCOPE] = 5.0

    def test_to_dict_allowlisted(self):
        assessment = RiskAssessment(
            score=4.5,
            dimension_scores={RiskDimension.SCOPE: 2.0},
            reason_codes=(ReasonCode.BROAD_OR_UNKNOWN_SCOPE,),
            bypass_council=False,
        )
        d = assessment.to_dict()
        assert d["score"] == 4.5
        assert d["dimension_scores"] == {"SCOPE": 2.0}
        assert d["reason_codes"] == ["BROAD_OR_UNKNOWN_SCOPE"]


class TestSentinelResult:
    def test_valid_result(self):
        result = SentinelResult(
            classification=SentinelClass.REAL_PROGRESS,
            evidence_codes=(EvidenceCode.PROGRESS_COUNTER_INCREASED,),
        )
        assert result.to_dict()["classification"] == "REAL_PROGRESS"

    def test_rejects_bad_classification_type(self):
        with pytest.raises(ContractValidationError):
            SentinelResult(classification="REAL_PROGRESS", evidence_codes=())

    def test_rejects_bad_evidence_code(self):
        with pytest.raises(ContractValidationError):
            SentinelResult(
                classification=SentinelClass.INDETERMINATE,
                evidence_codes=("NOT_A_CODE",),
            )

    def test_materializes_evidence_code_generator_once(self):
        result = SentinelResult(
            classification=SentinelClass.PROBABLE_INACTIVITY,
            evidence_codes=(code for code in (EvidenceCode.IDLE_THRESHOLD_EXCEEDED,)),
        )

        assert result.evidence_codes == (EvidenceCode.IDLE_THRESHOLD_EXCEEDED,)


class TestCouncilOpinion:
    def test_valid_opinion_constructs(self):
        opinion = make_opinion()
        assert opinion.eligible is True

    @pytest.mark.parametrize(
        "capability_class",
        [ModelCapabilityClass.EDGE, ModelCapabilityClass.UNKNOWN],
    )
    def test_edge_and_unknown_are_ineligible(self, capability_class):
        opinion = make_opinion(capability_class=capability_class)
        assert opinion.eligible is False

    @pytest.mark.parametrize(
        "capability_class",
        [ModelCapabilityClass.FRONTIER, ModelCapabilityClass.CAPABLE_GENERAL],
    )
    def test_frontier_and_capable_general_are_eligible(self, capability_class):
        opinion = make_opinion(capability_class=capability_class)
        assert opinion.eligible is True

    def test_rejects_bad_reviewer_id(self):
        with pytest.raises(SanitizationError):
            make_opinion(reviewer_id="bad id")

    def test_rejects_risk_score_out_of_range(self):
        with pytest.raises(ContractValidationError):
            make_opinion(risk_score=10.1)

    def test_rejects_confidence_out_of_range(self):
        with pytest.raises(ContractValidationError):
            make_opinion(confidence=1.1)

    def test_rejects_non_finite_confidence(self):
        with pytest.raises(ContractValidationError):
            make_opinion(confidence=float("nan"))

    def test_rejects_bad_mitigation_code(self):
        with pytest.raises(ContractValidationError):
            make_opinion(mitigation_codes=("NOT_A_CODE",))

    def test_materializes_both_code_generators_once(self):
        opinion = make_opinion(
            reason_codes=(code for code in (ReasonCode.COUNCIL_VETO,)),
            mitigation_codes=(
                code for code in (MitigationCode.REQUIRE_HUMAN_APPROVAL,)
            ),
        )

        assert opinion.reason_codes == (ReasonCode.COUNCIL_VETO,)
        assert opinion.mitigation_codes == (MitigationCode.REQUIRE_HUMAN_APPROVAL,)

    def test_to_dict_has_no_free_text_rationale(self):
        opinion = make_opinion()
        d = opinion.to_dict()
        assert set(d.keys()) == {
            "schema_version",
            "reviewer_id",
            "model_id",
            "role",
            "capability_class",
            "risk_score",
            "confidence",
            "veto",
            "dimension_scores",
            "reason_codes",
            "mitigation_codes",
        }


class TestCouncilDecision:
    def test_executed_always_false(self):
        decision = CouncilDecision(
            verdict=Verdict.HUMAN_REQUIRED,
            final_score=5.0,
            council_bypassed=False,
            reason_codes=(),
        )
        assert decision.executed is False
        assert decision.mode == "shadow"

    def test_rejects_executed_true(self):
        with pytest.raises(ContractValidationError):
            CouncilDecision(
                verdict=Verdict.HUMAN_REQUIRED,
                final_score=5.0,
                council_bypassed=False,
                reason_codes=(),
                executed=True,
            )

    def test_rejects_non_shadow_mode(self):
        with pytest.raises(ContractValidationError):
            CouncilDecision(
                verdict=Verdict.HUMAN_REQUIRED,
                final_score=5.0,
                council_bypassed=False,
                reason_codes=(),
                mode="live",
            )

    def test_materializes_reason_code_generator_once(self):
        decision = CouncilDecision(
            verdict=Verdict.STOP_AND_HUMAN,
            final_score=10.0,
            council_bypassed=True,
            reason_codes=(code for code in (ReasonCode.HARD_STOP_ACTION,)),
        )

        assert decision.reason_codes == (ReasonCode.HARD_STOP_ACTION,)

    def test_to_dict_allowlisted(self):
        decision = CouncilDecision(
            verdict=Verdict.STOP_AND_HUMAN,
            final_score=10.0,
            council_bypassed=True,
            reason_codes=(ReasonCode.HARD_STOP_ACTION,),
        )
        d = decision.to_dict()
        assert d["verdict"] == "STOP_AND_HUMAN"
        assert d["executed"] is False
        assert d["mode"] == "shadow"
