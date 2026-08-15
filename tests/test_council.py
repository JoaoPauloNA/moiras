import pytest

from moiras.contracts import (
    CouncilOpinion,
    CouncilRole,
    Environment,
    ModelCapabilityClass,
    ReasonCode,
    RiskAssessment,
    Verdict,
)
from moiras.council import AggregationError, aggregate

ALL_ROLES = list(CouncilRole)


def make_risk(**overrides):
    fields = dict(
        score=2.0,
        dimension_scores={},
        reason_codes=(),
        bypass_council=False,
    )
    fields.update(overrides)
    return RiskAssessment(**fields)


def make_opinion(role, **overrides):
    fields = dict(
        reviewer_id=f"rev-{role.value.lower()}",
        model_id="model-a",
        role=role,
        capability_class=ModelCapabilityClass.FRONTIER,
        risk_score=2.0,
        confidence=0.9,
        veto=False,
        dimension_scores={},
        reason_codes=(),
        mitigation_codes=(),
    )
    fields.update(overrides)
    return CouncilOpinion(**fields)


def full_panel(risk_score=2.0, veto_role=None, capability_class=None):
    opinions = []
    for role in ALL_ROLES:
        kwargs = {"risk_score": risk_score}
        if veto_role is not None and role == veto_role:
            kwargs["veto"] = True
        if capability_class is not None:
            kwargs["capability_class"] = capability_class
        opinions.append(make_opinion(role, **kwargs))
    return opinions


class TestHardStopBypass:
    def test_bypass_flag_short_circuits_to_stop_and_human(self):
        risk = make_risk(score=5.0, bypass_council=True)
        decision = aggregate(risk, [], environment=Environment.DISPOSABLE)
        assert decision.verdict == Verdict.STOP_AND_HUMAN
        assert decision.council_bypassed is True
        assert ReasonCode.HARD_STOP_ACTION in decision.reason_codes
        assert decision.executed is False
        assert decision.mode == "shadow"

    def test_score_ten_short_circuits_even_without_bypass_flag(self):
        risk = make_risk(score=10.0, bypass_council=False)
        decision = aggregate(risk, [], environment=Environment.DISPOSABLE)
        assert decision.verdict == Verdict.STOP_AND_HUMAN
        assert decision.council_bypassed is True
        assert ReasonCode.SCORE_TEN in decision.reason_codes

    def test_hard_stop_ignores_opinions_entirely(self):
        risk = make_risk(score=10.0, bypass_council=True)
        # A panel that would otherwise clearly approve must be ignored.
        opinions = full_panel(risk_score=0.0)
        decision = aggregate(risk, opinions, environment=Environment.DISPOSABLE)
        assert decision.verdict == Verdict.STOP_AND_HUMAN

    def test_hard_stop_ignores_malformed_opinions_too(self):
        risk = make_risk(score=10.0, bypass_council=True)
        decision = aggregate(risk, "not a list of opinions", environment=Environment.DISPOSABLE)
        assert decision.verdict == Verdict.STOP_AND_HUMAN


class TestRoleCoverage:
    def test_missing_role_requires_human(self):
        risk = make_risk(score=2.0)
        opinions = [make_opinion(role) for role in ALL_ROLES if role != CouncilRole.SECURITY]
        decision = aggregate(risk, opinions, environment=Environment.DISPOSABLE)
        assert decision.verdict == Verdict.HUMAN_REQUIRED
        assert ReasonCode.COUNCIL_INCOMPLETE in decision.reason_codes

    def test_duplicate_eligible_role_requires_human(self):
        risk = make_risk(score=2.0)
        opinions = full_panel(risk_score=2.0)
        opinions.append(make_opinion(CouncilRole.SECURITY, reviewer_id="rev-security-2"))
        decision = aggregate(risk, opinions, environment=Environment.DISPOSABLE)
        assert decision.verdict == Verdict.HUMAN_REQUIRED
        assert ReasonCode.COUNCIL_DUPLICATE_ROLE in decision.reason_codes

    def test_duplicate_and_missing_panel_has_deterministic_duplicate_reason(self):
        risk = make_risk(score=2.0)
        opinions = [
            make_opinion(CouncilRole.SECURITY),
            make_opinion(CouncilRole.SECURITY, reviewer_id="rev-security-2"),
            make_opinion(CouncilRole.INTEGRITY),
            make_opinion(CouncilRole.GOVERNANCE),
        ]
        decision = aggregate(risk, opinions, environment=Environment.DISPOSABLE)
        assert decision.verdict == Verdict.HUMAN_REQUIRED
        assert ReasonCode.COUNCIL_DUPLICATE_ROLE in decision.reason_codes
        assert ReasonCode.COUNCIL_INCOMPLETE not in decision.reason_codes

    @pytest.mark.parametrize(
        "capability_class",
        [ModelCapabilityClass.EDGE, ModelCapabilityClass.UNKNOWN],
    )
    def test_ineligible_only_role_counts_as_missing(self, capability_class):
        risk = make_risk(score=2.0)
        opinions = [make_opinion(role) for role in ALL_ROLES if role != CouncilRole.SECURITY]
        opinions.append(make_opinion(CouncilRole.SECURITY, capability_class=capability_class))
        decision = aggregate(risk, opinions, environment=Environment.DISPOSABLE)
        assert decision.verdict == Verdict.HUMAN_REQUIRED
        assert ReasonCode.COUNCIL_INELIGIBLE_MODEL in decision.reason_codes

    def test_any_extra_edge_opinion_forces_human_review(self):
        risk = make_risk(score=2.0)
        opinions = full_panel(risk_score=2.0)
        opinions.append(
            make_opinion(
                CouncilRole.SECURITY,
                reviewer_id="rev-security-edge",
                capability_class=ModelCapabilityClass.EDGE,
            )
        )
        decision = aggregate(risk, opinions, environment=Environment.DISPOSABLE)
        assert decision.verdict == Verdict.HUMAN_REQUIRED
        assert ReasonCode.COUNCIL_INELIGIBLE_MODEL in decision.reason_codes

    def test_complete_eligible_panel_of_four_roles_proceeds(self):
        risk = make_risk(score=2.0)
        opinions = full_panel(risk_score=2.0)
        decision = aggregate(risk, opinions, environment=Environment.DISPOSABLE)
        assert decision.verdict == Verdict.SHADOW_AUTOAPPROVE_CANDIDATE
        assert ReasonCode.SHADOW_CANDIDATE_ONLY in decision.reason_codes

    def test_rejects_non_opinion_items_in_list(self):
        risk = make_risk(score=2.0)
        with pytest.raises(AggregationError):
            aggregate(risk, [{"role": "SECURITY"}], environment=Environment.DISPOSABLE)


class TestVeto:
    def test_any_veto_requires_human(self):
        risk = make_risk(score=2.0)
        opinions = full_panel(risk_score=2.0, veto_role=CouncilRole.INTEGRITY)
        decision = aggregate(risk, opinions, environment=Environment.DISPOSABLE)
        assert decision.verdict == Verdict.HUMAN_REQUIRED
        assert ReasonCode.COUNCIL_VETO in decision.reason_codes


class TestDivergence:
    def test_divergence_over_three_requires_human(self):
        risk = make_risk(score=2.0)
        opinions = [
            make_opinion(CouncilRole.SECURITY, risk_score=1.0),
            make_opinion(CouncilRole.INTEGRITY, risk_score=1.0),
            make_opinion(CouncilRole.GOVERNANCE, risk_score=1.0),
            make_opinion(CouncilRole.OPERATIONS, risk_score=5.0),
        ]
        decision = aggregate(risk, opinions, environment=Environment.DISPOSABLE)
        assert decision.verdict == Verdict.HUMAN_REQUIRED
        assert ReasonCode.COUNCIL_DIVERGENCE in decision.reason_codes

    def test_divergence_of_exactly_three_is_allowed(self):
        risk = make_risk(score=1.0)
        opinions = [
            make_opinion(CouncilRole.SECURITY, risk_score=1.0),
            make_opinion(CouncilRole.INTEGRITY, risk_score=1.0),
            make_opinion(CouncilRole.GOVERNANCE, risk_score=1.0),
            make_opinion(CouncilRole.OPERATIONS, risk_score=4.0),
        ]
        decision = aggregate(risk, opinions, environment=Environment.DISPOSABLE)
        assert decision.verdict != Verdict.HUMAN_REQUIRED


class TestScoreBands:
    def test_seven_to_nine_requires_human(self):
        risk = make_risk(score=2.0)
        opinions = full_panel(risk_score=8.0)
        decision = aggregate(risk, opinions, environment=Environment.DISPOSABLE)
        assert decision.verdict == Verdict.HUMAN_REQUIRED
        assert decision.final_score == 8.0
        assert ReasonCode.RISK_BAND_HUMAN in decision.reason_codes

    def test_four_to_six_is_mitigate_and_reassess(self):
        risk = make_risk(score=2.0)
        opinions = full_panel(risk_score=5.0)
        decision = aggregate(risk, opinions, environment=Environment.DISPOSABLE)
        assert decision.verdict == Verdict.MITIGATE_AND_REASSESS
        assert ReasonCode.RISK_BAND_MITIGATE in decision.reason_codes

    def test_zero_to_three_disposable_unanimous_is_shadow_autoapprove(self):
        risk = make_risk(score=1.0)
        opinions = full_panel(risk_score=1.0)
        decision = aggregate(risk, opinions, environment=Environment.DISPOSABLE)
        assert decision.verdict == Verdict.SHADOW_AUTOAPPROVE_CANDIDATE

    def test_zero_to_three_non_disposable_requires_human(self):
        risk = make_risk(score=1.0)
        opinions = full_panel(risk_score=1.0)
        decision = aggregate(risk, opinions, environment=Environment.DEVELOPMENT)
        assert decision.verdict == Verdict.HUMAN_REQUIRED
        assert ReasonCode.NON_DISPOSABLE_ENVIRONMENT in decision.reason_codes

    def test_zero_to_three_unknown_environment_requires_human(self):
        risk = make_risk(score=1.0)
        opinions = full_panel(risk_score=1.0)
        decision = aggregate(risk, opinions, environment=Environment.UNKNOWN)
        assert decision.verdict == Verdict.HUMAN_REQUIRED

    def test_boundary_at_seven_is_human_required(self):
        risk = make_risk(score=2.0)
        opinions = full_panel(risk_score=7.0)
        decision = aggregate(risk, opinions, environment=Environment.DISPOSABLE)
        assert decision.verdict == Verdict.HUMAN_REQUIRED

    def test_boundary_at_four_is_mitigate(self):
        risk = make_risk(score=2.0)
        opinions = full_panel(risk_score=4.0)
        decision = aggregate(risk, opinions, environment=Environment.DISPOSABLE)
        assert decision.verdict == Verdict.MITIGATE_AND_REASSESS

    def test_boundary_just_below_four_is_eligible_for_autoapprove(self):
        risk = make_risk(score=2.0)
        opinions = full_panel(risk_score=3.9)
        decision = aggregate(risk, opinions, environment=Environment.DISPOSABLE)
        assert decision.verdict == Verdict.SHADOW_AUTOAPPROVE_CANDIDATE


class TestExecutedAlwaysFalse:
    @pytest.mark.parametrize(
        "risk_score,environment",
        [
            (10.0, Environment.PRODUCTION),
            (8.0, Environment.DISPOSABLE),
            (5.0, Environment.DEVELOPMENT),
            (1.0, Environment.DISPOSABLE),
        ],
    )
    def test_executed_is_always_false_and_mode_is_shadow(self, risk_score, environment):
        risk = make_risk(score=min(risk_score, 9.9))
        opinions = full_panel(risk_score=risk_score)
        decision = aggregate(risk, opinions, environment=environment)
        assert decision.executed is False
        assert decision.mode == "shadow"
