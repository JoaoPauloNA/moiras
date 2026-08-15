import pytest

from moiras.contracts import (
    ActionRequest,
    ActionType,
    Environment,
    ReasonCode,
    Reversibility,
    Scope,
)
from moiras.risk import HARD_STOP_ACTIONS, assess


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


class TestHardStops:
    @pytest.mark.parametrize(
        "action_type",
        [
            ActionType.DELETE_BROAD_PATH,
            ActionType.DATABASE_DELETE,
            ActionType.DATABASE_DROP,
            ActionType.REQUEST_SUDO,
            ActionType.REQUEST_CREDENTIAL,
            ActionType.CREATE_PRIVILEGED_USER,
        ],
    )
    def test_hard_stop_scores_ten_and_bypasses_council(self, action_type):
        action = make_action(
            action_type=action_type,
            environment=Environment.DISPOSABLE,
            reversibility=Reversibility.REVERSIBLE,
            scope=Scope.SINGLE,
        )
        result = assess(action)
        assert result.score == 10.0
        assert result.bypass_council is True
        assert ReasonCode.HARD_STOP_ACTION in result.reason_codes

    def test_hard_stop_set_matches_action_type_list(self):
        assert HARD_STOP_ACTIONS == {
            ActionType.DELETE_BROAD_PATH,
            ActionType.DATABASE_DELETE,
            ActionType.DATABASE_DROP,
            ActionType.REQUEST_SUDO,
            ActionType.REQUEST_CREDENTIAL,
            ActionType.CREATE_PRIVILEGED_USER,
        }


class TestBaselineFloors:
    def test_public_web_read_is_low_but_not_zero(self):
        action = make_action(
            action_type=ActionType.PUBLIC_WEB_READ,
            environment=Environment.DISPOSABLE,
            reversibility=Reversibility.REVERSIBLE,
            scope=Scope.SINGLE,
        )
        assert assess(action).score == 1.0

    def test_ambiguous_is_at_least_nine(self):
        action = make_action(
            action_type=ActionType.AMBIGUOUS,
            environment=Environment.DISPOSABLE,
            reversibility=Reversibility.REVERSIBLE,
            scope=Scope.SINGLE,
        )
        assert assess(action).score >= 9.0

    def test_edit_auth_is_at_least_nine(self):
        action = make_action(
            action_type=ActionType.EDIT_AUTH,
            environment=Environment.DISPOSABLE,
            reversibility=Reversibility.REVERSIBLE,
            scope=Scope.SINGLE,
        )
        assert assess(action).score >= 9.0

    def test_external_send_is_at_least_eight(self):
        action = make_action(
            action_type=ActionType.EXTERNAL_SEND,
            environment=Environment.DISPOSABLE,
            reversibility=Reversibility.REVERSIBLE,
            scope=Scope.SINGLE,
        )
        assert assess(action).score >= 8.0

    def test_sensitive_config_requires_mitigation_band_or_higher(self):
        action = make_action(
            action_type=ActionType.CREATE_SENSITIVE_CONFIG,
            environment=Environment.DISPOSABLE,
            reversibility=Reversibility.REVERSIBLE,
            scope=Scope.SINGLE,
        )
        assert assess(action).score >= 6.0

    def test_delete_unique_file_requires_human_band(self):
        action = make_action(
            action_type=ActionType.DELETE_UNIQUE_FILE,
            environment=Environment.DEVELOPMENT,
            reversibility=Reversibility.PARTIAL,
            scope=Scope.SINGLE,
        )
        assert assess(action).score >= 8.0


class TestCreateTempFileZeroExemption:
    def test_zero_only_in_disposable_reversible_single_no_sensitive_no_external(self):
        action = make_action(
            action_type=ActionType.CREATE_TEMP_FILE,
            environment=Environment.DISPOSABLE,
            reversibility=Reversibility.REVERSIBLE,
            scope=Scope.SINGLE,
            sensitive_data=False,
            external_side_effect=False,
        )
        result = assess(action)
        assert result.score == 0.0
        assert ReasonCode.ZERO_RISK_EXEMPTION in result.reason_codes

    @pytest.mark.parametrize(
        "overrides",
        [
            {"environment": Environment.DEVELOPMENT},
            {"environment": Environment.PRODUCTION},
            {"reversibility": Reversibility.PARTIAL},
            {"reversibility": Reversibility.IRREVERSIBLE},
            {"scope": Scope.LIMITED},
            {"scope": Scope.BROAD},
            {"sensitive_data": True},
            {"external_side_effect": True},
        ],
    )
    def test_never_zero_outside_the_exact_combination(self, overrides):
        fields = dict(
            action_type=ActionType.CREATE_TEMP_FILE,
            environment=Environment.DISPOSABLE,
            reversibility=Reversibility.REVERSIBLE,
            scope=Scope.SINGLE,
            sensitive_data=False,
            external_side_effect=False,
        )
        fields.update(overrides)
        result = assess(make_action(**fields))
        assert result.score > 0.0


class TestCreationNeverZeroOutsideExemption:
    def test_create_sensitive_config_never_zero(self):
        action = make_action(
            action_type=ActionType.CREATE_SENSITIVE_CONFIG,
            environment=Environment.DISPOSABLE,
            reversibility=Reversibility.REVERSIBLE,
            scope=Scope.SINGLE,
            sensitive_data=False,
            external_side_effect=False,
        )
        assert assess(action).score > 0.0

    def test_create_privileged_user_is_hard_stop_never_zero(self):
        action = make_action(
            action_type=ActionType.CREATE_PRIVILEGED_USER,
            environment=Environment.DISPOSABLE,
            reversibility=Reversibility.REVERSIBLE,
            scope=Scope.SINGLE,
            sensitive_data=False,
            external_side_effect=False,
        )
        assert assess(action).score == 10.0


class TestModifiersElevateConservatively:
    def test_production_elevates_above_development_baseline(self):
        dev = assess(make_action(environment=Environment.DEVELOPMENT))
        prod = assess(make_action(environment=Environment.PRODUCTION))
        assert prod.score > dev.score

    def test_irreversible_elevates_above_reversible(self):
        reversible = assess(make_action(reversibility=Reversibility.REVERSIBLE))
        irreversible = assess(make_action(reversibility=Reversibility.IRREVERSIBLE))
        assert irreversible.score > reversible.score

    def test_broad_scope_elevates_above_single(self):
        single = assess(make_action(scope=Scope.SINGLE))
        broad = assess(make_action(scope=Scope.BROAD))
        assert broad.score > single.score

    def test_unknown_scope_elevates_conservatively(self):
        single = assess(make_action(scope=Scope.SINGLE))
        unknown = assess(make_action(scope=Scope.UNKNOWN))
        assert unknown.score > single.score
        assert unknown.score >= 7.0

    def test_unknown_environment_elevates_conservatively(self):
        development = assess(make_action(environment=Environment.DEVELOPMENT))
        unknown = assess(make_action(environment=Environment.UNKNOWN))
        assert unknown.score >= development.score
        assert unknown.score >= 7.0

    def test_sensitive_data_elevates_score(self):
        plain = assess(make_action(sensitive_data=False))
        sensitive = assess(make_action(sensitive_data=True))
        assert sensitive.score > plain.score

    def test_external_side_effect_elevates_score(self):
        plain = assess(make_action(external_side_effect=False))
        external = assess(make_action(external_side_effect=True))
        assert external.score > plain.score

    def test_modifiers_never_lower_the_baseline(self):
        # A DISPOSABLE + REVERSIBLE + SINGLE EDIT_AUTH action must still
        # respect the EDIT_AUTH >= 9 floor: modifiers only ever raise,
        # combination via max, never average.
        action = make_action(
            action_type=ActionType.EDIT_AUTH,
            environment=Environment.DISPOSABLE,
            reversibility=Reversibility.REVERSIBLE,
            scope=Scope.SINGLE,
            sensitive_data=False,
            external_side_effect=False,
        )
        assert assess(action).score >= 9.0

    def test_combination_is_max_not_average(self):
        # PRODUCTION alone contributes a high dimension score; combined
        # with a low-baseline action type the result must still reflect
        # the max, not a blended average pulled down by the baseline.
        action = make_action(
            action_type=ActionType.EDIT_DOCUMENTATION,
            environment=Environment.PRODUCTION,
            reversibility=Reversibility.REVERSIBLE,
            scope=Scope.SINGLE,
        )
        result = assess(action)
        assert result.score == max(result.dimension_scores.values())


class TestRejectsNonActionRequest:
    def test_rejects_non_action_request(self):
        with pytest.raises(TypeError):
            assess({"action_type": "EDIT_CODE"})


class TestScoreBounds:
    @pytest.mark.parametrize("action_type", list(ActionType))
    def test_score_always_in_bounds(self, action_type):
        action = make_action(
            action_type=action_type,
            environment=Environment.PRODUCTION,
            reversibility=Reversibility.IRREVERSIBLE,
            scope=Scope.BROAD,
            sensitive_data=True,
            external_side_effect=True,
        )
        result = assess(action)
        assert 0.0 <= result.score <= 10.0
