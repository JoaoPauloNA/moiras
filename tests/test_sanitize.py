from datetime import datetime, timezone

import pytest

from moiras.contracts import (
    ActionRequest,
    ActionType,
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
from moiras.sanitize import (
    MAX_ID_LENGTH,
    SanitizationError,
    sanitize_value,
    validate_id,
)


class TestValidateId:
    def test_accepts_allowed_charset(self):
        assert validate_id("exec.1_2:3-4") == "exec.1_2:3-4"

    def test_accepts_single_character(self):
        assert validate_id("a") == "a"

    def test_rejects_empty_string(self):
        with pytest.raises(SanitizationError):
            validate_id("")

    def test_rejects_non_string(self):
        with pytest.raises(SanitizationError):
            validate_id(123)

    def test_rejects_too_long(self):
        with pytest.raises(SanitizationError):
            validate_id("a" * (MAX_ID_LENGTH + 1))

    def test_accepts_max_length(self):
        value = "a" * MAX_ID_LENGTH
        assert validate_id(value) == value

    @pytest.mark.parametrize(
        "bad",
        [
            "secret-id",
            "api_token_1",
            "api-key-1",
            "password",
            "sk-abcdef",
            "Bearer-abc",
            "user-123",
            "path-node",
        ],
    )
    def test_rejects_sensitive_identifiers(self, bad):
        with pytest.raises(SanitizationError):
            validate_id(bad)

    @pytest.mark.parametrize(
        "bad",
        [
            "has space",
            "has/slash",
            "has\\backslash",
            "has$dollar",
            "has#hash",
            "has\nnewline",
            "has\ttab",
            "unicode-\u00e9",
            "semi;colon",
            "quote'd",
        ],
    )
    def test_rejects_disallowed_characters(self, bad):
        with pytest.raises(SanitizationError):
            validate_id(bad)


class TestSanitizeValuePrimitives:
    def test_passes_through_safe_scalars(self):
        assert sanitize_value(1) == 1
        assert sanitize_value(1.5) == 1.5
        assert sanitize_value(True) is True
        assert sanitize_value(None) is None
        assert sanitize_value("safe-string") == "safe-string"

    def test_passes_through_nested_list_and_dict(self):
        value = {"profile": "dev", "counters": [1, 2, {"artifact_revision": 3}]}
        assert sanitize_value(value) == value

    def test_rejects_unsupported_type(self):
        with pytest.raises(SanitizationError):
            sanitize_value(object())

    @pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
    def test_rejects_non_finite_numbers(self, value):
        with pytest.raises(SanitizationError):
            sanitize_value(value)


class TestSanitizeValueForbiddenKeys:
    @pytest.mark.parametrize(
        "key",
        [
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
            "PROMPT",
            "Password",
            "API_KEY",
            "user_password",
            "auth_token",
            "db_credential",
        ],
    )
    def test_rejects_forbidden_key(self, key):
        with pytest.raises(SanitizationError):
            sanitize_value({key: "x"})

    def test_rejects_forbidden_key_nested(self):
        with pytest.raises(SanitizationError):
            sanitize_value({"outer": {"inner": {"token": "x"}}})

    def test_rejects_forbidden_key_inside_list(self):
        with pytest.raises(SanitizationError):
            sanitize_value([{"secret": "x"}])

    def test_rejects_non_string_key(self):
        with pytest.raises(SanitizationError):
            sanitize_value({1: "x"})

    def test_allows_benign_key_that_is_not_a_forbidden_token(self):
        # "path" is forbidden as a whole token but "artifact_revision" and
        # "waiting_for_authorization"-shaped keys with no forbidden token
        # inside must pass.
        assert sanitize_value({"artifact_revision": 3}) == {"artifact_revision": 3}

    @pytest.mark.parametrize("key", ["rapid", "compassionate", "environmental"])
    def test_does_not_reject_incidental_substrings(self, key):
        assert sanitize_value({key: "safe"}) == {key: "safe"}


class TestSanitizeValueSecretsAndPaths:
    @pytest.mark.parametrize(
        "value",
        [
            "sk-abcdefghijklmnop",
            "ghp_abcdefghijklmnop",
            "gho_abcdefghijklmnop",
            "github_pat_abcdefg",
            "xoxb-123456",
            "AKIAABCDEFGHIJKLMNOP",
            "AIzaSyABCDEFG",
            "Bearer abc123",
            "-----BEGIN PRIVATE KEY-----",
        ],
    )
    def test_rejects_secret_shaped_strings(self, value):
        with pytest.raises(SanitizationError):
            sanitize_value(value)

    @pytest.mark.parametrize(
        "value",
        [
            "/etc/passwd",
            "/Users/someone/project",
            "\\\\server\\share",
            "C:\\Windows\\System32",
            "~/secrets.txt",
        ],
    )
    def test_rejects_absolute_path_shaped_strings(self, value):
        with pytest.raises(SanitizationError):
            sanitize_value(value)

    def test_rejects_secret_inside_nested_structure(self):
        with pytest.raises(SanitizationError):
            sanitize_value({"notes": ["fine", "sk-leaked-secret-value"]})

    @pytest.mark.parametrize(
        "value",
        [
            "meu token ghp_abcdefghijklmnop apareceu",
            "a chave sk-abcdefghijklmnop vazou",
            "AWS AKIAABCDEFGHIJKLMNOP detectada",
            "Header Bearer abc123 recebido",
            "texto -----BEGIN PRIVATE KEY----- embutido",
        ],
    )
    def test_rejects_embedded_secret_shapes(self, value):
        with pytest.raises(SanitizationError):
            sanitize_value(value)

    @pytest.mark.parametrize(
        "value",
        [
            "  SK-secret",
            "bearer abc123",
            "note /Users/name/project",
            "pasta /tmp",
            "confira /etc",
        ],
    )
    def test_rejects_case_whitespace_and_embedded_sensitive_shapes(self, value):
        with pytest.raises(SanitizationError):
            sanitize_value(value)

    def test_allows_relative_looking_strings(self):
        assert sanitize_value("relative/looking/string") == "relative/looking/string"


def test_every_contract_serialization_passes_sanitization():
    snapshot = ExecutionSnapshot(
        execution_id="exec-1",
        attempt_id="attempt-1",
        profile="safe-profile",
        lifecycle_state=LifecycleState.RUNNING,
        captured_at_utc=datetime(2026, 8, 14, tzinfo=timezone.utc),
        monotonic_offset_s=1.0,
        progress_counter=1,
        activity_counter=2,
        artifact_revision=3,
        waiting_for_authorization=False,
        waiting_for_credential=False,
        external_block=False,
        terminal=False,
    )
    action = ActionRequest(
        action_type=ActionType.EDIT_DOCUMENTATION,
        environment=Environment.DISPOSABLE,
        reversibility=Reversibility.REVERSIBLE,
        scope=Scope.SINGLE,
        sensitive_data=False,
        external_side_effect=False,
    )
    assessment = RiskAssessment(
        score=2.0,
        dimension_scores={RiskDimension.ENVIRONMENT: 0.0},
        reason_codes=(ReasonCode.SHADOW_CANDIDATE_ONLY,),
        bypass_council=False,
    )
    sentinel = SentinelResult(
        classification=SentinelClass.REAL_PROGRESS,
        evidence_codes=(EvidenceCode.PROGRESS_COUNTER_INCREASED,),
    )
    opinion = CouncilOpinion(
        reviewer_id="reviewer-1",
        model_id="model-1",
        role=CouncilRole.SECURITY,
        capability_class=ModelCapabilityClass.FRONTIER,
        risk_score=2.0,
        confidence=0.9,
        veto=False,
        dimension_scores={RiskDimension.SCOPE: 1.0},
        reason_codes=(ReasonCode.SHADOW_CANDIDATE_ONLY,),
        mitigation_codes=(MitigationCode.NONE,),
    )
    decision = CouncilDecision(
        verdict=Verdict.SHADOW_AUTOAPPROVE_CANDIDATE,
        final_score=2.0,
        council_bypassed=False,
        reason_codes=(ReasonCode.SHADOW_CANDIDATE_ONLY,),
    )

    for contract in (snapshot, action, assessment, sentinel, opinion, decision):
        serialized = contract.to_dict()
        assert sanitize_value(serialized) == serialized
