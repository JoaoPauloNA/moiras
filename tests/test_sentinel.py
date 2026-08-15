from datetime import datetime, timedelta, timezone

import pytest

from moiras.contracts import EvidenceCode, ExecutionSnapshot, LifecycleState, SentinelClass
from moiras.sentinel import SentinelComparisonError, compare_snapshots

BASE_TIME = datetime(2026, 1, 1, tzinfo=timezone.utc)


def make_snapshot(**overrides):
    fields = dict(
        execution_id="exec-1",
        attempt_id="att-1",
        profile="dev",
        lifecycle_state=LifecycleState.RUNNING,
        captured_at_utc=BASE_TIME,
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


class TestComparisonValidation:
    def test_rejects_mismatched_execution_id(self):
        first = make_snapshot()
        second = make_snapshot(execution_id="exec-2")
        with pytest.raises(SentinelComparisonError):
            compare_snapshots(first, second, idle_threshold_s=10.0)

    def test_rejects_mismatched_attempt_id(self):
        first = make_snapshot()
        second = make_snapshot(attempt_id="att-2")
        with pytest.raises(SentinelComparisonError):
            compare_snapshots(first, second, idle_threshold_s=10.0)

    def test_rejects_mismatched_profile(self):
        first = make_snapshot()
        second = make_snapshot(profile="prod")
        with pytest.raises(SentinelComparisonError):
            compare_snapshots(first, second, idle_threshold_s=10.0)

    def test_rejects_non_monotonic_wall_clock(self):
        first = make_snapshot(captured_at_utc=BASE_TIME + timedelta(seconds=5))
        second = make_snapshot(captured_at_utc=BASE_TIME)
        with pytest.raises(SentinelComparisonError):
            compare_snapshots(first, second, idle_threshold_s=10.0)

    def test_rejects_non_monotonic_offset(self):
        first = make_snapshot(monotonic_offset_s=10.0)
        second = make_snapshot(monotonic_offset_s=5.0)
        with pytest.raises(SentinelComparisonError):
            compare_snapshots(first, second, idle_threshold_s=10.0)

    @pytest.mark.parametrize(
        "field",
        ["progress_counter", "activity_counter", "artifact_revision"],
    )
    def test_rejects_counter_regression(self, field):
        first = make_snapshot(**{field: 2})
        second = make_snapshot(**{field: 1}, monotonic_offset_s=1.0)
        with pytest.raises(SentinelComparisonError):
            compare_snapshots(first, second, idle_threshold_s=10.0)

    def test_rejects_negative_idle_threshold(self):
        first = make_snapshot()
        second = make_snapshot()
        with pytest.raises(SentinelComparisonError):
            compare_snapshots(first, second, idle_threshold_s=-1.0)

    def test_rejects_non_finite_idle_threshold(self):
        first = make_snapshot()
        second = make_snapshot()
        with pytest.raises(SentinelComparisonError):
            compare_snapshots(first, second, idle_threshold_s=float("inf"))

    def test_rejects_non_snapshot_arguments(self):
        with pytest.raises(SentinelComparisonError):
            compare_snapshots({}, make_snapshot(), idle_threshold_s=10.0)

    def test_accepts_equal_timestamps(self):
        first = make_snapshot()
        second = make_snapshot()
        result = compare_snapshots(first, second, idle_threshold_s=10.0)
        assert result is not None


class TestSentinelClassification:
    def test_progress_counter_increase_is_real_progress(self):
        first = make_snapshot(progress_counter=1, monotonic_offset_s=0.0)
        second = make_snapshot(progress_counter=2, monotonic_offset_s=100.0)
        result = compare_snapshots(first, second, idle_threshold_s=10.0)
        assert result.classification == SentinelClass.REAL_PROGRESS
        assert EvidenceCode.PROGRESS_COUNTER_INCREASED in result.evidence_codes

    def test_artifact_revision_increase_is_real_progress(self):
        first = make_snapshot(artifact_revision=0, monotonic_offset_s=0.0)
        second = make_snapshot(artifact_revision=1, monotonic_offset_s=100.0)
        result = compare_snapshots(first, second, idle_threshold_s=10.0)
        assert result.classification == SentinelClass.REAL_PROGRESS
        assert EvidenceCode.ARTIFACT_REVISION_INCREASED in result.evidence_codes

    def test_becoming_terminal_is_real_progress(self):
        first = make_snapshot(terminal=False, monotonic_offset_s=0.0)
        second = make_snapshot(terminal=True, monotonic_offset_s=100.0)
        result = compare_snapshots(first, second, idle_threshold_s=10.0)
        assert result.classification == SentinelClass.REAL_PROGRESS
        assert EvidenceCode.BECAME_TERMINAL in result.evidence_codes

    def test_already_terminal_is_not_new_progress_evidence(self):
        first = make_snapshot(terminal=True, monotonic_offset_s=0.0)
        second = make_snapshot(terminal=True, monotonic_offset_s=100.0)
        result = compare_snapshots(first, second, idle_threshold_s=10.0)
        assert result.classification != SentinelClass.REAL_PROGRESS

    def test_external_block_takes_precedence_over_inactivity(self):
        first = make_snapshot(monotonic_offset_s=0.0)
        second = make_snapshot(external_block=True, monotonic_offset_s=100.0)
        result = compare_snapshots(first, second, idle_threshold_s=10.0)
        assert result.classification == SentinelClass.EXTERNAL_BLOCK
        assert EvidenceCode.EXTERNAL_BLOCK_FLAG in result.evidence_codes

    def test_external_block_takes_precedence_over_activity(self):
        first = make_snapshot(activity_counter=0, monotonic_offset_s=0.0)
        second = make_snapshot(activity_counter=1, external_block=True, monotonic_offset_s=1.0)
        result = compare_snapshots(first, second, idle_threshold_s=10.0)
        assert result.classification == SentinelClass.EXTERNAL_BLOCK

    def test_waiting_for_credential_is_legitimate_wait(self):
        first = make_snapshot(monotonic_offset_s=0.0)
        second = make_snapshot(waiting_for_credential=True, monotonic_offset_s=100.0)
        result = compare_snapshots(first, second, idle_threshold_s=10.0)
        assert result.classification == SentinelClass.LEGITIMATE_WAIT
        assert EvidenceCode.WAITING_FOR_CREDENTIAL in result.evidence_codes

    def test_waiting_for_authorization_is_legitimate_wait(self):
        first = make_snapshot(monotonic_offset_s=0.0)
        second = make_snapshot(waiting_for_authorization=True, monotonic_offset_s=100.0)
        result = compare_snapshots(first, second, idle_threshold_s=10.0)
        assert result.classification == SentinelClass.LEGITIMATE_WAIT
        assert EvidenceCode.WAITING_FOR_AUTHORIZATION in result.evidence_codes

    def test_wait_flags_take_precedence_over_probable_inactivity(self):
        first = make_snapshot(monotonic_offset_s=0.0)
        second = make_snapshot(waiting_for_credential=True, monotonic_offset_s=9999.0)
        result = compare_snapshots(first, second, idle_threshold_s=10.0)
        assert result.classification == SentinelClass.LEGITIMATE_WAIT

    def test_activity_without_progress(self):
        first = make_snapshot(activity_counter=0, monotonic_offset_s=0.0)
        second = make_snapshot(activity_counter=1, monotonic_offset_s=1.0)
        result = compare_snapshots(first, second, idle_threshold_s=10.0)
        assert result.classification == SentinelClass.ACTIVITY_WITHOUT_PROGRESS
        assert EvidenceCode.ACTIVITY_COUNTER_INCREASED in result.evidence_codes

    def test_probable_inactivity_when_idle_threshold_exceeded(self):
        first = make_snapshot(monotonic_offset_s=0.0)
        second = make_snapshot(monotonic_offset_s=20.0)
        result = compare_snapshots(first, second, idle_threshold_s=10.0)
        assert result.classification == SentinelClass.PROBABLE_INACTIVITY
        assert EvidenceCode.NO_PROGRESS_NO_ACTIVITY in result.evidence_codes
        assert EvidenceCode.IDLE_THRESHOLD_EXCEEDED in result.evidence_codes

    def test_probable_inactivity_at_exact_threshold(self):
        first = make_snapshot(monotonic_offset_s=0.0)
        second = make_snapshot(monotonic_offset_s=10.0)
        result = compare_snapshots(first, second, idle_threshold_s=10.0)
        assert result.classification == SentinelClass.PROBABLE_INACTIVITY

    def test_indeterminate_when_below_idle_threshold(self):
        first = make_snapshot(monotonic_offset_s=0.0)
        second = make_snapshot(monotonic_offset_s=5.0)
        result = compare_snapshots(first, second, idle_threshold_s=10.0)
        assert result.classification == SentinelClass.INDETERMINATE
        assert EvidenceCode.IDLE_THRESHOLD_NOT_EXCEEDED in result.evidence_codes

    def test_no_change_at_all_is_indeterminate_below_threshold(self):
        first = make_snapshot(monotonic_offset_s=0.0)
        second = make_snapshot(monotonic_offset_s=0.0)
        result = compare_snapshots(first, second, idle_threshold_s=10.0)
        assert result.classification == SentinelClass.INDETERMINATE

    def test_result_never_carries_an_action(self):
        first = make_snapshot(monotonic_offset_s=0.0)
        second = make_snapshot(progress_counter=1, monotonic_offset_s=1.0)
        result = compare_snapshots(first, second, idle_threshold_s=10.0)
        assert not hasattr(result, "action")
        assert not hasattr(result, "execute")
