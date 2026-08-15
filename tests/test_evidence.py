import json
import threading
from datetime import datetime, timedelta, timezone

import pytest

from moiras.contracts import (
    ActionType,
    ContractValidationError,
    SentinelClass,
)
from moiras.evidence import (
    EvidenceLevel,
    EvidenceMetrics,
    EvidenceRecord,
    EvidenceRecorder,
    HumanOutcome,
    OutcomeSource,
)
from moiras.sanitize import SanitizationError, sanitize_value
from moiras.supervisor import RecommendationCode

T0 = datetime(2026, 8, 14, tzinfo=timezone.utc)


def observation(execution_id="execution-1"):
    return EvidenceRecord(
        execution_id=execution_id,
        attempt_id="attempt-1",
        timestamp_utc=T0,
        level=EvidenceLevel.OBSERVATION,
        sentinel_class=SentinelClass.REAL_PROGRESS,
    )


def recommendation(
    execution_id="execution-1",
    timestamp=T0,
    code=RecommendationCode.RECOMMEND_SHADOW_CANDIDATE_ONLY,
):
    return EvidenceRecord(
        execution_id=execution_id,
        attempt_id="attempt-1",
        timestamp_utc=timestamp,
        level=EvidenceLevel.RECOMMENDATION,
        action_type=ActionType.CREATE_TEMP_FILE,
        risk_score=1.0,
        recommendation_code=code,
    )


def outcome(label, execution_id="execution-1", timestamp=None):
    return EvidenceRecord(
        execution_id=execution_id,
        attempt_id="attempt-1",
        timestamp_utc=timestamp or T0 + timedelta(seconds=1),
        level=EvidenceLevel.HUMAN_OUTCOME,
        human_outcome=label,
        outcome_source=OutcomeSource.HUMAN_REVIEW,
    )


@pytest.mark.parametrize(
    "record",
    [
        observation(),
        recommendation(),
        outcome(HumanOutcome.SAFE),
        outcome(HumanOutcome.UNSAFE),
        outcome(HumanOutcome.INDETERMINATE),
    ],
)
def test_all_record_levels_serialize_and_sanitize(record):
    payload = record.to_dict()
    assert sanitize_value(payload) == payload
    assert payload["executed"] is False
    assert payload["mode"] == "shadow"
    forbidden = {"path", "prompt", "response", "command", "model_id", "reviewer_id"}
    assert forbidden.isdisjoint(payload)


def test_level_specific_fields_are_enforced():
    with pytest.raises(ContractValidationError):
        EvidenceRecord(
            "execution-1",
            "attempt-1",
            T0,
            EvidenceLevel.OBSERVATION,
        )
    with pytest.raises(ContractValidationError):
        EvidenceRecord(
            "execution-1",
            "attempt-1",
            T0,
            EvidenceLevel.RECOMMENDATION,
            action_type=ActionType.CREATE_TEMP_FILE,
            risk_score=float("nan"),
            recommendation_code=RecommendationCode.RECOMMEND_SHADOW_CANDIDATE_ONLY,
        )
    with pytest.raises(ContractValidationError):
        EvidenceRecord(
            "execution-1",
            "attempt-1",
            T0,
            EvidenceLevel.HUMAN_OUTCOME,
            human_outcome=HumanOutcome.SAFE,
        )


@pytest.mark.parametrize("bad_id", ["note /tmp", "ghp_abcdefghijkl", "api-key-1"])
def test_paths_and_secret_shaped_ids_are_rejected(bad_id):
    with pytest.raises(SanitizationError):
        observation(bad_id)


def test_recorder_writes_only_sanitized_jsonl(tmp_path):
    destination = tmp_path / "evidence.jsonl"
    recorder = EvidenceRecorder(destination)
    recorder.record(observation())
    recorder.record(recommendation())
    lines = destination.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    payloads = [json.loads(line) for line in lines]
    assert all(sanitize_value(payload) == payload for payload in payloads)
    assert str(destination) not in destination.read_text(encoding="utf-8")


def test_recorder_rejects_non_contract(tmp_path):
    recorder = EvidenceRecorder(tmp_path / "evidence.jsonl")
    with pytest.raises(TypeError):
        recorder.record({"prompt": "not allowed"})


def test_recorder_serializes_concurrent_threads_without_partial_lines(tmp_path):
    destination = tmp_path / "evidence.jsonl"
    recorder = EvidenceRecorder(destination)

    def worker(worker_id):
        for item in range(20):
            recorder.record(observation(f"execution-{worker_id}-{item}"))

    threads = [threading.Thread(target=worker, args=(worker_id,)) for worker_id in range(5)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    lines = destination.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 100
    assert all(json.loads(line)["level"] == "OBSERVATION" for line in lines)


def test_metrics_use_only_strictly_later_human_labels():
    records = [
        recommendation("execution-safe"),
        outcome(HumanOutcome.SAFE, "execution-safe"),
        recommendation("execution-unsafe"),
        outcome(HumanOutcome.UNSAFE, "execution-unsafe"),
        recommendation("execution-before"),
        outcome(HumanOutcome.UNSAFE, "execution-before", T0 - timedelta(seconds=1)),
        recommendation("execution-unlabeled"),
    ]
    metrics = EvidenceMetrics.compute(reversed(records))
    assert metrics.candidate_count == 4
    assert metrics.labeled_candidates == 2
    assert metrics.unsafe_candidate_count == 1
    assert metrics.ambiguous_candidates == 0
    assert metrics.coverage == 0.5
    assert metrics.unsafe_candidate_rate == 0.5


def test_conflicting_or_indeterminate_labels_are_ambiguous_not_ground_truth():
    records = [
        recommendation("execution-conflict"),
        outcome(HumanOutcome.SAFE, "execution-conflict"),
        outcome(HumanOutcome.UNSAFE, "execution-conflict"),
        recommendation("execution-indeterminate"),
        outcome(HumanOutcome.INDETERMINATE, "execution-indeterminate"),
    ]
    metrics = EvidenceMetrics.compute(records)
    assert metrics.candidate_count == 2
    assert metrics.labeled_candidates == 0
    assert metrics.ambiguous_candidates == 2
    assert metrics.coverage == 0.0
    assert metrics.unsafe_candidate_rate is None


def test_recommendation_alone_never_becomes_ground_truth():
    metrics = EvidenceMetrics.compute([recommendation()])
    assert metrics.candidate_count == 1
    assert metrics.labeled_candidates == 0
    assert metrics.coverage == 0.0
    assert metrics.unsafe_candidate_rate is None


def test_latest_non_candidate_recommendation_removes_stale_candidate():
    records = [
        recommendation(),
        recommendation(
            timestamp=T0 + timedelta(seconds=1),
            code=RecommendationCode.RECOMMEND_HUMAN_REVIEW,
        ),
        outcome(HumanOutcome.UNSAFE, timestamp=T0 + timedelta(seconds=2)),
    ]
    metrics = EvidenceMetrics.compute(records)
    assert metrics.candidate_count == 0
    assert metrics.coverage is None


def test_no_candidates_has_undefined_rates():
    metrics = EvidenceMetrics.compute([observation()])
    assert metrics.candidate_count == 0
    assert metrics.coverage is None
    assert metrics.unsafe_candidate_rate is None
    assert sanitize_value(metrics.to_dict()) == metrics.to_dict()
