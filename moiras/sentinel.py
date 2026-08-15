"""Sentinel: classifies execution state from two temporal snapshots.

The Sentinel never acts. It compares two ``ExecutionSnapshot`` instances
from the same execution/attempt/profile and returns a ``SentinelResult``
carrying a classification and the evidence codes that justify it. It
never triggers, cancels, authorizes, or supplies anything.

Classification precedence (checked in order, first match wins):

1. ``REAL_PROGRESS`` -- progress_counter increased, artifact_revision
   increased, or the execution became terminal.
2. ``EXTERNAL_BLOCK`` -- the second snapshot reports external_block.
3. ``LEGITIMATE_WAIT`` -- the second snapshot reports
   waiting_for_credential or waiting_for_authorization.
4. ``ACTIVITY_WITHOUT_PROGRESS`` -- activity_counter increased but none
   of the above applied.
5. ``PROBABLE_INACTIVITY`` -- no progress and no activity, and the
   monotonic elapsed time is >= idle_threshold_s.
6. ``INDETERMINATE`` -- no progress and no activity, but not enough
   elapsed time has passed to call it inactivity.

Credential/authorization waits and external blocks are checked ahead of
the inactivity checks (steps 2-3 before step 5) so that a legitimate wait
is never misclassified as probable inactivity.
"""

from __future__ import annotations

import math

from .contracts import EvidenceCode, ExecutionSnapshot, SentinelClass, SentinelResult

__all__ = ["SentinelComparisonError", "compare_snapshots"]


class SentinelComparisonError(ValueError):
    """Raised when two snapshots cannot be meaningfully compared."""


def compare_snapshots(
    first: ExecutionSnapshot,
    second: ExecutionSnapshot,
    *,
    idle_threshold_s: float,
) -> SentinelResult:
    """Compare two snapshots of the same execution/attempt/profile.

    ``second`` must be at or after ``first`` in both wall-clock
    (``captured_at_utc``) and monotonic (``monotonic_offset_s``) time.
    Raises ``SentinelComparisonError`` if the snapshots do not share an
    identity, are out of order, or ``idle_threshold_s`` is invalid.
    """

    if not isinstance(first, ExecutionSnapshot) or not isinstance(second, ExecutionSnapshot):
        raise SentinelComparisonError("both arguments must be ExecutionSnapshot instances")

    if isinstance(idle_threshold_s, bool) or not isinstance(idle_threshold_s, (int, float)):
        raise SentinelComparisonError("idle_threshold_s must be a number")
    if not math.isfinite(idle_threshold_s) or idle_threshold_s < 0:
        raise SentinelComparisonError("idle_threshold_s must be finite and >= 0")

    if (
        first.execution_id != second.execution_id
        or first.attempt_id != second.attempt_id
        or first.profile != second.profile
    ):
        raise SentinelComparisonError("snapshots must share execution_id, attempt_id, and profile")

    if second.captured_at_utc < first.captured_at_utc:
        raise SentinelComparisonError("second.captured_at_utc must be >= first.captured_at_utc")
    if second.monotonic_offset_s < first.monotonic_offset_s:
        raise SentinelComparisonError(
            "second.monotonic_offset_s must be >= first.monotonic_offset_s"
        )

    evidence: list = []

    progress_delta = second.progress_counter - first.progress_counter
    artifact_delta = second.artifact_revision - first.artifact_revision
    activity_delta = second.activity_counter - first.activity_counter
    became_terminal = second.terminal and not first.terminal

    if progress_delta < 0 or artifact_delta < 0 or activity_delta < 0:
        raise SentinelComparisonError(
            "progress_counter, activity_counter, and artifact_revision must not decrease"
        )

    if progress_delta > 0:
        evidence.append(EvidenceCode.PROGRESS_COUNTER_INCREASED)
    if artifact_delta > 0:
        evidence.append(EvidenceCode.ARTIFACT_REVISION_INCREASED)
    if became_terminal:
        evidence.append(EvidenceCode.BECAME_TERMINAL)

    if progress_delta > 0 or artifact_delta > 0 or became_terminal:
        return SentinelResult(SentinelClass.REAL_PROGRESS, tuple(evidence))

    if second.external_block:
        evidence.append(EvidenceCode.EXTERNAL_BLOCK_FLAG)
        return SentinelResult(SentinelClass.EXTERNAL_BLOCK, tuple(evidence))

    if second.waiting_for_credential:
        evidence.append(EvidenceCode.WAITING_FOR_CREDENTIAL)
        return SentinelResult(SentinelClass.LEGITIMATE_WAIT, tuple(evidence))

    if second.waiting_for_authorization:
        evidence.append(EvidenceCode.WAITING_FOR_AUTHORIZATION)
        return SentinelResult(SentinelClass.LEGITIMATE_WAIT, tuple(evidence))

    if activity_delta > 0:
        evidence.append(EvidenceCode.ACTIVITY_COUNTER_INCREASED)
        return SentinelResult(SentinelClass.ACTIVITY_WITHOUT_PROGRESS, tuple(evidence))

    evidence.append(EvidenceCode.NO_PROGRESS_NO_ACTIVITY)
    elapsed_s = second.monotonic_offset_s - first.monotonic_offset_s
    if elapsed_s >= idle_threshold_s:
        evidence.append(EvidenceCode.IDLE_THRESHOLD_EXCEEDED)
        return SentinelResult(SentinelClass.PROBABLE_INACTIVITY, tuple(evidence))

    evidence.append(EvidenceCode.IDLE_THRESHOLD_NOT_EXCEEDED)
    return SentinelResult(SentinelClass.INDETERMINATE, tuple(evidence))
