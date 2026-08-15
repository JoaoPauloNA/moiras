"""Council aggregation: turns a baseline risk plus role opinions into a
shadow-mode verdict. Never executes, never bypasses a human for anything
but the explicit hard-stop path, and never produces ``executed=True``.

Aggregation algorithm
----------------------

1. If the baseline ``RiskAssessment`` is a hard stop (``bypass_council`` or
   ``score >= 10``), the verdict is ``STOP_AND_HUMAN`` with
   ``council_bypassed=True``. Opinions are ignored entirely.
2. Otherwise, exactly one *eligible* opinion is required per role
   (SECURITY, INTEGRITY, GOVERNANCE, OPERATIONS). An opinion is eligible
   only if its ``capability_class`` is FRONTIER or CAPABLE_GENERAL --
   EDGE and UNKNOWN models are always ineligible and never counted. A
   missing, duplicated, or fully-ineligible role produces
   ``HUMAN_REQUIRED``.
3. Any veto among the four opinions used produces ``HUMAN_REQUIRED``.
4. Divergence (max - min risk_score among the four opinions used) greater
   than 3 produces ``HUMAN_REQUIRED``.
5. The combined score is ``max(baseline.score, *opinion.risk_score)``.
   Bands: [7, 10] -> HUMAN_REQUIRED; [4, 7) -> MITIGATE_AND_REASSESS;
   [0, 4) -> SHADOW_AUTOAPPROVE_CANDIDATE only if ``environment`` is
   DISPOSABLE (having already passed the veto and divergence checks
   above); otherwise HUMAN_REQUIRED.

Every ``CouncilDecision`` returned has ``executed=False`` and
``mode="shadow"`` -- this module never represents anything as having
happened.
"""

from __future__ import annotations

from collections.abc import Sequence

from .contracts import (
    CouncilDecision,
    CouncilOpinion,
    CouncilRole,
    Environment,
    ReasonCode,
    RiskAssessment,
    Verdict,
)

__all__ = ["AggregationError", "aggregate"]

_REQUIRED_ROLES = frozenset(CouncilRole)
_DIVERGENCE_LIMIT = 3.0
_HUMAN_REQUIRED_FLOOR = 7.0
_MITIGATE_FLOOR = 4.0


class AggregationError(ValueError):
    """Raised when the council inputs are structurally invalid."""


def _is_hard_stop(baseline: RiskAssessment) -> bool:
    return baseline.bypass_council or baseline.score >= 10.0


def _with_reason(
    baseline: RiskAssessment,
    reason: ReasonCode,
) -> tuple[ReasonCode, ...]:
    return tuple(dict.fromkeys((*baseline.reason_codes, reason)))


def _select_role_opinions(
    opinions: Sequence[CouncilOpinion],
) -> tuple[dict[CouncilRole, CouncilOpinion] | None, ReasonCode | None]:
    """Require exactly four eligible opinions, one for each role."""

    by_role: dict[CouncilRole, list[CouncilOpinion]] = {role: [] for role in _REQUIRED_ROLES}
    for opinion in opinions:
        if not isinstance(opinion, CouncilOpinion):
            raise AggregationError("opinions must be CouncilOpinion instances")
        if not opinion.eligible:
            return None, ReasonCode.COUNCIL_INELIGIBLE_MODEL
        by_role[opinion.role].append(opinion)

    if len(opinions) != len(_REQUIRED_ROLES):
        if any(len(items) > 1 for items in by_role.values()):
            return None, ReasonCode.COUNCIL_DUPLICATE_ROLE
        return None, ReasonCode.COUNCIL_INCOMPLETE

    # Check the panel as a whole before iterating the role set so malformed
    # panels always receive the same reason code regardless of hash order.
    if any(len(items) > 1 for items in by_role.values()):
        return None, ReasonCode.COUNCIL_DUPLICATE_ROLE
    if any(not items for items in by_role.values()):
        return None, ReasonCode.COUNCIL_INCOMPLETE

    selected: dict[CouncilRole, CouncilOpinion] = {}
    for role in _REQUIRED_ROLES:
        candidates = by_role[role]
        if not candidates:
            return None, ReasonCode.COUNCIL_INCOMPLETE
        if len(candidates) > 1:
            return None, ReasonCode.COUNCIL_DUPLICATE_ROLE
        selected[role] = candidates[0]
    return selected, None


def aggregate(
    baseline: RiskAssessment,
    opinions: Sequence[CouncilOpinion],
    *,
    environment: Environment,
) -> CouncilDecision:
    """Aggregate a baseline risk assessment and council opinions into a
    shadow-mode ``CouncilDecision``. Never executes anything.
    """

    if not isinstance(baseline, RiskAssessment):
        raise AggregationError("baseline must be a RiskAssessment")
    if not isinstance(environment, Environment):
        raise AggregationError("environment must be an Environment")

    if _is_hard_stop(baseline):
        reason = ReasonCode.HARD_STOP_ACTION if baseline.bypass_council else ReasonCode.SCORE_TEN
        return CouncilDecision(
            verdict=Verdict.STOP_AND_HUMAN,
            final_score=10.0,
            council_bypassed=True,
            reason_codes=_with_reason(baseline, reason),
        )

    selected, selection_error = _select_role_opinions(opinions)
    if selected is None:
        observed_scores = [
            opinion.risk_score for opinion in opinions if isinstance(opinion, CouncilOpinion)
        ]
        return CouncilDecision(
            verdict=Verdict.HUMAN_REQUIRED,
            final_score=max([baseline.score, *observed_scores]),
            council_bypassed=False,
            reason_codes=_with_reason(
                baseline,
                selection_error or ReasonCode.COUNCIL_INCOMPLETE,
            ),
        )

    role_opinions = list(selected.values())

    if any(opinion.veto for opinion in role_opinions):
        return CouncilDecision(
            verdict=Verdict.HUMAN_REQUIRED,
            final_score=max(baseline.score, *(o.risk_score for o in role_opinions)),
            council_bypassed=False,
            reason_codes=_with_reason(baseline, ReasonCode.COUNCIL_VETO),
        )

    opinion_scores = [opinion.risk_score for opinion in role_opinions]
    divergence = max(opinion_scores) - min(opinion_scores)
    if divergence > _DIVERGENCE_LIMIT:
        return CouncilDecision(
            verdict=Verdict.HUMAN_REQUIRED,
            final_score=max(baseline.score, *opinion_scores),
            council_bypassed=False,
            reason_codes=_with_reason(baseline, ReasonCode.COUNCIL_DIVERGENCE),
        )

    combined_score = max(baseline.score, *opinion_scores)

    if combined_score >= _HUMAN_REQUIRED_FLOOR:
        verdict = Verdict.HUMAN_REQUIRED
        decision_reason = ReasonCode.RISK_BAND_HUMAN
    elif combined_score >= _MITIGATE_FLOOR:
        verdict = Verdict.MITIGATE_AND_REASSESS
        decision_reason = ReasonCode.RISK_BAND_MITIGATE
    elif environment == Environment.DISPOSABLE:
        verdict = Verdict.SHADOW_AUTOAPPROVE_CANDIDATE
        decision_reason = ReasonCode.SHADOW_CANDIDATE_ONLY
    else:
        verdict = Verdict.HUMAN_REQUIRED
        decision_reason = ReasonCode.NON_DISPOSABLE_ENVIRONMENT

    return CouncilDecision(
        verdict=verdict,
        final_score=combined_score,
        council_bypassed=False,
        reason_codes=_with_reason(baseline, decision_reason),
    )
