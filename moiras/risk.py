"""Baseline risk scoring for a single ``ActionRequest``.

This module never decides whether an action proceeds. It produces a
``RiskAssessment`` -- a score in [0, 10], per-dimension contributions, and
allowlisted reason codes -- that feeds the Council aggregator in
``moiras.council``.

Scoring model
-------------

Each ``ActionType`` has a baseline minimum score. Independently, five
allowlisted dimensions (reversibility, scope, environment, sensitive_data,
external_side_effect) each contribute a score derived only from their own
field. The final score is ``max(action_type_baseline, *dimension_scores)``
-- modifiers only ever raise the score, never average it down.

Six action types are hard stops: DELETE_BROAD_PATH, DATABASE_DELETE,
DATABASE_DROP, REQUEST_SUDO, REQUEST_CREDENTIAL, CREATE_PRIVILEGED_USER.
These always score 10 and set ``bypass_council=True``, short-circuiting
before any dimension scoring.

CREATE_TEMP_FILE is the only action type whose baseline is 0, and even
then the final score is 0 only when every dimension also lands at 0 --
i.e. exactly DISPOSABLE + REVERSIBLE + SINGLE scope with no sensitive
data and no external side effect. Every other creating action type
(CREATE_SENSITIVE_CONFIG, CREATE_PRIVILEGED_USER) has a strictly positive
baseline, so creation is never zero outside that one combination.
"""

from __future__ import annotations

from .contracts import (
    ActionRequest,
    ActionType,
    Environment,
    ReasonCode,
    Reversibility,
    RiskAssessment,
    RiskDimension,
    Scope,
)

__all__ = ["assess"]

HARD_STOP_ACTIONS = frozenset(
    {
        ActionType.DELETE_BROAD_PATH,
        ActionType.DATABASE_DELETE,
        ActionType.DATABASE_DROP,
        ActionType.REQUEST_SUDO,
        ActionType.REQUEST_CREDENTIAL,
        ActionType.CREATE_PRIVILEGED_USER,
    }
)

# Minimum score for each action type before dimension modifiers are applied.
_BASELINE_MIN_SCORE = {
    ActionType.PUBLIC_WEB_READ: 1.0,
    ActionType.CREATE_TEMP_FILE: 0.0,
    ActionType.EDIT_DOCUMENTATION: 2.0,
    ActionType.CREATE_SENSITIVE_CONFIG: 6.0,
    ActionType.EDIT_CODE: 3.0,
    ActionType.EDIT_AUTH: 9.0,
    ActionType.DELETE_REPRODUCIBLE_CACHE: 3.0,
    ActionType.DELETE_UNIQUE_FILE: 8.0,
    ActionType.EXTERNAL_SEND: 8.0,
    ActionType.AMBIGUOUS: 9.0,
    # Hard stops are handled separately and never consult this table, but
    # entries are kept here so every ActionType is accounted for.
    ActionType.DELETE_BROAD_PATH: 10.0,
    ActionType.DATABASE_DELETE: 10.0,
    ActionType.DATABASE_DROP: 10.0,
    ActionType.REQUEST_SUDO: 10.0,
    ActionType.REQUEST_CREDENTIAL: 10.0,
    ActionType.CREATE_PRIVILEGED_USER: 10.0,
}

_CREATE_ACTIONS = frozenset(
    {
        ActionType.CREATE_TEMP_FILE,
        ActionType.CREATE_SENSITIVE_CONFIG,
        ActionType.CREATE_PRIVILEGED_USER,
    }
)

_REVERSIBILITY_SCORE = {
    Reversibility.REVERSIBLE: 0.0,
    Reversibility.PARTIAL: 5.0,
    Reversibility.IRREVERSIBLE: 8.0,
    Reversibility.UNKNOWN: 7.0,
}

_SCOPE_SCORE = {
    Scope.SINGLE: 0.0,
    Scope.LIMITED: 4.0,
    Scope.BROAD: 8.0,
    Scope.UNKNOWN: 7.0,
}

_ENVIRONMENT_SCORE = {
    Environment.DISPOSABLE: 0.0,
    Environment.DEVELOPMENT: 2.0,
    Environment.PRODUCTION: 8.0,
    Environment.UNKNOWN: 7.0,
}


def assess(action: ActionRequest) -> RiskAssessment:
    """Compute the baseline ``RiskAssessment`` for a single action.

    Pure function of ``action``; consults no external state and performs
    no I/O. Never returns a score below the applicable action-type floor.
    """

    if not isinstance(action, ActionRequest):
        raise TypeError("action must be an ActionRequest")

    if action.action_type in HARD_STOP_ACTIONS:
        dimension_scores = {dim: 10.0 for dim in RiskDimension}
        return RiskAssessment(
            score=10.0,
            dimension_scores=dimension_scores,
            reason_codes=(ReasonCode.HARD_STOP_ACTION,),
            bypass_council=True,
        )

    reason_codes = []

    reversibility_score = _REVERSIBILITY_SCORE[action.reversibility]
    scope_score = _SCOPE_SCORE[action.scope]
    environment_score = _ENVIRONMENT_SCORE[action.environment]
    sensitive_score = 8.0 if action.sensitive_data else 0.0
    external_score = 8.0 if action.external_side_effect else 0.0

    dimension_scores = {
        RiskDimension.REVERSIBILITY: reversibility_score,
        RiskDimension.SCOPE: scope_score,
        RiskDimension.ENVIRONMENT: environment_score,
        RiskDimension.SENSITIVE_DATA: sensitive_score,
        RiskDimension.EXTERNAL_EXPOSURE: external_score,
    }

    if action.reversibility in (Reversibility.PARTIAL, Reversibility.IRREVERSIBLE):
        reason_codes.append(ReasonCode.IRREVERSIBLE_OR_PARTIAL)
    if action.scope in (Scope.BROAD, Scope.UNKNOWN):
        reason_codes.append(ReasonCode.BROAD_OR_UNKNOWN_SCOPE)
    if action.environment in (Environment.PRODUCTION, Environment.UNKNOWN):
        reason_codes.append(ReasonCode.PRODUCTION_OR_UNKNOWN_ENVIRONMENT)
    if action.sensitive_data:
        reason_codes.append(ReasonCode.SENSITIVE_DATA_INVOLVED)
    if action.external_side_effect:
        reason_codes.append(ReasonCode.EXTERNAL_SIDE_EFFECT)

    baseline = _BASELINE_MIN_SCORE[action.action_type]
    score = max(baseline, *dimension_scores.values())

    if score == 0.0:
        reason_codes.append(ReasonCode.ZERO_RISK_EXEMPTION)
    elif action.action_type in _CREATE_ACTIONS or baseline >= 8.0:
        reason_codes.append(ReasonCode.HIGH_SEVERITY_ACTION_TYPE)

    return RiskAssessment(
        score=score,
        dimension_scores=dimension_scores,
        reason_codes=tuple(reason_codes),
        bypass_council=False,
    )
