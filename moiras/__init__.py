"""Moiras -- a shadow-mode supervision lab for agentic execution.

Moiras is advisory-only. It never executes an action, cancels a process,
supplies a credential, approves a CLI prompt, or changes the lifecycle of
any supervised system (including Athena). Every decision this library
produces is a labeled, non-binding recommendation (``mode="shadow"``,
``executed=False``).

Status: milestones M0-M9 of the v1-independent shadow-lab design. There is no
integration with Athena yet -- see docs/protocol.md for the full status
and docs/threat-model.md for what this library does and does not defend
against.
"""

from .broker import (
    BrokerError,
    CapabilityReceipt,
    ConsumeStatus,
    SyntheticCapability,
    SyntheticCapabilityBroker,
)
from .contracts import (
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
from .council import AggregationError, aggregate
from .evidence import (
    EvidenceLevel,
    EvidenceMetrics,
    EvidenceRecord,
    EvidenceRecorder,
    HumanOutcome,
    OutcomeSource,
)
from .harness import (
    SCENARIOS,
    GateResult,
    Scenario,
    run_gate,
)
from .risk import assess
from .sanitize import SanitizationError, sanitize_value, validate_id
from .sentinel import SentinelComparisonError, compare_snapshots
from .supervisor import (
    CounterfactualCode,
    RecommendationCode,
    ShadowReport,
    ShadowSupervisor,
    SupervisionError,
    supervise,
)

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "SCHEMA_VERSION",
    "ActionRequest",
    "ActionType",
    "ContractValidationError",
    "CouncilDecision",
    "CouncilOpinion",
    "CouncilRole",
    "Environment",
    "EvidenceCode",
    "ExecutionSnapshot",
    "LifecycleState",
    "MitigationCode",
    "ModelCapabilityClass",
    "ReasonCode",
    "RiskAssessment",
    "RiskDimension",
    "Reversibility",
    "Scope",
    "SentinelClass",
    "SentinelResult",
    "Verdict",
    "BrokerError",
    "ConsumeStatus",
    "SyntheticCapability",
    "CapabilityReceipt",
    "SyntheticCapabilityBroker",
    "AggregationError",
    "aggregate",
    "assess",
    "SanitizationError",
    "sanitize_value",
    "validate_id",
    "SentinelComparisonError",
    "compare_snapshots",
    "SupervisionError",
    "RecommendationCode",
    "CounterfactualCode",
    "ShadowReport",
    "supervise",
    "ShadowSupervisor",
    "EvidenceLevel",
    "OutcomeSource",
    "HumanOutcome",
    "EvidenceRecord",
    "EvidenceRecorder",
    "EvidenceMetrics",
    "Scenario",
    "SCENARIOS",
    "run_gate",
    "GateResult",
]
