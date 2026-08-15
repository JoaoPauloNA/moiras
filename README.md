# Moiras

**When an agent appears inactive or asks for authority, what evidence should
reach a human — and what must remain mechanically blocked?**

Moiras is a standalone shadow-mode supervision laboratory for agentic
execution. It turns allowlisted lifecycle snapshots, a categorical action
request, and injected council opinions into an inert recommendation. It also
provides a synthetic capability broker, sanitized research evidence, and an
offline scenario gate.

Moiras does not execute, authorize, retry, cancel, type confirmation, supply a
credential, or call a model. Every decision remains `executed=false` and
`mode=shadow`.

[Português](README.pt-BR.md)

## Why it exists

An absolute timeout cannot distinguish a dead process from slow but valid
work, a CLI waiting for approval, or an external dependency. At the same time,
letting another model silently approve risky actions creates a new authority
problem. Moiras separates these concerns:

- the Sentinel classifies temporal evidence but never cancels;
- deterministic risk floors prevent a council from averaging down hard stops;
- a four-role council accepts only declared capable/frontier reviewers;
- recommendations remain advisory until a later, independent human outcome;
- evidence records contain categories and counters, not working content.

The policy values are research hypotheses encoded as testable rules. They are
not a safety certification or a validated benchmark.

## Protocol

```text
ExecutionSnapshot pair ──> Sentinel ───────────────┐
ActionRequest ───────────> deterministic risk ────┼─> ShadowReport
Injected CouncilOpinions ─> conservative council ─┘   executed=false

ShadowReport ──> sanitized recommendation record ──> later HUMAN_REVIEW label
Candidate ─────> synthetic one-use capability ─────> status only; no authority
```

The council requires exactly one opinion for each role: security, integrity,
governance, and operations. `EDGE` and `UNKNOWN` capability classes invalidate
the panel. A veto or excessive score divergence requires a human. Score 10 and
hard-stop action types bypass deliberation and stop for a human decision.

See [the protocol](docs/protocol.md) and
[the threat model](docs/threat-model.md) for exact precedence and boundaries.

## Install locally

Moiras requires Python 3.10 or newer and has no third-party runtime dependency.

```bash
python -m pip install -e ".[dev]"
```

## Minimal example

```python
from moiras import (
    ActionRequest,
    ActionType,
    CouncilOpinion,
    CouncilRole,
    Environment,
    ModelCapabilityClass,
    Reversibility,
    Scope,
    supervise,
)

action = ActionRequest(
    action_type=ActionType.CREATE_TEMP_FILE,
    environment=Environment.DISPOSABLE,
    reversibility=Reversibility.REVERSIBLE,
    scope=Scope.SINGLE,
    sensitive_data=False,
    external_side_effect=False,
)

opinions = [
    CouncilOpinion(
        reviewer_id=f"reviewer-{role.value.lower()}",
        model_id="capable-model",
        role=role,
        capability_class=ModelCapabilityClass.FRONTIER,
        risk_score=1.0,
        confidence=0.9,
        veto=False,
        dimension_scores={},
        reason_codes=(),
        mitigation_codes=(),
    )
    for role in CouncilRole
]

report = supervise(action, opinions)
assert report.executed is False
assert report.mode == "shadow"
```

The library does not create those opinions with live models. Callers inject
already-structured opinions; model selection and transport are outside this
repository.

## Reproducible validation

```bash
ruff check .
pytest
python -m moiras
python -m moiras --json /tmp/moiras-gate.json
```

The offline gate covers 12 named scenarios: real progress, probable
inactivity, approval/credential-like waits, three hard stops, a disposable
low-risk action, non-disposable context, an edge-model panel, veto, and
divergence. Its report contains only generic platform/Python metadata,
scenario names, and pass/fail counts. The output path is never serialized.

Local validation on 2026-08-14: lint passed, 317 tests passed on Python 3.12,
the gate passed 12/12 on Python 3.11 and 3.12. Python 3.10 is configured in CI
but was not available for the local run.

## Implemented milestones

| Milestone | Implemented scope |
| --- | --- |
| M0–M1 | repository boundary, typed contracts, fail-closed sanitization |
| M2 | deterministic risk baseline and hard stops |
| M3 | two-snapshot temporal Sentinel |
| M4–M5 | capable-only council and conservative aggregation |
| M6 | in-memory synthetic, single-use, short-TTL capability broker |
| M7 | inert shadow supervisor and categorical counterfactual |
| M8 | three-level JSONL evidence and human-label-only descriptive metrics |
| M9 | deterministic offline harness, CLI, and CI definitions |

## Repository layout

```text
moiras/
  contracts.py    immutable schemas and enums
  sanitize.py     identifier and outbound-data guard
  risk.py         deterministic 0–10 policy baseline
  sentinel.py     temporal comparison without action
  council.py      four-role conservative aggregation
  broker.py       synthetic capability lifecycle, no real authority
  supervisor.py   pure shadow orchestration
  evidence.py     sanitized JSONL and descriptive correlations
  harness.py      offline scenario gate
tests/             unit, adversarial, concurrency, privacy, and CLI tests
docs/              protocol and threat model
```

## What Moiras is not

- Not an execution engine, credential vault, authorization service, sandbox,
  or model router.
- No Athena integration code lives in this repository. Athena exposes a
  separate [optional, disabled-by-default observer](https://github.com/JoaoPauloNA/athena)
  that preserves Moiras as advisory and fail-closed.
- Not a production or multi-tenant service. The broker and evidence lock are
  process-local; JSONL is not a multi-process ledger.
- Not a benchmark result. No real agents or models are called, and advisory
  output is never treated as ground truth.
- Not proof that an agent is alive or dead. The Sentinel reports only what two
  allowlisted snapshots support.

## License

MIT — see [LICENSE](LICENSE).
