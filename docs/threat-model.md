# Moiras threat model

Scope: v0.1 shadow laboratory, milestones M0–M9.

## Assets and invariants

1. A recommendation must never be represented as an executed action.
2. Hard-stop risk must never be lowered by averaging or council consensus.
3. Edge/unknown models must never satisfy council coverage.
4. Work content and identifying machine data must not enter evidence records.
5. Advisory output must not become ground truth without later human review.
6. A synthetic capability must never carry real authority or a secret value.

## Trust boundaries

- **Caller → contracts:** untrusted values are accepted only through frozen,
  validated dataclasses and enums.
- **Snapshots → Sentinel:** snapshot producers are trusted only to provide the
  declared counters; Moiras detects ordering/identity violations, not forged
  telemetry.
- **Opinions → council:** model capability class is caller-declared. Moiras can
  enforce eligibility and panel shape but cannot attest model identity.
- **Contracts → JSONL:** every record uses explicit serialization and recursive
  sanitization before append.
- **Human review → outcome:** the enum records the declared source; this local
  library cannot authenticate the human or the review procedure.
- **CLI path → filesystem:** the user explicitly selects a report destination;
  the path stays outside the report. Filesystem access control remains an OS
  responsibility.

## Mitigated within this repository

| Threat | Mitigation |
| --- | --- |
| malformed scores/enums/IDs | frozen contracts, finite bounds, strict enums |
| secret/path-shaped outbound content | forbidden keys, normalized IDs, secret/path detection, explicit `to_dict` |
| false inactivity during a declared wait | wait/block precedence over inactivity |
| counter regression or unrelated snapshots | comparison rejects regression, order, and identity mismatch |
| risk dilution | maximum aggregation and hard-stop short circuit |
| weak/edge reviewer admitted | any `EDGE`/`UNKNOWN` opinion invalidates panel |
| veto hidden by majority | one veto forces human review |
| split council hidden by average | divergence greater than 3 forces human review |
| recommendation self-labels as success | metrics require strictly later `HUMAN_REVIEW` outcome |
| conflicting labels silently selected | conflict/indeterminate becomes ambiguous and leaves denominator |
| synthetic capability replay | lock, TTL, terminal states, single successful consumption |
| capability mistaken for authority | no payload; `synthetic=true`; `authorizes_real_action=false` |
| exception leaks in gate | exceptions become boolean scenario failure; message is not serialized |

## Explicit non-goals

- Process isolation, sandboxing, lifecycle ownership, cancellation, fallback,
  workspace locking, or remote termination.
- Real model selection, invocation, identity attestation, or council quality.
- Real credentials, sudo, authorization prompts, secret storage, or privileged
  action execution.
- Network service, multi-tenant deployment, multi-process broker, or durable
  ledger.
- Proof that an agent is alive/dead or that an action is safe.
- Benchmark, calibrated risk probability, formal verification, or certified
  governance compliance.

## Residual risks

Risk floors and score bands are judgment calls that need empirical calibration.
Snapshot producers can lie while preserving schema. Capability classes and
human-review sources are declared, not cryptographically attested. The
sanitizer recognizes known shapes but cannot prove absence of all encoded or
novel secrets. JSONL can be truncated, reordered, or modified by another
process. Intraprocess locks do not protect multiple workers or hosts.

Any future Athena adapter must therefore remain optional and fail-closed:
Moiras may add an advisory signal, but its absence, failure, or disagreement
must not weaken Athena's deterministic lifecycle and safety gates.
