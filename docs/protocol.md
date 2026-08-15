# Moiras shadow protocol

Status: v0.1 laboratory contract, milestones M0–M9. The protocol is
advisory-only and independent from Athena.

## Authority boundary

Moiras receives typed, allowlisted data and returns typed, allowlisted data.
It has no executor callback, process handle, CLI adapter, model client,
credential provider, network client, or cancellation primitive. `executed` is
structurally fixed to `false`; `mode` is fixed to `shadow`.

Athena remains responsible for its own deterministic lifecycle, cancellation,
termination confirmation, workspace lease, and fallback gates. Its optional
observer adapter lives in the Athena repository; no adapter or Athena control
logic is implemented here.

## 1. Temporal observation

`compare_snapshots(first, second, idle_threshold_s)` requires identical
execution, attempt, and profile identifiers; non-decreasing UTC/monotonic time;
and non-decreasing progress, activity, and artifact counters. Its precedence is:

1. `REAL_PROGRESS`: progress/artifact increased or execution became terminal;
2. `EXTERNAL_BLOCK`;
3. `LEGITIMATE_WAIT`: approval or protected-input wait;
4. `ACTIVITY_WITHOUT_PROGRESS`;
5. `PROBABLE_INACTIVITY`: no activity/progress for the configured interval;
6. `INDETERMINATE`.

The result is a classification with evidence codes, never a timeout or cancel
request. In particular, `PROBABLE_INACTIVITY` is not proof of termination.

## 2. Deterministic risk baseline

`assess(ActionRequest)` computes the maximum of the action-type floor and five
dimensions: reversibility, scope, environment, sensitive data, and external
exposure. Scores are not averaged.

| Policy band | Shadow interpretation |
| --- | --- |
| 10 / hard stop | council bypassed; stop for human decision |
| 7–9 | human required |
| 4–6 | mitigate and reassess |
| 0–3 | candidate only when the environment is disposable |

Hard stops are broad deletion, database delete/drop, sudo, credential request,
and privileged-user creation. A temporary-file creation reaches zero only for
the exact disposable, reversible, single-scope, non-sensitive, non-external
combination. These values are policy hypotheses, not calibrated probabilities.

## 3. Council protocol

The caller injects exactly four `CouncilOpinion` values, one per role:
security, integrity, governance, and operations. This package never calls the
models that produced them.

- Only `FRONTIER` and `CAPABLE_GENERAL` are eligible.
- Any `EDGE` or `UNKNOWN` opinion invalidates the complete panel.
- Missing or duplicate roles require a human.
- Any veto requires a human.
- Risk-score divergence greater than 3 requires a human.
- The final score is the maximum of baseline and opinions.
- A low score is only a `SHADOW_AUTOAPPROVE_CANDIDATE`, never approval.

Reasons and mitigations are enums. Free-text rationale is deliberately absent.

## 4. Shadow supervisor

`supervise` composes the baseline, optional Sentinel comparison, and council.
It maps the council verdict to an inert recommendation and a categorical
counterfactual. A counterfactual describes which separate gate would be needed;
it does not invoke that gate. The public signature has no callback, tool,
provider, broker, or execution parameter.

## 5. Synthetic capability broker

`SyntheticCapabilityBroker` is an in-memory experiment for a future separation
between evaluation and authority. It mints only for a shadow candidate, with a
TTL in `(0, 60]` seconds. Capabilities are synthetic, process-local, atomic
within one process, and single-use. Consumption returns only `CONSUMED`,
`EXPIRED`, `ALREADY_CONSUMED`, or `UNKNOWN`.

There is no payload or secret value. `authorizes_real_action` is fixed to
`false`. Consuming a capability performs no action. The broker is not a
credential architecture and must not be adapted into one without a new threat
model and human gate.

## 6. Evidence methodology

`EvidenceRecord` has three mutually exclusive levels:

- `OBSERVATION`: a Sentinel category;
- `RECOMMENDATION`: categorical action type, risk score, and recommendation;
- `HUMAN_OUTCOME`: later `SAFE`, `UNSAFE`, or `INDETERMINATE` with mandatory
  source `HUMAN_REVIEW`.

Records omit prompt, response, command, file path, host, user, process ID,
environment variables, reviewer/model identity, rationale, and credentials.
The destination path belongs to the recorder and is never serialized.

Metrics correlate `(execution_id, attempt_id)` only. The latest recommendation
must be a shadow candidate, and a human outcome must be strictly later. Equal
duplicate labels are tolerated; conflicting or indeterminate labels are marked
ambiguous and excluded from the unsafe-rate denominator. A recommendation is
never converted into its own label. The resulting coverage and unsafe-candidate
rate are descriptive research signals, not accuracy, precision, certification,
or a benchmark.

The JSONL lock is intraprocess only. Multi-process integrity, retention,
signatures, access control, and deletion policy are outside v0.1.

## 7. Offline gate

`python -m moiras` runs 12 fixed synthetic scenarios. It performs no model,
network, subprocess, or real-action call. The report contains only schema,
Python major/minor, generic platform family, scenario identifiers, booleans,
and counts. `--json PATH` writes the same sanitized object without serializing
or printing the path.

Passing the gate means that these fixtures match the encoded policy. It does
not validate real-world safety or publication readiness.
