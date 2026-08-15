# Changelog

## 0.1.1 — 2026-08-15

- Hardened outbound sanitization for Unicode-normalized forbidden keys, known
  secret and credential shapes, and quoted or punctuated absolute paths.
- Fixed identifier handling so ordinary identifiers containing strings such as
  `task-`, `risk-`, or `disk-` are not mistaken for secret prefixes.
- Materialized iterable reason and mitigation codes once, preventing valid
  generators from being consumed during validation and serialized as empty.
- Made the offline gate reject an empty scenario sequence and require both
  `executed=false` and `mode=shadow` for every passing report.
- Added a negative invariant test for non-shadow `ShadowReport` values.
- Replaced the import-only execution-surface check with AST checks for ordinary,
  aliased and dynamic imports, dangerous calls, reflection and unapproved file
  access. The two deliberate writes remain narrowly allowlisted.
- Added an isolated runtime audit-hook test over the pure gate, supervision and
  synthetic-broker path. Process, network, dynamic-code and write events fail
  the test before the operation proceeds.
- Clarified that Athena integration is external, optional and disabled by
  default, and that Moiras never receives real authority.

Validation snapshot recorded on 2026-08-15: 380 tests passed in the reviewed
checkout. This number describes that checkout, not a permanent suite-size or
coverage guarantee. The 12-scenario offline gate is synthetic and is not a
safety benchmark.

Version 0.1.1 is published as a source tag. No PyPI package is claimed.

## Unpublished baseline — 0.1.0 shadow laboratory

- Added frozen, versioned contracts and fail-closed outbound sanitization.
- Added deterministic risk floors, hard stops, temporal Sentinel, and
  capable-only four-role council.
- Added a synthetic, one-use, short-TTL broker with no payload or authority.
- Added pure shadow supervision and categorical counterfactuals.
- Added three-level sanitized JSONL evidence and descriptive metrics that use
  only later human-review outcomes.
- Added a 12-scenario offline gate, English/Portuguese documentation, and
  GitHub/GitLab CI definitions for Python 3.10–3.12.

No public release, real-model evaluation, in-package Athena integration or
benchmark is claimed by this entry.
