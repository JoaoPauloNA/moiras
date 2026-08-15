# Contributing

Contributions are welcome when they preserve the shadow-only boundary.

## Local gate

```bash
python -m pip install -e ".[dev]"
ruff check .
pytest
python -m moiras
```

Every policy change needs boundary tests, not only a happy path. Include cases
for malformed values, privacy, ordering, replay/concurrency when applicable,
and a fail-closed result.

## Non-negotiable constraints

- no execution, authorization, cancellation, CLI confirmation, credential
  handling, live model call, or network call;
- no `EDGE`/`UNKNOWN` model in validation or council coverage;
- no free-text rationale or work content in contracts/evidence;
- no advisory result used as a human outcome;
- no production, benchmark, paper, or safety-certification claim without a
  separate reviewed evidence package;
- no new runtime dependency without explicit design review.

Keep commits focused and update the protocol/threat model when a trust boundary
changes.
