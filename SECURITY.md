# Security policy

Moiras 0.1.1 is an alpha source release: a local, shadow-mode research library.
It is not a production authorization boundary.

## Reportable issues

Please use a private repository security advisory for:

- an API that can execute, authorize, cancel, or supply a credential;
- leakage of prompt, response, command, path, host, user, model identity, or
  secret through an allowlisted record or gate report;
- creation of `executed=true` or real authority through public contracts;
- bypass of a hard stop, edge-model exclusion, veto, or human-label boundary;
- capability replay producing more than one successful consumption.

Do not include real credentials, private work content, or personal paths in a
report. Use synthetic reproduction data.

The outbound sanitizer is defense in depth for typed, allowlisted records and
known sensitive shapes. It is not a universal detector for PII, secrets,
encoded data or novel credential formats. Passing arbitrary work content
through it does not make that content safe to store or publish.

Regression tests combine AST inspection with an isolated runtime audit hook for
the pure supervision path. Those tests narrow accidental execution surfaces;
they are not formal isolation, a sandbox, or permission to grant Moiras real
authority.

## Unsupported deployments

Production, network-facing, multi-tenant, multi-process, and privileged use are
unsupported. No security SLA or compatibility promise is offered while the
project remains alpha.
