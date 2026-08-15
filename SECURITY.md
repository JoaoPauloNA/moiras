# Security policy

Moiras v0.1 is an alpha, local, shadow-mode research library. It is not a
production authorization boundary.

## Reportable issues

Please use a private security advisory after the repository is published for:

- an API that can execute, authorize, cancel, or supply a credential;
- leakage of prompt, response, command, path, host, user, model identity, or
  secret through an allowlisted record or gate report;
- creation of `executed=true` or real authority through public contracts;
- bypass of a hard stop, edge-model exclusion, veto, or human-label boundary;
- capability replay producing more than one successful consumption.

Do not include real credentials, private work content, or personal paths in a
report. Use synthetic reproduction data.

## Unsupported deployments

Production, network-facing, multi-tenant, multi-process, and privileged use are
unsupported. No security SLA or compatibility promise is offered while the
project remains alpha.
