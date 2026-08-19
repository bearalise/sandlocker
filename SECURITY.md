# Security Policy

Security is SandLocker's first-order requirement — the product exists to execute untrusted code,
and we hold our own security to the strictest standard.

## Reporting a vulnerability

**Please do not report security vulnerabilities through public issues.**

Report privately through one of:

- GitHub Private Vulnerability Reporting (repository **Security** tab → "Report a vulnerability").
- Email: security@sandlocker.dev (domain pending registration; until then, please use the GitHub
  channel).

Please include, where possible: affected version, reproduction steps, and potential impact. We aim
to **acknowledge receipt within 48 hours**.

## Response targets

| Severity | Acknowledge | Fix target |
| --- | --- | --- |
| High (isolation escape, unauthorized access) | 48h | ≤ 7 days |
| Medium | 48h | ≤ 30 days |
| Low | within a week | in a regular release |

Once a fix ships, we credit the reporter in the release notes (unless you ask to remain anonymous).
We will not pursue legal action against good-faith security research.

## Scope

- Sandbox isolation boundary (microVM / guest agent / snapshot & network stack) — highest priority.
- Control plane (API authentication, quotas, audit).
- Supply chain (release artifact signing, SBOM, kernel images).

**Out of scope:** consequences of the sandboxed code a user chooses to run (that is exactly what the
sandbox is meant to contain); residual risks explicitly accepted in the threat model.

## Threat model

The threat model is maintained alongside releases. See the PRD (§8.2, under `docs/design/`) and the
dedicated documents under `docs/security/` as they land.
