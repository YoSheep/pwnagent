---
id: "A04_insecure_design"
title: "A04:2021 - Insecure Design"
source: "OWASP Top 10 2021"
source_url: "https://owasp.org/Top10/A04_2021-Insecure_Design/"
version: "2021"
tags:
  - owasp
  - design
  - threat-modeling
---
# Insecure Design

Insecure design is not a single bug class. It is a structural weakness created when the product lacks abuse-case thinking, security requirements, or safe defaults. Even perfect code cannot fully protect a workflow that was designed without adversarial assumptions.

## Typical attack paths

- Examine business flows for missing approval steps, unsafe fallbacks, and privilege boundaries that exist only in the UI.
- Look for password reset, invite, checkout, and file-sharing workflows that trust user-controlled state.
- Test whether rate limits, lockouts, or anti-automation controls are absent on sensitive features.
- Evaluate multi-step workflows for state confusion, race conditions, or skipped validations.

## Evidence and detection ideas

- A feature is working as implemented, but the implementation itself is unsafe.
- Abuse cases succeed without exploiting a parser, library, or memory-safety bug.
- Security controls are bolted on after the fact and are easy to bypass by changing flow order.
- Tenant, role, or trust boundaries are not reflected in the domain model.

## Remediation

- Add threat modeling and abuse-case review during design, not only during testing.
- Define security requirements for identity, authorization, workflow integrity, and anti-automation controls.
- Prefer secure-by-default workflows with explicit approvals for dangerous operations.
- Validate assumptions with architecture review, misuse-case testing, and production telemetry.
