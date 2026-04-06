---
id: "A03_injection"
title: "A03:2021 - Injection"
source: "OWASP Top 10 2021"
source_url: "https://owasp.org/Top10/A03_2021-Injection/"
version: "2021"
tags:
  - owasp
  - injection
  - sqli
---
# Injection

Injection flaws appear when untrusted input reaches an interpreter or query engine without strict separation between code and data. Common examples include SQL injection, NoSQL injection, OS command injection, LDAP injection, and expression injection in template or search systems.

## Typical attack paths

- Add a quote, parenthesis, or special operator to a parameter and look for parser errors.
- Compare boolean conditions such as `1 OR 1=1` versus `1 OR 1=2` and watch for response differences.
- Test whether user-controlled data is concatenated into shell commands, filters, or template expressions.
- Probe search endpoints, report exports, and backend automation hooks that pass user input to external commands.

## Evidence and detection ideas

- Database or interpreter errors leak into the response.
- Response length, status code, or timing changes in ways that imply query manipulation.
- Inputs influence command output, file paths, or server-side expressions.
- Security logs show syntax errors or failed parser operations tied to attacker-controlled input.

## Remediation

- Use parameterized queries and safe ORM APIs instead of string concatenation.
- Apply allowlists and strong input validation for commands, identifiers, and templates.
- Escape output only when escaping is the correct control for the target context.
- Run backend services with the minimum privilege needed so a successful injection has reduced impact.
