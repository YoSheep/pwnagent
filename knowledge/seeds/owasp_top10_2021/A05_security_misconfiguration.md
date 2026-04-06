---
id: "A05_security_misconfiguration"
title: "A05:2021 - Security Misconfiguration"
source: "OWASP Top 10 2021"
source_url: "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"
version: "2021"
tags:
  - owasp
  - misconfiguration
  - hardening
---
# Security Misconfiguration

Security misconfiguration covers unsafe defaults, incomplete hardening, verbose error handling, unnecessary services, exposed administrative interfaces, and insecure cloud or framework settings. It is often the fastest path to compromise because the application already exposes a weakness without requiring a deep exploit chain.

## Typical attack paths

- Search for public `.git`, `.env`, backup archives, debug endpoints, and default admin panels.
- Check directory listing, Swagger or OpenAPI exposure, and sample files left in production.
- Trigger malformed requests to see whether stack traces, framework banners, or internal errors leak.
- Review CORS, CSP, cookie flags, and reverse proxy behavior for permissive defaults.

## Evidence and detection ideas

- Sensitive files are downloadable directly.
- Debug information reveals internal paths, framework versions, or credentials.
- Cloud storage, containers, or reverse proxies allow broad unauthenticated access.
- Admin or maintenance features are reachable from the public network.

## Remediation

- Build from a hardened baseline and remove unnecessary features, files, and services.
- Turn off debug mode and standardize safe production error handling.
- Review headers, cookie settings, CORS, and deployment templates as code.
- Automate configuration validation in CI/CD and infrastructure provisioning.
