---
id: "A02_cryptographic_failures"
title: "A02:2021 - Cryptographic Failures"
source: "OWASP Top 10 2021"
source_url: "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"
version: "2021"
tags:
  - owasp
  - crypto
  - tls
---
# Cryptographic Failures

Cryptographic failures cover weak or missing protection for sensitive data in transit, at rest, or during processing. The risk is often caused by plaintext transport, weak password hashing, outdated ciphers, misconfigured TLS, predictable secrets, or keys that are exposed in code and deployment artifacts.

## Typical attack paths

- Inspect whether credentials, cookies, and API tokens travel over HTTP instead of HTTPS.
- Look for weak password storage patterns such as MD5, SHA-1, or reversible encryption.
- Search repositories, logs, backups, and environment files for hard-coded keys.
- Check for missing HSTS, expired certificates, or insecure TLS versions and cipher suites.

## Evidence and detection ideas

- Secrets appear in `.env`, backups, source code, or JavaScript bundles.
- Password hashes match weak one-way functions without salting.
- Sensitive fields are readable in responses, logs, or client-side storage.
- TLS scanners report deprecated protocol versions or cipher suites.

## Remediation

- Enforce HTTPS everywhere and enable HSTS where appropriate.
- Use modern password hashing such as Argon2id, scrypt, or bcrypt with proper cost factors.
- Centralize key management and rotate compromised secrets immediately.
- Minimize sensitive data retention and encrypt data at rest when business requirements demand it.
