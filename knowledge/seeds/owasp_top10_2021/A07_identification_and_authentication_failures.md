---
id: "A07_identification_and_authentication_failures"
title: "A07:2021 - Identification and Authentication Failures"
source: "OWASP Top 10 2021"
source_url: "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"
version: "2021"
tags:
  - owasp
  - authentication
  - session
---
# Identification and Authentication Failures

Identification and authentication failures happen when the application cannot reliably prove who the user is, preserve session integrity, or protect authentication workflows from abuse. Weak password reset logic, session fixation, missing MFA, and predictable tokens are common examples.

## Typical attack paths

- Test for weak password policies, credential stuffing resistance, and absent MFA on sensitive roles.
- Check whether reset links, magic links, or OTP flows can be replayed or brute-forced.
- Observe whether session cookies rotate after login, logout, and privilege changes.
- Look for user enumeration through login, registration, and password reset responses.

## Evidence and detection ideas

- Session identifiers remain valid after logout or privilege escalation.
- Password reset tokens are predictable, long-lived, or not bound to the user.
- Login responses reveal whether a username exists.
- Multi-factor requirements can be bypassed by alternate endpoints or race conditions.

## Remediation

- Implement strong session lifecycle controls and rotate tokens after authentication events.
- Enforce MFA on privileged access and high-risk operations.
- Protect authentication flows with rate limiting, lockouts, and anomaly detection.
- Standardize user-facing messages to reduce enumeration signals.
