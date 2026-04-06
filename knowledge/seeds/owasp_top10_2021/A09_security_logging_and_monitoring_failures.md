---
id: "A09_security_logging_and_monitoring_failures"
title: "A09:2021 - Security Logging and Monitoring Failures"
source: "OWASP Top 10 2021"
source_url: "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/"
version: "2021"
tags:
  - owasp
  - logging
  - monitoring
---
# Security Logging and Monitoring Failures

Security logging and monitoring failures make real attacks hard to detect, investigate, and contain. Even when prevention controls fail, strong telemetry can reduce dwell time and improve incident response. Weak or missing logs turn small security issues into long-running breaches.

## Typical attack paths

- Trigger authentication failures, suspicious parameter patterns, or privilege-sensitive actions and check whether they are logged.
- Review whether alerts exist for brute force, access control failures, or scanner-like traffic.
- Verify time synchronization and traceability across application, proxy, and backend logs.
- Check whether security events are retained long enough and protected from tampering.

## Evidence and detection ideas

- Critical actions are missing from logs or lack user, source, and request context.
- Alerts are absent for repeated failed logins, privilege changes, or exploitation attempts.
- Logs are stored locally only and can be modified by the compromised service.
- Incident responders cannot reconstruct an attack timeline from available telemetry.

## Remediation

- Log authentication, authorization, administrative actions, and high-risk input validation failures.
- Centralize logs and alerts in systems that support retention, correlation, and integrity controls.
- Synchronize clocks and include stable request identifiers for cross-system tracing.
- Regularly test detections against realistic attack behaviors instead of assuming telemetry is sufficient.
