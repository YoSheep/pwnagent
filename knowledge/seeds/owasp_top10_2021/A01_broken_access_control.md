---
id: "A01_broken_access_control"
title: "A01:2021 - Broken Access Control"
source: "OWASP Top 10 2021"
source_url: "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"
version: "2021"
tags:
  - owasp
  - access-control
  - idor
---
# Broken Access Control

Broken access control happens when the server does not reliably enforce who is allowed to do what. It commonly appears as insecure direct object references, privilege escalation between users, missing server-side checks on administrative routes, and weak tenant isolation in APIs.

## Typical attack paths

- Change object identifiers such as `user_id`, `account_id`, `invoice_id`, or tenant IDs and check whether another user's data becomes accessible.
- Request routes like `/admin`, `/internal`, or management APIs without the required role.
- Replay privileged actions with a low-privilege session and compare responses.
- Test `PUT`, `PATCH`, and `DELETE` on resources that are only guarded in the frontend.

## Evidence and detection ideas

- Response data belongs to another user or tenant.
- Access is denied in the UI but accepted by direct HTTP requests.
- Different accounts can access the same object by modifying one parameter.
- CORS or cache behavior exposes resources across trust boundaries.

## Remediation

- Enforce authorization checks on the server for every object access and state-changing action.
- Use deny-by-default rules and centralize access control decisions where possible.
- Avoid trusting identifiers supplied by the client without ownership checks.
- Add audit logging for denied access attempts and privilege-sensitive operations.
