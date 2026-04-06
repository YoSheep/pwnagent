---
id: "A10_server_side_request_forgery"
title: "A10:2021 - Server-Side Request Forgery (SSRF)"
source: "OWASP Top 10 2021"
source_url: "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/"
version: "2021"
tags:
  - owasp
  - ssrf
  - metadata
---
# Server-Side Request Forgery

SSRF exists when the application fetches attacker-controlled URLs or network locations on the server side without strict validation. It often becomes a pivot into internal services, cloud metadata endpoints, or administrative interfaces that are not reachable directly from the internet.

## Typical attack paths

- Identify URL-like parameters such as `url`, `callback`, `redirect`, `image`, `file`, or webhook fields.
- Try loopback, private network, and cloud metadata addresses and compare behavior.
- Look for open redirects or URL parsers that can be abused to bypass filters.
- Test whether alternate schemes, DNS rebinding, or redirects reach protected internal targets.

## Evidence and detection ideas

- Responses include cloud metadata, internal banners, or service-specific error messages.
- The server follows redirects into loopback or private ranges.
- Timeouts and response-size differences imply outbound requests to filtered targets.
- Request logs or DNS interactions show the application contacting attacker-controlled infrastructure.

## Remediation

- Apply strict allowlists for outbound destinations and protocols.
- Resolve and re-check hosts against private and link-local ranges after redirects and DNS resolution.
- Segment egress traffic so application servers cannot reach metadata or management networks by default.
- Prefer indirect fetch designs that avoid arbitrary user-supplied URLs when possible.
