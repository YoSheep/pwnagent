---
id: "A08_software_and_data_integrity_failures"
title: "A08:2021 - Software and Data Integrity Failures"
source: "OWASP Top 10 2021"
source_url: "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/"
version: "2021"
tags:
  - owasp
  - integrity
  - ci-cd
---
# Software and Data Integrity Failures

Software and data integrity failures appear when applications trust code, packages, updates, CI/CD pipelines, or serialized data without verifying authenticity and integrity. The modern supply-chain threat model makes this category especially important because compromise can happen before a request ever reaches the app.

## Typical attack paths

- Review package, plugin, and image download paths for missing signature or checksum validation.
- Inspect CI/CD automation for secrets exposure, unsafe runners, and unreviewed deployment paths.
- Test whether insecure deserialization or signed object handling can be abused.
- Look at webhooks, auto-update channels, and extension systems that trust external data implicitly.

## Evidence and detection ideas

- Build or deployment artifacts are accepted from untrusted sources.
- Pipelines can be modified without proper review or environment isolation.
- Serialized objects are processed without integrity protection.
- Dependency pinning, provenance, or checksum validation is absent.

## Remediation

- Require trusted package sources, pinned versions, and checksum or signature verification.
- Harden CI/CD with least privilege, branch protections, and isolated runners.
- Avoid unsafe deserialization patterns and verify signed data correctly.
- Treat build pipelines and update paths as high-value production assets.
