---
id: "A06_vulnerable_and_outdated_components"
title: "A06:2021 - Vulnerable and Outdated Components"
source: "OWASP Top 10 2021"
source_url: "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/"
version: "2021"
tags:
  - owasp
  - components
  - cve
---
# Vulnerable and Outdated Components

Applications inherit risk from libraries, frameworks, containers, operating systems, and third-party services. If a component is unpatched or unsupported, attackers can often map the exposed version to known CVEs and use public exploit material with minimal customization.

## Typical attack paths

- Fingerprint framework, server, and plugin versions through headers, static assets, and known files.
- Compare discovered versions against public advisories and vendor bulletins.
- Check whether end-of-life software remains exposed to the internet.
- Test whether vulnerable plugins or extensions are installed even if they are rarely used.

## Evidence and detection ideas

- Version strings match vulnerable releases or unsupported branches.
- Components are present but patch history or inventory is unclear.
- Security scanners identify known CVEs for public-facing software.
- Asset inventories differ between code, containers, and running services.

## Remediation

- Maintain a current SBOM or component inventory for application and infrastructure dependencies.
- Patch internet-facing and privilege-bearing components first.
- Remove unused plugins, packages, and images from deployments.
- Track vendor support windows and replace abandoned dependencies early.
