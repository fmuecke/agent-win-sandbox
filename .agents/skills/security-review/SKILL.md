---
name: security-review
description: Review a security-sensitive change for trust-boundary, input, authorization, secret, data, execution, dependency, and failure risks.
---

# Security Review

Review the actual change and relevant call paths. Avoid checklist theatre.

1. Identify affected assets, trust boundaries, attacker-controlled inputs, and changed capabilities.
2. Trace untrusted input to sensitive operations and data.
3. Check only relevant risk areas, including:
   - authentication and authorization
   - command, code, query, template, and path injection
   - file access and traversal
   - network access, redirects, and SSRF
   - secrets and credential exposure
   - parsing, validation, and deserialization
   - data confidentiality and integrity
   - privileges, isolation, and sandbox boundaries
   - resource exhaustion, races, and unsafe failure modes
   - dependencies and supply-chain changes
   - logs, diagnostics, and privacy
4. Verify material risks with focused tests or available analysis tools where practical.
5. Prefer fixes that remove the dangerous capability or trust assumption over filters layered on top.

Report findings by severity with concrete evidence, impact, and the smallest sound fix. Distinguish confirmed findings from hypotheses.

If no issue is found, say so without claiming the code is "secure"; state the review scope and anything important that remained unverified.
