---
name: vuln-hunt
description: Evidence-gated vulnerability research. Use when the user asks to find, hunt, audit, or research exploitable security vulnerabilities (CVEs) in a codebase — trace source to sink, prove with a runnable PoC, and gate disclosure behind real validation. Also use when reviewing code for SSRF, path traversal, auth bypass, IDOR, SQLi, RCE, deserialization, SSTI, or command injection.
---

# VulntraceAI — evidence-gated vulnerability research

Apply this whenever the user wants to **find or validate exploitable
vulnerabilities** in a repository. It produces CVE-grade advisories with runnable
PoCs, entirely on the user's machine. For a full guided run, the user can invoke
the `/vulntrace` command; this skill applies the same discipline inline.

## Core principles

- **Trace, don't pattern-match.** A finding is real only when you have read every
  function from the attacker-controlled **source** to the dangerous **sink** and the
  sanitizers in between. Cite concrete `file:line` at each step.
- **Find the negative control.** The strongest evidence is the *sibling* code path
  that handles the same input correctly (calls the guard the vulnerable path skips).
  Always locate and quote it.
- **Cross a real boundary.** Only report unauth→auth, userA→userB, or user→admin.
  NOT self-harm (a user changing their own settings) and NOT an admin configuring
  their own system. Skip anything documented as intentional or admin-configurable.
- **Prefer High/Critical, CVSS v4.0 ≥ 4.0.** Race conditions needing pre-existing
  credentials are almost always Low — skip them.
- **An empty result is a valid, valuable answer.** For a hardened repo, report zero
  findings with a short rationale. Never invent or pad.

## The gate (the point of VulntraceAI)

A finding is a **candidate** until its PoC has actually been run and the boundary
crossing observed. Write the advisory + a non-destructive PoC (127.0.0.1 only, with a
negative control), then tell the user to validate it before disclosing. Offer to run
the PoC locally and show the real output. Never auto-submit anywhere — the user
discloses on their own terms.

## Report shape (per finding)

Metadata table (project, affected version, component file→function, CWE, severity,
chained + un-chained CVSS v4.0, who can exploit, boundary crossed, confidence) →
Summary → Affected Code (source/sink annotated) → Negative Control → Proof of Concept
(with negative control + observed output) → Impact → CVSS justification (per metric) →
Remediation (concrete fix + systemic fix) → Distinctness & Disclosure.

The full phase-by-phase methodology (Recon → Architecture → Intent → Advisories →
Attack surface → Deep analysis → Negative control → Impact chaining → Validate) lives
in the `/vulntrace` command in this plugin.
