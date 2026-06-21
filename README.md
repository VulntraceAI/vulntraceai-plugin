# VulntraceAI — plugin & CLI

**Evidence-gated vulnerability research, in your terminal.** No app, no account, no
upload. VulntraceAI drives **your own coding agent** (Claude Code / Codex) over a
repository, traces each candidate from **source to sink**, proves it with a **runnable
PoC**, and gates the advisory behind real validation. Your code never leaves your
machine.

Created by [Himanshu Gupta](https://github.com/r1zzg0d) · website
<https://vulntraceai.com> · 10 credited CVEs and counting.

This repo is two things in one:

1. A **Claude Code plugin** (a `/vulntrace` command + a `vuln-hunt` skill).
2. A standalone **CLI** that works in any shell with `node`.

---

## 1. Claude Code plugin

```text
/plugin marketplace add VulntraceAI/vulntraceai-plugin
/plugin install vulntraceai@vulntraceai
```

Then:

```text
/vulntrace                 # hunt the current directory
/vulntrace src/server      # hunt a subdirectory
/vulntrace ../some-repo    # hunt another local checkout
```

You can also just ask Claude to *"hunt this repo for exploitable vulnerabilities"* —
the bundled `vuln-hunt` skill applies the same discipline automatically.

## 2. CLI (any shell, no Claude Code)

Drives your own `claude` or `codex` CLI locally and writes the advisories + PoCs to
`vulntrace-out/`:

```bash
# zero install — runs straight from GitHub
npx github:VulntraceAI/vulntraceai-plugin ./your-repo

# or clone and run
git clone https://github.com/VulntraceAI/vulntraceai-plugin
node vulntraceai-plugin/cli/vulntrace.mjs ./your-repo --engine claude
```

```text
Usage: vulntrace <repo> [options]
  <repo>            local path or git URL to analyze
  -e, --engine X    claude | codex | builtin  (default: first agent on PATH)
  -r, --ref REF     git ref to check out (default: HEAD)
  -o, --out DIR     output directory (default: vulntrace-out)
```

The CLI is dependency-free (Node ≥ 18 stdlib only). With `claude`/`codex` on your
`PATH` it runs a full agent-driven analysis; otherwise it falls back to built-in
source→sink detectors.

## What you get

For each qualifying finding, a **CVE-grade advisory**: a metadata table, the annotated
source→sink code, a **negative control** (the sibling path that *is* guarded), a
non-destructive PoC bound to `127.0.0.1`, full CVSS v4.0 justification (chained + a
conservative floor), and a concrete remediation. For a hardened repo you get an honest
**zero-finding** result — never invented findings.

## The gate

A finding is a *candidate* until **you** run its PoC and observe the boundary crossing
(the negative control fails, the positive trigger succeeds). VulntraceAI never
auto-submits anything — you disclose, on your terms.

## Prefer a desktop app + browser workflow?

Download the VulntraceAI Companion at <https://vulntraceai.com/download>.

---

Apache-2.0. Methodology and tooling © Himanshu Gupta.
