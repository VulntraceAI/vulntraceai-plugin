# VulntraceAI — Claude Code plugin

Evidence-gated vulnerability research, right in your terminal. No Companion app, no
account, no upload — VulntraceAI drives **your own Claude** over a repository, traces
each candidate from **source to sink**, proves it with a **runnable PoC**, and gates
the advisory behind real validation. Your code never leaves your machine.

Created by [Himanshu Gupta](https://github.com/r1zzg0d) · <https://vulntraceai.com>

## Install

```text
/plugin marketplace add VulntraceAI/vulntraceai
/plugin install vulntraceai@vulntraceai
```

(Replace `VulntraceAI/vulntraceai` with whatever public repo hosts this marketplace.)

## Use

```text
/vulntrace                 # hunt the current directory
/vulntrace src/server      # hunt a subdirectory
/vulntrace ../some-repo    # hunt another local checkout
```

You can also just ask Claude to *"hunt this repo for exploitable vulnerabilities"* —
the bundled `vuln-hunt` skill applies the same discipline automatically.

## What you get

For each qualifying finding, a **CVE-grade advisory**: a metadata table, the annotated
source→sink code, a **negative control** (the sibling path that *is* guarded), a
non-destructive **PoC** that binds only to `127.0.0.1`, full CVSS v4.0 justification
(chained + a conservative floor), and a concrete remediation. For a hardened repo you
get an honest **zero-finding** result with the rationale — never invented findings.

## The gate

A finding is a *candidate* until **you** run its PoC and observe the boundary crossing
(the negative control fails, the positive trigger succeeds). VulntraceAI never
auto-submits anything — you disclose, on your terms.

## Prefer not to use Claude Code?

- **CLI:** run `node companion/cli.mjs <repo>` from the main repo to drive your local
  `claude` or `codex` over a repo and write the advisories + PoCs to `vulntrace-out/`.
- **Companion app + Workspace:** download the desktop Companion at
  <https://vulntraceai.com/download> for the browser-based gate workflow.

Apache-2.0.
