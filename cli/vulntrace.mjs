#!/usr/bin/env node
// VulntraceAI CLI — one-shot vulnerability hunt in your terminal, no Companion app,
// no relay, no account. Drives your own `claude` or `codex` over a repo using the
// same engine as the Companion, then writes CVE-grade advisories + runnable PoCs to
// disk. Your code never leaves your machine.
//
//   node cli/vulntrace.mjs <repo>            # repo = local path or git URL
//   node cli/vulntrace.mjs <repo> --engine codex --ref v1.2.3 --out ./out
//
import { runScan } from "./scanner.mjs";
import { detectLLMs } from "./llm.mjs";
import { mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import crypto from "node:crypto";

const C = { dim: (s) => `\x1b[2m${s}\x1b[0m`, b: (s) => `\x1b[1m${s}\x1b[0m`, g: (s) => `\x1b[32m${s}\x1b[0m`, y: (s) => `\x1b[33m${s}\x1b[0m`, c: (s) => `\x1b[36m${s}\x1b[0m` };

function parseArgs(argv) {
  const out = { repo: "", ref: "HEAD", engine: undefined, out: "vulntrace-out" };
  const rest = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--engine" || a === "-e") out.engine = String(argv[++i] || "").toLowerCase();
    else if (a === "--ref" || a === "-r") out.ref = String(argv[++i] || "HEAD");
    else if (a === "--out" || a === "-o") out.out = String(argv[++i] || "vulntrace-out");
    else if (a === "--help" || a === "-h") out.help = true;
    else rest.push(a);
  }
  out.repo = rest[0] || "";
  return out;
}

function usage() {
  process.stdout.write(
    `\n${C.b("VulntraceAI CLI")} — evidence-gated vulnerability research in your terminal\n\n` +
    `${C.b("Usage:")} node cli/vulntrace.mjs <repo> [options]\n\n` +
    `  <repo>            local path or git URL to analyze\n` +
    `  -e, --engine X    claude | codex | builtin  (default: first agent on PATH)\n` +
    `  -r, --ref REF     git ref to check out (default: HEAD)\n` +
    `  -o, --out DIR     output directory (default: vulntrace-out)\n` +
    `  -h, --help        this help\n\n` +
    `${C.b("Examples:")}\n` +
    `  node cli/vulntrace.mjs ./my-service\n` +
    `  node cli/vulntrace.mjs https://github.com/owner/repo --engine claude\n\n` +
    `Drives your OWN ${C.b("claude")}/${C.b("codex")} CLI locally. Your code never leaves the machine.\n\n`,
  );
}

const slug = (s) => String(s || "finding").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 60);

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.help || !opts.repo) {
    usage();
    process.exit(opts.help ? 0 : 1);
  }

  // Resolve the engine: explicit --engine wins; otherwise the first installed agent.
  const installed = (() => { try { return detectLLMs(); } catch { return []; } })();
  let engine = opts.engine;
  if (engine === "builtin") engine = "";
  else if (!engine) engine = installed[0] || "";
  else if (!installed.includes(engine)) {
    process.stdout.write(C.y(`\n! '${engine}' not found on PATH`) + C.dim(` (detected: ${installed.join(", ") || "none"}). `) + `Falling back to built-in detectors.\n`);
    engine = "";
  }

  const label = engine === "claude" ? "Claude Code" : engine === "codex" ? "Codex" : "built-in detectors";
  process.stdout.write(`\n${C.b("VulntraceAI")} · engine: ${C.c(label)} · target: ${C.c(opts.repo)} @ ${opts.ref}\n${C.dim("─".repeat(60))}\n`);

  const findings = [];
  const emit = (e) => {
    if (e.type === "phase") process.stdout.write(`\n${C.b(`▸ ${e.name}`)}\n`);
    else if (e.type === "log") process.stdout.write(`  ${C.dim("·")} ${e.line}\n`);
    else if (e.type === "error") process.stdout.write(C.y(`  ! ${e.message}\n`));
    else if (e.type === "finding") findings.push(e.finding);
  };

  const scanId = "cli_" + crypto.randomBytes(4).toString("hex");
  let result;
  try {
    result = await runScan(scanId, { repo: opts.repo, ref: opts.ref, llm: engine }, emit, () => false);
  } catch (err) {
    process.stdout.write(C.y(`\nscan failed: ${String((err && err.message) || err)}\n`));
    process.exit(1);
  }

  process.stdout.write(`\n${C.dim("─".repeat(60))}\n`);
  if (!findings.length) {
    process.stdout.write(`${C.g("✓")} ${C.b("No qualifying findings.")} ` + C.dim("For a hardened repo this is the correct answer.\n\n"));
    process.exit(0);
  }

  // Write each finding's advisory + PoC to disk.
  const outDir = path.resolve(opts.out);
  mkdirSync(outDir, { recursive: true });
  const index = [];
  for (const f of findings) {
    const name = `${slug(f.severity)}-${slug(f.title)}`;
    const dir = path.join(outDir, name);
    mkdirSync(dir, { recursive: true });
    if (f.report) writeFileSync(path.join(dir, "report.md"), f.report);
    if (f.poc) {
      const isPy = /^\s*#!.*python|^\s*import \w|^\s*from \w+ import/m.test(f.poc);
      writeFileSync(path.join(dir, isPy ? "poc.py" : "poc.sh"), f.poc);
    }
    index.push({ name, title: f.title, severity: f.severity, cvss: f.cvss || "", file: f.file, line: f.line, confidence: f.confidence });
    const sev = String(f.severity || "").toUpperCase();
    process.stdout.write(`  ${C.b(sev.padEnd(8))} ${f.title} ${C.dim(`(${f.file}:${f.line}, conf ${f.confidence})`)}\n`);
  }
  writeFileSync(path.join(outDir, "findings.json"), JSON.stringify(index, null, 2));

  process.stdout.write(
    `\n${C.b(`${findings.length} candidate finding(s)`)} written to ${C.c(outDir)}/\n\n` +
    `${C.y("⚠ The gate:")} these are CANDIDATES. Run each ${C.b("poc.sh")}/${C.b("poc.py")} yourself and\n` +
    `  confirm the negative control fails and the positive trigger crosses the boundary\n` +
    `  BEFORE you disclose. VulntraceAI never auto-submits — you disclose, on your terms.\n\n`,
  );
  process.exit(0);
}

main();
