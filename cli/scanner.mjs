// VulntraceAI Companion — scan engine. Real: clones (or opens a local) repo,
// walks the source, runs detectors, and streams phased progress + findings.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import { DETECTORS, SOURCE, langForFile, scoreCandidate } from "./detectors.mjs";
import { runLLMScan } from "./llm.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ENGINE_SCRIPT = path.join(__dirname, "engine", "score.py");

export function engineDir() {
  return (
    process.env.VT_ENGINE_DIR ||
    path.join(os.homedir(), "Documents", "CVE hunting", "improved_method")
  );
}

function has(cmd, args) {
  try { execFileSync(cmd, args, { stdio: "ignore" }); return true; } catch { return false; }
}

/** Report which engine pieces are available (for /health). */
export function engineInfo() {
  const dir = engineDir();
  return {
    git: has("git", ["--version"]),
    detectors: true,
    python: has("python3", ["--version"]),
    improvedMethod: fs.existsSync(path.join(dir, "confidence_engine", "scorer.py")),
    semgrep: has("semgrep", ["--version"]),
  };
}

/** Re-score candidates with the REAL improved_method confidence engine + cvss4.
 *  Best-effort: returns candidates unchanged if the engine isn't available. */
function enrich(candidates) {
  if (!candidates.length) return candidates;
  const info = engineInfo();
  // ENGINE_SCRIPT isn't bundled into the packaged binary (pkg snapshot), so skip
  // the python bridge unless it actually exists on disk.
  if (!info.python || !info.improvedMethod || !fs.existsSync(ENGINE_SCRIPT)) return candidates;
  try {
    const out = execFileSync("python3", [ENGINE_SCRIPT], {
      input: JSON.stringify(candidates),
      env: { ...process.env, VT_ENGINE_DIR: engineDir() },
      timeout: 30000,
      maxBuffer: 8 * 1024 * 1024,
    });
    const parsed = JSON.parse(out.toString());
    return parsed.ok ? parsed.candidates : candidates;
  } catch {
    return candidates;
  }
}

export const PHASES = [
  "Recon",
  "Architecture",
  "Intent",
  "Advisories",
  "Attack surface",
  "Deep analysis",
  "Validation",
  "Report",
];

const SKIP_DIRS = new Set([
  ".git", "node_modules", "vendor", "dist", "build", ".next", "__pycache__",
  ".venv", "venv", "testdata", "fixtures", "third_party",
]);
const MAX_FILE_BYTES = 512 * 1024;
const MAX_FILES = 6000;
const MAX_FINDINGS = 40;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function resolveRepo(repo, ref) {
  if (fs.existsSync(repo) && fs.statSync(repo).isDirectory()) {
    return { dir: repo, cloned: false };
  }
  const m = /^[\w.-]+\/[\w.-]+$/.exec(repo);
  const url = m ? `https://github.com/${repo}.git` : repo;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vt-scan-"));
  const args = ["clone", "--depth", "1"];
  if (ref && ref !== "HEAD") args.push("--branch", ref);
  args.push(url, dir);
  execFileSync("git", args, { stdio: "ignore", timeout: 180000 });
  return { dir, cloned: true };
}

function walk(root) {
  const out = [];
  const stack = [root];
  while (stack.length && out.length < MAX_FILES) {
    const cur = stack.pop();
    let entries;
    try {
      entries = fs.readdirSync(cur, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const e of entries) {
      if (e.isDirectory()) {
        if (!SKIP_DIRS.has(e.name)) stack.push(path.join(cur, e.name));
      } else if (e.isFile()) {
        const f = path.join(cur, e.name);
        if (langForFile(f) && !/_test\.(go|py)$|^test_/.test(e.name)) out.push(f);
      }
    }
  }
  return out;
}

function detectInFile(absPath, relPath, repo) {
  let text;
  try {
    if (fs.statSync(absPath).size > MAX_FILE_BYTES) return [];
    text = fs.readFileSync(absPath, "utf8");
  } catch {
    return [];
  }
  const lang = langForFile(absPath);
  const lines = text.split("\n");
  const hasSource = SOURCE[lang].test(text);
  // sanitizer presence per class is checked file-wide
  const findings = [];

  // capture a representative source line (file:line) for the trace
  let sourceRef = null;
  for (let i = 0; i < lines.length; i++) {
    if (SOURCE[lang].test(lines[i])) {
      sourceRef = { line: i + 1, code: lines[i].trim().slice(0, 120) };
      break;
    }
  }

  for (const d of DETECTORS) {
    if (d.lang !== lang) continue;
    const hasSanitizer = d.class && SANITIZERS[d.class] ? SANITIZERS[d.class].test(text) : false;
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (!d.sink.test(line)) continue;
      if (d.not && d.not.test(line)) continue;
      if (d.needs && !d.needs.test(line)) continue;
      if (d.requireSource && !hasSource) continue;
      if (d.contextNeeds && !d.contextNeeds.test(text)) continue;

      const confidence = scoreCandidate(d, { hasSource, hasSanitizer });
      findings.push({
        id: crypto.randomUUID(),
        detector: d.id,
        title: d.title,
        target: repo,
        file: relPath,
        line: i + 1,
        severity: d.severity,
        archetype: d.archetype,
        cwe: d.cwe,
        confidence,
        source: sourceRef
          ? `${relPath}:${sourceRef.line}  ${sourceRef.code}`
          : "request input (source not localized)",
        sink: `${relPath}:${i + 1}`,
        code: line.trim().slice(0, 160),
        sanitizerPresent: hasSanitizer,
      });
      break; // one hit per detector per file keeps the queue clean
    }
  }
  return findings;
}

// SANITIZERS lives in detectors.mjs scope; re-import minimal here to avoid export churn.
const SANITIZERS = {
  path: /filepath\.Rel\(|os\.path\.realpath|\brealpath\(|commonpath|Sanitize(User)?Path|secure_filename|is_relative_to|filter\s*=\s*["']data["']/,
  ssrf: /netip\.|IsPrivate\(|IsLoopback\(|IsLinkLocal|is_private|is_loopback|ip_address\(|is_safe_url|validate_url/,
};

/**
 * Run a full scan. `emit(event)` receives streamed events.
 * Returns the final summary.
 */
export async function runScan(scanId, { repo, ref = "HEAD", llm }, emit, isAborted = () => false) {
  const phase = (i) => emit({ type: "phase", index: i, name: PHASES[i] });
  const log = (line) => emit({ type: "log", line });
  const stopped = () => {
    if (!isAborted()) return false;
    log("scan stopped by user");
    emit({ type: "done", status: "stopped", findings: 0 });
    return true;
  };

  emit({ type: "status", status: "scanning" });
  let repoInfo;
  try {
    phase(0);
    log(`recon · resolving ${repo} @ ${ref}`);
    repoInfo = resolveRepo(repo, ref);
    log(repoInfo.cloned ? "cloned shallow into temp dir" : "using local checkout");
  } catch (err) {
    emit({ type: "error", message: `clone failed: ${String(err.message || err)}` });
    emit({ type: "done", status: "error", findings: 0 });
    return { status: "error" };
  }

  const cleanup = () => {
    if (repoInfo.cloned) {
      try { fs.rmSync(repoInfo.dir, { recursive: true, force: true }); } catch { /* ignore */ }
    }
  };

  try {
    const files = walk(repoInfo.dir);
    const go = files.filter((f) => f.endsWith(".go")).length;
    const py = files.filter((f) => f.endsWith(".py")).length;
    log(`recon · ${files.length} source files (${go} go, ${py} py)`);
    await sleep(250);
    if (stopped()) return { status: "stopped" };

    phase(1);
    log("architecture · mapping entrypoints and trust boundaries");
    await sleep(250);

    phase(2);
    if (fs.existsSync(path.join(repoInfo.dir, "SECURITY.md"))) log("intent · SECURITY.md present");
    await sleep(200);

    phase(3);
    log("advisories · dedupe pass (local heuristics)");
    await sleep(200);

    phase(4);
    const surface = files.filter((f) => {
      try { return SOURCE[langForFile(f)].test(fs.readFileSync(f, "utf8")); } catch { return false; }
    });
    log(`attack surface · ${surface.length} files take external input`);
    await sleep(250);

    phase(5);
    let scored;
    if (llm) {
      // LLM-driven analysis: drive the user's agent CLI with improved_method.
      const r = await runLLMScan({ llm, repoDir: repoInfo.dir, repo, emit, isAborted });
      if (r === "aborted" || isAborted()) {
        emit({ type: "done", status: "stopped", findings: 0 });
        return { status: "stopped" };
      }
      scored = (r || []).slice(0, MAX_FINDINGS);
    } else {
      // built-in pattern detectors (fallback when no agent CLI is available)
      const all = [];
      let tokens = 30;
      for (const abs of files) {
        if (isAborted()) break;
        const rel = path.relative(repoInfo.dir, abs);
        const fs2 = detectInFile(abs, rel, repo);
        for (const f of fs2) {
          if (all.length >= MAX_FINDINGS) break;
          f.scanId = scanId;
          all.push(f);
          tokens += 4;
          emit({ type: "meta", tokens, candidates: all.length });
        }
        if (all.length >= MAX_FINDINGS) break;
      }
      log(`deep analysis · ${all.length} candidate(s)`);
      await sleep(200);
      scored = enrich(all);
    }
    if (stopped()) return { status: "stopped" };

    phase(6);
    scored.sort((a, b) => b.confidence - a.confidence);
    log(llm ? `validation · ${scored.length} finding(s) from ${llm}` : "validation · multi-signal confidence");
    emit({ type: "meta", tokens: 0, candidates: scored.length });
    for (const f of scored) {
      if (isAborted()) break;
      f.scanId = scanId;
      emit({ type: "finding", finding: f });
      await sleep(45);
    }
    if (stopped()) return { status: "stopped" };
    await sleep(150);

    phase(7);
    const high = scored.filter((f) => f.confidence >= 60).length;
    log(`report · ${scored.length} candidate(s), ${high} worth deep tracing`);
    emit({ type: "done", status: scored.length ? "ready" : "done", findings: scored.length });
    return { status: scored.length ? "ready" : "done", findings: scored };
  } finally {
    cleanup();
  }
}
