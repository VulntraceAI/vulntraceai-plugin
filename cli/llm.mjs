// LLM-driven analysis. The Companion drives the user's own coding agent CLI
// (Claude Code or Codex) over the cloned repo, applying the improved_method
// methodology, and parses structured findings (with full reports + PoCs) back.
// The repo and the LLM credentials never leave the user's machine.
import { spawn, execFileSync } from "node:child_process";

const LLMS = {
  claude: { bin: "claude", label: "Claude Code" },
  codex: { bin: "codex", label: "Codex" },
};

/** Which agent CLIs are installed and on PATH. */
export function detectLLMs() {
  const found = [];
  for (const [name, cfg] of Object.entries(LLMS)) {
    try {
      execFileSync(cfg.bin, ["--version"], { stdio: "ignore", timeout: 6000 });
      found.push(name);
    } catch {
      /* not installed */
    }
  }
  return found;
}

const METHODOLOGY = `You are a Senior Application Security Researcher hunting for EXPLOITABLE vulnerabilities in the repository in the current working directory. Explore the code thoroughly using ONLY the Read, Grep, and Glob tools — do NOT run shell commands. Read every entry point and every function along each candidate data-flow chain before drawing conclusions; do not stop early or give up after one or two files.

Apply this methodology (improved_method):
1. RECON — framework, language, entry points (routes, handlers, CLI, RPC, deserialization, file uploads).
2. ARCHITECTURE — where untrusted input enters, and the trust/authorization boundaries.
3. INTENT — read SECURITY.md and docs. SKIP anything documented as intentional, admin-configurable, or an operator responsibility.
4. ADVISORIES — avoid already-known / duplicate issues; note how this finding is DISTINCT from existing advisories.
5. ATTACK SURFACE — enumerate source→sink paths where attacker-controlled input reaches a dangerous sink: command/shell exec, SQL, SSRF/outbound HTTP with a user URL, path traversal/LFI, unsafe deserialization, SSTI, auth bypass / IDOR, prototype pollution.
6. DEEP ANALYSIS — for each candidate, TRACE the full data flow source→sink, reading every function in the chain. Confirm ALL of: (a) an EXTERNAL/unprivileged attacker controls the source; (b) NO sanitizer/validation neutralizes it on the path; (c) it crosses a REAL security boundary (unauth→auth, userA→userB, user→admin).
7. NEGATIVE CONTROL — find the SIBLING / supported code path that handles the SAME kind of input CORRECTLY (it calls the sanitizer/ACL the vulnerable path skips). This asymmetry — the safe path is guarded, the vulnerable one is not — is the single strongest piece of evidence. Cite it with file:line.
8. IMPACT CHAINING — if the primitive can reach further (e.g., arbitrary read → leak a signing key/credential → forge an admin token → full takeover; or write → include → RCE), follow the chain end-to-end through the real verification/auth code and report the CHAINED severity, while also giving a conservative un-chained floor.
9. VALIDATE — only keep findings you can trace with certainty at real file:line. Read the actual sanitizer/guard code; do not assume.

HARD RULES — report a finding ONLY if ALL hold:
- Exploitable by a realistic external/unprivileged attacker (not theoretical, not self-harm, not an admin configuring their own system).
- Crosses a real security boundary and is NOT documented as intentional.
- CVSS v4 >= 4.0; strongly prefer High/Critical.
- You traced source→sink with concrete file:line references and read the sanitizers in between.
Be precise and conservative. For a hardened repo, an EMPTY result is the correct answer — do NOT invent or pad findings. Quality over quantity.

The report must be at the level of a CVE-grade advisory: every claim backed by exact file:line and real code; a negative control proving the omission; the impact chain demonstrated through the project's OWN code; CVSS justified per-metric.

When finished, FIRST output a brief "## Analysis Notes" section (5-15 lines): the entry points / attack surface you examined, and for EACH serious candidate you considered, ONE line on why it qualifies or why you rejected it, with file:line — e.g. "client.go:90 http.NewRequestWithContext(baseURL+path) — baseURL is SDK/operator config, not attacker-controlled → not SSRF". This makes a zero-finding result trustworthy. THEN output a single fenced \`\`\`json code block containing the array of QUALIFYING findings (or [] if none), then stop. Each finding:
{
  "title": "specific title naming the full chain, e.g. 'Authenticated path traversal in GET /api/x → arbitrary file read → admin takeover'",
  "class": "SSRF|RCE|SQLi|Path Traversal|Auth Bypass|IDOR|XSS|Deserialization|SSTI|Command Injection|...",
  "severity": "Critical|High|Medium",
  "cvss": "8.7",
  "cvssVector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:H/SI:H/SA:N",
  "cwe": "CWE-###",
  "file": "relative/path.go",
  "line": 90,
  "source": "relative/path.go:LINE — what the attacker controls and how it enters",
  "sink": "relative/path.go:LINE — the dangerous sink, with the exact line of code",
  "confidence": 0-100,
  "summary": "2-3 sentences: what is broken and the realistic impact.",
  "report": "A COMPLETE CVE-grade markdown advisory. Use EXACTLY these sections:\\n\\nA metadata table (rows: Project, Affected version + commit if known, Component (file → function), Vulnerability class (CWE-### + full name, note any chained CWE), Severity, CVSS v4.0 (the chained vector+score AND a conservative un-chained floor vector+score), Authentication (who can exploit), Security boundary crossed (explicit: unauth→auth / userA→userB / user→admin), Confidence).\\n\\n## 1. Summary — what the guard normally is, how this path bypasses it, and what it discloses/enables (bullet the concrete impacts).\\n## 2. Affected Code — the vulnerable handler/function quoted as a code block with the SOURCE and SINK lines annotated; then the sink function; then WHY the guard does not apply (quote the sanitizer/ACL that the safe path calls but this one does NOT).\\n## 3. Negative Control — quote the sibling/supported path showing it DOES call the guard. State the asymmetry plainly.\\n## 4. Proof of Concept — (a) the real attacker request and response; (b) under a bold '**Runnable PoC:**' label, the COMPLETE runnable PoC presented INLINE as a fenced code block containing the FULL script (never a summary, never a pointer to it elsewhere — the entire script must appear here). It reuses the project's OWN functions where possible, is non-destructive (127.0.0.1 only), has a clearly-labelled negative control, and prints the OBSERVED output; (c) if chained, the end-to-end PoC (e.g. read→key→forged admin token verified by the project's own verification code) with output.\\n## 5. Impact — Confidentiality/Integrity/Availability, the escalation chain quoted through the real verification code, and the numbered attack steps.\\n## 6. CVSS v4.0 Justification — both vectors, each metric (AV/AC/AT/PR/UI/VC/VI/VA/SC/SI/SA) justified in one line.\\n## 7. Remediation — a concrete code fix (a diff or corrected snippet), plus the stronger systemic fix.\\n## 8. Related observations — any sibling lower-severity variant (file:line) worth the same fix.\\n## 9. Distinctness & Disclosure — how this differs from existing advisories, and whether SECURITY.md exists / how to report.",
  "poc": "A complete, self-contained, NON-DESTRUCTIVE PoC (bash preferred; python ok). Bind only to 127.0.0.1; never target third parties or exfiltrate. Reuse the project's own code/functions where possible. It MUST include: a clearly-labelled NEGATIVE CONTROL proving the safe path is rejected/blocked, the positive trigger proving the boundary is crossed, and printed observed output (echo the leaked/forbidden result). If the finding chains to higher impact, demonstrate the chain end-to-end. Use comments to explain each step."
}
Output the json block and nothing after it.`;

function extractFindings(text) {
  if (!text) return [];
  const asArray = (p) => (Array.isArray(p) ? p : p && p.findings ? p.findings : p ? [p] : []);
  // Find the JSON array by string-aware bracket balancing — the report/poc
  // fields contain markdown code fences and brackets, so a fence/regex match is
  // unreliable. Start from the first '[' at/after a ```json marker if present.
  const fence = text.search(/```json/i);
  const from = fence >= 0 ? fence : 0;
  const start = text.indexOf("[", from);
  if (start < 0) return [];
  let depth = 0, inStr = false, esc = false;
  for (let i = start; i < text.length; i++) {
    const c = text[i];
    if (inStr) {
      if (esc) esc = false;
      else if (c === "\\") esc = true;
      else if (c === '"') inStr = false;
    } else if (c === '"') inStr = true;
    else if (c === "[") depth++;
    else if (c === "]") {
      if (--depth === 0) {
        try { return asArray(JSON.parse(text.slice(start, i + 1))); } catch { return []; }
      }
    }
  }
  return [];
}

function slug(s) {
  return String(s || "finding").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 48);
}

function normalize(f, repo, i) {
  const sev = String(f.severity || "medium").toLowerCase();
  const severity = ["critical", "high", "medium", "low"].includes(sev) ? sev : "medium";
  const line = Number(f.line) || 0;
  const file = String(f.file || "").trim();
  return {
    id: `llm-${slug(f.title)}-${i}`,
    detector: "llm",
    engine: "llm",
    title: String(f.title || "Untitled finding").slice(0, 140),
    cls: String(f.class || ""),
    target: repo,
    file,
    line,
    severity,
    archetype: String(f.class || "—"),
    cwe: String(f.cwe || ""),
    confidence: Math.max(0, Math.min(100, Number(f.confidence) || 60)),
    source: String(f.source || ""),
    sink: String(f.sink || ""),
    code: String(f.sink || ""),
    sanitizerPresent: false,
    cvss: String(f.cvss || ""),
    cvssVector: String(f.cvssVector || ""),
    summary: String(f.summary || ""),
    report: String(f.report || ""),
    poc: String(f.poc || ""),
  };
}

/** Run the chosen agent CLI over repoDir; emit log + finding + done events. */
export function runLLMScan({ llm, repoDir, repo, emit, isAborted }) {
  return new Promise((resolve) => {
    const bin = LLMS[llm]?.bin;
    if (!bin) {
      emit({ type: "log", line: `llm · ${llm} not available` });
      return resolve(null);
    }
    const label = LLMS[llm].label;
    emit({ type: "log", line: `deep analysis · ${label} is reading the repo and tracing source→sink (a few minutes)` });

    // text output: most reliable (stream-json made the agent stop early here).
    const args =
      llm === "claude"
        ? ["-p", METHODOLOGY, "--output-format", "text", "--allowedTools", "Read", "Grep", "Glob"]
        : ["exec", "--skip-git-repo-check", METHODOLOGY];

    const child = spawn(bin, args, { cwd: repoDir, stdio: ["ignore", "pipe", "pipe"] });
    let out = "";
    const started = Date.now();
    const killTimer = setTimeout(() => child.kill("SIGKILL"), 12 * 60 * 1000);
    const beat = setInterval(() => {
      if (isAborted?.()) { child.kill("SIGKILL"); return; }
      emit({ type: "log", line: `deep analysis · ${label} analyzing… (${Math.round((Date.now() - started) / 1000)}s)` });
    }, 15000);

    child.stdout.on("data", (d) => { out += d.toString(); });
    child.stderr.on("data", (d) => {
      const s = d.toString().trim();
      if (s) emit({ type: "log", line: `llm · ${s.slice(0, 100)}` });
    });
    child.on("error", (err) => {
      clearTimeout(killTimer); clearInterval(beat);
      emit({ type: "error", message: `could not start ${llm}: ${err.message}` });
      resolve(null);
    });
    child.on("close", () => {
      clearTimeout(killTimer); clearInterval(beat);
      if (isAborted?.()) return resolve("aborted");
      const findings = extractFindings(out).map((f, i) => normalize(f, repo, i));
      // Surface the LLM's reasoning — especially valuable for a zero result.
      const nm = out.match(/##\s*Analysis Notes\s*([\s\S]*?)(?:```json|\n\s*\[)/i);
      if (nm) {
        for (const ln of nm[1].split("\n").map((s) => s.trim()).filter(Boolean).slice(0, 18)) {
          emit({ type: "log", line: `notes · ${ln.replace(/^[-*#]+\s*/, "")}` });
        }
      }
      emit({ type: "log", line: `deep analysis · ${label} returned ${findings.length} finding(s)` });
      resolve(findings);
    });
  });
}
