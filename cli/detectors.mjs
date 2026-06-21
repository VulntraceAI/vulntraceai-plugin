// VulntraceAI Companion — source→sink detectors.
// Lightweight, dependency-free ports of the improved_method semgrep rules.
// These produce CANDIDATE leads (Phase 1.5 of the methodology) — confidence is
// deliberately capped unless multiple independent signals agree. The gate/PoC
// flow is what raises a candidate to a real finding.

/** Source indicators (attacker-controlled input) by language. */
export const SOURCE = {
  go: /r\.URL\.Query|\.FormValue|\.PostFormValue|mux\.Vars|chi\.URLParam|c\.(Param|Query|PostForm)\(|r\.Header\.Get|\.PathValue\(|sftp\.Request|req\.URL|request\./,
  python: /request\.(args|form|json|values|data|GET|POST|FILES|cookies)|\.query_params|\.path_params|get_argument|match_info|request\.body/,
};

/** Sanitizer indicators by vulnerability class. */
const SANITIZERS = {
  path: /filepath\.Rel\(|os\.path\.realpath|\brealpath\(|commonpath|Sanitize(User)?Path|secure_filename|is_relative_to|filter\s*=\s*["']data["']/,
  ssrf: /netip\.|IsPrivate\(|IsLoopback\(|IsLinkLocal|is_private|is_loopback|ip_address\(|is_safe_url|validate_url/,
};

/**
 * Each detector: id, lang, title, archetype, cwe, severity, class (for sanitizer
 * lookup), sink (RegExp that must match a line), optional `not` (must NOT match
 * the line), optional `precise` (high-precision → confidence bonus).
 */
export const DETECTORS = [
  // ── Go ────────────────────────────────────────────────────────────────
  {
    id: "go-path-hasprefix",
    lang: "go",
    title: "Path containment via strings.HasPrefix without a separator",
    archetype: "F",
    cwe: "CWE-22",
    severity: "high",
    class: "path",
    precise: true,
    sink: /strings\.HasPrefix\(\s*\w[\w.]*\s*,\s*\w[\w.]*\s*\)/,
    needs: /(root|dir|path|base|jail|prefix|home)/i,
    not: /\+\s*["'`]\/|PathSeparator|\+\s*sep|filepath\.Clean/,
  },
  {
    id: "go-filepath-join-tainted",
    lang: "go",
    title: "Externally controlled value joined into a filesystem path",
    archetype: "F·G",
    cwe: "CWE-22",
    severity: "medium",
    class: "path",
    sink: /filepath\.Join\([^)]*\b(name|path|file|target|rel|clientPath|userPath|fname|filename)\b/i,
    requireSource: true,
  },
  {
    id: "go-ssrf-http",
    lang: "go",
    title: "Externally controlled URL reaches an HTTP client",
    archetype: "F",
    cwe: "CWE-918",
    severity: "high",
    class: "ssrf",
    sink: /\b(http\.(Get|Post|Head)|http\.NewRequest(WithContext)?|retryablehttp\.NewRequest)\(\s*[^"'`]/,
    requireSource: true,
  },
  {
    id: "go-archive-slip",
    lang: "go",
    title: "Archive member name joined into the output path (zip/tar slip)",
    archetype: "E",
    cwe: "CWE-22",
    severity: "high",
    class: "path",
    precise: true,
    sink: /(filepath|path)\.Join\([^)]*\.Name\b/,
  },
  {
    id: "go-cmd-exec",
    lang: "go",
    title: "Command built from non-literal arguments",
    archetype: "—",
    cwe: "CWE-78",
    severity: "high",
    class: "cmd",
    sink: /exec\.Command(Context)?\(\s*("sh"|"bash"|"cmd"|[a-z]\w*)/,
    not: /exec\.Command(Context)?\(\s*"[\w/.-]+",\s*"[\w/.=-]+"\s*\)/,
  },
  {
    id: "go-get-state-change",
    lang: "go",
    title: "State-changing filesystem op inside a GET handler (CSRF-able)",
    archetype: "C",
    cwe: "CWE-352",
    severity: "medium",
    class: "csrf",
    sink: /os\.(Remove|RemoveAll|Rename|Mkdir|MkdirAll|Create)\(/,
    contextNeeds: /r\.Method\s*==\s*"GET"|MethodGet/,
  },

  // ── Python ────────────────────────────────────────────────────────────
  {
    id: "py-cmd-shell",
    lang: "python",
    title: "Shell command execution (shell=True / os.system)",
    archetype: "—",
    cwe: "CWE-78",
    severity: "high",
    class: "cmd",
    precise: true,
    sink: /subprocess\.(run|call|Popen|check_output|check_call)\([^)]*shell\s*=\s*True|os\.system\(|os\.popen\(/,
  },
  {
    id: "py-deser",
    lang: "python",
    title: "Unsafe deserialization (pickle / yaml.load / marshal)",
    archetype: "I",
    cwe: "CWE-502",
    severity: "high",
    class: "deser",
    precise: true,
    sink: /pickle\.loads?\(|jsonpickle\.decode\(|marshal\.loads\(|yaml\.load\((?![^)]*Loader)/,
  },
  {
    id: "py-ssrf",
    lang: "python",
    title: "Externally controlled URL reaches an HTTP client",
    archetype: "F",
    cwe: "CWE-918",
    severity: "high",
    class: "ssrf",
    sink: /\b(requests\.(get|post|put|head|request)|httpx\.(get|post)|urllib\.request\.urlopen|urlopen)\(/,
    requireSource: true,
  },
  {
    id: "py-path",
    lang: "python",
    title: "Externally controlled value reaches a file sink",
    archetype: "F·G",
    cwe: "CWE-22",
    severity: "medium",
    class: "path",
    sink: /\b(open|send_file|FileResponse|send_from_directory|shutil\.(copy|move))\(/,
    requireSource: true,
  },
  {
    id: "py-extractall",
    lang: "python",
    title: "Archive extracted without per-member containment (zip/tar slip)",
    archetype: "E",
    cwe: "CWE-22",
    severity: "high",
    class: "path",
    precise: true,
    sink: /\.extractall\(/,
    not: /filter\s*=\s*["']data["']/,
  },
];

/** Map file extension → language. */
export function langForFile(file) {
  if (file.endsWith(".go")) return "go";
  if (file.endsWith(".py")) return "python";
  return null;
}

/**
 * Score a candidate 0–100 from independent signals, mirroring the confidence
 * engine: a lone syntactic match stays low; source + no-sanitizer raise it.
 */
export function scoreCandidate(detector, { hasSource, hasSanitizer }) {
  let c = 34;
  if (hasSource) c += 16;
  if (detector.class === "path" || detector.class === "ssrf") {
    c += hasSanitizer ? -14 : 14;
  }
  if (detector.precise) c += 8;
  if (detector.requireSource && !hasSource) c -= 20;
  return Math.max(10, Math.min(92, c));
}
