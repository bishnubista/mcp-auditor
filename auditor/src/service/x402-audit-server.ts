#!/usr/bin/env bun
// x402-audit-server.ts — monetize the MCP security audit via the x402 protocol.
//
// WHAT THIS IS
// ------------
// An HTTP service that turns our autonomous, governed MCP auditor into a
// *transacting agent*: it sells a single audit run for a micro-payment using
// x402 (Coinbase's HTTP 402 "Payment Required" standard for agent payment rails).
//
//   POST /audit  (no payment)   -> 402 Payment Required + x402 payment requirements
//   POST /audit  (with payment) -> verify -> run the GOVERNED audit -> 200 + cited report
//   GET  /health                -> 200
//
// WHY HAND-ROLLED WIRE PROTOCOL (not the SDK middleware)
// ------------------------------------------------------
// The official `x402` / `x402-express` npm packages exist and were inspected
// (v1.2.0). They expose `useFacilitator()` (a remote verify/settle client over
// plain HTTP), `processPriceToAtomicAmount()`, and `PaymentRequirements` /
// `PaymentPayload` zod schemas. We would happily use them — BUT adding them
// means editing auditor/package.json, which another agent owns and we must not
// touch. So instead we implement the x402 WIRE PROTOCOL faithfully by hand,
// matching the exact field shapes extracted from the real SDK's type defs, and
// we verify against the real facilitator over `fetch` (the facilitator's
// /verify endpoint is a documented HTTP contract — no SDK required). If the
// `x402` package later becomes resolvable, `verifyWithFacilitator()` will use
// it via a dynamic import automatically.
//
// x402 WIRE SHAPES (from x402@1.2.0 `dist/.../x402Specs.d.ts`, scheme "exact"):
//   402 response body:  { x402Version: 1, error: string, accepts: PaymentRequirements[] }
//   PaymentRequirements: {
//     scheme: "exact",
//     network: "base-sepolia" | "base" | ...,
//     maxAmountRequired: string,   // atomic units of `asset` (USDC has 6 decimals)
//     resource: string,            // the URL being paid for
//     description: string,
//     mimeType: string,
//     payTo: string,               // recipient address (0x… on EVM)
//     maxTimeoutSeconds: number,
//     asset: string,               // token contract address
//     extra?: { name, version }    // EIP-712 domain for EVM USDC
//   }
//   Request header:  X-PAYMENT: base64( JSON PaymentPayload )
//   PaymentPayload:  { x402Version: 1, scheme, network, payload: { signature, authorization } }
//   Facilitator:     POST {facilitator}/verify
//                      body { x402Version, paymentPayload, paymentRequirements }
//                      -> { isValid: boolean, invalidReason?: string, payer?: string }
//
// GRACEFUL DEGRADATION (this is a live demo):
//   - The 402 path ALWAYS works fully offline (no network to RETURN a 402).
//   - Paid path: if X402_FACILITATOR_URL is set/reachable we verify for real.
//     If not reachable AND X402_DEMO_ACCEPT=1 (or an x402-demo payment header is
//     present), we run in clearly-labeled DEMO settlement mode so the stage demo
//     of 402 -> pay -> 200 is deterministic. We NEVER silently accept a payment
//     outside demo mode.
//
// SECURITY: no private keys or secrets are ever read or stored here. All config
// is read from env with safe base-sepolia (testnet) defaults.

import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { copyFileSync, existsSync, mkdirSync, readFileSync, rmSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

// ---------------------------------------------------------------------------
// Paths — mirror demo-local.ts so we reuse the exact same governed pipeline.
// ---------------------------------------------------------------------------
const HERE = dirname(fileURLToPath(import.meta.url)); // auditor/src/service
const AUDITOR = resolve(HERE, "..", ".."); // auditor/
const ROOT = resolve(AUDITOR, ".."); // mcp-auditor/
const OUT = resolve(ROOT, "out");
const FINDINGS = resolve(OUT, "findings.jsonl");
const AUDIT = resolve(OUT, "audit.jsonl");
const REPORT = resolve(OUT, "audit-report.md");
const CITED = resolve(OUT, "cited.md"); // produced by T11 (optional)

// #6 ISOLATED PAID-RUN ROOT — each paid audit snapshots its artifacts into its
// OWN per-request directory under out/x402-runs/<nonce>/ and serves from there,
// so a concurrent `demo:local` (a SEPARATE process that owns the shared out/*
// files) can never clobber what THIS paid response returns. The shared
// demo:local pipeline is untouched and stays byte-identical.
const X402_RUNS = resolve(OUT, "x402-runs");

// Monotonic in-process counter for run nonces — Date.now()/Math.random may be
// restricted, and a counter is sufficient for in-process uniqueness. Combined
// with a payment-payload hash for cross-restart uniqueness.
let runCounter = 0;

const TARGET_CMD =
  process.env.DEMO_TARGET_CMD ??
  `bun run ${resolve(ROOT, "target-server/src/index.ts")}`;

// ---------------------------------------------------------------------------
// x402 config — all from env with testnet-safe defaults. No secrets here.
// ---------------------------------------------------------------------------
const PORT = Number(process.env.PORT ?? 8902);

// The price of one audit. Accepts a human "$0.10" or a raw atomic amount.
const PRICE = process.env.X402_PRICE ?? "$0.10";

// EVM network for the payment (x402 "exact" scheme). base-sepolia = free testnet.
const NETWORK = process.env.X402_NETWORK ?? "base-sepolia";

// Recipient address. Demo testnet recipient (NOT a funded treasury) — override
// with PAY_TO_ADDRESS in prod.
const PAY_TO =
  process.env.PAY_TO_ADDRESS ??
  "0x8430154a89111f27cd1bb2f1a3f81961b04391a8";

// Default facilitator that exposes POST /verify + /settle. The reference x402
// testnet facilitator. Only contacted on the PAID path, never for the 402.
const DEFAULT_FACILITATOR = "https://x402.org/facilitator";
const FACILITATOR_URL = process.env.X402_FACILITATOR_URL ?? "";

// USDC token addresses per network (6 decimals) — the canonical x402 default
// asset. Used to build payment requirements. base-sepolia testnet USDC below.
const USDC: Record<string, { address: string; name: string; version: string }> = {
  "base-sepolia": {
    address: "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
    name: "USDC",
    version: "2",
  },
  base: {
    address: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    name: "USD Coin",
    version: "2",
  },
};

const USDC_DECIMALS = 6;
const PAYMENT_HEADER = "x-payment";
const X402_VERSION = 1 as const;

// ---------------------------------------------------------------------------
// x402 wire types (mirrors x402@1.2.0 "exact" scheme).
// ---------------------------------------------------------------------------
interface PaymentRequirements {
  scheme: "exact";
  network: string;
  maxAmountRequired: string; // atomic units
  resource: string;
  description: string;
  mimeType: string;
  payTo: string;
  maxTimeoutSeconds: number;
  asset: string;
  extra?: { name: string; version: string };
}

interface PaymentPayload {
  x402Version: number;
  scheme: string;
  network: string;
  // Scheme-specific payload (signature + EIP-3009 authorization for "exact").
  payload: unknown;
}

interface VerifyResponse {
  isValid: boolean;
  invalidReason?: string;
  payer?: string;
}

// Facilitator /settle response (documented x402 settlement contract).
interface SettleResponse {
  success: boolean;
  errorReason?: string;
  txHash?: string;
  networkId?: string;
  payer?: string;
}

// ---------------------------------------------------------------------------
// Pricing: convert "$0.10" (or a raw atomic string) into atomic USDC units.
// ---------------------------------------------------------------------------
function priceToAtomic(price: string): string {
  const trimmed = price.trim();
  if (trimmed.startsWith("$")) {
    const dollars = Number(trimmed.slice(1));
    if (!Number.isFinite(dollars) || dollars < 0) {
      throw new Error(`Invalid X402_PRICE: ${price}`);
    }
    // Round to atomic units of a 6-decimal token.
    const atomic = Math.round(dollars * 10 ** USDC_DECIMALS);
    return String(atomic);
  }
  // Already an atomic integer string.
  if (!/^\d+$/.test(trimmed)) {
    throw new Error(`Invalid X402_PRICE (expected "$x.xx" or atomic int): ${price}`);
  }
  return trimmed;
}

// ---------------------------------------------------------------------------
// Build the x402 payment requirements (the body of the 402 response).
// Pure, offline, deterministic — this is the part that MUST always work.
// ---------------------------------------------------------------------------
function buildPaymentRequirements(resourceUrl: string): PaymentRequirements {
  const asset = USDC[NETWORK] ?? USDC["base-sepolia"];
  // asset is always defined (fallback above) but satisfy noUncheckedIndexedAccess.
  const token = asset ?? {
    address: "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
    name: "USDC",
    version: "2",
  };
  return {
    scheme: "exact",
    network: NETWORK,
    maxAmountRequired: priceToAtomic(PRICE),
    resource: resourceUrl,
    description: "Governed MCP security audit (SAFE-T) — one cited report per payment.",
    mimeType: "application/json",
    payTo: PAY_TO,
    maxTimeoutSeconds: 120,
    asset: token.address,
    extra: { name: token.name, version: token.version },
  };
}

function paymentRequiredBody(reqs: PaymentRequirements, error: string) {
  return { x402Version: X402_VERSION, error, accepts: [reqs] };
}

// ---------------------------------------------------------------------------
// Parse the X-PAYMENT header: base64(JSON PaymentPayload).
// ---------------------------------------------------------------------------
function decodePaymentHeader(raw: string): PaymentPayload | null {
  try {
    const json = Buffer.from(raw, "base64").toString("utf8");
    const obj = JSON.parse(json) as PaymentPayload;
    if (typeof obj !== "object" || obj === null) return null;
    if (typeof obj.scheme !== "string" || typeof obj.network !== "string") {
      return null;
    }
    return obj;
  } catch {
    return null;
  }
}

// A clearly-labeled DEMO payment header lets the stage demo pay deterministically
// without an onchain wallet. It is ONLY honored when demo mode is enabled.
function isDemoPaymentHeader(payload: PaymentPayload | null, raw: string): boolean {
  if (raw.trim().toLowerCase() === "demo") return true;
  if (payload && typeof payload.payload === "object" && payload.payload !== null) {
    const p = payload.payload as Record<string, unknown>;
    if (p.demo === true || p.mode === "demo") return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Verify a payment. Real facilitator if configured+reachable; otherwise the
// clearly-labeled demo mode (never silent).
// ---------------------------------------------------------------------------
type VerifyOutcome =
  | { ok: true; mode: "facilitator" | "demo"; payer?: string }
  | { ok: false; reason: string; demoHint: boolean };

async function verifyPayment(
  payload: PaymentPayload,
  rawHeader: string,
  reqs: PaymentRequirements,
): Promise<VerifyOutcome> {
  // #4 SECURITY — a demo/placeholder payment is ONLY ever honored when the
  // operator started the server with X402_DEMO_ACCEPT=1. A bare `X-PAYMENT: demo`
  // (or demo-flagged payload) MUST NOT grant a free report on a server running in
  // real/production mode. So demo acceptance gates on the SERVER-START flag, and
  // a demo-shaped header without that flag is rejected (402), never served.
  const demoAccept = process.env.X402_DEMO_ACCEPT === "1";
  const demoHeaderShape = isDemoPaymentHeader(payload, rawHeader);

  // A demo-shaped header is only an accept signal when demo mode is enabled.
  const demoAccepted = demoAccept && demoHeaderShape;

  // Reject a demo header outright when demo mode is OFF (closes the bypass).
  if (demoHeaderShape && !demoAccept) {
    console.error(
      "[x402] REJECT — demo payment header presented but X402_DEMO_ACCEPT is not set (bypass closed)",
    );
    return {
      ok: false,
      reason: "demo_payment_rejected_demo_mode_disabled",
      demoHint: false,
    };
  }

  // Explicit facilitator configured -> verify for real (no demo shortcut).
  const facilitatorConfigured = FACILITATOR_URL.length > 0;
  if (facilitatorConfigured) {
    const res = await verifyWithFacilitator(FACILITATOR_URL, payload, reqs);
    if (res === "unreachable") {
      // Configured but down. Degrade to demo ONLY if demo mode is explicitly
      // enabled AND a demo header was presented (never on a real payment).
      if (demoAccepted) {
        console.error(
          "[x402] facilitator unreachable — falling back to DEMO settlement (X402_DEMO_ACCEPT=1 + demo header)",
        );
        return { ok: true, mode: "demo" };
      }
      return {
        ok: false,
        reason: "facilitator_unreachable",
        demoHint: demoAccept,
      };
    }
    if (res.isValid) {
      return { ok: true, mode: "facilitator", payer: res.payer };
    }
    return {
      ok: false,
      reason: res.invalidReason ?? "verification_failed",
      demoHint: false,
    };
  }

  // No facilitator configured. The ONLY way to accept is explicit demo mode
  // (server started with X402_DEMO_ACCEPT=1) AND a demo header. Never silent.
  if (demoAccepted) {
    console.error(
      "[x402] DEMO mode — payment accepted (X402_DEMO_ACCEPT=1); settlement is simulated, no onchain tx",
    );
    return { ok: true, mode: "demo" };
  }

  return {
    ok: false,
    reason: demoAccept
      ? "no_facilitator_configured"
      : "no_facilitator_and_demo_disabled",
    demoHint: true,
  };
}

// Call the x402 facilitator's documented HTTP /verify endpoint. Prefers the real
// `x402` SDK if it ever becomes resolvable; otherwise plain fetch against the
// documented contract. Returns "unreachable" on any network/transport failure so
// the caller can degrade gracefully.
async function verifyWithFacilitator(
  facilitatorUrl: string,
  payload: PaymentPayload,
  reqs: PaymentRequirements,
): Promise<VerifyResponse | "unreachable"> {
  // 1) Try the real SDK (dynamic import; absent in this workspace by design).
  try {
    // @ts-expect-error optional dep — not installed here (cannot edit package.json)
    const mod = await import("x402/verify");
    if (mod && typeof mod.useFacilitator === "function") {
      const { verify } = mod.useFacilitator({ url: facilitatorUrl });
      const r = (await verify(payload, reqs)) as VerifyResponse;
      return r;
    }
  } catch {
    // SDK not present — fall through to the hand-rolled HTTP call.
  }

  // 2) Hand-rolled call against the documented facilitator HTTP contract.
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 4000);
    const res = await fetch(`${facilitatorUrl.replace(/\/$/, "")}/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        x402Version: X402_VERSION,
        paymentPayload: payload,
        paymentRequirements: reqs,
      }),
      signal: controller.signal,
    });
    clearTimeout(timer);
    if (!res.ok) {
      // A 4xx from the facilitator is a definitive "invalid", not unreachable.
      if (res.status >= 400 && res.status < 500) {
        return { isValid: false, invalidReason: `facilitator_${res.status}` };
      }
      return "unreachable";
    }
    const data = (await res.json()) as VerifyResponse;
    return data;
  } catch {
    return "unreachable";
  }
}

// #5 SETTLEMENT — `isValid` from /verify is NOT payment collection. After a
// successful verify against a REAL facilitator we MUST call its /settle endpoint
// to actually collect onchain, and only serve the report once settlement
// succeeds. Documented x402 contract:
//   POST {facilitatorUrl}/settle
//     body { x402Version, paymentPayload, paymentRequirements }
//     -> { success: boolean, txHash?: string, errorReason?: string, payer?: string }
// Prefers the real x402 SDK's settle() if resolvable, else plain fetch. Returns
// "unreachable" on any network/transport failure so the caller can refuse to
// serve (never serve a paid report when settlement could not be confirmed).
async function settleWithFacilitator(
  facilitatorUrl: string,
  payload: PaymentPayload,
  reqs: PaymentRequirements,
): Promise<SettleResponse | "unreachable"> {
  // 1) Real SDK path (dynamic import; absent here by design — package.json owned).
  try {
    // @ts-expect-error optional dep — not installed here (cannot edit package.json)
    const mod = await import("x402/verify");
    if (mod && typeof mod.useFacilitator === "function") {
      const { settle } = mod.useFacilitator({ url: facilitatorUrl });
      if (typeof settle === "function") {
        const r = (await settle(payload, reqs)) as SettleResponse;
        return r;
      }
    }
  } catch {
    // SDK absent — fall through to the documented HTTP contract.
  }

  // 2) Hand-rolled call against the documented /settle HTTP contract.
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 8000);
    const res = await fetch(`${facilitatorUrl.replace(/\/$/, "")}/settle`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        x402Version: X402_VERSION,
        paymentPayload: payload,
        paymentRequirements: reqs,
      }),
      signal: controller.signal,
    });
    clearTimeout(timer);
    if (!res.ok) {
      if (res.status >= 400 && res.status < 500) {
        return { success: false, errorReason: `facilitator_settle_${res.status}` };
      }
      return "unreachable";
    }
    return (await res.json()) as SettleResponse;
  } catch {
    return "unreachable";
  }
}

// Build the base64 X-PAYMENT-RESPONSE settlement receipt header value.
// Real settlement carries the onchain txHash; demo settlement is clearly labeled.
function settlementReceipt(
  settlement: SettleResponse | { demo: true },
): string {
  return Buffer.from(JSON.stringify(settlement)).toString("base64");
}

// ---------------------------------------------------------------------------
// Run the governed audit pipeline (reuse, don't reimplement).
// Spawns the existing orchestrator -> 6 governed probers, then the synthesizer,
// exactly like demo:local. Returns the assembled JSON report.
// ---------------------------------------------------------------------------
interface Finding {
  ts?: string;
  safeT?: string;
  tool?: string;
  severity?: string;
  probe?: string;
  evidence?: string;
  prober?: string;
}

interface AuditResult {
  serverId: string;
  scanTs: string;
  findings: Finding[];
  severityBreakdown: Record<string, number>;
  safeTClasses: string[];
  governedProbeCount: number;
  report: string; // audit-report.md contents
  citedMarkdownPath: string | null;
  citedMarkdown: string | null;
  isolatedDir: string; // out/x402-runs/<nonce>/ — this run's private snapshot
}

function runStep(cmd: string, args: string[], label: string): Promise<void> {
  return new Promise((res, rej) => {
    const child = spawn(cmd, args, {
      cwd: AUDITOR,
      stdio: ["ignore", "inherit", "inherit"],
      env: process.env,
    });
    child.on("error", (e) => rej(new Error(`${label}: ${e.message}`)));
    child.on("exit", (code) =>
      code === 0
        ? res()
        : rej(new Error(`${label}: exited with code ${code ?? "null"}`)),
    );
  });
}

// Serialize audit runs — the artifact files are append-only/shared, so two
// concurrent runs would interleave. A simple in-process mutex is enough here.
let auditChain: Promise<unknown> = Promise.resolve();
function withAuditLock<T>(fn: () => Promise<T>): Promise<T> {
  const run = auditChain.then(fn, fn);
  // Keep the chain alive regardless of success/failure.
  auditChain = run.then(
    () => undefined,
    () => undefined,
  );
  return run;
}

// Derive a per-run nonce: monotonic in-process counter + short payment-payload
// hash. Counter guarantees in-process uniqueness; the hash disambiguates across
// process restarts. No Date.now()/Math.random (those may be restricted).
function runNonce(payload: PaymentPayload): string {
  const n = ++runCounter;
  const h = createHash("sha256")
    .update(JSON.stringify(payload) ?? "")
    .digest("hex")
    .slice(0, 8);
  return `${String(n).padStart(4, "0")}-${h}`;
}

async function runGovernedAudit(payload: PaymentPayload): Promise<AuditResult> {
  return withAuditLock(async () => {
    // Clean append-only artifacts so counts reflect THIS run (same as demo:local).
    for (const p of [FINDINGS, AUDIT, REPORT, CITED]) {
      if (existsSync(p)) rmSync(p);
    }

    const parts = TARGET_CMD.split(/\s+/).filter((s) => s.length > 0);
    const tcmd = parts[0];
    if (!tcmd) throw new Error("DEMO_TARGET_CMD is empty");
    const targs = parts.slice(1);

    console.error("[x402] running governed audit (orchestrator -> 6 probers)…");
    await runStep("bun", ["run", "src/orchestrator.ts", "--", tcmd, ...targs], "orchestrator");

    console.error("[x402] synthesizing cited SAFE-T report…");
    await runStep("bun", ["run", "src/synthesizer.ts"], "synthesizer");

    // Render cited.md to include in the paid response. If CITED_API_KEY is set we
    // ALSO publish to cited.md for real; otherwise --offline renders the doc locally
    // (the payer still gets the cited report). Non-fatal either way.
    if (existsSync(resolve(AUDITOR, "src/actions/cited.ts"))) {
      const citedArgs = ["run", "src/actions/cited.ts"];
      if (!process.env.CITED_API_KEY) citedArgs.push("--offline");
      await runStep("bun", citedArgs, "cited").catch((e) =>
        console.error(`[x402] cited.md step skipped: ${(e as Error).message}`),
      );
    }

    if (!existsSync(REPORT)) throw new Error("audit-report.md missing after run");

    // #6 SNAPSHOT into this run's ISOLATED directory IMMEDIATELY (still under the
    // lock, before yielding) so a concurrent demo:local cannot clobber the bytes
    // this paid response will serve. From here on we read ONLY the isolated copy.
    const nonce = runNonce(payload);
    const isolatedDir = resolve(X402_RUNS, nonce);
    mkdirSync(isolatedDir, { recursive: true });
    const isoReport = resolve(isolatedDir, "audit-report.md");
    const isoFindings = resolve(isolatedDir, "findings.jsonl");
    const isoAudit = resolve(isolatedDir, "audit.jsonl");
    const isoCited = resolve(isolatedDir, "cited.md");
    copyFileSync(REPORT, isoReport);
    if (existsSync(FINDINGS)) copyFileSync(FINDINGS, isoFindings);
    if (existsSync(AUDIT)) copyFileSync(AUDIT, isoAudit);
    if (existsSync(CITED)) copyFileSync(CITED, isoCited);
    console.error(`[x402] snapshotted paid-run artifacts -> ${isolatedDir}`);

    // Read artifacts FROM THE ISOLATED SNAPSHOT (never the shared out/* again).
    const report = readFileSync(isoReport, "utf8");

    const findings: Finding[] = existsSync(isoFindings)
      ? readFileSync(isoFindings, "utf8")
          .split("\n")
          .filter((l) => l.trim().length > 0)
          .map((l) => JSON.parse(l) as Finding)
      : [];

    const governedProbeCount = existsSync(isoAudit)
      ? readFileSync(isoAudit, "utf8")
          .split("\n")
          .filter((l) => l.trim().length > 0).length
      : 0;

    const severityBreakdown: Record<string, number> = {};
    const safeTSet = new Set<string>();
    for (const f of findings) {
      const sev = f.severity ?? "unknown";
      severityBreakdown[sev] = (severityBreakdown[sev] ?? 0) + 1;
      if (f.safeT) safeTSet.add(f.safeT);
    }

    const citedMarkdown = existsSync(isoCited) ? readFileSync(isoCited, "utf8") : null;

    return {
      serverId: "target-local",
      scanTs: new Date().toISOString(),
      findings,
      severityBreakdown,
      safeTClasses: [...safeTSet].sort(),
      governedProbeCount,
      report,
      citedMarkdownPath: citedMarkdown ? isoCited : null,
      citedMarkdown,
      isolatedDir,
    };
  });
}

// ---------------------------------------------------------------------------
// HTTP helpers.
// ---------------------------------------------------------------------------
function json(body: unknown, status: number, extraHeaders?: Record<string, string>): Response {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: { "Content-Type": "application/json", ...extraHeaders },
  });
}

function resourceUrlFor(req: Request): string {
  try {
    const u = new URL(req.url);
    return `${u.protocol}//${u.host}/audit`;
  } catch {
    return `http://localhost:${PORT}/audit`;
  }
}

// ---------------------------------------------------------------------------
// Request handler.
// ---------------------------------------------------------------------------
async function handle(req: Request): Promise<Response> {
  const url = new URL(req.url);

  if (req.method === "GET" && url.pathname === "/health") {
    return json(
      {
        status: "ok",
        service: "x402-audit-server",
        x402: {
          network: NETWORK,
          price: PRICE,
          payTo: PAY_TO,
          facilitator: FACILITATOR_URL || `${DEFAULT_FACILITATOR} (default, not auto-contacted)`,
          demoMode: process.env.X402_DEMO_ACCEPT === "1",
        },
      },
      200,
    );
  }

  if (url.pathname === "/audit" && req.method === "POST") {
    const reqs = buildPaymentRequirements(resourceUrlFor(req));
    const rawHeader = req.headers.get(PAYMENT_HEADER) ?? "";

    // No payment presented -> 402 with x402 payment requirements. ALWAYS offline-safe.
    if (rawHeader.trim().length === 0) {
      console.error("[x402] 402 Payment Required — no X-PAYMENT header presented");
      return json(
        paymentRequiredBody(reqs, "X-PAYMENT header required to run a paid audit"),
        402,
      );
    }

    // Payment presented -> verify.
    const payload = decodePaymentHeader(rawHeader);
    if (!payload && rawHeader.trim().toLowerCase() !== "demo") {
      return json(
        paymentRequiredBody(reqs, "Malformed X-PAYMENT header (expected base64 JSON payment payload)"),
        402,
      );
    }

    const effectivePayload: PaymentPayload =
      payload ?? { x402Version: X402_VERSION, scheme: "exact", network: NETWORK, payload: {} };

    const outcome = await verifyPayment(effectivePayload, rawHeader, reqs);

    if (!outcome.ok) {
      const body = paymentRequiredBody(reqs, `Payment not accepted: ${outcome.reason}`) as Record<
        string,
        unknown
      >;
      if (outcome.demoHint) {
        body.hint =
          "Start the server with X402_DEMO_ACCEPT=1 and send X-PAYMENT: demo for deterministic demo settlement, or configure X402_FACILITATOR_URL for real onchain verify+settle.";
      }
      console.error(`[x402] payment rejected — ${outcome.reason}`);
      return json(body, 402);
    }

    // #5 SETTLEMENT GATE — verify (`isValid`) is NOT collection. We only serve the
    // paid report AFTER settlement is confirmed.
    //   - facilitator mode: call /settle; require success + capture txHash. If
    //     /settle is unreachable or fails, DO NOT serve (402/502).
    //   - demo mode: skip real onchain settle (clearly labeled), set a demo
    //     X-PAYMENT-RESPONSE receipt.
    let paymentResponseHeader: string;
    let settlementLabel: string;
    let settlementTxHash: string | null = null;

    if (outcome.mode === "facilitator") {
      console.error("[x402] payment verified (facilitator) — settling onchain via /settle");
      const settle = await settleWithFacilitator(FACILITATOR_URL, effectivePayload, reqs);
      if (settle === "unreachable") {
        console.error("[x402] /settle unreachable AFTER verify — refusing to serve paid report");
        return json(
          paymentRequiredBody(
            reqs,
            "Payment verified but settlement could not be completed (facilitator /settle unreachable); report NOT served",
          ),
          502,
        );
      }
      if (!settle.success) {
        console.error(`[x402] /settle FAILED (${settle.errorReason ?? "unknown"}) — refusing to serve`);
        return json(
          paymentRequiredBody(
            reqs,
            `Settlement failed: ${settle.errorReason ?? "unknown"}; report NOT served`,
          ),
          402,
        );
      }
      settlementTxHash = settle.txHash ?? null;
      settlementLabel = `[x402] facilitator settlement OK${settle.txHash ? ` tx=${settle.txHash}` : ""}`;
      paymentResponseHeader = settlementReceipt(settle);
      console.error(settlementLabel);
    } else {
      // DEMO mode — explicitly enabled (X402_DEMO_ACCEPT=1). No onchain tx.
      settlementLabel = "[x402] DEMO settlement, no onchain tx";
      paymentResponseHeader = settlementReceipt({ demo: true });
      console.error(settlementLabel);
    }

    // Settled -> run the governed audit and return the cited report.
    console.error(`[x402] payment settled (${outcome.mode}) — running governed audit`);
    try {
      const result = await runGovernedAudit(effectivePayload);
      return json(
        {
          paid: true,
          settlement: outcome.mode, // "facilitator" | "demo"
          settlementLabel,
          txHash: settlementTxHash,
          payer: outcome.mode === "facilitator" ? outcome.payer ?? null : null,
          report: result.report,
          citedMarkdownPath: result.citedMarkdownPath,
          citedMarkdown: result.citedMarkdown,
          findings: result.findings,
          summary: {
            serverId: result.serverId,
            scanTs: result.scanTs,
            severityBreakdown: result.severityBreakdown,
            safeTClasses: result.safeTClasses,
            governedProbeCount: result.governedProbeCount,
            findingCount: result.findings.length,
            isolatedRunDir: result.isolatedDir,
          },
        },
        200,
        { "X-PAYMENT-RESPONSE": paymentResponseHeader },
      );
    } catch (e) {
      console.error(`[x402] audit failed AFTER settlement: ${(e as Error).message}`);
      return json(
        { paid: true, settlement: outcome.mode, error: "audit_failed", detail: (e as Error).message },
        500,
      );
    }
  }

  return json({ error: "not_found", routes: ["GET /health", "POST /audit"] }, 404);
}

// ---------------------------------------------------------------------------
// Boot.
// ---------------------------------------------------------------------------
const server = Bun.serve({
  port: PORT,
  // 5 minutes — an audit run can take a little while (spawns + probers).
  idleTimeout: 255,
  fetch: handle,
});

console.error(`[x402] audit server listening on http://localhost:${server.port}`);
console.error(`[x402] price=${PRICE} network=${NETWORK} payTo=${PAY_TO}`);
console.error(
  `[x402] facilitator=${FACILITATOR_URL || "(none configured; demo mode via X402_DEMO_ACCEPT=1 or X-PAYMENT: demo)"}`,
);
console.error("[x402] POST /audit (no header) -> 402; (with X-PAYMENT) -> verify -> audit -> 200; GET /health -> 200");
