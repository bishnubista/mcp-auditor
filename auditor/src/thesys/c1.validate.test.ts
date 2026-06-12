/**
 * C1 output-validation trust-gate tests (FIX #7).
 *
 * Proves the hardened validator rejects injected markup and unsafe URL schemes
 * while accepting a clean, allowlisted spec. extractAndValidateSpec consumes an
 * OpenAI-compatible response shape; we wrap each candidate spec as the
 * assistant message content (object form, so no JSON re-parse is needed).
 */
import { test, expect } from "bun:test";
import { extractAndValidateSpec } from "./c1.ts";

/** Wrap a candidate UI spec into the OpenAI-compatible response envelope. */
function asResponse(spec: unknown): unknown {
  return { choices: [{ message: { content: spec } }] };
}

test("REJECTS a spec with <b>hi</b> in a text field -> fallback (null)", () => {
  const spec = {
    type: "card",
    title: "Finding",
    children: [{ type: "text", text: "<b>hi</b>" }],
  };
  const out = extractAndValidateSpec(asResponse(spec));
  expect(out).toBeNull();
});

test("REJECTS a lone raw angle bracket in a string value -> fallback (null)", () => {
  const spec = { type: "text", text: "a < b means less-than" };
  const out = extractAndValidateSpec(asResponse(spec));
  expect(out).toBeNull();
});

test("REJECTS an http:// href -> fallback (null)", () => {
  const spec = {
    type: "card",
    children: [{ type: "text", text: "link", href: "http://attacker.example/x" }],
  };
  const out = extractAndValidateSpec(asResponse(spec));
  expect(out).toBeNull();
});

test("REJECTS a javascript: href -> fallback (null)", () => {
  const spec = { type: "text", text: "x", href: "javascript:steal()" };
  const out = extractAndValidateSpec(asResponse(spec));
  expect(out).toBeNull();
});

test("ACCEPTS a clean spec with https:// href + plain text", () => {
  const spec = {
    type: "card",
    title: "Audit summary",
    children: [
      { type: "heading", level: 2, text: "Findings" },
      { type: "text", text: "DB_PASSWORD was exposed by get_config." },
      { type: "text", text: "See docs", href: "https://docs.example/safe-t1502" },
      { type: "badge", variant: "critical", label: "SAFE-T1502" },
    ],
  };
  const out = extractAndValidateSpec(asResponse(spec));
  expect(out).not.toBeNull();
  expect(out).toEqual(spec);
});

test("ACCEPTS a fragment (#) href", () => {
  const spec = { type: "text", text: "jump", href: "#finding-1" };
  const out = extractAndValidateSpec(asResponse(spec));
  expect(out).not.toBeNull();
});
