#!/usr/bin/env bun
// pay.ts — pay the x402 audit server for real on Base Sepolia.
//
// Flow (handled by x402-fetch v1, matching the server's v1 wire format):
//   POST /audit -> 402 + PaymentRequirements
//   sign EIP-3009 transferWithAuthorization (offchain, gasless for us)
//   retry with X-PAYMENT -> server verifies + settles via facilitator -> 200
//
// Usage: bun run pay.ts [url]   (default http://localhost:8902/audit)
import { createWalletClient, http } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { baseSepolia } from "viem/chains";
import { wrapFetchWithPayment } from "x402-fetch";

const key = process.env.PAYER_PRIVATE_KEY as `0x${string}` | undefined;
if (!key) throw new Error("PAYER_PRIVATE_KEY missing — run gen-wallets.ts first");

const account = privateKeyToAccount(key);
const client = createWalletClient({ account, chain: baseSepolia, transport: http() });

const url = process.argv[2] ?? "http://localhost:8902/audit";
// maxValue 0.5 USDC (atomic) — comfortably above the $0.10 price; the default
// cap is exactly 0.10 and an equality edge could reject our own price.
const fetchWithPay = wrapFetchWithPayment(fetch, client, BigInt(500_000));

console.log(`payer  : ${account.address}`);
console.log(`target : ${url}`);

const res = await fetchWithPay(url, { method: "POST" });
console.log(`status : ${res.status}`);

const receiptB64 = res.headers.get("x-payment-response");
if (receiptB64) {
  const receipt = JSON.parse(Buffer.from(receiptB64, "base64").toString("utf8"));
  console.log("receipt:", JSON.stringify(receipt, null, 2));
  if (receipt.txHash) {
    console.log(`basescan: https://sepolia.basescan.org/tx/${receipt.txHash}`);
  }
}

const body = (await res.json()) as Record<string, unknown>;
// The full body embeds the whole report — print just the proof-of-payment bits.
console.log(
  "body   :",
  JSON.stringify(
    {
      paid: body.paid,
      settlement: body.settlement,
      txHash: body.txHash,
      payer: body.payer,
      summary: body.summary,
      error: body.error,
    },
    null,
    2,
  ),
);
