#!/usr/bin/env bun
// gen-wallets.ts — mint two fresh TESTNET-ONLY keypairs (payer + payTo recipient)
// and write them to .env (gitignored). Idempotent: refuses to overwrite an
// existing .env so funded keys are never clobbered.
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { existsSync, writeFileSync } from "node:fs";

if (existsSync(".env")) {
  console.log("refusing to overwrite existing .env (keys may be funded)");
  process.exit(0);
}

const payerKey = generatePrivateKey();
const payToKey = generatePrivateKey();
const payer = privateKeyToAccount(payerKey);
const payTo = privateKeyToAccount(payToKey);

writeFileSync(
  ".env",
  [
    "# TESTNET-ONLY keys (Base Sepolia). Never fund with real assets.",
    `PAYER_PRIVATE_KEY=${payerKey}`,
    `PAYER_ADDRESS=${payer.address}`,
    `PAY_TO_PRIVATE_KEY=${payToKey}`,
    `PAY_TO_ADDRESS=${payTo.address}`,
    "",
  ].join("\n"),
);

console.log(JSON.stringify({ payer: payer.address, payTo: payTo.address }));
