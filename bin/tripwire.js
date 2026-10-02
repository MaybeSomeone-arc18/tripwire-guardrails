#!/usr/bin/env node
// Usage:
//   echo "text" | tripwire [--output] [--block-at 2] [--policy policy.json]
//   tripwire "text to check"            (text as an argument)
// Exit code: 0 allowed, 1 blocked, 2 usage error.
import { readFileSync } from "node:fs";
import { createGuard } from "../src/index.js";

const args = process.argv.slice(2);
const HELP = `tripwire [--output] [--block-at N] [--policy file.json] [--quiet] [text]
Reads text from the argument or stdin. Prints the verdict as JSON. Exit 0 = allowed, 1 = blocked, 2 = usage error.`;
if (args.includes("--help") || args.includes("-h")) { console.log(HELP); process.exit(0); }

const flagsWithValue = new Set(["--block-at", "--policy"]);
const positional = [];
for (let k = 0; k < args.length; k++) {
  if (flagsWithValue.has(args[k])) { k++; continue; }
  if (args[k].startsWith("--")) continue;
  positional.push(args[k]);
}
const direction = args.includes("--output") ? "output" : "input";
const val = (name) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : undefined; };
let policy = {};
try {
  if (val("--policy")) policy = JSON.parse(readFileSync(val("--policy"), "utf8"));
  if (args.includes("--block-at")) {
    const n = Number(val("--block-at"));
    if (![1, 2, 3].includes(n)) throw new Error("--block-at must be 1, 2 or 3");
    policy.blockAt = n;
  }
} catch (e) { console.error(`tripwire: ${e.message}`); process.exit(2); }

let text = positional.join(" ");
if (!text) {
  if (process.stdin.isTTY) { console.error(HELP); process.exit(2); }
  text = "";
  for await (const chunk of process.stdin) text += chunk;
}

const guard = createGuard(policy);
const v = direction === "input" ? guard.checkInput(text) : guard.checkOutput(text);
if (!args.includes("--quiet")) console.log(JSON.stringify(v, null, 2));
process.exit(v.allowed ? 0 : 1);
