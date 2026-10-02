#!/usr/bin/env node
// Usage: echo "text" | tripwire [--output] [--block-at 2]
import { createGuard } from "../src/index.js";

const args = process.argv.slice(2);
const direction = args.includes("--output") ? "output" : "input";
const i = args.indexOf("--block-at");
const blockAt = i >= 0 ? Number(args[i + 1]) : 3;

let text = "";
for await (const chunk of process.stdin) text += chunk;

const guard = createGuard({ blockAt });
const v = direction === "input" ? guard.checkInput(text) : guard.checkOutput(text);
console.log(JSON.stringify(v, null, 2));
process.exit(v.allowed ? 0 : 1);
