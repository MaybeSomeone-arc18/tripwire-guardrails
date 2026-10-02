#!/usr/bin/env node
// Tiny HTTP wrapper so non-Node apps (Python, Go, Ruby...) can use Tripwire:
//   tripwire-server --port 8787 [--host 127.0.0.1] [--policy policy.json]
//   POST /check  {"text": "...", "direction": "input" | "output"}  ->  verdict JSON
//   GET  /health -> {"ok":true}
// Binds to localhost by default. Bad requests get 400, never an "allowed" verdict.
import { createServer } from "node:http";
import { readFileSync } from "node:fs";
import { createGuard } from "../src/index.js";

const args = process.argv.slice(2);
const opt = (name, d) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : d; };
if (args.includes("--help") || args.includes("-h")) {
  console.log("Usage: tripwire-server [--port 8787] [--host 127.0.0.1] [--policy file.json]\nPOST /check {\"text\":\"...\",\"direction\":\"input|output\"}");
  process.exit(0);
}
const policy = opt("--policy") ? JSON.parse(readFileSync(opt("--policy"), "utf8")) : {};
const guard = createGuard(policy);
const MAX_BODY = 1_000_000;

const send = (res, code, obj) => { res.writeHead(code, { "content-type": "application/json" }); res.end(JSON.stringify(obj)); };

const server = createServer((req, res) => {
  if (req.method === "GET" && req.url === "/health") return send(res, 200, { ok: true });
  if (req.method !== "POST" || req.url !== "/check") return send(res, 404, { error: "POST /check or GET /health" });
  let size = 0; const chunks = [];
  req.on("data", (c) => { size += c.length; if (size > MAX_BODY) { send(res, 413, { error: "body too large" }); req.destroy(); } else chunks.push(c); });
  req.on("end", () => {
    if (res.writableEnded) return;
    let body;
    try { body = JSON.parse(Buffer.concat(chunks).toString("utf8")); } catch { return send(res, 400, { error: "invalid JSON" }); }
    if (typeof body?.text !== "string") return send(res, 400, { error: "\"text\" must be a string" });
    const direction = body.direction ?? "input";
    if (direction !== "input" && direction !== "output") return send(res, 400, { error: "\"direction\" must be input or output" });
    send(res, 200, direction === "input" ? guard.checkInput(body.text) : guard.checkOutput(body.text));
  });
});
const port = Number(opt("--port", 8787));
const host = opt("--host", "127.0.0.1");
server.listen(port, host, () => console.error(`tripwire-server listening on http://${host}:${port}`));
