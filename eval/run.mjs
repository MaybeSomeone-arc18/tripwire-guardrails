import { createGuard } from "../src/index.js";
import { hostile, benign } from "./corpus.mjs";

const g = createGuard();
const rows = { hostile: {}, benign: { total: 0, blocked: 0, flagged: 0 } };
const missed = [], falsePos = [];

for (const [text, kind] of hostile) {
  const v = g.checkInput(text);
  const r = (rows.hostile[kind] ??= { total: 0, blocked: 0, flagged: 0 });
  r.total++;
  if (!v.allowed) r.blocked++;
  else if (v.findings.length) r.flagged++;
  if (v.allowed) missed.push(`[${kind}] ${text.slice(0, 70)}`);
}
for (const text of benign) {
  const v = g.checkInput(text);
  rows.benign.total++;
  if (!v.allowed) { rows.benign.blocked++; falsePos.push(text.slice(0, 70)); }
  else if (v.findings.length) rows.benign.flagged++;
}

const H = Object.values(rows.hostile).reduce((a, r) => ({ total: a.total + r.total, blocked: a.blocked + r.blocked }), { total: 0, blocked: 0 });
const tp = H.blocked, fn = H.total - H.blocked, fp = rows.benign.blocked;
const precision = tp / (tp + fp || 1), recall = tp / (tp + fn || 1);
console.log("rules only, blocking threshold = 3");
for (const [k, r] of Object.entries(rows.hostile)) console.log(`  ${k.padEnd(13)} blocked ${r.blocked}/${r.total}`);
console.log(`  benign        blocked ${rows.benign.blocked}/${rows.benign.total} (flagged but allowed: ${rows.benign.flagged})`);
console.log(`recall ${(recall * 100).toFixed(1)}%  precision ${(precision * 100).toFixed(1)}%  (hostile n=${H.total}, benign n=${rows.benign.total})`);
if (process.argv.includes("--verbose")) { console.log("\nmissed:\n" + missed.join("\n")); console.log("\nfalse positives:\n" + falsePos.join("\n")); }
