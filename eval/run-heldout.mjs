import { createGuard } from "../src/index.js";
import { hostile, benign } from "./heldout.mjs";
const g = createGuard();
const miss = [], fp = [];
for (const [t, k] of hostile) { const v = g.checkInput(t); if (v.allowed) miss.push(`[${k}] ${t.slice(0, 80)}`); }
for (const t of benign) { const v = g.checkInput(t); if (!v.allowed) fp.push(t.slice(0, 80)); }
const tp = hostile.length - miss.length;
console.log(`held-out: recall ${tp}/${hostile.length} = ${(100 * tp / hostile.length).toFixed(1)}%, false positives ${fp.length}/${benign.length}, precision ${(100 * tp / (tp + fp.length)).toFixed(1)}%`);
console.log("missed:\n" + miss.join("\n")); console.log("false positives:\n" + fp.join("\n"));
