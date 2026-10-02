import { INPUT_RULES, PARAPHRASE_RULES, MULTILINGUAL_RULES, SECRET_RULES, PII_RULES, OUTPUT_RULES } from "./rules.js";
import { variants } from "./normalize.js";

const JUDGEABLE = new Set(["prompt_injection", "off_topic", "prompt_leak"]);

const DEFAULT_POLICY = {
  // A finding at or above blockAt severity blocks. Below it, the text passes with a warning.
  blockAt: 3,
  // Categories to ignore entirely, e.g. ["pii"] for an internal tool.
  ignoreCategories: [],
  // Optional topic allowlist. If set, input with none of these words is "off_topic" (severity 1).
  topics: null,
  maxInputChars: 8000,
  redactWith: "[REDACTED]",
  // Also scan unicode-folded, de-spaced, leetspeak, ROT13 and base64/hex-decoded variants of the input.
  scanVariants: true,
};

export function createGuard(policy = {}) {
  const p = { ...DEFAULT_POLICY, ...policy };
  const skip = new Set(p.ignoreCategories);

  function run(rules, text) {
    const findings = [];
    for (const rule of rules) {
      if (skip.has(rule.category)) continue;
      const re = new RegExp(rule.pattern.source, rule.pattern.flags.replace("g", "") + "g");
      for (const m of text.matchAll(re)) {
        if (rule.check && !rule.check(m[0])) continue;
        findings.push({
          id: rule.id,
          category: rule.category,
          severity: rule.severity,
          reason: rule.reason,
          start: m.index,
          end: m.index + m[0].length,
        });
        break; // one finding per rule is enough to act on
      }
    }
    return findings;
  }

  function verdict(findings, text) {
    let top = findings.reduce((s, f) => Math.max(s, f.severity), 0);
    // Two separate medium-severity manipulation signals together are treated as a block.
    const mediums = new Set(findings.filter((f) => f.category === "prompt_injection" && f.severity >= 2).map((f) => f.id));
    if (mediums.size >= 2) top = Math.max(top, p.blockAt);
    return {
      allowed: top < p.blockAt,
      severity: top,
      findings: findings.map(({ start, end, snippet, ...f }) => ({ ...f, snippet: snippet ?? text.slice(start, Math.min(end, start + 60)) })),
      categories: [...new Set(findings.map((f) => f.category))],
      // Gray zone: a manipulation-type rule fired but not hard enough to block. Pattern matches on
      // secrets and PII are already decisive, so only these categories are worth a model call.
      needsJudge: findings.some((f) => f.severity < p.blockAt && JUDGEABLE.has(f.category)),
    };
  }

  function redact(text, findings) {
    const spans = findings
      .filter((f) => f.category === "secret" || f.category === "pii")
      .sort((a, b) => b.start - a.start);
    let out = text;
    for (const s of spans) out = out.slice(0, s.start) + p.redactWith + out.slice(s.end);
    return out;
  }

  function checkInput(text) {
    const t = String(text ?? "");
    const findings = [...run(SECRET_RULES, t), ...run(PII_RULES, t)];
    // Manipulation rules also run on cleaned-up and decoded variants of the text.
    const seen = new Set();
    for (const v of variants(t)) {
      if (p.scanVariants === false && v.via !== "original") continue;
      for (const f of run([...INPUT_RULES, ...PARAPHRASE_RULES, ...MULTILINGUAL_RULES], v.text)) {
        if (seen.has(f.id)) continue;
        seen.add(f.id);
        findings.push(v.via === "original" ? f : { ...f, via: v.via, start: 0, end: 0, snippet: v.text.slice(f.start, f.end) });
      }
    }
    if (t.length > p.maxInputChars) {
      findings.push({ id: "in.too-long", category: "size", severity: p.blockAt, reason: `Input is over ${p.maxInputChars} characters.`, start: 0, end: 0 });
    }
    if (p.topics && !skip.has("off_topic")) {
      const lower = t.toLowerCase();
      if (!p.topics.some((w) => lower.includes(String(w).toLowerCase()))) {
        findings.push({ id: "in.off-topic", category: "off_topic", severity: 1, reason: "None of the allowed topic words appear.", start: 0, end: 0 });
      }
    }
    return verdict(findings, t);
  }

  function checkOutput(text) {
    const t = String(text ?? "");
    const findings = run(OUTPUT_RULES, t);
    const v = verdict(findings, t);
    v.redacted = redact(t, findings);
    return v;
  }

  return { checkInput, checkOutput, policy: p };
}

export { INPUT_RULES, PARAPHRASE_RULES, MULTILINGUAL_RULES, SECRET_RULES, PII_RULES, OUTPUT_RULES };
