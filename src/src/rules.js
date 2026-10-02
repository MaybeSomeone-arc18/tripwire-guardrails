// Each rule: id, category, severity (1 low .. 3 block), pattern, and a short reason.
// Rules are plain data so you can copy one, tweak it, or delete it.

export const INPUT_RULES = [
  {
    id: "inj.ignore-previous",
    category: "prompt_injection",
    severity: 3,
    pattern: /\b(ignore|disregard|forget|override)\b[^.\n]{0,40}\b(previous|prior|above|earlier|all|system)\b[^.\n]{0,30}\b(instructions?|prompts?|rules?|messages?)\b/i,
    reason: "Tries to cancel earlier instructions.",
  },
  {
    id: "inj.reveal-system-prompt",
    category: "prompt_injection",
    severity: 3,
    pattern: /\b(reveal|show|print|repeat|leak|output)\b[^.\n]{0,40}\b(system|hidden|developer|initial)\s+(prompt|message|instructions?)\b/i,
    reason: "Asks the model to expose its hidden prompt.",
  },
  {
    id: "inj.role-swap",
    category: "prompt_injection",
    severity: 2,
    pattern: /\b(you are now|act as|pretend to be|from now on you)\b[^.\n]{0,60}\b(unrestricted|jailbroken|dan|no rules|without (any )?restrictions?)\b/i,
    reason: "Tries to swap the model into an unrestricted role.",
  },
  {
    id: "inj.fake-delimiter",
    category: "prompt_injection",
    severity: 2,
    pattern: /(<\/?(system|assistant|instructions?)>|\[\/?INST\]|<\|im_(start|end)\|>|^#{2,}\s*system\b)/im,
    reason: "Contains chat-template markers that look like a forged system turn.",
  },
  {
    id: "inj.exfil-link",
    category: "prompt_injection",
    severity: 2,
    pattern: /!\[[^\]]*\]\(https?:\/\/[^)\s]*[?&][^)\s]*(\{|%7B|data=|q=)[^)]*\)/i,
    reason: "Markdown image with a query string can leak data when rendered.",
  },
];

export const SECRET_RULES = [
  { id: "sec.aws-access-key", category: "secret", severity: 3, pattern: /\bAKIA[0-9A-Z]{16}\b/, reason: "Looks like an AWS access key id." },
  { id: "sec.github-token", category: "secret", severity: 3, pattern: /\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b|\bgithub_pat_[A-Za-z0-9_]{40,}\b/, reason: "Looks like a GitHub token." },
  { id: "sec.google-api-key", category: "secret", severity: 3, pattern: /\bAIza[0-9A-Za-z_-]{35}\b/, reason: "Looks like a Google API key." },
  { id: "sec.openai-style-key", category: "secret", severity: 3, pattern: /\bsk-[A-Za-z0-9_-]{20,}\b/, reason: "Looks like a secret API key (sk-...)." },
  { id: "sec.slack-token", category: "secret", severity: 3, pattern: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/, reason: "Looks like a Slack token." },
  { id: "sec.private-key", category: "secret", severity: 3, pattern: /-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/, reason: "Contains a private key block." },
  { id: "sec.jwt", category: "secret", severity: 2, pattern: /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/, reason: "Looks like a JSON web token." },
];

export const PII_RULES = [
  { id: "pii.email", category: "pii", severity: 1, pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/, reason: "Email address." },
  { id: "pii.phone-in", category: "pii", severity: 1, pattern: /(?<!\d)(?:\+91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}(?!\d)/, reason: "Indian mobile number." },
  { id: "pii.aadhaar", category: "pii", severity: 3, pattern: /(?<!\d[ -]?)[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}(?![ -]?\d)/, reason: "12-digit number that passes the Aadhaar (Verhoeff) check.", check: verhoeff },
  { id: "pii.pan", category: "pii", severity: 2, pattern: /\b[A-Z]{5}\d{4}[A-Z]\b/, reason: "Shaped like an Indian PAN." },
  { id: "pii.card", category: "pii", severity: 3, pattern: /(?<!\d)(?:\d[ -]?){13,19}(?!\d)/, reason: "Digit run that may be a card number (Luhn checked).", check: luhn },
];

const D = [[0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],[3,4,0,1,2,8,9,5,6,7],[4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],[6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],[8,7,6,5,9,3,2,1,0,4],[9,8,7,6,5,4,3,2,1,0]];
const P = [[0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],[8,9,1,6,0,4,3,5,2,7],[9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],[2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]];

function verhoeff(match) {
  const digits = match.replace(/\D/g, "");
  if (digits.length !== 12) return false;
  let c = 0;
  [...digits].reverse().forEach((ch, i) => { c = D[c][P[i % 8][Number(ch)]]; });
  return c === 0;
}

function luhn(match) {
  const digits = match.replace(/\D/g, "");
  if (digits.length < 13 || digits.length > 19) return false;
  let sum = 0;
  let alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = Number(digits[i]);
    if (alt) { n *= 2; if (n > 9) n -= 9; }
    sum += n;
    alt = !alt;
  }
  return sum % 10 === 0;
}

export const OUTPUT_RULES = [
  ...SECRET_RULES,
  ...PII_RULES,
  {
    id: "out.system-prompt-echo",
    category: "prompt_leak",
    severity: 3,
    pattern: /\b(my|the) (system|hidden) (prompt|instructions?) (is|are|says?|reads?)\b/i,
    reason: "Output claims to quote its system prompt.",
  },
];
