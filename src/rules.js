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
    id: "inj.exfil-template",
    category: "prompt_injection",
    severity: 3,
    pattern: /!\[[^\]]*\]\(https?:\/\/[^)\s]*(\{\{|%7B%7B|\$\{)[^)]*\)/i,
    reason: "Markdown image whose URL carries a template placeholder, a classic data-leak trick.",
  },
  {
    id: "inj.exfil-link",
    category: "prompt_injection",
    severity: 2,
    pattern: /!\[[^\]]*\]\(https?:\/\/[^)\s]*[?&][^)\s]*(\{|%7B|data=|q=)[^)]*\)/i,
    reason: "Markdown image with a query string can leak data when rendered.",
  },
];


// Paraphrases, personas, prompt-extraction and indirect injection (English).
export const PARAPHRASE_RULES = [
  { id: "inj.persona-no-rules", category: "prompt_injection", severity: 3,
    pattern: /\b(ai|assistant|model|bot|chatbot|you)\b[^.\n]{0,40}\b(no rules|without (any )?(restrictions?|limits?|filters?|guardrails?)|no (restrictions?|limits|filters))\b/i,
    reason: "Asks for an assistant with no rules or restrictions." },
  { id: "inj.forget-told", category: "prompt_injection", severity: 3,
    pattern: /\bforget what (the|your) (developer|creator|operator|owner|system) (told|said|gave)\b|\b(disregard|forget|drop|stop following)\b[^.\n]{0,40}\b(told|guidelines?|developer|setup|configuration|instructions?|rules?)\b[^.\n]{0,40}\b(before|earlier|previously|for this|and (reply|answer|say|tell|print|show|output)|new)\b/i,
    reason: "Tries to drop earlier guidance." },
  { id: "inj.rules-void", category: "prompt_injection", severity: 3,
    pattern: /\b(your|all|the)\s+(\w+\s+)?(rules?|guidelines?|guidance|instructions?)\s+(are|is)?\s*(now\s+)?(void|null|cancelled|canceled|no longer (apply|applies|valid))\b|\bno longer applies?\b[^.\n]{0,30}\b(guidance|rules?|instructions?)\b|\b(guidance|rules?|instructions?)\b[^.\n]{0,30}\bno longer apply\b/i,
    reason: "Declares the earlier rules void." },
  { id: "inj.clean-slate", category: "prompt_injection", severity: 2,
    pattern: /\b(start over|reset)\b[^.\n]{0,30}\b(clean slate|from scratch|fresh)\b[^.\n]{0,80}\b(earlier|previous|prior|your)\b/i,
    reason: "Frames a reset of the assistant's earlier setup." },
  { id: "inj.new-orders", category: "prompt_injection", severity: 2,
    pattern: /\bnew (orders|instructions|policy|rules)\s*:/i,
    reason: "Announces replacement orders." },
  { id: "inj.extract-config", category: "prompt_injection", severity: 3,
    pattern: /\b(exact words|verbatim|word for word|in full|quote|repeat back|write out|list every)\b[^.\n]{0,80}\b(message|prompt|instructions?|rules?|guidelines?|setup|configuration)\b[^.\n]{0,40}\b(configured|gave|given|told|set up|you had|you were|you received|original)\b|\b(configured|gave|given|told) you\b[^.\n]{0,60}\b(exact words|verbatim|quote|in full)\b|\b(original|initial|hidden|developer)\s+(instructions?|setup|prompt|message)\b[^.\n]{0,30}\b(word for word|verbatim|in full)\b|\bwhat were the (exact )?words\b[^.\n]{0,60}\bconfigured you\b/i,
    reason: "Tries to extract the assistant's hidden configuration." },
  { id: "inj.note-to-assistant", category: "prompt_injection", severity: 3,
    pattern: /\b(note|message|instruction)s? (to|for) (the )?(ai|assistant|model|llm|agent)\b[^.\n]{0,60}\b(skip|ignore|instead|send|forward|do not|don't)\b/i,
    reason: "Text addressed to the assistant inside content (indirect injection)." },
  { id: "inj.send-data-out", category: "prompt_injection", severity: 3,
    pattern: /\b(send|forward|email|post|upload)\b[^.\n]{0,40}\b(saved notes|chat history|conversation|user'?s? (data|notes|messages)|memory|system prompt)\b[^.\n]{0,40}\b(to|at)\b[^.\n]{0,20}(https?:\/\/|[\w.+-]+@[\w-]+\.|address below)/i,
    reason: "Asks the assistant to send private data to an outside address." },
  { id: "inj.obey-fully", category: "prompt_injection", severity: 2,
    pattern: /\byou must (now )?obey\b|\bobey the user (fully|completely)\b/i,
    reason: "Demands unconditional obedience." },
];

// Other languages. Each pattern pairs an ignore-verb with an instructions-noun in the same language.
export const MULTILINGUAL_RULES = [
  { id: "inj.es", category: "prompt_injection", severity: 3,
    pattern: /\b(ignora|olvida|descarta)\b[^.\n]{0,40}\b(instrucciones|reglas)\b|\b(muestra|revela|imprime)\b[^.\n]{0,30}\b(prompt del sistema|instrucciones ocultas)\b/iu,
    reason: "Instruction override or prompt extraction (Spanish)." },
  { id: "inj.fr", category: "prompt_injection", severity: 3,
    pattern: /\b(ignore|oublie|ignorez)\s+(?:tout(?:es)?\s+)?(?:les|vos|ces|mes|toutes)\b[^.\n]{0,40}\b(instructions|règles)\b|\b(révèle|montre|affiche)\b[^.\n]{0,30}\b(prompt système|instructions cachées)\b/iu,
    reason: "Instruction override or prompt extraction (French)." },
  { id: "inj.de", category: "prompt_injection", severity: 3,
    pattern: /\b(ignoriere|vergiss|missachte)\b[^.\n]{0,40}\b(anweisungen|regeln)\b|\b(zeige|verrate|gib)\b[^.\n]{0,30}\b(system-?prompt)\b/iu,
    reason: "Instruction override or prompt extraction (German)." },
  { id: "inj.hi-deva", category: "prompt_injection", severity: 3,
    pattern: /(निर्देश|नियम)[^\n।.]{0,30}(अनदेखा|नज़रअंदाज़|नजरअंदाज|भूल)|(अनदेखा|नज़रअंदाज़|नजरअंदाज|भूल)[^\n।.]{0,30}(निर्देश|नियम)|सिस्टम\s*प्रॉम्प्ट[^\n।.]{0,20}(दिखा|बता|प्रिंट)/u,
    reason: "Instruction override or prompt extraction (Hindi)." },
  { id: "inj.hinglish", category: "prompt_injection", severity: 3,
    pattern: /\b(instructions?|rules?|niyam)\b[^.\n]{0,30}\b(ignore\s+(?:karo|kar\s+do)|bhool|bhul)\b|\b(ignore\s+(?:karo|kar\s+do)|bhool|bhul)\s*(?:jao|ja)?\b[^.\n]{0,30}\b(instructions?|rules?)\b|\bsystem prompt\b[^.\n]{0,20}\b(batao|bata do|dikhao|print karo)\b|\bhidden instructions?\b[^.\n]{0,40}\b(print|batao|dikhao)\b/i,
    reason: "Instruction override or prompt extraction (Hinglish)." },
  { id: "inj.zh", category: "prompt_injection", severity: 3,
    pattern: /忽略[^\n。]{0,12}(指令|提示|规则)|(显示|透露|输出)[^\n。]{0,10}(系统提示|系统提示词)/u,
    reason: "Instruction override or prompt extraction (Chinese)." },
];

export const SECRET_RULES = [
  { id: "sec.aws-access-key", category: "secret", severity: 3, pattern: /\bAKIA[0-9A-Z]{16}\b/, reason: "Looks like an AWS access key id." },
  { id: "sec.github-token", category: "secret", severity: 3, pattern: /\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b|\bgithub_pat_[A-Za-z0-9_]{40,}\b/, reason: "Looks like a GitHub token." },
  { id: "sec.google-api-key", category: "secret", severity: 3, pattern: /\bAIza[0-9A-Za-z_-]{35}\b/, reason: "Looks like a Google API key." },
  { id: "sec.openai-style-key", category: "secret", severity: 3, pattern: /\bsk-[A-Za-z0-9_-]{20,}/, reason: "Looks like a secret API key (sk-...)." },
  { id: "sec.slack-token", category: "secret", severity: 3, pattern: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/, reason: "Looks like a Slack token." },
  { id: "sec.private-key", category: "secret", severity: 3, pattern: /-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/, reason: "Contains a private key block." },
  { id: "sec.jwt", category: "secret", severity: 2, pattern: /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/, reason: "Looks like a JSON web token." },
];

export const PII_RULES = [
  { id: "pii.email", category: "pii", severity: 1, pattern: /\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,24}\b/, reason: "Email address." },
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
