// Text variants for scanning. Attackers rarely type the plain phrase, so the rules also run on
// cleaned-up and decoded versions of the input. Every variant is derived from the same text;
// nothing is fetched or executed.

const ZERO_WIDTH = /[\u00ad\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff]/g;

// Cyrillic and Greek letters that look like Latin ones.
const CONFUSABLES = {
  а: "a", е: "e", о: "o", р: "p", с: "c", у: "y", х: "x", і: "i", ј: "j", ѕ: "s", һ: "h", ԁ: "d", ɡ: "g",
  А: "A", В: "B", Е: "E", К: "K", М: "M", Н: "H", О: "O", Р: "P", С: "C", Т: "T", Х: "X",
  ο: "o", ν: "v", ι: "i", α: "a", ρ: "p", τ: "t", Ο: "O", Α: "A", Β: "B", Ε: "E", Ι: "I",
};

const LEET = { 0: "o", 1: "i", 3: "e", 4: "a", 5: "s", 7: "t", "@": "a", $: "s" };

export function stripInvisible(text) {
  return text.replace(ZERO_WIDTH, "");
}

export function foldConfusables(text) {
  return [...text].map((c) => CONFUSABLES[c] ?? c).join("");
}

// "i g n o r e" -> "ignore"; "ignore-all-previous" -> "ignore all previous"
export function unspace(text) {
  const joined = text.replace(/\b(?:[A-Za-z] ){3,}[A-Za-z]\b/g, (m) => m.replace(/ /g, ""));
  return joined.replace(/(?<=[A-Za-z])[-_.](?=[A-Za-z])/g, " ");
}

// Only touches words that mix letters and digits, so "4111 1111" and plain numbers stay as they are.
export function deleet(text) {
  return text.replace(/\b[\p{L}\d@$]{3,}\b/gu, (w) => {
    if (!/[A-Za-z]/.test(w) || !/[\d@$]/.test(w)) return w;
    return [...w].map((c) => LEET[c] ?? c).join("");
  });
}

export function rot13(text) {
  return text.replace(/[A-Za-z]/g, (c) => {
    const base = c <= "Z" ? 65 : 97;
    return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base);
  });
}

function printable(s) {
  return s.length >= 8 && /^[\x09\x0a\x0d\x20-\x7e]+$/.test(s);
}

export function decodeSegments(text) {
  const out = [];
  for (const m of text.matchAll(/[A-Za-z0-9+/_-]{24,}={0,2}/g)) {
    try {
      const s = Buffer.from(m[0].replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8");
      if (printable(s)) out.push({ via: "base64", text: s });
    } catch { /* not base64 */ }
  }
  for (const m of text.matchAll(/\b(?:[0-9a-fA-F]{2}){12,}\b/g)) {
    try {
      const s = Buffer.from(m[0], "hex").toString("utf8");
      if (printable(s)) out.push({ via: "hex", text: s });
    } catch { /* not hex */ }
  }
  return out;
}

// Returns [{via, text}] with the original first. Duplicates are dropped.
export function variants(text) {
  const base = stripInvisible(text.normalize("NFKC"));
  const folded = foldConfusables(base);
  const list = [
    { via: "original", text },
    { via: "normalized", text: unspace(folded) },
    { via: "leetspeak", text: unspace(deleet(folded)) },
    { via: "rot13", text: rot13(folded) },
  ];
  for (const d of decodeSegments(folded)) list.push({ via: d.via, text: unspace(foldConfusables(d.text)) });
  const seen = new Set();
  return list.filter((v) => (seen.has(v.text) ? false : seen.add(v.text)));
}
