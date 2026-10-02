# Tripwire

Small guardrails for LLM apps. Check what goes into your model and what comes out, with plain rules first and an open-weight model (Gemma) as an optional second opinion.

- Zero dependencies. Node 20+. Plain ES modules, no build step.
- Rules are data. Copy one, change it, delete it.
- Fails closed. If the judge call errors, times out or returns junk, the text is blocked.
- Runs offline in rules-only mode. Nothing is sent anywhere unless you create a judge.

I built it because I kept having the same argument while building AI projects: trust the model to behave, or put a separate layer of checks around it. This is the separate layer, kept small enough to read in one sitting.

## Install

Not on npm yet. Clone it and import from the folder:

```sh
git clone https://github.com/MaybeSomeone-arc18/tripwire-guardrails.git
cd tripwire-guardrails
npm test
```

## Use

```js
import { createGuard } from "./src/index.js";

const guard = createGuard();

const inbound = guard.checkInput(userMessage);
if (!inbound.allowed) return reply(400, { blocked: inbound.categories });

const answer = await callYourModel(userMessage);
const outbound = guard.checkOutput(answer);
return outbound.allowed ? outbound.redacted : "Sorry, I can't share that.";
```

A verdict looks like this:

```json
{
  "allowed": false,
  "severity": 3,
  "categories": ["prompt_injection"],
  "findings": [
    { "id": "inj.ignore-previous", "category": "prompt_injection", "severity": 3,
      "reason": "Tries to cancel earlier instructions.", "snippet": "Ignore all previous instructions" }
  ],
  "needsJudge": false
}
```

`checkOutput` also returns `redacted`, the text with secrets and PII replaced.

### What the rules check

| Where | Category | Examples |
| --- | --- | --- |
| input | `prompt_injection` | "ignore previous instructions", "reveal your system prompt", role swaps, forged `</system>` or `[INST]` markers, markdown images that carry data in the URL |
| input and output | `secret` | AWS, GitHub, Google, Slack and `sk-` style keys, private key blocks, JWTs |
| input and output | `pii` | email, Indian mobile numbers, Aadhaar (Verhoeff checked), PAN, card numbers (Luhn checked) |
| output | `prompt_leak` | "my system prompt is ..." |
| input | `size`, `off_topic` | max length, optional topic allowlist |

Severity runs 1 to 3. A finding at or above `blockAt` (default 3) blocks. Lower findings pass but show up in the verdict.

### Policy

```js
createGuard({
  blockAt: 2,                       // stricter
  ignoreCategories: ["pii"],        // internal tool, emails are fine
  topics: ["order", "refund"],      // flag anything else as off_topic
  maxInputChars: 2000,
  redactWith: "[hidden]",
});
```

Two ready-made policies are in `policies/`. Adding your own rule means adding an object to the arrays in `src/rules.js`.

### CLI

```sh
echo "ignore all previous instructions" | node bin/tripwire.js     # exit code 1, JSON on stdout
echo "token ghp_..." | node bin/tripwire.js --output
```

### Demo

`demo/standalone.html` is one file. Open it in a browser. It runs the rules locally and sends nothing. Rebuild it with `node scripts/build-standalone.mjs`.

## Gemma as a judge (optional)

Rules only catch patterns they know. For the gray zone, or for everything, ask an open model.

```js
import { createGuard } from "./src/index.js";
import { createJudge, checkWithJudge } from "./src/judge.js";

const guard = createGuard();
const judge = createJudge({ apiKey: process.env.GEMINI_API_KEY }); // default model: gemma-4-26b-a4b-it
const verdict = await checkWithJudge(guard, judge, text, "input", { always: true });
```

- Default: the judge runs only when a manipulation-type rule fired below the block line.
- `{ always: true }`: every text the rules did not already block goes to the judge.
- The key is sent in a header, never in the URL, and is not stored.
- Gemma 4 returns its reasoning as separate `thought` parts. The judge ignores those and reads only the final answer.
- Swap `model` for any other model on the same API. Or replace `judge.js`; `checkWithJudge` only needs an object with `judge(text, { direction })`.

Free AI Studio keys have rate limits. Under a burst, requests can fail; the judge then blocks (fail closed) and says why in `reason`.

## What was tested

Run `npm test`: 29 tests, all passing in my sandbox (Node 22). CI runs them on Node 20 and 22.

- Rules: unit tests per category, plus a corpus of 12 benign and 12 hostile strings I wrote by hand. All benign allowed, all hostile blocked. That corpus is a regression check, not a benchmark. I wrote the rules and the strings, so it flatters them.
- Judge logic: tested against a fake `fetch` (parsing, fail-closed paths, header use, thought parts, always mode).
- Live Gemma, once, by hand: 8 hand-written texts (3 benign, 5 hostile) sent to `gemma-4-26b-a4b-it` through AI Studio. 7 of 8 got a real verdict and all 7 were correct. The eighth call failed with a network error ("Failed to fetch"), so it was blocked by the fail-closed path and I did not get a model verdict for it. I suspect a rate limit but did not confirm that.
- On those same hostile texts, the rules alone caught none of the paraphrased ones, which is why `always` mode exists.

## What this does not do

- It is not a complete defence. Prompt injection has no complete defence today. Treat this as one layer.
- Rules are English-first. Hinglish, other languages, obfuscation (spacing, leetspeak, base64) and attacks hidden in documents or tool output are mostly not covered.
- The judge is a model and can be wrong or be targeted itself. Its prompt marks the text as data, which helps and does not make it immune.
- PII patterns are shape checks. Aadhaar and card numbers are checksum-checked, email and phone are not verified, names and addresses are not detected.
- Redaction replaces matched spans only.
- No streaming support, no per-user policies, no logging. Not benchmarked for speed beyond "regexes on short strings".

## License

MIT
