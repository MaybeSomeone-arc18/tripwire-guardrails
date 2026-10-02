// Express (and Connect-style) middleware. No dependency on express itself: it only uses req, res, next.
//   app.use(express.json());
//   app.post("/chat", tripwire(guard), handler);
// Input: checks req.body[field] (or getText(req)). A blocked or non-string value gets a 400 and the handler never runs.
// Output: wraps res.json so a string at body[outputField] is checked and redacted before it leaves.
import { checkWithJudge } from "./judge.js";

export function tripwire(guard, {
  field = "message",
  getText,
  outputField = "reply",
  guardOutput = true,
  judge,                          // optional createJudge() result: rules first, then the judge for gray-zone text
  always = false,                 // with a judge: send every rule-passing input to it
  fallback = "Sorry, I can't share that.",
  onBlock,                        // (req, res, verdict) => void, replaces the default 400 JSON
} = {}) {
  const check = async (text, dir) => judge ? checkWithJudge(guard, judge, text, dir, { always }) : (dir === "input" ? guard.checkInput(text) : guard.checkOutput(text));
  return async function tripwireMiddleware(req, res, next) {
    try {
      const raw = getText ? getText(req) : req.body?.[field];
      // A missing text on a GET/HEAD/OPTIONS is normal. On anything else it is blocked, so leaving the field out cannot skip the check.
      if ((raw === undefined || raw === null) && ["GET", "HEAD", "OPTIONS"].includes(req.method)) return next();
      if (typeof raw !== "string") return block(req, res, { allowed: false, categories: ["invalid_input"], findings: [] });
      const v = await check(raw, "input");
      req.tripwire = v;
      if (!v.allowed) return block(req, res, v);
      if (guardOutput) {
        const json = res.json.bind(res);
        res.json = (body) => {
          const out = body?.[outputField];
          if (typeof out !== "string") return json(body);
          const ov = guard.checkOutput(out);
          return json({ ...body, [outputField]: ov.allowed ? ov.redacted : fallback });
        };
      }
      return next();
    } catch (err) {
      // Fail closed: if the check itself throws, the request does not go through.
      return block(req, res, { allowed: false, categories: ["tripwire_error"], findings: [] });
    }
  };
  function block(req, res, v) {
    if (onBlock) return onBlock(req, res, v);
    return res.status(400).json({ error: "message blocked", categories: v.categories });
  }
}
