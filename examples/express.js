// Wrap any chat endpoint: check the user's message in, check the model's reply out.
// Not run in CI (needs express). The same two calls work in any framework.
import express from "express";
import { createGuard } from "../src/index.js";
import policy from "../policies/support-bot.json" with { type: "json" };

const guard = createGuard(policy);
const app = express();
app.use(express.json());

app.post("/chat", async (req, res) => {
  const inbound = guard.checkInput(req.body.message);
  if (!inbound.allowed) return res.status(400).json({ error: "message blocked", categories: inbound.categories });

  const reply = await callYourModel(req.body.message); // your code
  const outbound = guard.checkOutput(reply);
  res.json({ reply: outbound.allowed ? outbound.redacted : "Sorry, I can't share that." });
});

async function callYourModel(message) { return `You said: ${message}`; }
app.listen(3000);
