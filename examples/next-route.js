// Next.js App Router: save as app/api/chat/route.js. It uses only the Web Request/Response API,
// so the same handler runs on Node, Deno, Bun and edge runtimes (tripwire has no Node-only imports).
import { createGuard } from "tripwire-guardrails";

const guard = createGuard();

export async function POST(request) {
  const { message } = await request.json();
  const v = guard.checkInput(message);
  if (!v.allowed) return Response.json({ error: "message blocked", categories: v.categories }, { status: 400 });
  const reply = `echo: ${message}`; // call your model here
  const out = guard.checkOutput(reply);
  return Response.json({ reply: out.allowed ? out.redacted : "Sorry, I can't share that." });
}
