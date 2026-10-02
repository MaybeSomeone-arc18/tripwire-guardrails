// Fastify: a preHandler hook on the route. npm i fastify && node examples/fastify.js
import Fastify from "fastify";
import { createGuard } from "tripwire-guardrails";

const guard = createGuard();
const app = Fastify();

app.post("/chat", {
  preHandler: async (req, reply) => {
    const v = guard.checkInput(req.body?.message);
    if (!v.allowed) return reply.code(400).send({ error: "message blocked", categories: v.categories });
  },
}, async (req) => {
  const out = guard.checkOutput(`echo: ${req.body.message}`);
  return { reply: out.allowed ? out.redacted : "Sorry, I can't share that." };
});

await app.listen({ port: Number(process.env.PORT ?? 3001) });
console.log("listening");
