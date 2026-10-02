// Guard a streamed reply. A key split across chunks is still caught because text is held back briefly.
import { createGuard } from "tripwire-guardrails";
import { createStreamGuard } from "tripwire-guardrails/stream";

const sg = createStreamGuard(createGuard(), { holdBack: 64 });
const chunks = ["Sure, here is the config you asked for. The access key is AKIA", "ABCDEFGHIJKLMNOP and the region is us-east-1. ", "Anything else?"];
let sent = "";
for (const c of chunks) {
  sent += sg.write(c);
  if (sg.blocked) break; // stop sending to the client
}
sent += sg.end();
console.log(JSON.stringify({ sent, blocked: sg.blocked }));
