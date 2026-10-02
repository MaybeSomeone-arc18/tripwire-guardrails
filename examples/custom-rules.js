// Add your own rules. They run next to the built-in ones.
import { createGuard } from "tripwire-guardrails";

const guard = createGuard({
  rules: [
    { id: "acme.internal-host", category: "secret", severity: 3, pattern: /\b[\w-]+\.corp\.acme\.internal\b/i, reason: "Internal hostname.", direction: "both" },
    { id: "acme.competitor", category: "off_topic", severity: 1, pattern: /\bglobex\b/i, reason: "Mentions a competitor." },
  ],
});
console.log(guard.checkOutput("Deploy it on build-7.corp.acme.internal").redacted);
console.log(guard.checkInput("what does Globex charge?").findings.map((f) => f.id));
