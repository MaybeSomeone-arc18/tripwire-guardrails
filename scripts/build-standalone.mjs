// Inlines the demo and the library into one HTML file you can open with a double click.
import { readFileSync, writeFileSync } from "node:fs";
const strip = (s) => s.replace(/^import .*$/gm, "").replace(/^export \{[^}]*\};?$/gm, "").replace(/^export /gm, "");
const lib = ["src/normalize.js", "src/rules.js", "src/index.js", "src/judge.js"].map((f) => strip(readFileSync(f, "utf8"))).join("\n");
const css = readFileSync("demo/style.css", "utf8");
const app = readFileSync("demo/app.js", "utf8");
let html = readFileSync("demo/index.html", "utf8");
html = html.replace('<link rel="stylesheet" href="style.css">', `<style>${css}</style>`);
html = html.replace(/<script type="module">[\s\S]*<\/script>/, `<script>\n${lib}\n${app}\n</script>`);
writeFileSync("demo/standalone.html", html);
console.log("wrote demo/standalone.html", html.length, "bytes");
