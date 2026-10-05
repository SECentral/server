import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const indexFile = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "public", "spa", "index.html");
const html = readFileSync(indexFile, "utf8");

const inlineScripts = [...html.matchAll(/<script(?![^>]*\bsrc=)[^>]*>/g)];
const inlineStyles = [...html.matchAll(/<style[^>]*>/g)];

if (inlineScripts.length > 0 || inlineStyles.length > 0) {
  console.error(
    `Build guard failed: ${inlineScripts.length} inline script(s) and ${inlineStyles.length} inline style(s) in ${indexFile}. ` +
      "The deployment CSP (script-src 'self') forbids them."
  );
  process.exit(1);
}

console.log("Build guard passed: no inline scripts or styles in index.html.");
