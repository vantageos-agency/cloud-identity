// Marks dist/cjs as CommonJS. The package root is "type": "module", so without
// this marker Node and TypeScript would read dist/cjs/*.js and *.d.ts as ESM.
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const target = resolve(dirname(fileURLToPath(import.meta.url)), "..", "dist", "cjs", "package.json");
mkdirSync(dirname(target), { recursive: true });
writeFileSync(target, `${JSON.stringify({ type: "commonjs" }, null, 2)}\n`);
