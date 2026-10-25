import { execSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { build } from "esbuild";
import { beforeAll, describe, expect, it } from "vitest";

/**
 * A Convex function that resolves a machine caller must be able to import the
 * resolver WITHOUT the root index: the root re-exports `clerk-handshake`,
 * which pulls `@clerk/backend` into the Convex bundle. `./machine-caller` is
 * the narrow subpath. Measured with esbuild from the published `exports` map,
 * the same way as the `./org-guard` subpath test.
 */

const REPO_ROOT = resolve(__dirname, "..");
const PKG = JSON.parse(
	readFileSync(resolve(REPO_ROOT, "package.json"), "utf-8"),
);
const ENTRY = "resolveConvexMachineCallerFromDigest";

async function bundle(spec: string) {
	const r = await build({
		stdin: {
			contents: `import { ${ENTRY} } from "${spec}"; export const f = ${ENTRY};`,
			resolveDir: REPO_ROOT,
			loader: "js",
		},
		bundle: true,
		write: false,
		platform: "neutral",
		format: "esm",
		metafile: true,
		logLevel: "silent",
		mainFields: ["module", "main"],
		conditions: ["import"],
	});
	const inputs = Object.keys(r.metafile.inputs);
	return {
		bytes: r.outputFiles[0].contents.length,
		clerk: inputs.filter((i) => i.includes("@clerk")),
		inputs,
	};
}

beforeAll(() => {
	const built = resolve(REPO_ROOT, "dist/machine-caller.js");
	// Build when dist is absent or predates the digest entry point.
	if (!existsSync(built) || !readFileSync(built, "utf-8").includes(ENTRY)) {
		execSync("npx tsc", { cwd: REPO_ROOT, stdio: "ignore" });
	}
});

describe("./machine-caller subpath", () => {
	it("the exports map declares ./machine-caller -> dist/machine-caller.{js,d.ts}", () => {
		expect(PKG.exports["./machine-caller"]).toEqual({
			types: "./dist/machine-caller.d.ts",
			import: "./dist/machine-caller.js",
		});
	});

	it("the exports map declares ./presented-bearer -> dist/presented-bearer.{js,d.ts}", () => {
		expect(PKG.exports["./presented-bearer"]).toEqual({
			types: "./dist/presented-bearer.d.ts",
			import: "./dist/presented-bearer.js",
		});
	});

	it("a narrow import of the digest machine-caller entry bundles no @clerk module", async () => {
		const narrow = await bundle("@vantageos/cloud-identity/machine-caller");
		expect(narrow.clerk).toEqual([]);
		expect(narrow.inputs.every((i) => !/clerk-handshake/.test(i))).toBe(true);
	});

	it("the root import still resolves and is the costly path the subpath avoids", async () => {
		const root = await bundle("@vantageos/cloud-identity");
		const narrow = await bundle("@vantageos/cloud-identity/machine-caller");
		expect(root.clerk.length).toBeGreaterThan(0);
		expect(narrow.bytes).toBeLessThan(root.bytes);
	});

	it("both paths hand out the SAME functions (behaviour unchanged)", async () => {
		const rootMod = await import("../dist/index.js");
		const narrowMod = await import("../dist/machine-caller.js");
		expect(typeof narrowMod.resolveConvexMachineCallerFromDigest).toBe(
			"function",
		);
		expect(narrowMod.resolveConvexMachineCallerFromDigest).toBe(
			rootMod.resolveConvexMachineCallerFromDigest,
		);
		expect(narrowMod.resolveConvexMachineCaller).toBe(
			rootMod.resolveConvexMachineCaller,
		);
	});
});
