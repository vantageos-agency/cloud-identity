/**
 * The typecheck covers every TypeScript file in the repository (ported from the boilerplate; task k174jk4q83hxg0nrexmeg3pdpn8js6t3).
 *
 * `npm run typecheck` runs `tsc -p tsconfig.check.json`. A file outside that project's file set is
 * never typechecked, and a type error in it passes the build, the typecheck and the suite. The set
 * this test compares against is derived from the disk (every .ts, .tsx, .mts and .cts file outside
 * node_modules, dist and coverage), never from a hand-written list, so a new directory or a new
 * extension is covered or named here without editing anything.
 *
 * The disk is walked rather than `git ls-files` read: a checkout exported without .git must still
 * be judged, not refused.
 */
import { execFileSync } from "node:child_process";
import { readdirSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const SKIPPED_DIRS = new Set(["node_modules", "dist", "coverage", ".git"]);
const TS_FILE = /\.(ts|tsx|mts|cts)$/;

function typeScriptFilesOnDisk(dir: string): string[] {
  const found: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      if (!SKIPPED_DIRS.has(entry.name))
        found.push(...typeScriptFilesOnDisk(join(dir, entry.name)));
    } else if (TS_FILE.test(entry.name)) {
      found.push(relative(ROOT, join(dir, entry.name)));
    }
  }
  return found;
}

function filesInCheckProject(): Set<string> {
  const tsc = join(ROOT, "node_modules", "typescript", "bin", "tsc");
  const out = execFileSync(
    process.execPath,
    [tsc, "-p", "tsconfig.check.json", "--listFilesOnly"],
    {
      cwd: ROOT,
      encoding: "utf8",
    }
  );
  return new Set(
    out
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => line.length > 0)
      .map((line) => relative(ROOT, line))
      .filter((path) => !path.startsWith("..") && !path.split("/").includes("node_modules"))
  );
}

describe("typecheck coverage", () => {
  it("every TypeScript file on disk is in the typecheck project", () => {
    const onDisk = typeScriptFilesOnDisk(ROOT);
    // Positive control: the walk reads this very file, so an empty walk can never pass as "covered".
    expect(onDisk).toContain("test/typecheck-coverage.test.ts");
    const checked = filesInCheckProject();
    const uncovered = onDisk.filter((path) => !checked.has(path));
    expect(uncovered, `not typechecked by tsconfig.check.json: ${uncovered.join(", ")}`).toEqual(
      []
    );
  }, 60_000);
});
