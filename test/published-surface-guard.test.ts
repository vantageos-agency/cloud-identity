import { describe, it, expect, beforeAll } from "vitest";
import { execSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

/**
 * Guards the published npm tarball, not the whole repository.
 *
 *   (a) reads the PACKED file list via `npm pack --dry-run --json`
 *       (never the repo tree — files excluded by "files" / .npmignore must
 *       not fail this test, and files included must not escape it either).
 *   (b) asserts no packed file carries a derivable internal reference:
 *       a bare 32-hex id, a sprint identifier (S3.1, B2...), an absolute
 *       /root or /home path, or a path traversing another repo
 *       (vantage-memory/, mcp-server/).
 *   (c) asserts every symbol the built bundle actually exports (parsed from
 *       dist/index.d.ts, not a hand-typed list) is named in README.md.
 */

const REPO_ROOT = resolve(__dirname, "..");

// ---------------------------------------------------------------------------
// Shared detector — exercised against real files AND, for the positive
// control, against an in-memory synthetic file so the detector itself is
// proven sensitive without mutating anything on disk.
// ---------------------------------------------------------------------------

interface InternalReferenceMatch {
  path: string;
  pattern: string;
  snippet: string;
}

const INTERNAL_REFERENCE_PATTERNS: Array<{ name: string; re: RegExp }> = [
  { name: "bare-32-hex-id", re: /\b[a-z0-9]{32}\b/ },
  { name: "sprint-identifier", re: /\b[SB]\d+(?:\.\d+)?\b/ },
  { name: "absolute-root-or-home-path", re: /(?:^|[\s"'`(])\/(?:root|home)\// },
  { name: "other-repo-path", re: /vantage-memory\/|mcp-server\// },
];

function findInternalReferences(
  files: Array<{ path: string; content: string }>,
): InternalReferenceMatch[] {
  const hits: InternalReferenceMatch[] = [];
  for (const file of files) {
    for (const { name, re } of INTERNAL_REFERENCE_PATTERNS) {
      const m = file.content.match(re);
      if (m) {
        hits.push({ path: file.path, pattern: name, snippet: m[0] });
      }
    }
  }
  return hits;
}

// Text-ish extensions only — binary packed content (there is none today, but
// this guards against a future binary asset short-circuiting the scan).
const TEXT_EXTENSIONS = [".md", ".json", ".ts", ".js", ".map"];

function isTextFile(path: string): boolean {
  return TEXT_EXTENSIONS.some((ext) => path.endsWith(ext));
}

function getPackedFiles(): string[] {
  const json = execSync("npm pack --dry-run --json", {
    cwd: REPO_ROOT,
    encoding: "utf-8",
  });
  const parsed = JSON.parse(json) as Array<{ files: Array<{ path: string }> }>;
  return parsed[0].files.map((f) => f.path);
}

describe("published-surface guard", () => {
  let packedPaths: string[];

  beforeAll(() => {
    // Assertion (c) reads the REAL bundle surface from dist/index.d.ts —
    // build fresh so this test never depends on a stale or absent dist/.
    execSync("npm run build", { cwd: REPO_ROOT, stdio: "pipe" });
    packedPaths = getPackedFiles();
  }, 60_000);

  it("packs README.md (sanity check for the rest of this suite)", () => {
    expect(packedPaths).toContain("README.md");
  });

  it("(b) contains no internal reference in any packed file", () => {
    const files = packedPaths
      .filter(isTextFile)
      .map((path) => ({
        path,
        content: readFileSync(resolve(REPO_ROOT, path), "utf-8"),
      }));

    const hits = findInternalReferences(files);

    expect(
      hits,
      hits
        .map((h) => `${h.path}: ${h.pattern} -> "${h.snippet}"`)
        .join("\n"),
    ).toEqual([]);
  });

  it("(b) positive control: the detector CAN catch a planted internal reference", () => {
    const files = packedPaths
      .filter(isTextFile)
      .map((path) => ({
        path,
        content: readFileSync(resolve(REPO_ROOT, path), "utf-8"),
      }));

    // RED: an in-memory copy with a fake 32-char id planted in one file.
    // Nothing on disk is touched — this proves detector sensitivity without
    // any risk of leaving the repository dirty.
    const poisoned = files.map((f, i) =>
      i === 0
        ? { ...f, content: `${f.content}\n// id abcdef0123456789abcdef0123456789\n` }
        : f,
    );
    const redHits = findInternalReferences(poisoned);
    expect(redHits.length).toBeGreaterThan(0);
    expect(redHits[0]?.pattern).toBe("bare-32-hex-id");

    // GREEN: the same files, unmodified, restored to their real content.
    const greenHits = findInternalReferences(files);
    expect(greenHits).toEqual([]);
  });

  it("(c) every symbol exported by the built bundle is named in README.md", () => {
    const dts = readFileSync(resolve(REPO_ROOT, "dist/index.d.ts"), "utf-8");
    const readme = readFileSync(resolve(REPO_ROOT, "README.md"), "utf-8");

    // Parse the REAL export surface out of the built declaration file —
    // both `export { a, b }` and `export type { c, d }` blocks — rather than
    // hand-maintaining a symbol list that drifts from the source.
    const exportBlockRe = /export\s+(?:type\s+)?\{([^}]*)\}/g;
    const symbols = new Set<string>();
    let match: RegExpExecArray | null;
    // eslint-disable-next-line no-cond-assign
    while ((match = exportBlockRe.exec(dts)) !== null) {
      const inner = match[1] ?? "";
      for (const rawEntry of inner.split(",")) {
        const entry = rawEntry.trim().replace(/^type\s+/, "").trim();
        if (entry.length > 0) symbols.add(entry);
      }
    }

    expect(symbols.size).toBeGreaterThan(0);

    const missing = [...symbols].filter(
      (sym) => !new RegExp(`\\b${sym}\\b`).test(readme),
    );

    expect(
      missing,
      `symbols exported by dist/index.d.ts but not named in README.md: ${missing.join(", ")}`,
    ).toEqual([]);
  });
});
