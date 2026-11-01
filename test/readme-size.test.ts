import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

/**
 * The npm registry truncates a package's `readme` field at 64 KiB, so any
 * README section past that point is invisible on the npm page. This suite
 * keeps README.md under the limit (with headroom) and proves that splitting
 * the long sections out to docs/ lost none of them:
 *
 *   (a) README.md is at most 61440 bytes (60 KiB, 4 KiB under the cut).
 *   (b) every docs/*.md page README.md links to exists, and README links to
 *       docs/ by absolute GitHub URL (a relative link is dead on npm).
 *   (c) every heading of the pre-split README (fixture committed with this
 *       test) appears, at the same level, exactly once across README.md and
 *       docs/*.md — so no section can silently disappear or be duplicated.
 */

const REPO_ROOT = resolve(__dirname, "..");
const README = resolve(REPO_ROOT, "README.md");
const DOCS_DIR = resolve(REPO_ROOT, "docs");
const README_MAX_BYTES = 61440;
const DOCS_URL_PREFIX = "https://github.com/vantageos-agency/cloud-identity/blob/main/docs/";

interface Heading {
  level: number;
  text: string;
}

const fixture = JSON.parse(
  readFileSync(resolve(__dirname, "fixtures/readme-headings.pre-split.json"), "utf-8"),
) as { headings: Heading[] };

/** Markdown headings outside fenced code blocks. */
function headingsOf(markdown: string): Heading[] {
  const out: Heading[] = [];
  let inFence = false;
  for (const line of markdown.split("\n")) {
    if (/^(```|~~~)/.test(line)) {
      inFence = !inFence;
      continue;
    }
    if (inFence) continue;
    const m = /^(#{1,6}) (.+?)\s*$/.exec(line);
    if (m) out.push({ level: m[1].length, text: m[2] });
  }
  return out;
}

function docsPages(): string[] {
  if (!existsSync(DOCS_DIR)) return [];
  return readdirSync(DOCS_DIR).filter((f) => f.endsWith(".md"));
}

describe("README stays inside the npm readme limit", () => {
  const readme = readFileSync(README, "utf-8");

  it(`(a) README.md is at most ${README_MAX_BYTES} bytes`, () => {
    expect(statSync(README).size).toBeLessThanOrEqual(README_MAX_BYTES);
  });

  it("(b) every docs/*.md page linked from README.md exists", () => {
    const linked = [...readme.matchAll(/\]\(([^)\s]*docs\/[^)\s#]+\.md)(?:#[^)\s]*)?\)/g)].map(
      (m) => m[1],
    );
    const missing = linked.filter((href) => {
      const file = href.slice(href.lastIndexOf("docs/") + "docs/".length);
      return !existsSync(resolve(DOCS_DIR, file));
    });
    expect(missing, `README links to absent docs pages: ${missing.join(", ")}`).toEqual([]);
  });

  it("(b) README.md links to docs/ by absolute GitHub URL only", () => {
    const relative = [...readme.matchAll(/\]\(((?:\.\/)?docs\/[^)]*)\)/g)].map((m) => m[1]);
    expect(relative, `relative docs links are dead on npm: ${relative.join(", ")}`).toEqual([]);
    const absolute = [...readme.matchAll(/\]\((https?:\/\/[^)\s]*\/docs\/[^)\s]*)\)/g)].map(
      (m) => m[1],
    );
    const offPrefix = absolute.filter((href) => !href.startsWith(DOCS_URL_PREFIX));
    expect(offPrefix).toEqual([]);
  });

  it("(c) every pre-split heading appears exactly once across README.md and docs/*.md", () => {
    expect(fixture.headings.filter((h) => h.level === 2).length).toBeGreaterThan(0);

    const sources = [
      { name: "README.md", headings: headingsOf(readme) },
      ...docsPages().map((f) => ({
        name: `docs/${f}`,
        headings: headingsOf(readFileSync(resolve(DOCS_DIR, f), "utf-8")),
      })),
    ];

    const problems: string[] = [];
    for (const h of fixture.headings) {
      const holders = sources.filter((s) =>
        s.headings.some((x) => x.level === h.level && x.text === h.text),
      );
      if (holders.length !== 1) {
        problems.push(
          `${"#".repeat(h.level)} ${h.text} -> ${holders.length} holders [${holders
            .map((s) => s.name)
            .join(", ")}]`,
        );
      }
    }
    expect(problems, problems.join("\n")).toEqual([]);
  });

  it("(c) every docs page holding a moved section is linked from README.md", () => {
    const moved = new Set(fixture.headings.map((h) => `${h.level}|${h.text}`));
    const unlinked = docsPages().filter((f) => {
      const holds = headingsOf(readFileSync(resolve(DOCS_DIR, f), "utf-8")).some((h) =>
        moved.has(`${h.level}|${h.text}`),
      );
      return holds && !readme.includes(`${DOCS_URL_PREFIX}${f}`);
    });
    expect(unlinked, `docs pages not reachable from README: ${unlinked.join(", ")}`).toEqual([]);
  });
});
