import { resolve } from "node:path";
import ts from "typescript";
import { beforeAll, describe, expect, it } from "vitest";

/**
 * Property: no function of the principal-by-id API accepts a bare name as an
 * identity input.
 *
 * Read from the EXPORTED SIGNATURES by the TypeScript checker, not from a
 * hand-typed list: every parameter of every exported function, every property
 * of every object type reachable from those parameters (unions, intersections,
 * callback parameters and labelled tuple elements included), and every
 * property of every exported type alias. Any identifier spelled like a name
 * field fails.
 *
 * Bipolar: the same collector is run against the 0.9.0
 * `resolvePersonActingName`, which DOES take names, and must find them, so the
 * detector is proven able to see what it is asked to exclude.
 */

const REPO_ROOT = resolve(__dirname, "..");
const NAME_LIKE = /name|orchestrator|assignedto|createdby/i;

let program: ts.Program;
let checker: ts.TypeChecker;

function moduleExports(relPath: string): ts.Symbol[] {
  const sf = program.getSourceFile(resolve(REPO_ROOT, relPath));
  if (sf === undefined) throw new Error(`not in program: ${relPath}`);
  const moduleSymbol = checker.getSymbolAtLocation(sf);
  if (moduleSymbol === undefined) throw new Error(`no module symbol: ${relPath}`);
  return checker.getExportsOfModule(moduleSymbol);
}

function collectIdentifiers(type: ts.Type, out: Set<string>, seen: Set<ts.Type>): void {
  if (seen.has(type)) return;
  seen.add(type);
  if (type.flags & (ts.TypeFlags.Primitive | ts.TypeFlags.Literal | ts.TypeFlags.Never)) return;
  if (type.isUnionOrIntersection()) {
    for (const t of type.types) collectIdentifiers(t, out, seen);
    return;
  }
  if (checker.isTupleType(type)) {
    const target = (type as ts.TypeReference).target as ts.TupleType;
    for (const decl of target.labeledElementDeclarations ?? []) {
      if (decl !== undefined) out.add(decl.name.getText());
    }
    for (const t of checker.getTypeArguments(type as ts.TypeReference)) {
      collectIdentifiers(t, out, seen);
    }
    return;
  }
  for (const sig of type.getCallSignatures()) collectSignature(sig, out, seen);
  for (const prop of type.getProperties()) {
    out.add(prop.getName());
    const decl = prop.valueDeclaration ?? prop.declarations?.[0];
    if (decl !== undefined) {
      collectIdentifiers(checker.getTypeOfSymbolAtLocation(prop, decl), out, seen);
    }
  }
}

function collectSignature(sig: ts.Signature, out: Set<string>, seen: Set<ts.Type>): void {
  for (const param of sig.getParameters()) {
    out.add(param.getName());
    const decl = param.valueDeclaration ?? param.declarations?.[0];
    if (decl !== undefined) {
      collectIdentifiers(checker.getTypeOfSymbolAtLocation(param, decl), out, seen);
    }
  }
}

/** Identifiers reachable from the inputs of exported functions and exported types. */
function identityInputs(relPath: string, only?: string[]): Set<string> {
  const out = new Set<string>();
  const seen = new Set<ts.Type>();
  for (const sym of moduleExports(relPath)) {
    if (only !== undefined && !only.includes(sym.getName())) continue;
    const resolved = sym.flags & ts.SymbolFlags.Alias ? checker.getAliasedSymbol(sym) : sym;
    const decl = resolved.declarations?.[0];
    if (decl === undefined) continue;
    if (resolved.flags & ts.SymbolFlags.Function) {
      const type = checker.getTypeOfSymbolAtLocation(resolved, decl);
      for (const sig of type.getCallSignatures()) collectSignature(sig, out, seen);
    } else if (resolved.flags & ts.SymbolFlags.TypeAlias) {
      collectIdentifiers(checker.getDeclaredTypeOfSymbol(resolved), out, seen);
    }
  }
  return out;
}

describe("principal-by-id — no exported function accepts a name as identity", () => {
  beforeAll(() => {
    program = ts.createProgram(
      [resolve(REPO_ROOT, "src/principal-by-id.ts"), resolve(REPO_ROOT, "src/person-principal.ts")],
      {
        strict: true,
        target: ts.ScriptTarget.ES2022,
        module: ts.ModuleKind.ESNext,
        moduleResolution: ts.ModuleResolutionKind.Bundler,
        skipLibCheck: true,
        noEmit: true,
      },
    );
    checker = program.getTypeChecker();
  }, 60_000);

  it("the exported functions are the two expected, so the scan is not vacuous", () => {
    const fns = moduleExports("src/principal-by-id.ts")
      .filter((s) => s.flags & ts.SymbolFlags.Function)
      .map((s) => s.getName())
      .sort();
    expect(fns).toEqual(["assertTargetBelongsTo", "resolveActingPrincipal"]);
  });

  it("every identifier reachable from their inputs is an ID, a kind, an option or a door", () => {
    const ids = identityInputs("src/principal-by-id.ts");
    // sanity: the scan reached the credential, the lookups and the target
    for (const expected of ["agentId", "personId", "serviceAccountId", "actingForAgentId", "verifiedOrgId", "agentById", "ownerId", "principalId"]) {
      expect(ids, `scan did not reach ${expected}`).toContain(expected);
    }
    const nameLike = [...ids].filter((id) => NAME_LIKE.test(id));
    expect(nameLike, `name-like identity inputs: ${nameLike.join(", ")}`).toEqual([]);
  });

  it("positive control: the same collector finds the names that resolvePersonActingName takes", () => {
    const ids = identityInputs("src/person-principal.ts", ["resolvePersonActingName"]);
    const nameLike = [...ids].filter((id) => NAME_LIKE.test(id)).sort();
    expect(nameLike).toEqual(expect.arrayContaining(["agentName", "claimedName"]));
  });
});
