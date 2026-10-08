import { resolve } from "node:path";
import ts from "typescript";
import { beforeAll, describe, expect, it } from "vitest";
import { scopeFilterList } from "../src/index.js";

/**
 * Property: no function of the principal-by-id API, and no NEW export of the
 * package root, accepts a bare name as an identity input (backend standard
 * R-53, clause 4).
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
const NAME_LIKE_RE = /name|orchestrator|assignedto|createdby/i;
/** `namespace` is a path, not a name: strip it before testing. */
function isNameLike(identifier: string): boolean {
  return NAME_LIKE_RE.test(identifier.replace(/namespace/gi, ""));
}

/** Types from the TypeScript standard library or Node's typings are not walked. */
function isPlatformType(type: ts.Type): boolean {
  const decls = (type.aliasSymbol ?? type.getSymbol())?.declarations ?? [];
  return (
    decls.length > 0 &&
    decls.every((d) => /[\\/]typescript[\\/]lib[\\/]|[\\/]@types[\\/]node[\\/]/.test(d.getSourceFile().fileName))
  );
}

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
  if (isPlatformType(type)) {
    // a platform generic (`T[]`, `Promise<T>`, `ReadonlyArray<T>`) is not
    // walked itself, but what it carries is
    if ((type.flags & ts.TypeFlags.Object) !== 0 &&
      ((type as ts.ObjectType).objectFlags & ts.ObjectFlags.Reference) !== 0) {
      for (const t of checker.getTypeArguments(type as ts.TypeReference)) {
        collectIdentifiers(t, out, seen);
      }
    }
    return;
  }
  if (type.flags & ts.TypeFlags.TypeParameter) {
    // a generic input (`rows: T[]`, `T extends ScopeFilterable`) is read
    // through its constraint, so a name field behind a generic is still seen
    const constraint = checker.getBaseConstraintOfType(type);
    if (constraint !== undefined) collectIdentifiers(constraint, out, seen);
    return;
  }
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
    if (resolved.flags & (ts.SymbolFlags.Function | ts.SymbolFlags.Class)) {
      const type = checker.getTypeOfSymbolAtLocation(resolved, decl);
      for (const sig of [...type.getCallSignatures(), ...type.getConstructSignatures()]) {
        collectSignature(sig, out, seen);
      }
    } else if (resolved.flags & ts.SymbolFlags.TypeAlias) {
      collectIdentifiers(checker.getDeclaredTypeOfSymbol(resolved), out, seen);
    }
  }
  return out;
}

describe("principal-by-id — no exported function accepts a name as identity", () => {
  beforeAll(() => {
    program = ts.createProgram(
      [resolve(REPO_ROOT, "src/index.ts")],
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

  it("the exported functions are the three expected, so the scan is not vacuous", () => {
    const fns = moduleExports("src/principal-by-id.ts")
      .filter((s) => s.flags & ts.SymbolFlags.Function)
      .map((s) => s.getName())
      .sort();
    expect(fns).toEqual(["assertOrgAdmin", "assertTargetBelongsTo", "resolveActingPrincipal"]);
  });

  it("every identifier reachable from their inputs is an ID, a kind, an option or a door", () => {
    const ids = identityInputs("src/principal-by-id.ts");
    // sanity: the scan reached the credential, the lookups and the target
    for (const expected of ["agentId", "personId", "serviceAccountId", "actingForAgentId", "verifiedOrgId", "agentById", "ownerId", "principalId", "verifiedOrgRole", "orgRole", "adminRoles", "targetOrgId"]) {
      expect(ids, `scan did not reach ${expected}`).toContain(expected);
    }
    const nameLike = [...ids].filter(isNameLike);
    expect(nameLike, `name-like identity inputs: ${nameLike.join(", ")}`).toEqual([]);
  });

  it("positive control: the same collector finds the names that resolvePersonActingName takes", () => {
    const ids = identityInputs("src/person-principal.ts", ["resolvePersonActingName"]);
    const nameLike = [...ids].filter(isNameLike).sort();
    expect(nameLike).toEqual(expect.arrayContaining(["agentName", "claimedName"]));
  });
});

// ---------------------------------------------------------------------------
// The whole public surface: any NEW export taking a name fails
// ---------------------------------------------------------------------------

/**
 * The deprecated legacy exceptions, each with the source file that declares
 * it. Every one is `@deprecated Since 0.11.0`, kept (behaviour unchanged)
 * until consumers migrate off it, then removed in a major release. Never add
 * to this list.
 *   - resolvePersonActingName: names as identity input (R-53 clause 4);
 *     replaced by `resolveActingPrincipal`.
 *   - passesScopeFilter / scopeFilterGet / scopeFilterList: a `createdBy`
 *     name selects the row (R-53 clause 1); scopeFilterList does it through
 *     passesScopeFilter.
 */
const LEGACY_NAME_INPUT_EXCEPTIONS = {
  resolvePersonActingName: "src/person-principal.ts",
  passesScopeFilter: "src/scope-filter.ts",
  scopeFilterGet: "src/scope-filter.ts",
  scopeFilterList: "src/scope-filter.ts",
} as const;

/**
 * Measured at 0.10.0 and FROZEN: exports that already carried a name-like
 * field before this rule existed, with the exact fields. The test pins this
 * map to the measured surface, so it can only shrink when the code does; an
 * entry may never be added. None of them resolves an acting principal or
 * selects a row by a name:
 *   - isPersonActorName: classifies a label as reserved;
 *   - checkPersonCallShape: `actingName` is accepted only to be refused.
 */
const FROZEN_PRE_RULE_NAME_FIELDS: Record<string, readonly string[]> = {
  isPersonActorName: ["name"],
  checkPersonCallShape: ["actingName"],
};

function rootCallableExports(): string[] {
  return moduleExports("src/index.ts")
    .filter((s) => {
      const r = s.flags & ts.SymbolFlags.Alias ? checker.getAliasedSymbol(s) : s;
      return (r.flags & (ts.SymbolFlags.Function | ts.SymbolFlags.Class)) !== 0;
    })
    .map((s) => s.getName())
    .sort();
}

function nameInputsOf(exportName: string): string[] {
  return [...identityInputs("src/index.ts", [exportName])].filter(isNameLike).sort();
}

describe("package root — no new export takes a name as identity", () => {
  it("the legacy exception list is exactly [resolvePersonActingName, passesScopeFilter, scopeFilterGet, scopeFilterList]", () => {
    expect(Object.keys(LEGACY_NAME_INPUT_EXCEPTIONS)).toEqual([
      "resolvePersonActingName",
      "passesScopeFilter",
      "scopeFilterGet",
      "scopeFilterList",
    ]);
  });

  it.each(Object.entries(LEGACY_NAME_INPUT_EXCEPTIONS))(
    "%s is marked @deprecated Since 0.11.0 in %s",
    (name, file) => {
      const sf = program.getSourceFile(resolve(REPO_ROOT, file));
      expect(sf, file).toBeDefined();
      const fn = sf?.statements.find(
        (st): st is ts.FunctionDeclaration =>
          ts.isFunctionDeclaration(st) && st.name?.text === name,
      );
      expect(fn, `${name} not declared in ${file}`).toBeDefined();
      const deprecated =
        fn === undefined ? [] : ts.getJSDocTags(fn).filter((t) => t.tagName.text === "deprecated");
      expect(deprecated.length, `${name} carries no @deprecated tag`).toBe(1);
      const text = ts.getTextOfJSDocComment(deprecated[0]?.comment) ?? "";
      expect(text).toMatch(/^Since 0\.11\.0\b/);
    },
  );

  it("each legacy exception still takes a name (otherwise it must leave the list)", () => {
    expect(nameInputsOf("resolvePersonActingName")).toEqual(
      expect.arrayContaining(["agentName", "claimedName"]),
    );
    expect(nameInputsOf("passesScopeFilter")).toContain("createdBy");
    expect(nameInputsOf("scopeFilterGet")).toContain("createdBy");
  });

  it("scopeFilterList: tagged @deprecated, and still selecting rows by a createdBy name", () => {
    // tagged (the same check as above, named for this function)
    const sf = program.getSourceFile(resolve(REPO_ROOT, "src/scope-filter.ts"));
    const fn = sf?.statements.find(
      (st): st is ts.FunctionDeclaration =>
        ts.isFunctionDeclaration(st) && st.name?.text === "scopeFilterList",
    );
    const tag = fn === undefined ? [] : ts.getJSDocTags(fn).filter((t) => t.tagName.text === "deprecated");
    expect(tag.length, "scopeFilterList carries no @deprecated tag").toBe(1);
    // structurally: its generic row input carries a name field
    expect(nameInputsOf("scopeFilterList")).toContain("createdBy");
    // behaviourally: a row is selected by its createdBy NAME and nothing else
    const ctx = { fromAllowList: ["eta"], namespaceReadPrefixes: [], namespaceWritePrefixes: [] };
    const orgA = { createdBy: "eta", orgId: "org_a" };
    const orgB = { createdBy: "eta", orgId: "org_b" };
    const other = { createdBy: "rho", orgId: "org_a" };
    expect(scopeFilterList(ctx, [orgA, orgB, other])).toEqual([orgA, orgB]);
  });

  it("the frozen pre-rule map equals the measured surface exactly", () => {
    for (const [fn, fields] of Object.entries(FROZEN_PRE_RULE_NAME_FIELDS)) {
      expect(nameInputsOf(fn), fn).toEqual([...fields].sort());
    }
  });

  it("every other callable export of the root takes no name-like input", () => {
    const exports = rootCallableExports();
    // the scan is not vacuous: it sees the old surface and the new one
    expect(exports).toEqual(
      expect.arrayContaining([
        "resolveActingPrincipal",
        "assertTargetBelongsTo",
        "resolvePersonActingName",
        "validatePresentedBearer",
        "resolveMembership",
      ]),
    );
    const legacy: readonly string[] = Object.keys(LEGACY_NAME_INPUT_EXCEPTIONS);
    const violations = exports
      .filter((fn) => !legacy.includes(fn))
      .map((fn) => {
        const allowed = FROZEN_PRE_RULE_NAME_FIELDS[fn] ?? [];
        const extra = nameInputsOf(fn).filter((id) => !allowed.includes(id));
        return extra.length > 0 ? `${fn}: ${extra.join(", ")}` : null;
      })
      .filter((v): v is string => v !== null);
    expect(violations, `exports taking a name: ${violations.join("; ")}`).toEqual([]);
  });
});
