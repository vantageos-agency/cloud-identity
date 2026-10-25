/**
 * Type-level fixture for test/optional-name-lists.test.ts. Never executed:
 * the test compiles it with the TypeScript checker and requires zero
 * diagnostics. Each declaration below is a consumer that has REMOVED one of
 * the two name lists and must still compile.
 */
import type { OAuthCtx, OrgMappingRow, ResolvedOrg } from "../../src/index.js";

/** A context carrying no `fromAllowList` at all. */
export const ctxWithoutNames: OAuthCtx = {
  scope: "tenant",
  namespaceReadPrefixes: ["team/a"],
  namespaceWritePrefixes: ["team/a"],
};

/** A master context carrying no `fromAllowList`: master is the declared scope. */
export const masterWithoutNames: OAuthCtx = {
  scope: "master",
  namespaceReadPrefixes: [],
  namespaceWritePrefixes: [],
};

/** A mapping row carrying no `allowedOrchestrators`, with its ID roster. */
export const rowWithoutNames: OrgMappingRow = {
  id: "org_a",
  label: "acme",
  active: true,
  scopes: [],
  allowedAgentIds: ["agent_1"],
};

/** Readers see both rosters as possibly absent. */
export function readRosters(org: ResolvedOrg): {
  names: string[] | undefined;
  ids: string[] | undefined;
} {
  return { names: org.allowedOrchestrators, ids: org.allowedAgentIds };
}
