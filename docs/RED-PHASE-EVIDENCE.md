# RED-PHASE Evidence — @vantageos/cloud-identity 0.1.0

Mission: `k57c7s478gw1a3e5gmhdeptg5n87z78n` (S2.3 D8 — cloud-identity brick).
Task: `k1707g7qa0stt6bd2g0w2pnp3h87y9xw`.
Orchestrator: Sigma — VantageOS Team | 2026-06-04.

## TDD ledger

| Phase | Commit SHA | Test ratio | Notes |
| --- | --- | --- | --- |
| Skeleton | `df6850e4146d2601b5c62c9c7ccf342f84635be5` | N/A | package.json, tsconfig, vitest config, LICENSE, README, CHANGELOG, empty src/test. |
| RED | `4dece84cc8c9c8e9d5de9995210fab76fa2d8f3a` | 0 / 27 (all 3 suites fail to load — modules absent in src/) | Tests reference `../src/crypto.js`, `../src/scope-filter.js`, `../src/bearer-validation.js` which do not exist yet. |
| GREEN | `9287db2b4e12320b0c0a0d88d2b83055291ac9b9` | 31 / 31 PASS, tsc --noEmit clean | crypto + scope-filter + bearer-validation + types ported and implemented. |
| DOC | (HEAD after this commit) | unchanged (31/31) | README usage examples + this evidence file. |

> Test count grew from 27 (planned floor) to 31 (delivered) once extra coverage rows were folded in (deny-by-default, empty fields, sha256 same-length-wrong, partial-match constant-time property).

## RED proof (vitest output, commit 4dece84)

```
 FAIL  test/crypto.test.ts                     [ Failed to load url ../src/crypto.js ]
 FAIL  test/scope-filter.test.ts               [ Failed to load url ../src/scope-filter.js ]
 FAIL  test/bearer-validation.test.ts          [ Failed to load url ../src/bearer-validation.js ]
 Test Files  3 failed (3)
      Tests  no tests
```

All three suites failed at module-resolution time because the source files
they import (`src/crypto.ts`, `src/scope-filter.ts`, `src/bearer-validation.ts`)
did not exist. This is a genuine RED phase — no test could even register, let
alone pass. The delta from RED → GREEN is the 5 source files added in commit
`9287db2` (+ `src/types.ts` + `src/index.ts`).

## GREEN proof (vitest output, commit 9287db2)

```
 ✓ test/scope-filter.test.ts        (14 tests) 24ms
 ✓ test/crypto.test.ts              (8 tests)  20ms
 ✓ test/bearer-validation.test.ts   (9 tests)  27ms

 Test Files  3 passed (3)
      Tests  31 passed (31)
```

`npx tsc --noEmit` exits 0.

## Port provenance

| Brick module | Source file (vantage-memory mcp-server) | Notes |
| --- | --- | --- |
| `src/crypto.ts` | `src/crypto.ts` (Day 47 Eta F1 master-token gate) | Surface adapted from `(string, string)` → `(Uint8Array, Uint8Array)` per 0.1.0 contract; algorithm verbatim. |
| `src/scope-filter.ts` | `src/scope-filter.ts` (Sprint S3.1 B2) | Verbatim, only the type dependency on `OAuthContext` replaced with the brick-local `OAuthCtx`. `isMasterScope` re-implemented in-module against the new type (uses `scope === "master"` + `fromAllowList.includes("*")`). |
| `src/bearer-validation.ts` | `server-http.ts` `masterOnlyMiddleware` | Extracted as framework-agnostic helper AND hardened — original middleware did `token !== masterToken` (non-constant-time); brick version sha256-hashes both sides and uses `timingSafeEqual`. |

## Deferred to 0.2.0

- `getEffectiveWorkspaceId` — depends on `convex/lib/workspace.ts` owned by Theta in vantageos-crm.
- D1 ghost Clerk identity injection — co-designed Theta cycle.

## Day 79 NPM PUBLISH PROTOCOL

Awaits Eta APPROVED verdict citing final HEAD SHA. Publish executed from
theta-vps path with both env tokens set (`ETA_APPROVED_TASK_ID` +
`ETA_APPROVED_COMMIT_SHA`). Sigma does NOT publish from sigma-vps.
