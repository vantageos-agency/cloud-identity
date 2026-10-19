import {
  type AuthorizationCodeRecord,
  type AuthorizationCodeStore,
  type AuthorizeConfig,
  type AuthorizeDeps,
  type ClerkOrgMembership,
  type ConsumeCodeResult,
  type OrgPickerModel,
} from "./authorize-flow.js";
import { type AuthorizeRefusal, refusal } from "./authorize-shared.js";
import type { ClerkJwks } from "./clerk-session.js";
import type { ClerkUserLike } from "./oidc.js";

/**
 * The runtime glue around the authorize decisions (`startAuthorize`,
 * `resumeAuthorize`, `exchangeAuthorizationCode`, `buildDiscoveryDocument`):
 * the settings read from an environment object, the Clerk key-set cache, the
 * code-store adapter, the organisation picker page with its CSP, and the
 * function that wires them into an `AuthorizeConfig` and `AuthorizeDeps`.
 *
 * Store-agnostic and framework-agnostic. Every collaborator is injected (code
 * store, client lookup, membership lister, key-set fetch, clock). Nothing here
 * reads `process.env`, opens a connection, or logs a value.
 *
 * FAIL-CLOSED: unusable settings are a typed refusal naming the variable; a
 * collaborator that throws or answers malformed never becomes a grant.
 */

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

/** Environment variable names read by {@link readAuthorizeSettings}. Values are never logged. */
export const AUTHORIZE_ENV = {
  stateSecret: "AUTHORIZE_STATE_SECRET",
  clerkIssuer: "CLERK_DOMAIN",
  signInUrl: "AUTHORIZE_SIGN_IN_URL",
  callbackUrl: "AUTHORIZE_CALLBACK_URL",
  publicBaseUrl: "PUBLIC_BASE_URL",
  clerkSecretKey: "CLERK_SECRET_KEY",
  extraAuthorizedParties: "AUTHORIZE_AUTHORIZED_PARTIES",
} as const;

/** Scope granted when a client names none: MCP access plus the OIDC subject. */
export const DEFAULT_AUTHORIZE_SCOPE = "mcp:full openid";

/** Where an environment is read from. A plain object; `process.env` satisfies it. */
export type AuthorizeEnv = Readonly<Record<string, string | undefined>>;

export interface AuthorizeSettings {
  /** HMAC secret of the signed state, at least 32 characters. */
  stateSecret: string;
  /** The Clerk frontend API origin, no trailing slash. */
  issuer: string;
  signInUrl: string;
  callbackUrl: string;
  /** The server's public base URL, no trailing slash. */
  baseUrl: string;
  /** Null only when {@link ReadAuthorizeSettingsOptions.requireClerkSecretKey} is `false`. */
  clerkSecretKey: string | null;
  /** Origins a Clerk session token's `azp` may carry. */
  authorizedParties: string[];
}

export type AuthorizeSettingsResult =
  | { ok: true; settings: AuthorizeSettings }
  | {
      ok: false;
      /** The NAMES of the variables that are absent or unusable. Never a value. */
      missing: string[];
      refusal: AuthorizeRefusal;
    };

export interface ReadAuthorizeSettingsOptions {
  /**
   * Require `CLERK_SECRET_KEY`. Default `true`. Pass `false` when the host
   * supplies its own membership lister and user lookup.
   */
  requireClerkSecretKey?: boolean;
}

function originOf(url: string): string | null {
  try {
    return new URL(url).origin;
  } catch {
    return null;
  }
}

/**
 * Reads the authorize configuration from `env`. A variable that is absent, a
 * state secret shorter than 32 characters, or a URL that does not parse is
 * reported by NAME in `missing`; the caller refuses (503). `env` is the only
 * source: this function never reads `process.env` itself.
 */
export function readAuthorizeSettings(
  env: AuthorizeEnv,
  options: ReadAuthorizeSettingsOptions = {},
): AuthorizeSettingsResult {
  const missing: string[] = [];
  const stateSecret = env[AUTHORIZE_ENV.stateSecret] ?? "";
  if (stateSecret.length < 32) missing.push(AUTHORIZE_ENV.stateSecret);
  const issuer = (env[AUTHORIZE_ENV.clerkIssuer] ?? "").replace(/\/+$/, "");
  if (!originOf(issuer)) missing.push(AUTHORIZE_ENV.clerkIssuer);
  const signInUrl = env[AUTHORIZE_ENV.signInUrl] ?? "";
  if (!originOf(signInUrl)) missing.push(AUTHORIZE_ENV.signInUrl);
  const callbackUrl = env[AUTHORIZE_ENV.callbackUrl] ?? "";
  if (!originOf(callbackUrl)) missing.push(AUTHORIZE_ENV.callbackUrl);
  const baseUrl = (env[AUTHORIZE_ENV.publicBaseUrl] ?? "").replace(/\/+$/, "");
  if (!originOf(baseUrl)) missing.push(AUTHORIZE_ENV.publicBaseUrl);
  const secretKey = env[AUTHORIZE_ENV.clerkSecretKey] ?? "";
  if (options.requireClerkSecretKey !== false && secretKey === "") {
    missing.push(AUTHORIZE_ENV.clerkSecretKey);
  }
  if (missing.length > 0) {
    return { ok: false, missing, refusal: refusal("server-misconfigured") };
  }

  // A Clerk session token minted for ANOTHER application carries that
  // application's origin as `azp`; only our own origins are accepted.
  const parties = new Set<string>();
  for (const url of [signInUrl, callbackUrl, baseUrl]) {
    const origin = originOf(url);
    if (origin) parties.add(origin);
  }
  for (const extra of (env[AUTHORIZE_ENV.extraAuthorizedParties] ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean)) {
    parties.add(extra);
  }
  return {
    ok: true,
    settings: {
      stateSecret,
      issuer,
      signInUrl,
      callbackUrl,
      baseUrl,
      clerkSecretKey: secretKey === "" ? null : secretKey,
      authorizedParties: [...parties],
    },
  };
}

// ---------------------------------------------------------------------------
// Clerk key-set cache
// ---------------------------------------------------------------------------

/** The slice of `fetch` the key-set source uses. */
export type JwksFetch = (url: string) => Promise<{
  ok: boolean;
  status: number;
  json(): Promise<unknown>;
}>;

export interface ClerkJwksSourceOptions {
  /** The Clerk frontend API origin; the key set is read from `<issuer>/.well-known/jwks.json`. */
  issuer: string;
  /** Default: the global `fetch`. */
  fetch?: JwksFetch;
  /** Epoch milliseconds. Default `Date.now`. */
  now?: () => number;
  /** Cache lifetime. Default 10 minutes. */
  ttlMs?: number;
}

const DEFAULT_JWKS_TTL_MS = 10 * 60 * 1000;

/**
 * A key-set source for `AuthorizeConfig.session.jwks`: serves the cached key
 * set within `ttlMs`, refetches after it. One cache per source, never per
 * process. A failed or malformed answer throws and is not cached, so the
 * verifier reports `jwks-unavailable` and the next call tries again. Concurrent
 * callers share one in-flight fetch.
 */
export function createClerkJwksSource(options: ClerkJwksSourceOptions): () => Promise<ClerkJwks> {
  const issuer = options.issuer.replace(/\/+$/, "");
  const now = options.now ?? Date.now;
  const ttlMs = options.ttlMs ?? DEFAULT_JWKS_TTL_MS;
  let cached: { at: number; keys: ClerkJwks } | null = null;
  let inflight: Promise<ClerkJwks> | null = null;

  async function load(): Promise<ClerkJwks> {
    const doFetch: JwksFetch = options.fetch ?? ((url) => fetch(url));
    const res = await doFetch(`${issuer}/.well-known/jwks.json`);
    if (!res.ok) throw new Error(`Clerk JWKS answered ${res.status}`);
    const body = (await res.json()) as { keys?: unknown } | null;
    if (!body || !Array.isArray(body.keys)) {
      throw new Error("Clerk JWKS answer is not a key set");
    }
    const keys = body as ClerkJwks;
    cached = { at: now(), keys };
    return keys;
  }

  return async () => {
    if (cached && now() - cached.at < ttlMs) return cached.keys;
    if (!inflight) {
      inflight = load().finally(() => {
        inflight = null;
      });
    }
    return inflight;
  };
}

// ---------------------------------------------------------------------------
// Code store
// ---------------------------------------------------------------------------

/**
 * What the host's storage provides. `takeOnce` MUST be atomic: of two
 * concurrent calls for the same digest exactly one answers `ok`. It returns
 * `unknown` so a backend that hands back raw rows is validated here, not
 * trusted.
 */
export interface CodeStoreBackend {
  insert(record: AuthorizationCodeRecord): Promise<void>;
  takeOnce(codeHash: string): Promise<unknown>;
}

const RECORD_STRINGS = [
  "codeHash",
  "clerkUserId",
  "orgId",
  "orgRole",
  "clientId",
  "redirectUri",
  "codeChallenge",
  "resource",
  "scope",
] as const;

function isRecord(value: unknown): value is AuthorizationCodeRecord {
  if (typeof value !== "object" || value === null) return false;
  const v = value as Record<string, unknown>;
  return (
    RECORD_STRINGS.every((k) => typeof v[k] === "string") &&
    (v.orgSlug === null || typeof v.orgSlug === "string") &&
    typeof v.expiresAt === "number" &&
    Number.isFinite(v.expiresAt)
  );
}

function parseConsume(answer: unknown): ConsumeCodeResult {
  if (typeof answer === "object" && answer !== null) {
    const a = answer as { status?: unknown; record?: unknown };
    if (a.status === "unknown") return { status: "unknown" };
    if (a.status === "already-used") return { status: "already-used" };
    if (a.status === "ok" && isRecord(a.record)) return { status: "ok", record: a.record };
  }
  throw new Error("code store returned a malformed consume result");
}

/**
 * Adapts the host's storage to `AuthorizationCodeStore`. The consume answer is
 * checked: anything that is not `ok` with a complete record, `unknown` or
 * `already-used` throws, which the exchange turns into `code-store-unavailable`
 * and never into a grant.
 */
export function codeStoreFrom(backend: CodeStoreBackend): AuthorizationCodeStore {
  return {
    put: (record) => backend.insert(record),
    consume: async (codeHash) => parseConsume(await backend.takeOnce(codeHash)),
  };
}

/**
 * A single-process code store with true single-use consume. For tests and a
 * single-instance development server only: codes do not survive a restart and
 * are not shared between instances.
 */
export function createInMemoryCodeStore(): AuthorizationCodeStore {
  const rows = new Map<string, { record: AuthorizationCodeRecord; used: boolean }>();
  return {
    async put(record) {
      rows.set(record.codeHash, { record, used: false });
    },
    async consume(codeHash) {
      const row = rows.get(codeHash);
      if (!row) return { status: "unknown" };
      if (row.used) return { status: "already-used" };
      row.used = true;
      return { status: "ok", record: row.record };
    },
  };
}

// ---------------------------------------------------------------------------
// Clerk Backend API directory (memberships, user)
// ---------------------------------------------------------------------------

/** The slice of a Clerk Backend client this module calls. `createClerkClient(...)` satisfies it. */
export interface ClerkUsersApi {
  users: {
    getOrganizationMembershipList(args: {
      userId: string;
      limit?: number;
      offset?: number;
    }): Promise<{
      data: readonly {
        role: string;
        organization: { id: string; slug?: string | null; name: string };
      }[];
      totalCount?: number;
    }>;
    getUser(userId: string): Promise<unknown>;
  };
}

export interface ClerkDirectoryOptions {
  /** Memberships requested per page. Default 100. */
  pageSize?: number;
  /** Pages read before the lister gives up. Default 50. */
  maxPages?: number;
}

export interface ClerkDirectory {
  listMemberships(userId: string): Promise<readonly ClerkOrgMembership[]>;
  getUser(userId: string): Promise<ClerkUserLike>;
}

/**
 * The membership lister and user lookup over a Clerk Backend client the host
 * created. The list is read in full: a Clerk failure, or a person whose list
 * does not end within `maxPages`, throws rather than returning a partial list
 * (the flow turns a throw into `membership-lookup-unavailable`).
 */
export function createClerkDirectory(
  clerk: ClerkUsersApi,
  options: ClerkDirectoryOptions = {},
): ClerkDirectory {
  const pageSize = options.pageSize ?? 100;
  const maxPages = options.maxPages ?? 50;
  return {
    async listMemberships(userId) {
      const out: ClerkOrgMembership[] = [];
      for (let page = 0; page < maxPages; page += 1) {
        const res = await clerk.users.getOrganizationMembershipList({
          userId,
          limit: pageSize,
          offset: page * pageSize,
        });
        for (const m of res.data) {
          out.push({
            role: m.role,
            organization: {
              id: m.organization.id,
              slug: m.organization.slug ?? null,
              name: m.organization.name,
            },
          });
        }
        const total = res.totalCount;
        if (res.data.length < pageSize || (total !== undefined && out.length >= total)) {
          return out;
        }
      }
      throw new Error(`Clerk membership list did not end within ${maxPages} pages`);
    },
    async getUser(userId) {
      return (await clerk.users.getUser(userId)) as ClerkUserLike;
    },
  };
}

// ---------------------------------------------------------------------------
// Runtime
// ---------------------------------------------------------------------------

export interface AuthorizeRuntimeOptions {
  settings: AuthorizeSettings;
  /** The host's client registry. Redirect URIs it returns are compared by exact equality. */
  lookupClient: AuthorizeDeps["lookupClient"];
  /** The organisations the picker may offer. A throw is a refusal, never a grant. */
  listMemberships: AuthorizeDeps["listMemberships"];
  codeStore: AuthorizationCodeStore;
  /** Default: {@link createClerkJwksSource} on `settings.issuer`. */
  jwks?: () => Promise<ClerkJwks>;
  /** Epoch milliseconds. */
  now?: () => number;
  generateCode?: () => string;
  /** Path of the protected resource under `settings.baseUrl` (RFC 8707). Default `/mcp`. */
  resourcePath?: string;
  /** Default {@link DEFAULT_AUTHORIZE_SCOPE}. */
  defaultScope?: string;
  /** When set, every requested scope must be listed. */
  supportedScopes?: readonly string[];
}

export interface AuthorizeRuntime {
  cfg: AuthorizeConfig;
  deps: AuthorizeDeps;
}

/**
 * Builds the `AuthorizeConfig` and `AuthorizeDeps` the flow functions take.
 * Consent is left at the package default (ON): the picker and its
 * `consentToken` are what stand between a registered client and a code issued
 * in a signed-in person's name. The only resource issued for is
 * `<baseUrl><resourcePath>`.
 */
export function buildAuthorizeRuntime(options: AuthorizeRuntimeOptions): AuthorizeRuntime {
  const { settings } = options;
  const jwks = options.jwks ?? createClerkJwksSource({ issuer: settings.issuer, ...(options.now ? { now: options.now } : {}) });
  const resourcePath = options.resourcePath ?? "/mcp";
  const cfg: AuthorizeConfig = {
    stateSecret: settings.stateSecret,
    signInUrl: settings.signInUrl,
    callbackUrl: settings.callbackUrl,
    allowedResources: [`${settings.baseUrl}${resourcePath}`],
    defaultScope: options.defaultScope ?? DEFAULT_AUTHORIZE_SCOPE,
    ...(options.supportedScopes ? { supportedScopes: options.supportedScopes } : {}),
    session: {
      issuer: settings.issuer,
      jwks,
      authorizedParties: settings.authorizedParties,
    },
  };
  const deps: AuthorizeDeps = {
    lookupClient: options.lookupClient,
    listMemberships: options.listMemberships,
    codeStore: options.codeStore,
    ...(options.now ? { now: options.now } : {}),
    ...(options.generateCode ? { generateCode: options.generateCode } : {}),
  };
  return { cfg, deps };
}

// ---------------------------------------------------------------------------
// Organisation picker page
// ---------------------------------------------------------------------------

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/**
 * The page's one inline stylesheet: dark first, light under
 * `prefers-color-scheme`, system fonts. Inline because the page loads no
 * external asset; the CSP below admits exactly this text by hash.
 */
const PICKER_STYLE = [
  ":root{color-scheme:dark light;--background:oklch(0.08 0.005 265);--foreground:oklch(0.95 0.005 265);" +
    "--card:oklch(0.11 0.005 265);--card-hover:oklch(0.14 0.005 265);--primary:oklch(0.95 0.005 265);" +
    "--primary-foreground:oklch(0.08 0.005 265);--secondary:oklch(0.16 0.005 265);" +
    "--muted-foreground:oklch(0.55 0.005 265);--border:oklch(0.22 0.005 265);" +
    "--border-hover:oklch(0.30 0.005 265);--ring:oklch(0.55 0.005 265);--warning:oklch(0.75 0.18 85);" +
    "--radius:0.75rem}",
  "@media (prefers-color-scheme:light){:root{--background:oklch(0.98 0.003 265);" +
    "--foreground:oklch(0.10 0.005 265);--card:oklch(1 0 0);--card-hover:oklch(0.96 0.003 265);" +
    "--primary:oklch(0.10 0.005 265);--primary-foreground:oklch(0.98 0.003 265);" +
    "--secondary:oklch(0.94 0.003 265);--muted-foreground:oklch(0.45 0.005 265);" +
    "--border:oklch(0.88 0.003 265);--border-hover:oklch(0.78 0.003 265);--ring:oklch(0.45 0.005 265);" +
    "--warning:oklch(0.65 0.18 85)}}",
  "*{box-sizing:border-box}",
  "body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:1.5rem;" +
    "background:var(--background);color:var(--foreground);" +
    "font:15px/1.55 ui-sans-serif,system-ui,-apple-system,'Segoe UI',sans-serif}",
  "main{width:100%;max-width:28rem;background:var(--card);border:1px solid var(--border);" +
    "border-radius:var(--radius);padding:2rem}",
  ".brand{margin:0 0 1.25rem;font-size:.8rem;font-weight:600;letter-spacing:.06em;text-transform:uppercase;" +
    "color:var(--muted-foreground)}",
  "h1{margin:0 0 .5rem;font-size:1.25rem;font-weight:600;letter-spacing:-.01em}",
  "p{margin:0 0 1rem}.muted{color:var(--muted-foreground);font-size:.875rem}",
  "fieldset{border:0;margin:0 0 1.5rem;padding:0}",
  "legend{font-size:.8rem;font-weight:600;color:var(--muted-foreground);margin-bottom:.5rem;padding:0}",
  ".org{display:flex;align-items:center;gap:.75rem;padding:.75rem .875rem;margin-bottom:.5rem;" +
    "border:1px solid var(--border);border-radius:.5rem;cursor:pointer}",
  ".org:hover{border-color:var(--border-hover);background:var(--card-hover)}",
  ".org:has(input:checked){border-color:var(--primary)}",
  ".org input{accent-color:var(--primary);margin:0}",
  ".name{flex:1;font-weight:500}",
  ".role{font-size:.75rem;color:var(--muted-foreground);background:var(--secondary);" +
    "padding:.125rem .5rem;border-radius:999px}",
  ".actions{display:flex;gap:.5rem}",
  "button{flex:1;font:inherit;font-weight:500;padding:.625rem 1rem;border-radius:.5rem;cursor:pointer;" +
    "border:1px solid var(--border);background:transparent;color:var(--foreground)}",
  "button.primary{background:var(--primary);color:var(--primary-foreground);border-color:var(--primary)}",
  "button:hover{opacity:.9}button:focus-visible,.org:focus-within{outline:2px solid var(--ring);outline-offset:2px}",
].join("");

let cspPromise: Promise<string> | null = null;

/**
 * The `Content-Security-Policy` header for the picker page: no scripts, no
 * external assets, no framing, and one inline style admitted by its hash.
 */
export function pickerContentSecurityPolicy(): Promise<string> {
  cspPromise ??= (async () => {
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(PICKER_STYLE));
    const hash = btoa(String.fromCharCode(...new Uint8Array(digest)));
    return [
      "default-src 'none'",
      `style-src 'sha256-${hash}'`,
      "base-uri 'none'",
      "frame-ancestors 'none'",
    ].join("; ");
  })();
  return cspPromise;
}

export interface OrgPickerOptions {
  /** The product name shown to the person ("Connect Claude to <productName>"). */
  productName: string;
  /** Where the form posts. Default `/authorize/org`. */
  formAction?: string;
}

/**
 * Server-rendered organisation picker and consent page. It posts `state`,
 * `orgId`, `approved` and the hidden `consentToken` to `formAction`. The
 * `consentToken` IS the CSRF protection of that POST; do not drop it. Every
 * interpolated value is HTML-escaped. Send it with
 * {@link pickerContentSecurityPolicy} as its `Content-Security-Policy`.
 */
export function renderOrgPicker(model: OrgPickerModel, options: OrgPickerOptions): string {
  const clientName = model.client.clientName ?? model.client.clientId;
  const product = escapeHtml(options.productName);
  const action = escapeHtml(options.formAction ?? "/authorize/org");
  const only = model.organizations.length === 1;
  const orgs = model.organizations
    .map(
      (o, i) =>
        `<label class="org"><input type="radio" name="orgId" value="${escapeHtml(o.id)}" required${only && i === 0 ? " checked" : ""}><span class="name">${escapeHtml(o.name)}</span><span class="role">${escapeHtml(o.role.replace(/^org:/, ""))}</span></label>`,
    )
    .join("\n");
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<meta name="color-scheme" content="dark light">
<title>Connect ${escapeHtml(clientName)} to ${product}</title>
<style>${PICKER_STYLE}</style>
</head>
<body>
<main>
<p class="brand">${product}</p>
<h1>Connect ${escapeHtml(clientName)}</h1>
<p>${escapeHtml(clientName)} asks to act in ${product} on your behalf. Choose the organisation it may reach, then approve or deny.</p>
<form method="post" action="${action}">
<input type="hidden" name="state" value="${escapeHtml(model.state)}">
<input type="hidden" name="consentToken" value="${escapeHtml(model.consentToken ?? "")}">
<fieldset>
<legend>Organisation</legend>
${orgs}
</fieldset>
<p class="actions">
<button class="primary" type="submit" name="approved" value="true">Approve</button>
<button type="submit" name="approved" value="false" formnovalidate>Deny</button>
</p>
</form>
</main>
</body>
</html>
`;
}
