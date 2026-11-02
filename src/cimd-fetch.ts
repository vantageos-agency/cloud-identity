/**
 * The SSRF-guarded fetch and the Client ID Metadata Document (CIMD) resolver behind
 * `./client-assertion`. Lifted unchanged from the vantage-mcp-boilerplate client registry
 * (`src/oauth/clientRegistry.ts`, the CIMD half; the DCR registry stays there).
 *
 * A URL-shaped client_id is a CIMD: fetched over https, SSRF-guarded (public addresses only,
 * no redirects, size and time capped), and accepted only when the document names exactly that
 * URL. The same guarded fetch reads the client's JWKS.
 *
 * Node only: address parsing and range matching are `node:net`'s BlockList, host resolution is
 * `node:dns/promises`. This module is therefore reachable from the `./client-assertion`
 * subpath and never from the package root.
 */

import { lookup } from "node:dns/promises";
import { BlockList, isIP } from "node:net";
import type { AuthorizeClient } from "./authorize-flow.js";

/** True for an https URL, or an http URL on a loopback host (native-app redirects). */
export function isAllowedRedirectUri(raw: unknown): raw is string {
  if (typeof raw !== "string") return false;
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return false;
  }
  if (url.hash) return false;
  if (url.protocol === "https:") return true;
  return (
    url.protocol === "http:" &&
    (url.hostname === "localhost" || url.hostname === "127.0.0.1" || url.hostname === "[::1]")
  );
}

// ---------------------------------------------------------------------------
// SSRF guard for the CIMD fetch
// ---------------------------------------------------------------------------

/**
 * Non-public ranges: the union required by the fleet MCP server standard, S-10 (cloud metadata,
 * 127/8, 0/8, ::1, RFC 1918, link-local, unique-local, multicast) plus the extra ranges this
 * guard has always refused (CGNAT, IETF protocol block, benchmarking, reserved >= 240).
 * Address parsing and range matching belong to `node:net` BlockList: this module writes no
 * address parser and compares the PARSER'S view of the address, never the raw string.
 */
const BLOCKED_V4: ReadonlyArray<readonly [string, number]> = [
  ["0.0.0.0", 8],
  ["10.0.0.0", 8],
  ["100.64.0.0", 10], // CGNAT
  ["127.0.0.0", 8],
  ["169.254.0.0", 16], // link-local, includes 169.254.169.254 cloud metadata
  ["172.16.0.0", 12],
  ["192.0.0.0", 24],
  ["192.168.0.0", 16],
  ["198.18.0.0", 15],
  ["224.0.0.0", 4], // multicast
  ["240.0.0.0", 4], // reserved, includes the broadcast address
];
const BLOCKED_V6: ReadonlyArray<readonly [string, number]> = [
  ["::", 96], // unspecified, loopback and every IPv4-compatible address (::a.b.c.d)
  ["fc00::", 7], // unique local
  ["fe80::", 10], // link-local
  ["ff00::", 8], // multicast
  ["64:ff9b:1::", 48], // local-use NAT64 (RFC 8215)
  ["2001::", 32], // Teredo (RFC 4380): embeds a server and an obfuscated client IPv4
];

/** The v4 prefix `addr/len` written as a prefix under an IPv6 embedding of 96 leading bits. */
function embedV4(v4: string, len: number, prefix6: string): [string, number] {
  const [a, b, c, d] = v4.split(".").map(Number) as [number, number, number, number];
  const hi = ((a << 8) | b).toString(16);
  const lo = ((c << 8) | d).toString(16);
  return [`${prefix6}${hi}:${lo}`, 96 + len];
}

/** 6to4 (RFC 3056): the v4 prefix `addr/len` sits in bits 16-47, under 2002::/16. */
function embedSixToFour(v4: string, len: number): [string, number] {
  const [a, b, c, d] = v4.split(".").map(Number) as [number, number, number, number];
  const hi = ((a << 8) | b).toString(16);
  const lo = ((c << 8) | d).toString(16);
  return [`2002:${hi}:${lo}::`, 16 + len];
}

const blockList = new BlockList();
for (const [addr, len] of BLOCKED_V4) {
  blockList.addSubnet(addr, len, "ipv4");
  // IPv4-mapped (::ffff:a.b.c.d, any textual form), NAT64 (64:ff9b::a.b.c.d) and
  // IPv4-translated (::ffff:0:a.b.c.d, RFC 2765): the embedded v4 address is held to the same
  // list, in the last 32 bits of a /96.
  for (const prefix6 of ["::ffff:", "64:ff9b::", "::ffff:0:"]) {
    const [sub, bits] = embedV4(addr, len, prefix6);
    blockList.addSubnet(sub, bits, "ipv6");
  }
  // 6to4 (2002::/16): the v4 address is in bits 16-47.
  const [sixToFour, sixToFourBits] = embedSixToFour(addr, len);
  blockList.addSubnet(sixToFour, sixToFourBits, "ipv6");
}
for (const [addr, len] of BLOCKED_V6) blockList.addSubnet(addr, len, "ipv6");

/**
 * The eight 16-bit groups of a SYNTACTICALLY VALID IPv6 literal (`isIP` has already accepted
 * it). Only used to read bits that no BlockList prefix can express.
 */
export function ipv6Groups(ip: string): number[] {
  let text = ip.toLowerCase();
  const dotted = /(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(text);
  if (dotted) {
    const [, a, b, c, d] = dotted.map(Number) as [number, number, number, number, number];
    text = `${text.slice(0, dotted.index)}${((a << 8) | b).toString(16)}:${((c << 8) | d).toString(16)}`;
  }
  const [head = "", tail] = text.split("::");
  const left = head ? head.split(":") : [];
  const right = tail === undefined ? [] : tail ? tail.split(":") : [];
  const fill = tail === undefined ? [] : Array<string>(8 - left.length - right.length).fill("0");
  return [...left, ...fill, ...right].map((g) => Number.parseInt(g, 16));
}

/**
 * ISATAP (RFC 5214): bits 64-95 are 0000:5efe (or 0200:5efe, universal/local variant) under ANY
 * prefix, and the low 32 bits are an embedded IPv4. No prefix expresses that, so it is read
 * from the groups; the embedded v4 is held to the same blocked list.
 */
function isatapEmbeddedV4(ip: string): string | null {
  const g = ipv6Groups(ip);
  if (g.length !== 8 || (g[4] !== 0x0000 && g[4] !== 0x0200) || g[5] !== 0x5efe) return null;
  const [hi, lo] = [g[6] as number, g[7] as number];
  return `${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`;
}

/** True only for a globally routable address. Fail-closed: anything unrecognised is refused. */
export function isPublicAddress(ip: string): boolean {
  if (typeof ip !== "string" || ip.includes("%")) return false; // zone ids are never public
  const version = isIP(ip);
  if (version !== 4 && version !== 6) return false;
  try {
    if (version === 6) {
      const isatap = isatapEmbeddedV4(ip);
      if (isatap !== null && blockList.check(isatap, "ipv4")) return false;
    }
    return !blockList.check(ip, version === 4 ? "ipv4" : "ipv6");
  } catch {
    return false;
  }
}

export async function defaultResolveHost(host: string): Promise<string[]> {
  const records = await lookup(host, { all: true });
  return records.map((r) => r.address);
}

export interface CimdOptions {
  fetchImpl?: typeof fetch;
  resolveHost?: (host: string) => Promise<string[]>;
  maxBytes?: number;
  timeoutMs?: number;
}

/**
 * Reads a response body as UTF-8 text, buffering at most `maxBytes`. The stream is cancelled
 * the moment the cap is crossed, so an oversized body is never held in memory. Null = too big
 * (or no body).
 */
async function readCappedText(res: Response, maxBytes: number): Promise<string | null> {
  if (!res.body) return null;
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let received = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    received += value.byteLength;
    if (received > maxBytes) {
      await reader.cancel().catch(() => undefined);
      return null;
    }
    chunks.push(value);
  }
  return new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks));
}

/** True when a client_id is URL-shaped, i.e. a CIMD identifier (valid or not). */
export function isUrlShapedClientId(clientId: string): boolean {
  return /^https?:\/\//i.test(clientId);
}

/**
 * The one SSRF-guarded fetch shared by the CIMD document and the client's JWKS: https only,
 * public addresses only, no redirects, size and time capped. Returns the parsed JSON, or null
 * for ANY failure.
 */
export async function fetchGuardedJson(url: URL, options: CimdOptions = {}): Promise<unknown> {
  const { fetchImpl = fetch, resolveHost = defaultResolveHost } = options;
  const maxBytes = options.maxBytes ?? 16 * 1024;
  const timeoutMs = options.timeoutMs ?? 5000;
  try {
    if (url.protocol !== "https:" || url.username || url.password || url.hash) return null;
    const host = url.hostname.replace(/^\[|\]$/g, "");
    const addresses = isIP(host) ? [host] : await resolveHost(host);
    if (addresses.length === 0 || !addresses.every(isPublicAddress)) return null;

    const res = await fetchImpl(url, {
      redirect: "error",
      headers: { Accept: "application/json" },
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (!res.ok) return null;
    const text = await readCappedText(res, maxBytes);
    if (text === null) return null;
    return JSON.parse(text) as unknown;
  } catch {
    return null;
  }
}

/** A validated CIMD: the client plus what `/token` needs to verify a private_key_jwt assertion. */
export interface CimdDocument {
  client: AuthorizeClient;
  /** Present only when the document declares an https `jwks_uri`. */
  jwksUri?: string;
  /** The document's `token_endpoint_auth_signing_alg`, when declared. */
  signingAlg?: string;
}

/**
 * Fetches and validates a Client ID Metadata Document. Returns null for ANY failure — an
 * unreachable, oversized, malformed, private-addressed or self-contradicting document is an
 * unknown client, never a partial one.
 *
 * Limitation (documented in docs/client-assertion.md): the address check resolves the host and
 * the fetch resolves it again, so a DNS-rebinding window exists. A hostile-network deployment
 * injects a `fetchImpl` that pins the validated address (for example an undici dispatcher).
 */
export async function resolveCimdDocument(
  clientId: string,
  options: CimdOptions = {}
): Promise<CimdDocument | null> {
  let url: URL;
  try {
    url = new URL(clientId);
  } catch {
    return null;
  }
  if (url.protocol !== "https:" || url.username || url.password || url.hash) return null;
  if (url.pathname === "/" || url.pathname === "") return null; // the spec requires a path
  if (url.href !== clientId) return null; // client_id is compared as a string; no normalisation

  const parsed = await fetchGuardedJson(url, options);
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return null;
  const doc = parsed as Record<string, unknown>;

  if (doc.client_id !== clientId) return null;
  // The document must offer "none", either as its method or among the methods it supports (a
  // client such as ChatGPT declares private_key_jwt and lists "none"). A client that sends no
  // assertion is a public client and PKCE carries the proof; one that does is verified at /token.
  const method = doc.token_endpoint_auth_method;
  const supported = doc.token_endpoint_auth_methods_supported;
  const acceptsNone = Array.isArray(supported) && supported.includes("none");
  if (method !== undefined && method !== "none" && !acceptsNone) return null;
  const uris = doc.redirect_uris;
  if (!Array.isArray(uris) || uris.length === 0 || uris.length > 20) return null;
  if (!uris.every(isAllowedRedirectUri)) return null;
  return {
    client: {
      clientId,
      redirectUris: uris as string[],
      ...(typeof doc.client_name === "string" ? { clientName: doc.client_name.slice(0, 200) } : {}),
    },
    ...(typeof doc.jwks_uri === "string" ? { jwksUri: doc.jwks_uri } : {}),
    ...(typeof doc.token_endpoint_auth_signing_alg === "string"
      ? { signingAlg: doc.token_endpoint_auth_signing_alg }
      : {}),
  };
}
