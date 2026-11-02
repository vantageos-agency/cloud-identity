import { describe, expect, it } from "vitest";
import {
  fetchGuardedJson,
  isPublicAddress,
  isUrlShapedClientId,
  resolveCimdDocument,
} from "../src/client-assertion.js";

/**
 * The SSRF guard and CIMD resolver the assertion verifier fetches through, ported from the
 * boilerplate's hardening suite (`isPublicAddress (CIMD SSRF guard)`, `resolveCimdClient`).
 *
 * CENSUS of address forms the guard must refuse (derived, not recalled): the blocklist union
 * (cloud metadata, 127/8, 0/8, ::1, RFC 1918, link-local, unique-local, multicast, CGNAT, IETF
 * protocol block, benchmarking, reserved >= 240) and the forms the WHATWG URL parser and
 * node:net accept for one IPv6 address: dotted-mapped, hex-mapped, IPv4-compatible, mixed
 * case, fully expanded, NAT64, zone id, IPv4-translated, 6to4, ISATAP (both interface ids,
 * under ANY prefix), and the FIRST address of every range in each embedding. Positive
 * controls prove the guard still lets a public address through in every form.
 */
const V4_RANGE_FIRST = [
  "0.0.0.0", // 0.0.0.0/8
  "10.0.0.0", // 10/8
  "100.64.0.0", // CGNAT 100.64/10
  "127.0.0.0", // 127/8
  "169.254.0.0", // 169.254/16
  "169.254.169.254", // cloud metadata
  "172.16.0.0", // 172.16/12
  "192.0.0.0", // 192.0.0/24
  "192.168.0.0", // 192.168/16
  "198.18.0.0", // 198.18/15
  "224.0.0.0", // multicast 224/4
  "240.0.0.0", // reserved 240/4
  "255.255.255.255",
];
const V6_RANGE_FIRST = [
  "::", // ::/128
  "::1", // ::1/128
  "fc00::", // fc00::/7
  "fd00::",
  "fe80::", // fe80::/10
  "febf::1",
  "ff00::", // ff00::/8
  "64:ff9b:1::", // NAT64 local-use 64:ff9b:1::/48
  "2001::", // Teredo 2001::/32 (embeds a server and an obfuscated client IPv4)
  "2001:0:4136:e378:8000:63bf:3fff:fdd2", // a Teredo address
];
const toHexMapped = (v4: string, prefix: string): string => {
  const [a, b, c, d] = v4.split(".").map(Number) as [number, number, number, number];
  const hi = ((a << 8) | b).toString(16);
  const lo = ((c << 8) | d).toString(16);
  return `${prefix}${hi}:${lo}`;
};

/** 6to4: 2002:AABB:CCDD::/48 carries a.b.c.d in bits 16-47. */
const toSixToFour = (v4: string): string => {
  const [a, b, c, d] = v4.split(".").map(Number) as [number, number, number, number];
  return `2002:${((a << 8) | b).toString(16)}:${((c << 8) | d).toString(16)}::1`;
};

/** ISATAP: <prefix>::[0000|0200]:5efe:<v4 high>:<v4 low>, on a global prefix. */
const toIsatap = (v4: string, iid: "0000" | "0200"): string => {
  const [a, b, c, d] = v4.split(".").map(Number) as [number, number, number, number];
  const hi = ((a << 8) | b).toString(16);
  const lo = ((c << 8) | d).toString(16);
  return `2606:4700:0:0:${iid}:5efe:${hi}:${lo}`;
};

describe("isPublicAddress (CIMD SSRF guard)", () => {
  it.each([
    "127.0.0.1",
    "10.1.2.3",
    "172.16.0.1",
    "172.31.255.255",
    "192.168.1.1",
    "169.254.169.254",
    "100.64.0.1",
    "0.0.0.0",
    "224.0.0.1",
    "::1",
    "::",
    "fe80::1",
    "fd00::1",
    "ff02::1",
    "::ffff:10.0.0.1",
    "::ffff:127.0.0.1",
    // hex-mapped (the bypass): loopback, cloud metadata, RFC 1918
    "::ffff:7f00:1",
    "::ffff:a9fe:a9fe",
    "::ffff:c0a8:101",
    "::ffff:a00:1",
    // IPv4-compatible, mixed case, expanded
    "::7f00:1",
    "::FFFF:7F00:1",
    "0:0:0:0:0:ffff:7f00:1",
    "0000:0000:0000:0000:0000:ffff:7f00:0001",
    // NAT64 embedding a private v4
    "64:ff9b::7f00:1",
    "64:ff9b::127.0.0.1",
    "64:ff9b::a9fe:a9fe",
    // IPv4-translated (::ffff:0:0/96) and 6to4 (2002::/16) embedding a private v4
    "::ffff:0:7f00:1",
    "::ffff:0:a9fe:a9fe",
    "2002:7f00:1::1",
    "2002:a9fe:a9fe::1",
    // ISATAP embedding a private v4: both interface-id variants, compressed, expanded, dotted
    "2606:4700::5efe:7f00:1",
    "2606:4700::200:5efe:7f00:1",
    "2606:4700:0:0:0:5efe:a9fe:a9fe",
    "2606:4700:0:0:0200:5efe:a9fe:a9fe",
    "2606:4700::5efe:127.0.0.1",
    "2606:4700::200:5efe:10.0.0.1",
    "2606:4700::5EFE:C0A8:101",
    // zone id, garbage, empty
    "fe80::1%eth0",
    "not-an-ip",
    "",
  ])("%s is refused", (ip) => {
    expect(isPublicAddress(ip)).toBe(false);
  });

  it.each(V4_RANGE_FIRST)(
    "range first address %s is refused (v4, hex-mapped, NAT64, translated, 6to4)",
    (v4) => {
      expect(isPublicAddress(v4)).toBe(false);
      expect(isPublicAddress(toHexMapped(v4, "::ffff:"))).toBe(false);
      expect(isPublicAddress(toHexMapped(v4, "64:ff9b::"))).toBe(false);
      expect(isPublicAddress(toHexMapped(v4, "::ffff:0:"))).toBe(false);
      expect(isPublicAddress(toSixToFour(v4))).toBe(false);
      expect(isPublicAddress(toIsatap(v4, "0000"))).toBe(false);
      expect(isPublicAddress(toIsatap(v4, "0200"))).toBe(false);
    }
  );

  it.each(V6_RANGE_FIRST)("range first address %s is refused (v6)", (v6) => {
    expect(isPublicAddress(v6)).toBe(false);
  });

  it.each([
    "93.184.216.34",
    "8.8.8.8",
    "172.32.0.1",
    "2606:4700:4700::1111",
    "::ffff:5db8:d822", // 93.184.216.34 hex-mapped
    "::ffff:93.184.216.34",
    "64:ff9b::5db8:d822", // 93.184.216.34 via NAT64
    "::ffff:0:5db8:d822", // 93.184.216.34 IPv4-translated
    "2002:5db8:d822::1", // 93.184.216.34 via 6to4
    "2606:4700::5efe:5db8:d822", // 93.184.216.34 via ISATAP (0000:5efe)
    "2606:4700::200:5efe:5db8:d822", // 93.184.216.34 via ISATAP (0200:5efe)
    "2606:4700::5efe:1", // 5efe outside bits 80-95 is not ISATAP
  ])("%s is accepted (positive control)", (ip) => {
    expect(isPublicAddress(ip)).toBe(true);
  });
});

const CHATGPT_ID = "https://chatgpt.com/oauth/client.json";
const CHATGPT_REDIRECT = "https://chatgpt.com/connector_platform_oauth_redirect";
const chatgptDoc = {
  client_id: CHATGPT_ID,
  client_name: "ChatGPT",
  redirect_uris: [CHATGPT_REDIRECT],
  token_endpoint_auth_method: "private_key_jwt",
  token_endpoint_auth_methods_supported: ["none", "private_key_jwt"],
  token_endpoint_auth_signing_alg: "RS256",
  jwks_uri: "https://chatgpt.com/oauth/jwks.json",
};

describe("resolveCimdDocument (ChatGPT document: private_key_jwt + none supported)", () => {
  const run = (doc: Record<string, unknown>) =>
    resolveCimdDocument(CHATGPT_ID, {
      resolveHost: async () => ["93.184.216.34"],
      fetchImpl: (async () => new Response(JSON.stringify(doc))) as typeof fetch,
    });

  it("accepts the exact ChatGPT document and returns its redirect URI", async () => {
    const out = await run(chatgptDoc);
    expect(out?.client.clientId).toBe(CHATGPT_ID);
    expect(out?.client.redirectUris).toEqual([CHATGPT_REDIRECT]);
    expect(out?.jwksUri).toBe("https://chatgpt.com/oauth/jwks.json");
    expect(out?.signingAlg).toBe("RS256");
  });

  it("still refuses a non-none method when none is not in the supported list", async () => {
    expect(
      await run({
        ...chatgptDoc,
        token_endpoint_auth_methods_supported: ["private_key_jwt"],
      })
    ).toBeNull();
    const { token_endpoint_auth_methods_supported: _omit, ...noList } = chatgptDoc;
    expect(await run(noList)).toBeNull();
  });
});

describe("resolveCimdDocument (CIMD fetch guard)", () => {
  const CLIENT_ID = "https://app.example.com/cimd.json";
  const doc = JSON.stringify({
    client_id: CLIENT_ID,
    redirect_uris: ["https://app.example.com/cb"],
  });

  it("refuses a host whose AAAA record is a hex-mapped loopback, and never fetches", async () => {
    let fetched = 0;
    const out = await resolveCimdDocument(CLIENT_ID, {
      resolveHost: async () => ["::ffff:7f00:1"],
      fetchImpl: (async () => {
        fetched++;
        return new Response(doc);
      }) as typeof fetch,
    });
    expect(out).toBeNull();
    expect(fetched).toBe(0);
  });

  it("refuses a hex-mapped literal host without fetching", async () => {
    let fetched = 0;
    const out = await resolveCimdDocument("https://[::ffff:a9fe:a9fe]/latest/meta-data", {
      fetchImpl: (async () => {
        fetched++;
        return new Response("{}");
      }) as typeof fetch,
    });
    expect(out).toBeNull();
    expect(fetched).toBe(0);
  });

  it("accepts a small document on a public address (positive control)", async () => {
    const out = await resolveCimdDocument(CLIENT_ID, {
      resolveHost: async () => ["93.184.216.34"],
      fetchImpl: (async () => new Response(doc)) as typeof fetch,
    });
    expect(out?.client.clientId).toBe(CLIENT_ID);
  });

  it("refuses a body over maxBytes AND cancels the reader before the full body is read", async () => {
    const chunk = new Uint8Array(1024).fill(32);
    const totalChunks = 200;
    let pulled = 0;
    let cancelled = false;
    const body = new ReadableStream<Uint8Array>({
      pull(controller) {
        if (pulled >= totalChunks) return controller.close();
        pulled++;
        controller.enqueue(chunk);
      },
      cancel() {
        cancelled = true;
      },
    });
    const out = await resolveCimdDocument(CLIENT_ID, {
      maxBytes: 4096,
      resolveHost: async () => ["93.184.216.34"],
      fetchImpl: (async () => new Response(body)) as typeof fetch,
    });
    expect(out).toBeNull();
    expect(cancelled).toBe(true);
    // At most maxBytes (+ the one chunk that crossed it, + stream queue read-ahead) was pulled.
    expect(pulled).toBeLessThan(totalChunks / 4);
  });
});

describe("resolveCimdDocument (document refusals)", () => {
  const ID = "https://app.example.com/cimd.json";
  const okDoc = { client_id: ID, redirect_uris: ["https://app.example.com/cb"] };
  const run = (id: string, doc: unknown) =>
    resolveCimdDocument(id, {
      resolveHost: async () => ["93.184.216.34"],
      fetchImpl: (async () => new Response(JSON.stringify(doc))) as typeof fetch,
    });

  it("positive control: a minimal document has no jwksUri and no signingAlg", async () => {
    expect(await run(ID, okDoc)).toEqual({
      client: { clientId: ID, redirectUris: ["https://app.example.com/cb"] },
    });
  });

  it.each([
    ["no path", "https://app.example.com/"],
    ["non-https", "http://app.example.com/cimd.json"],
    ["credentials", "https://u:p@app.example.com/cimd.json"],
    ["a fragment", "https://app.example.com/cimd.json#x"],
    ["not normalised (the client_id is compared as a string)", "https://APP.example.com/cimd.json"],
    ["not a URL", "client_abc"],
  ])("refuses a client_id with %s", async (_name, id) => {
    expect(await run(id, { ...okDoc, client_id: id })).toBeNull();
  });

  it.each([
    ["an array", [okDoc]],
    ["no redirect_uris", { client_id: ID }],
    ["an empty redirect_uris", { ...okDoc, redirect_uris: [] }],
    ["over 20 redirect_uris", { ...okDoc, redirect_uris: Array(21).fill("https://a.example/cb") }],
    ["a non-https, non-loopback redirect", { ...okDoc, redirect_uris: ["http://a.example/cb"] }],
    ["a client_secret_basic method", { ...okDoc, token_endpoint_auth_method: "client_secret_basic" }],
  ])("refuses a document with %s", async (_name, doc) => {
    expect(await run(ID, doc)).toBeNull();
  });
});

describe("fetchGuardedJson", () => {
  const url = new URL("https://keys.example.com/jwks.json");
  const pub = async () => ["93.184.216.34"];

  it("positive control: a public https URL returns parsed JSON", async () => {
    const out = await fetchGuardedJson(url, {
      resolveHost: pub,
      fetchImpl: (async () => Response.json({ a: 1 })) as typeof fetch,
    });
    expect(out).toEqual({ a: 1 });
  });

  it("asks fetch to refuse redirects", async () => {
    let redirect: RequestRedirect | undefined;
    await fetchGuardedJson(url, {
      resolveHost: pub,
      fetchImpl: (async (_u: unknown, init?: RequestInit) => {
        redirect = init?.redirect;
        return Response.json({});
      }) as typeof fetch,
    });
    expect(redirect).toBe("error");
  });

  it("a non-2xx answer, a throwing fetch and a throwing resolver are each null", async () => {
    const notOk = (async () => new Response("{}", { status: 500 })) as typeof fetch;
    const throws = (async () => {
      throw new Error("boom");
    }) as typeof fetch;
    expect(await fetchGuardedJson(url, { resolveHost: pub, fetchImpl: notOk })).toBeNull();
    expect(await fetchGuardedJson(url, { resolveHost: pub, fetchImpl: throws })).toBeNull();
    expect(
      await fetchGuardedJson(url, {
        resolveHost: async () => {
          throw new Error("ENOTFOUND");
        },
        fetchImpl: (async () => Response.json({})) as typeof fetch,
      }),
    ).toBeNull();
  });

  it("caps at 16 KiB by default", async () => {
    const big = JSON.stringify({ pad: "x".repeat(16 * 1024) });
    const out = await fetchGuardedJson(url, {
      resolveHost: pub,
      fetchImpl: (async () => new Response(big)) as typeof fetch,
    });
    expect(out).toBeNull();
  });
});

describe("isUrlShapedClientId", () => {
  it.each([
    ["https://a.example/c.json", true],
    ["HTTP://a.example/c.json", true],
    ["client_abc", false],
    ["", false],
  ])("%s -> %s", (id, want) => {
    expect(isUrlShapedClientId(id)).toBe(want);
  });
});
