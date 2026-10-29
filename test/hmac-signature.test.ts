import { createHmac } from "node:crypto";
import { beforeEach, describe, expect, it, vi } from "vitest";

// The compare is the package's existing `timingSafeEqualSync`; wrap it so the
// tests can see that every decision goes through it, with no shortcut before it.
vi.mock("../src/secret-compare-sync.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/secret-compare-sync.js")>();
  return { ...actual, timingSafeEqualSync: vi.fn(actual.timingSafeEqualSync) };
});

import { verifyHmacSha256Signature } from "../src/hmac-signature.js";
import { timingSafeEqualSync } from "../src/secret-compare-sync.js";

// Synthetic placeholders; nothing here is a live secret.
const SECRET = "synthetic-hmac-secret";
const BODY = "seller_id=abc&sale_id=123&email=buyer%40example.test";

// Oracle only: node:crypto computes the expected digest INSIDE THE TEST. The
// package itself uses Web Crypto and never imports node:crypto.
const hexOf = (body: string, secret = SECRET) => createHmac("sha256", secret).update(body).digest("hex");
const b64Of = (body: string, secret = SECRET) => createHmac("sha256", secret).update(body).digest("base64");

const reasonOf = (r: Awaited<ReturnType<typeof verifyHmacSha256Signature>>) => (r.ok ? null : r.refusal.reason);

beforeEach(() => {
  vi.mocked(timingSafeEqualSync).mockClear();
});

describe("verifyHmacSha256Signature: accepts", () => {
  it("a correct hex signature", async () => {
    expect(await verifyHmacSha256Signature({ body: BODY, signature: hexOf(BODY) }, { secret: SECRET })).toEqual({
      ok: true,
    });
  });

  it("an uppercase hex signature (hex is case-insensitive)", async () => {
    const r = await verifyHmacSha256Signature({ body: BODY, signature: hexOf(BODY).toUpperCase() }, { secret: SECRET });
    expect(r).toEqual({ ok: true });
  });

  it("a correct base64 signature when encoding is base64", async () => {
    const r = await verifyHmacSha256Signature(
      { body: BODY, signature: b64Of(BODY) },
      { secret: SECRET, encoding: "base64" },
    );
    expect(r).toEqual({ ok: true });
  });

  it("a `sha256=` prefixed signature, in either encoding", async () => {
    expect(
      await verifyHmacSha256Signature({ body: BODY, signature: `sha256=${hexOf(BODY)}` }, { secret: SECRET }),
    ).toEqual({ ok: true });
    expect(
      await verifyHmacSha256Signature(
        { body: BODY, signature: `sha256=${b64Of(BODY)}` },
        { secret: SECRET, encoding: "base64" },
      ),
    ).toEqual({ ok: true });
  });

  it("the body as bytes equals the body as text", async () => {
    const r = await verifyHmacSha256Signature(
      { body: new TextEncoder().encode(BODY), signature: hexOf(BODY) },
      { secret: SECRET },
    );
    expect(r).toEqual({ ok: true });
  });

  it("a known RFC 4231 vector (test case 2: key 'Jefe')", async () => {
    const r = await verifyHmacSha256Signature(
      {
        body: "what do ya want for nothing?",
        signature: "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
      },
      { secret: "Jefe" },
    );
    expect(r).toEqual({ ok: true });
  });

  it("a multibyte body is signed over its UTF-8 bytes", async () => {
    const body = "prix=12€&nom=Hélène";
    expect(await verifyHmacSha256Signature({ body, signature: hexOf(body) }, { secret: SECRET })).toEqual({ ok: true });
  });
});

describe("verifyHmacSha256Signature: refuses", () => {
  it("one flipped hex character -> webhook-signature-mismatch (CREDENTIAL_REFUSED)", async () => {
    const good = hexOf(BODY);
    for (const i of [0, 31, 63]) {
      const flipped = good.slice(0, i) + (good[i] === "0" ? "1" : "0") + good.slice(i + 1);
      const r = await verifyHmacSha256Signature({ body: BODY, signature: flipped }, { secret: SECRET });
      expect(r.ok).toBe(false);
      if (!r.ok) {
        expect(r.refusal.code).toBe("CREDENTIAL_REFUSED");
        expect(r.refusal.reason).toBe("webhook-signature-mismatch");
      }
    }
  });

  it("a signature over a different body or a different secret", async () => {
    expect(reasonOf(await verifyHmacSha256Signature({ body: BODY + "x", signature: hexOf(BODY) }, { secret: SECRET }))).toBe(
      "webhook-signature-mismatch",
    );
    expect(
      reasonOf(await verifyHmacSha256Signature({ body: BODY, signature: hexOf(BODY, "other") }, { secret: SECRET })),
    ).toBe("webhook-signature-mismatch");
  });

  it("a wrong length (truncated, extended) -> webhook-signature-mismatch", async () => {
    const good = hexOf(BODY);
    for (const sig of [good.slice(0, 62), good.slice(0, 32), good + "00", good + "0", "ab"]) {
      expect(reasonOf(await verifyHmacSha256Signature({ body: BODY, signature: sig }, { secret: SECRET }))).toBe(
        "webhook-signature-mismatch",
      );
    }
  });

  it("non-hex characters at the right length -> webhook-signature-mismatch", async () => {
    const nonHex = "zz" + hexOf(BODY).slice(2);
    expect(reasonOf(await verifyHmacSha256Signature({ body: BODY, signature: nonHex }, { secret: SECRET }))).toBe(
      "webhook-signature-mismatch",
    );
  });

  it("hex presented while base64 is declared (and the reverse) -> mismatch", async () => {
    expect(
      reasonOf(await verifyHmacSha256Signature({ body: BODY, signature: hexOf(BODY) }, { secret: SECRET, encoding: "base64" })),
    ).toBe("webhook-signature-mismatch");
    expect(reasonOf(await verifyHmacSha256Signature({ body: BODY, signature: b64Of(BODY) }, { secret: SECRET }))).toBe(
      "webhook-signature-mismatch",
    );
  });

  it("a malformed base64 string -> mismatch, never a throw", async () => {
    for (const sig of ["!!!!", "====", "a", b64Of(BODY).slice(0, 10)]) {
      expect(
        reasonOf(await verifyHmacSha256Signature({ body: BODY, signature: sig }, { secret: SECRET, encoding: "base64" })),
      ).toBe("webhook-signature-mismatch");
    }
  });

  it("an empty, absent or non-string secret -> webhook-secret-invalid, even with a signature that matches an empty key", async () => {
    const emptyKeySig = hexOf(BODY, "");
    for (const secret of ["", undefined, null, 42 as unknown as string]) {
      const r = await verifyHmacSha256Signature({ body: BODY, signature: emptyKeySig }, { secret });
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.refusal.reason).toBe("webhook-secret-invalid");
    }
  });

  it("an empty, absent or non-string signature -> webhook-headers-missing", async () => {
    for (const signature of ["", undefined, null, "sha256=", 7 as unknown as string]) {
      const r = await verifyHmacSha256Signature({ body: BODY, signature }, { secret: SECRET });
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.refusal.reason).toBe("webhook-headers-missing");
    }
  });

  it("an empty body is a body: its signature verifies, a wrong one does not", async () => {
    expect(await verifyHmacSha256Signature({ body: "", signature: hexOf("") }, { secret: SECRET })).toEqual({ ok: true });
    expect(reasonOf(await verifyHmacSha256Signature({ body: "", signature: hexOf(BODY) }, { secret: SECRET }))).toBe(
      "webhook-signature-mismatch",
    );
  });

  it("the refusal never carries the secret, the signature or the body", async () => {
    const sig = hexOf(BODY).replace(/.$/, "0");
    const r = await verifyHmacSha256Signature({ body: BODY, signature: sig }, { secret: SECRET });
    const text = JSON.stringify(r);
    expect(text).not.toContain(SECRET);
    expect(text).not.toContain(sig);
    expect(text).not.toContain("seller_id");
  });

  it("never writes the secret or the body to the console", async () => {
    const spies = (["log", "warn", "error", "info", "debug"] as const).map((m) => vi.spyOn(console, m));
    await verifyHmacSha256Signature({ body: BODY, signature: "nope" }, { secret: SECRET });
    await verifyHmacSha256Signature({ body: BODY, signature: hexOf(BODY) }, { secret: SECRET });
    for (const s of spies) {
      expect(s).not.toHaveBeenCalled();
      s.mockRestore();
    }
  });
});

describe("verifyHmacSha256Signature: constant-time compare, no early exit", () => {
  it("every decision on a non-empty secret and signature goes through timingSafeEqualSync, once", async () => {
    const good = hexOf(BODY);
    const cases = [
      good, // match
      "0" + good.slice(1), // first byte wrong
      good.slice(0, 63) + "0", // last byte wrong
      good.slice(0, 20), // wrong length
      "zz" + good.slice(2), // non-hex
      "not a signature at all", // garbage
    ];
    for (const signature of cases) {
      vi.mocked(timingSafeEqualSync).mockClear();
      await verifyHmacSha256Signature({ body: BODY, signature }, { secret: SECRET });
      expect(timingSafeEqualSync).toHaveBeenCalledTimes(1);
    }
  });

  it("the compare is fed the computed digest and a 32-byte candidate, whatever was presented", async () => {
    const good = hexOf(BODY);
    for (const signature of [good, good.slice(0, 20), "zz" + good.slice(2)]) {
      vi.mocked(timingSafeEqualSync).mockClear();
      await verifyHmacSha256Signature({ body: BODY, signature }, { secret: SECRET });
      const [a, b] = vi.mocked(timingSafeEqualSync).mock.calls[0] as [Uint8Array, Uint8Array];
      expect(Buffer.from(a).toString("hex")).toBe(good);
      expect(b).toBeInstanceOf(Uint8Array);
      expect(b.length).toBe(32);
    }
  });

  it("a malformed candidate that happens to decode to the digest bytes still cannot pass", async () => {
    // Non-hex input is forced false even if a compare were to return true.
    vi.mocked(timingSafeEqualSync).mockReturnValueOnce(true);
    const r = await verifyHmacSha256Signature({ body: BODY, signature: "zz" + hexOf(BODY).slice(2) }, { secret: SECRET });
    expect(r.ok).toBe(false);
  });
});
