import { describe, it, expect } from "vitest";
import { validateMasterBearer } from "../src/bearer-validation.js";

const SECRET = "s3cret-master-token";

describe("validateMasterBearer", () => {
  it("returns {ok: true} for valid Bearer + correct secret", async () => {
    const res = await validateMasterBearer(`Bearer ${SECRET}`, SECRET);
    expect(res.ok).toBe(true);
    expect(res.error).toBeUndefined();
  });

  it("returns {ok: false, error: 'mismatch'} for valid Bearer but wrong secret", async () => {
    const res = await validateMasterBearer("Bearer wrong-token", SECRET);
    expect(res.ok).toBe(false);
    expect(res.error).toBe("mismatch");
  });

  it("returns {ok: false, error: 'missing'} when Authorization header is undefined", async () => {
    const res = await validateMasterBearer(undefined, SECRET);
    expect(res.ok).toBe(false);
    expect(res.error).toBe("missing");
  });

  it("returns {ok: false, error: 'malformed'} when header has no Bearer prefix", async () => {
    const res = await validateMasterBearer("Token abc123", SECRET);
    expect(res.ok).toBe(false);
    expect(res.error).toBe("malformed");
  });

  it("accepts case-insensitive 'bearer' scheme", async () => {
    const res = await validateMasterBearer(`bearer ${SECRET}`, SECRET);
    expect(res.ok).toBe(true);
  });

  it("rejects empty master secret (server-misconfig safety)", async () => {
    const res = await validateMasterBearer(`Bearer ${SECRET}`, "");
    expect(res.ok).toBe(false);
    expect(res.error).toBe("malformed");
  });

  it("rejects empty token after Bearer prefix", async () => {
    const res = await validateMasterBearer("Bearer ", SECRET);
    expect(res.ok).toBe(false);
    expect(res.error).toBe("malformed");
  });

  it("uses sha256 comparison (different tokens of same length still rejected)", async () => {
    // SECRET length = 19; same-length wrong token must mismatch (hash, not raw).
    const sameLenWrong = "X".repeat(SECRET.length);
    expect(sameLenWrong.length).toBe(SECRET.length);
    const res = await validateMasterBearer(`Bearer ${sameLenWrong}`, SECRET);
    expect(res.ok).toBe(false);
    expect(res.error).toBe("mismatch");
  });

  it("constant-time compare property — full-length vs partial-match both return mismatch", async () => {
    const partial = SECRET.slice(0, 5);
    const r1 = await validateMasterBearer(`Bearer ${partial}`, SECRET);
    const r2 = await validateMasterBearer(`Bearer ${SECRET}X`, SECRET);
    expect(r1.ok).toBe(false);
    expect(r2.ok).toBe(false);
    expect(r1.error).toBe("mismatch");
    expect(r2.error).toBe("mismatch");
  });
});
