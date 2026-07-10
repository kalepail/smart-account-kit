import { describe, expect, it } from "vitest";
import { extractBearerToken, timingSafeEqual } from "./auth";

describe("extractBearerToken", () => {
  it("extracts the token from a well-formed header", () => {
    expect(extractBearerToken("Bearer abc123")).toBe("abc123");
  });

  it("is case-insensitive on the scheme and tolerates extra whitespace", () => {
    expect(extractBearerToken("bearer   abc123  ")).toBe("abc123");
    expect(extractBearerToken("  BEARER token  ")).toBe("token");
  });

  it("returns null for missing or malformed headers", () => {
    expect(extractBearerToken(undefined)).toBeNull();
    expect(extractBearerToken(null)).toBeNull();
    expect(extractBearerToken("")).toBeNull();
    expect(extractBearerToken("Basic abc123")).toBeNull();
    expect(extractBearerToken("Bearer")).toBeNull();
    expect(extractBearerToken("Bearer ")).toBeNull();
  });
});

describe("timingSafeEqual", () => {
  it("returns true only for identical strings", () => {
    expect(timingSafeEqual("s3cret-token", "s3cret-token")).toBe(true);
    expect(timingSafeEqual("", "")).toBe(true);
  });

  it("returns false for differing strings of equal length", () => {
    expect(timingSafeEqual("token", "toker")).toBe(false);
  });

  it("returns false for differing lengths", () => {
    expect(timingSafeEqual("token", "token-longer")).toBe(false);
    expect(timingSafeEqual("", "x")).toBe(false);
    expect(timingSafeEqual("x", "")).toBe(false);
  });
});
