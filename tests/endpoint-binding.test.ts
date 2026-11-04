// Endpoint binding canonicalization: credentials are minted for exactly one
// (oauthHost, baseUrl) pair; trivial spelling differences must not fragment
// the slot, and the normalized full /v1 path must be preserved.
import assert from "node:assert/strict";
import { afterEach, beforeEach, describe, it } from "node:test";

const ENV_KEYS = [
  "KIMI_CODE_REGION",
  "KIMI_CODE_OAUTH_HOST",
  "KIMI_OAUTH_HOST",
  "KIMI_CODE_BASE_URL",
  "KIMI_BASE_URL",
] as const;

let saved: Record<string, string | undefined>;

beforeEach(() => {
  saved = Object.fromEntries(ENV_KEYS.map((k) => [k, process.env[k]]));
  for (const k of ENV_KEYS) delete process.env[k];
});

afterEach(() => {
  for (const k of ENV_KEYS) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k];
  }
});

describe("canonicalizeKimiEndpointUrl", () => {
  it("lowercases scheme and host and drops the default port", () => {
    assert.equal(
      canonicalize("HTTPS://API.Kimi.COM:443/coding/v1"),
      "https://api.kimi.com/coding/v1",
    );
  });

  it("keeps a non-default port", () => {
    assert.equal(
      canonicalize("https://api.kimi.com:8443/coding/v1"),
      "https://api.kimi.com:8443/coding/v1",
    );
  });

  it("strips trailing slashes", () => {
    assert.equal(canonicalize("https://auth.kimi.com/"), "https://auth.kimi.com");
    assert.equal(
      canonicalize("https://api.kimi.com/coding/v1///"),
      "https://api.kimi.com/coding/v1",
    );
  });

  it("appends nothing and preserves the full path", () => {
    assert.equal(
      canonicalize("https://example.com/custom/prefix/v1"),
      "https://example.com/custom/prefix/v1",
    );
  });

  it("returns trimmed input for values URL cannot parse", () => {
    assert.equal(canonicalize("  not-a-url  "), "not-a-url");
  });
});

describe("getKimiEndpointBinding", () => {
  it("resolves the mainland default binding", () => {
    const binding = getKimiEndpointBinding();
    assert.deepEqual(binding, {
      oauthHost: "https://auth.kimi.com",
      baseUrl: "https://api.kimi.com/coding/v1",
    });
    assert.equal(isMainlandKimiEndpointBinding(binding), true);
  });

  it("resolves a custom env-defined binding, canonicalized", () => {
    process.env.KIMI_CODE_OAUTH_HOST = "HTTPS://Auth.Example.COM:443/";
    process.env.KIMI_CODE_BASE_URL = "https://api.example.com";
    const binding = getKimiEndpointBinding();
    assert.deepEqual(binding, {
      oauthHost: "https://auth.example.com",
      baseUrl: "https://api.example.com/v1",
    });
    assert.equal(isMainlandKimiEndpointBinding(binding), false);
  });

  it("compares bindings exactly", () => {
    assert.equal(
      kimiEndpointBindingsEqual(
        { oauthHost: "https://auth.kimi.com", baseUrl: "https://api.kimi.com/coding/v1" },
        { oauthHost: "https://auth.kimi.com", baseUrl: "https://api.kimi.com/coding/v1" },
      ),
      true,
    );
    assert.equal(
      kimiEndpointBindingsEqual(
        { oauthHost: "https://auth.kimi.com", baseUrl: "https://api.kimi.com/coding/v1" },
        { oauthHost: "https://auth.kimi.ai", baseUrl: "https://api.kimi.ai/coding/v1" },
      ),
      false,
    );
    assert.equal(kimiEndpointBindingsEqual(undefined, { oauthHost: "a", baseUrl: "b" }), false);
  });
});

import {
  canonicalizeKimiEndpointUrl as canonicalize,
  getKimiEndpointBinding,
  isMainlandKimiEndpointBinding,
  kimiEndpointBindingsEqual,
} from "../src/constants.ts";
