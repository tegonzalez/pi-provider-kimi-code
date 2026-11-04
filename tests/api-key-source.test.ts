// Key provenance: an explicit KIMI_API_KEY or configured apiKey is static and
// deliberate for the configured endpoint — it must not fall back to OAuth and
// must not trigger OAuth refresh. OAuth keys come only from credentials bound
// to the configured endpoints and never from a differently bound credential.
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, it } from "node:test";

import { KIMI_CODE_CREDENTIAL_API_KEY, PROVIDER_ID } from "../src/constants.ts";
import { resolveKimiCodeCredentialName } from "../src/oauth.ts";
import { resolveKimiApiKey, resolveKimiApiKeyWithSource } from "../src/stream.ts";

const ENV_KEYS = [
  "KIMI_CODE_HOME",
  "KIMI_SHARE_DIR",
  "PI_CODING_AGENT_DIR",
  "KIMI_API_KEY",
  "KIMI_CODE_REGION",
  "KIMI_CODE_OAUTH_HOST",
  "KIMI_OAUTH_HOST",
  "KIMI_CODE_BASE_URL",
  "KIMI_BASE_URL",
] as const;

const CUSTOM_HOST = "https://auth.custom.example";
const CUSTOM_BASE = "https://api.custom.example/v1";

let saved: Record<string, string | undefined>;
let dir: string;

function writeCliCredential(access: string, endpoint?: object): void {
  const credentialsDir = join(process.env.KIMI_CODE_HOME!, "credentials");
  mkdirSync(credentialsDir, { recursive: true });
  const slot = resolveKimiCodeCredentialName(CUSTOM_HOST, CUSTOM_BASE);
  writeFileSync(
    join(credentialsDir, `${slot}.json`),
    JSON.stringify({
      access_token: access,
      refresh_token: `refresh-${access}`,
      expires_at: Math.floor(Date.now() / 1000) + 3600,
      ...(endpoint ? { endpoint } : {}),
    }),
  );
}

beforeEach(() => {
  saved = Object.fromEntries(ENV_KEYS.map((k) => [k, process.env[k]]));
  for (const k of ENV_KEYS) delete process.env[k];
  dir = mkdtempSync(join(tmpdir(), "kimi-key-source-"));
  process.env.KIMI_CODE_HOME = join(dir, "kimi-code");
  process.env.KIMI_SHARE_DIR = join(dir, "no-legacy");
  process.env.PI_CODING_AGENT_DIR = join(dir, "pi-agent");
  process.env.KIMI_CODE_OAUTH_HOST = CUSTOM_HOST;
  process.env.KIMI_CODE_BASE_URL = CUSTOM_BASE;
});

afterEach(() => {
  for (const k of ENV_KEYS) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k];
  }
  rmSync(dir, { recursive: true, force: true });
});

describe("resolveKimiApiKeyWithSource", () => {
  it("treats an explicit apiKey and KIMI_API_KEY as static", () => {
    assert.deepEqual(resolveKimiApiKeyWithSource("explicit-key"), {
      key: "explicit-key",
      source: "static",
    });
    process.env.KIMI_API_KEY = "env-key";
    assert.deepEqual(resolveKimiApiKeyWithSource(undefined), { key: "env-key", source: "static" });
    assert.deepEqual(resolveKimiApiKeyWithSource("$KIMI_API_KEY"), {
      key: "env-key",
      source: "static",
    });
    assert.deepEqual(resolveKimiApiKeyWithSource("${KIMI_API_KEY}"), {
      key: "env-key",
      source: "static",
    });
  });

  it("resolves the marker to a bound OAuth token only, never to a mismatched credential", () => {
    // Exact slot for this binding is written by the fixture; a token bound to
    // another endpoint must be ignored.
    writeCliCredential("bound-ok", { oauthHost: CUSTOM_HOST, baseUrl: CUSTOM_BASE });
    assert.deepEqual(resolveKimiApiKeyWithSource(KIMI_CODE_CREDENTIAL_API_KEY), {
      key: "bound-ok",
      source: "oauth",
    });
    assert.equal(resolveKimiApiKey(KIMI_CODE_CREDENTIAL_API_KEY), "bound-ok");

    rmSync(join(process.env.KIMI_CODE_HOME!, "credentials"), { recursive: true, force: true });
    writeCliCredential("bound-elsewhere", {
      oauthHost: "https://auth.other.example",
      baseUrl: "https://api.other.example/v1",
    });
    const resolved = resolveKimiApiKeyWithSource(KIMI_CODE_CREDENTIAL_API_KEY);
    assert.equal(resolved.source, "oauth");
    assert.equal(resolved.key, "");
  });

  it("prefers a static env key over the OAuth credential", () => {
    writeCliCredential("bound-ok", { oauthHost: CUSTOM_HOST, baseUrl: CUSTOM_BASE });
    process.env.KIMI_API_KEY = "env-key";
    assert.deepEqual(resolveKimiApiKeyWithSource(KIMI_CODE_CREDENTIAL_API_KEY), {
      key: "env-key",
      source: "static",
    });
    // And an explicit static key wins over everything.
    assert.deepEqual(resolveKimiApiKeyWithSource("explicit-key"), {
      key: "explicit-key",
      source: "static",
    });
  });

  it("reads only binding-valid pi credentials from the store", () => {
    mkdirSync(process.env.PI_CODING_AGENT_DIR!, { recursive: true });
    const authPath = join(process.env.PI_CODING_AGENT_DIR!, "auth.json");
    writeFileSync(
      authPath,
      JSON.stringify({
        [PROVIDER_ID]: {
          type: "oauth",
          access: "pi-bound-ok",
          refresh: "r",
          expires: Date.now() + 3600_000,
          endpoint: { oauthHost: CUSTOM_HOST, baseUrl: CUSTOM_BASE },
        },
      }),
    );
    assert.equal(resolveKimiApiKey(undefined), "pi-bound-ok");
    // Bound elsewhere: not used, and no fallback to it.
    writeFileSync(
      authPath,
      JSON.stringify({
        [PROVIDER_ID]: {
          type: "oauth",
          access: "pi-bound-elsewhere",
          refresh: "r",
          expires: Date.now() + 3600_000,
          endpoint: {
            oauthHost: "https://auth.other.example",
            baseUrl: "https://api.other.example/v1",
          },
        },
      }),
    );
    assert.equal(resolveKimiApiKey(undefined), "");
  });
});
