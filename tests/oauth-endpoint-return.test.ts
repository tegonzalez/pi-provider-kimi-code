// The credentials loginKimiCode / refreshKimiCodeToken return are persisted by
// pi core verbatim into auth.json, so every return must carry the exact
// endpoint binding it was minted for. All tokens here are fake fixtures.
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, it } from "node:test";

import {
  PROVIDER_ID,
  canonicalizeKimiEndpointUrl,
  getKimiEndpointBinding,
  normalizeKimiBaseV1,
} from "../src/constants.ts";
import {
  loginKimiCode,
  readBoundStoredOAuthCredential,
  refreshKimiCodeToken,
  resolveKimiCodeCredentialName,
} from "../src/oauth.ts";

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

const FAKE_OAUTH_HOST = "https://auth.disabled.invalid";
const FAKE_BASE_URL = "https://api.disabled.invalid";
const EXPECTED_BINDING = {
  oauthHost: FAKE_OAUTH_HOST,
  baseUrl: `${FAKE_BASE_URL}/v1`,
};

let dir: string;
let home: string;
let agentDir: string;
let saved: Record<string, string | undefined>;
const realFetch = globalThis.fetch;

const nowSec = () => Math.floor(Date.now() / 1000);

function credentialSlot(): string {
  return join(home, "credentials", `${resolveKimiCodeCredentialName()}.json`);
}

function writeCliCredential(
  access: string,
  refresh: string,
  expiresAtSec: number,
  endpoint: unknown = { ...EXPECTED_BINDING },
): string {
  const path = credentialSlot();
  mkdirSync(join(home, "credentials"), { recursive: true });
  writeFileSync(
    path,
    JSON.stringify({
      access_token: access,
      refresh_token: refresh,
      expires_at: expiresAtSec,
      scope: "",
      token_type: "Bearer",
      ...(endpoint ? { endpoint } : {}),
    }),
  );
  return path;
}

function writePiCredential(
  access: string,
  refresh: string,
  expiresMs: number,
  endpoint: unknown = { ...EXPECTED_BINDING },
): void {
  mkdirSync(agentDir, { recursive: true });
  writeFileSync(
    join(agentDir, "auth.json"),
    JSON.stringify({
      [PROVIDER_ID]: {
        type: "oauth",
        access,
        refresh,
        expires: expiresMs,
        ...(endpoint ? { endpoint } : {}),
      },
    }),
  );
}

interface FetchRoute {
  (url: string, init: RequestInit | undefined): Response | Promise<Response>;
}

function mockFetch(route: FetchRoute): { calls: string[] } {
  const calls: string[] = [];
  globalThis.fetch = (async (input: unknown, init?: RequestInit) => {
    const url = String(input);
    calls.push(url);
    return route(url, init);
  }) as typeof fetch;
  return { calls };
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

const tokenJson = (access: string, refresh: string) => ({
  access_token: access,
  refresh_token: refresh,
  expires_in: 900,
  scope: "kimi-code",
  token_type: "Bearer",
});

const IGNORED_CREDENTIALS = { access: "ignored", refresh: "ignored", expires: 0 };

const silentCallbacks = {
  onAuth: () => {},
  onDeviceCode: () => {},
  onPrompt: async () => "",
  onSelect: async () => undefined,
  onProgress: () => {},
};

beforeEach(() => {
  saved = Object.fromEntries(ENV_KEYS.map((k) => [k, process.env[k]]));
  for (const k of ENV_KEYS) delete process.env[k];
  dir = mkdtempSync(join(tmpdir(), "kimi-endpoint-return-"));
  home = join(dir, "kimi-code-home");
  agentDir = join(dir, "pi-agent");
  process.env.KIMI_CODE_HOME = home;
  process.env.KIMI_SHARE_DIR = join(dir, "no-legacy");
  process.env.PI_CODING_AGENT_DIR = agentDir;
  process.env.KIMI_CODE_OAUTH_HOST = FAKE_OAUTH_HOST;
  process.env.KIMI_CODE_BASE_URL = FAKE_BASE_URL;
});

afterEach(() => {
  globalThis.fetch = realFetch;
  for (const k of ENV_KEYS) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k];
  }
  rmSync(dir, { recursive: true, force: true });
});

describe("returned credentials carry the current endpoint binding", () => {
  it("fresh device login returns the binding and records it in the derived slot", async () => {
    mockFetch((url, init) => {
      if (url.endsWith("/api/oauth/device_authorization")) {
        return jsonResponse({
          user_code: "CODE",
          device_code: "device-1",
          verification_uri: "https://auth.disabled.invalid/activate",
          verification_uri_complete: "https://auth.disabled.invalid/activate?code=CODE",
          expires_in: 600,
          interval: 1,
        });
      }
      if (url.endsWith("/api/oauth/token")) {
        assert.match(
          String(init?.body),
          /grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code/,
        );
        return jsonResponse(tokenJson("fresh-access", "fresh-refresh"));
      }
      throw new Error(`unexpected request: ${url}`);
    });

    const credentials = await loginKimiCode(silentCallbacks);
    assert.equal(credentials.access, "fresh-access");
    assert.equal(credentials.refresh, "fresh-refresh");
    assert.deepEqual(credentials.endpoint, EXPECTED_BINDING);

    // The credential file pi's peer reuse reads back must record it too.
    const stored = JSON.parse(readFileSync(credentialSlot(), "utf8"));
    assert.deepEqual(stored.endpoint, EXPECTED_BINDING);
  });

  it("login reusing a still-fresh CLI credential returns the binding", async () => {
    writeCliCredential("live-access", "live-refresh", nowSec() + 3600);
    mockFetch((url) => {
      if (url.endsWith("/me")) return new Response("ok", { status: 200 });
      throw new Error(`unexpected request: ${url}`);
    });

    const credentials = await loginKimiCode(silentCallbacks);
    assert.equal(credentials.access, "live-access");
    assert.deepEqual(credentials.endpoint, EXPECTED_BINDING);
  });

  it("login refreshing an expired CLI credential returns the binding", async () => {
    writeCliCredential("stale-access", "stale-refresh", nowSec() - 10);
    mockFetch((url, init) => {
      if (url.endsWith("/me")) return new Response("ok", { status: 200 });
      if (url.endsWith("/api/oauth/token")) {
        assert.match(String(init?.body), /grant_type=refresh_token/);
        return jsonResponse(tokenJson("rotated-access", "rotated-refresh"));
      }
      throw new Error(`unexpected request: ${url}`);
    });

    const credentials = await loginKimiCode(silentCallbacks);
    assert.equal(credentials.access, "rotated-access");
    assert.equal(credentials.refresh, "rotated-refresh");
    assert.deepEqual(credentials.endpoint, EXPECTED_BINDING);
    const stored = JSON.parse(readFileSync(credentialSlot(), "utf8"));
    assert.equal(stored.access_token, "rotated-access");
    assert.deepEqual(stored.endpoint, EXPECTED_BINDING);
  });

  it("refreshKimiCodeToken returns the binding when the CLI credential is still fresh", async () => {
    writeCliCredential("live-access", "live-refresh", nowSec() + 3600);
    const { calls } = mockFetch(() => {
      throw new Error("no network expected");
    });

    const credentials = await refreshKimiCodeToken(IGNORED_CREDENTIALS);
    assert.equal(credentials.access, "live-access");
    assert.deepEqual(credentials.endpoint, EXPECTED_BINDING);
    assert.deepEqual(calls, []);
  });

  it("refreshKimiCodeToken returns the binding when it refreshes the CLI credential", async () => {
    writeCliCredential("stale-access", "stale-refresh", nowSec() - 10);
    mockFetch((url, init) => {
      if (url.endsWith("/api/oauth/token")) {
        assert.match(String(init?.body), /grant_type=refresh_token/);
        return jsonResponse(tokenJson("rotated-access", "rotated-refresh"));
      }
      throw new Error(`unexpected request: ${url}`);
    });

    const credentials = await refreshKimiCodeToken(IGNORED_CREDENTIALS);
    assert.equal(credentials.access, "rotated-access");
    assert.deepEqual(credentials.endpoint, EXPECTED_BINDING);
    const stored = JSON.parse(readFileSync(credentialSlot(), "utf8"));
    assert.equal(stored.access_token, "rotated-access");
    assert.deepEqual(stored.endpoint, EXPECTED_BINDING);
  });

  it("refreshKimiCodeToken returns the binding when it refreshes pi's stored credential", async () => {
    writePiCredential("pi-stale", "pi-refresh", Date.now() - 10_000);
    mockFetch((url, init) => {
      if (url.endsWith("/api/oauth/token")) {
        assert.match(String(init?.body), /refresh_token=pi-refresh/);
        return jsonResponse(tokenJson("pi-rotated", "pi-refresh-2"));
      }
      throw new Error(`unexpected request: ${url}`);
    });

    const credentials = await refreshKimiCodeToken(IGNORED_CREDENTIALS);
    assert.equal(credentials.access, "pi-rotated");
    assert.deepEqual(credentials.endpoint, EXPECTED_BINDING);
  });

  it("refreshKimiCodeToken returns the binding when a bound peer is newer", async () => {
    writePiCredential("pi-stale", "pi-refresh", Date.now() - 10_000);
    writeCliCredential("peer-live", "peer-refresh", nowSec() + 3600);
    const { calls } = mockFetch(() => {
      throw new Error("no network expected: the newer bound peer wins");
    });

    const credentials = await refreshKimiCodeToken(IGNORED_CREDENTIALS);
    assert.equal(credentials.access, "peer-live");
    assert.equal(credentials.refresh, "peer-refresh");
    assert.deepEqual(credentials.endpoint, EXPECTED_BINDING);
    assert.deepEqual(calls, []);
  });

  it("refreshKimiCodeToken returns the binding when it adopts a peer credential after a refresh failure", async () => {
    writePiCredential("pi-stale", "pi-refresh", Date.now() - 10_000);
    writeCliCredential("stale-peer", "stale-peer-refresh", nowSec() - 10);
    mockFetch((url) => {
      if (url.endsWith("/api/oauth/token")) {
        // A peer rotates the shared credential while our refresh is in flight.
        writeCliCredential("peer-live", "peer-refresh", nowSec() + 3600);
        return jsonResponse({ error: "invalid_grant" }, 400);
      }
      throw new Error(`unexpected request: ${url}`);
    });

    const credentials = await refreshKimiCodeToken(IGNORED_CREDENTIALS);
    assert.equal(credentials.access, "peer-live");
    assert.equal(credentials.refresh, "peer-refresh");
    assert.deepEqual(credentials.endpoint, EXPECTED_BINDING);
  });

  it("a returned credential is accepted only at its own binding", async () => {
    writeCliCredential("live-access", "live-refresh", nowSec() + 3600);
    mockFetch((url) => {
      if (url.endsWith("/me")) return new Response("ok", { status: 200 });
      throw new Error(`unexpected request: ${url}`);
    });
    const credentials = await loginKimiCode(silentCallbacks);

    // Persist the returned object exactly the way pi core does.
    writePiCredential(
      credentials.access,
      credentials.refresh,
      credentials.expires,
      credentials.endpoint,
    );

    const current = getKimiEndpointBinding();
    const accepted = readBoundStoredOAuthCredential(PROVIDER_ID, current);
    assert.equal(accepted?.access, "live-access");

    // The same credential must not be accepted at a different endpoint pair.
    const other = readBoundStoredOAuthCredential(PROVIDER_ID, {
      oauthHost: "https://auth.other.invalid",
      baseUrl: "https://api.other.invalid/v1",
    });
    assert.equal(other, null);

    // Trivial spelling differences of the same pair still accept it: the
    // binding is canonicalized on both write and read.
    const respelled = readBoundStoredOAuthCredential(PROVIDER_ID, {
      oauthHost: canonicalizeKimiEndpointUrl(`${FAKE_OAUTH_HOST}/`),
      baseUrl: canonicalizeKimiEndpointUrl(normalizeKimiBaseV1(`${FAKE_BASE_URL}/`)),
    });
    assert.equal(respelled?.access, "live-access");
  });

  it("a credential returned for a custom pair is not accepted after switching to the mainland binding", async () => {
    writeCliCredential("custom-access", "custom-refresh", nowSec() + 3600);
    mockFetch((url) => {
      if (url.endsWith("/me")) return new Response("ok", { status: 200 });
      throw new Error(`unexpected request: ${url}`);
    });
    const credentials = await loginKimiCode(silentCallbacks);
    writePiCredential(
      credentials.access,
      credentials.refresh,
      credentials.expires,
      credentials.endpoint,
    );

    for (const key of [
      "KIMI_CODE_OAUTH_HOST",
      "KIMI_CODE_BASE_URL",
      "KIMI_OAUTH_HOST",
      "KIMI_BASE_URL",
    ] as const) {
      delete process.env[key];
    }
    const mainland = getKimiEndpointBinding();
    assert.equal(readBoundStoredOAuthCredential(PROVIDER_ID, mainland), null);
  });
});
