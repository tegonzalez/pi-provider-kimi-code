// Runtime reuse of the kimi-code CLI's live credential: discovery, translation,
// atomic write-back on refresh, and lock sharing with kimi-code. All tokens
// here are fake fixtures.
import assert from "node:assert/strict";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  utimesSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, it } from "node:test";
import { lock as acquireFileLock } from "proper-lockfile";

import { KIMI_CODE_CREDENTIAL_API_KEY } from "../src/constants.ts";
import {
  discoverKimiCodeCredentialPath,
  inferKimiCodeLoginRegion,
  isKimiCredentialRegionValid,
  readKimiCodeAccessToken,
  refreshKimiAuthToken,
  resolveKimiCodeCredentialName,
} from "../src/oauth.ts";
import { resolveKimiApiKey } from "../src/stream.ts";

const GLOBAL_HOST = "https://auth.kimi.ai";
const GLOBAL_BASE = "https://api.kimi.ai/coding/v1";
const GLOBAL_NAME = "kimi-code-env-0e4f99c69cc27850"; // kimi-code 2.2.0's slot for these endpoints

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

let dir: string;
let home: string;
let saved: Record<string, string | undefined>;
const realFetch = globalThis.fetch;

function writeCred(name: string, access: string, refresh: string, expiresAtSec: number): string {
  const path = join(home, "credentials", `${name}.json`);
  mkdirSync(join(home, "credentials"), { recursive: true });
  writeFileSync(
    path,
    JSON.stringify({
      access_token: access,
      refresh_token: refresh,
      expires_at: expiresAtSec,
      scope: "",
      token_type: "Bearer",
      expires_in: 0,
    }),
  );
  return path;
}

const nowSec = () => Math.floor(Date.now() / 1000);

beforeEach(() => {
  saved = Object.fromEntries(ENV_KEYS.map((k) => [k, process.env[k]]));
  for (const k of ENV_KEYS) delete process.env[k];
  dir = mkdtempSync(join(tmpdir(), "kimi-code-reuse-"));
  home = join(dir, "kimi-code-home");
  process.env.KIMI_CODE_HOME = home;
  process.env.KIMI_SHARE_DIR = join(dir, "no-legacy");
  process.env.PI_CODING_AGENT_DIR = join(dir, "pi-agent"); // empty: no auth.json seeding
  process.env.KIMI_CODE_OAUTH_HOST = GLOBAL_HOST;
  process.env.KIMI_CODE_BASE_URL = GLOBAL_BASE;
});

afterEach(() => {
  globalThis.fetch = realFetch;
  for (const k of ENV_KEYS) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k];
  }
  rmSync(dir, { recursive: true, force: true });
});

describe("kimi-code credential discovery", () => {
  it("derives the same slot name as kimi-code", () => {
    assert.equal(resolveKimiCodeCredentialName(GLOBAL_HOST, GLOBAL_BASE), GLOBAL_NAME);
    assert.equal(resolveKimiCodeCredentialName(`${GLOBAL_HOST}/`, `${GLOBAL_BASE}/`), GLOBAL_NAME);
    assert.equal(
      resolveKimiCodeCredentialName("https://auth.kimi.com", "https://api.kimi.com/coding/v1"),
      "kimi-code",
    );
    assert.equal(resolveKimiCodeCredentialName(), GLOBAL_NAME); // from env endpoints
  });

  it("selects only the exact slot for the current binding", () => {
    // At the custom env binding, a newer *other* env file must not be picked
    // up, and the mainland legacy file must not be picked up either.
    const legacy = writeCred("kimi-code", "a-legacy", "r-legacy", nowSec() + 3600);
    const other = writeCred("kimi-code-env-bbbbbbbbbbbbbbbb", "a-new", "r-new", nowSec() + 3600);
    utimesSync(other, new Date(Date.now() + 60_000), new Date(Date.now() + 60_000));
    const expected = join(home, "credentials", `${GLOBAL_NAME}.json`);
    assert.equal(discoverKimiCodeCredentialPath(), expected);
    assert.equal(readKimiCodeAccessToken(), null);
    assert.notEqual(discoverKimiCodeCredentialPath(), legacy);
    assert.notEqual(discoverKimiCodeCredentialPath(), other);
    // Now the exact slot appears (older than the decoys): it wins.
    const derived = writeCred(GLOBAL_NAME, "a-derived", "r-derived", nowSec() + 3600);
    utimesSync(derived, new Date(Date.now() - 120_000), new Date(Date.now() - 120_000));
    assert.equal(discoverKimiCodeCredentialPath(), derived);
    assert.equal(readKimiCodeAccessToken(), "a-derived");
    writeFileSync(`${derived}.tmp.1.abcd`, "partial"); // in-flight temp files are ignored
    assert.equal(discoverKimiCodeCredentialPath(), derived);
  });

  it("accepts the fixed legacy file only at the official mainland binding", () => {
    // Custom binding: legacy present but must not be used.
    const legacy = writeCred("kimi-code", "a-legacy", "r-legacy", nowSec() + 3600);
    assert.equal(readKimiCodeAccessToken(), null);
    // Mainland binding: the same file is the exact slot and is used.
    for (const key of ["KIMI_CODE_OAUTH_HOST", "KIMI_CODE_BASE_URL"] as const) {
      delete process.env[key];
    }
    assert.equal(discoverKimiCodeCredentialPath(), legacy);
    assert.equal(readKimiCodeAccessToken(), "a-legacy");
    // A global-region env slot does not count at the mainland binding either.
    writeCred(GLOBAL_NAME, "a-global", "r-global", nowSec() + 3600);
    assert.equal(discoverKimiCodeCredentialPath(), legacy);
    assert.equal(readKimiCodeAccessToken(), "a-legacy");
  });

  it("honors the binding recorded in the credential file", () => {
    const path = join(home, "credentials", `${GLOBAL_NAME}.json`);
    mkdirSync(join(home, "credentials"), { recursive: true });
    // Bound to a different pair: rejected even though the slot name matches.
    writeFileSync(
      path,
      JSON.stringify({
        access_token: "a-other",
        refresh_token: "r-other",
        expires_at: nowSec() + 3600,
        endpoint: { oauthHost: "https://auth.example.com", baseUrl: "https://api.example.com/v1" },
      }),
    );
    assert.equal(readKimiCodeAccessToken(), null);
    // Bound to the current pair: accepted.
    writeFileSync(
      path,
      JSON.stringify({
        access_token: "a-bound",
        refresh_token: "r-bound",
        expires_at: nowSec() + 3600,
        endpoint: { oauthHost: GLOBAL_HOST, baseUrl: GLOBAL_BASE },
      }),
    );
    assert.equal(readKimiCodeAccessToken(), "a-bound");
    // Spelling variants of the same pair canonicalize to the same binding.
    writeFileSync(
      path,
      JSON.stringify({
        access_token: "a-canonical",
        refresh_token: "r-canonical",
        expires_at: nowSec() + 3600,
        endpoint: {
          oauthHost: `${GLOBAL_HOST}:443/`.replace("https://", "HTTPS://"),
          baseUrl: `${GLOBAL_BASE}/`,
        },
      }),
    );
    assert.equal(readKimiCodeAccessToken(), "a-canonical");
  });

  it("points a fresh login at the derived slot when nothing exists", () => {
    assert.equal(
      discoverKimiCodeCredentialPath(),
      join(home, "credentials", `${GLOBAL_NAME}.json`),
    );
    assert.equal(readKimiCodeAccessToken(), null);
  });
});

describe("kimi-code login region", () => {
  it("follows the most recently written region slot unless KIMI_CODE_REGION is set", () => {
    assert.equal(inferKimiCodeLoginRegion(), null);
    const legacy = writeCred("kimi-code", "a-cn", "r-cn", nowSec() + 3600);
    assert.equal(inferKimiCodeLoginRegion(), "mainland-cn");
    utimesSync(legacy, new Date(Date.now() - 60_000), new Date(Date.now() - 60_000));
    writeCred(GLOBAL_NAME, "a-global", "r-global", nowSec() + 3600);
    assert.equal(inferKimiCodeLoginRegion(), "global");
    process.env.KIMI_CODE_REGION = "mainland-cn";
    assert.equal(inferKimiCodeLoginRegion(), null);
  });
});

describe("kimi-code credential translation", () => {
  it("resolves the registered marker to the live kimi-code access token", () => {
    writeCred(GLOBAL_NAME, "access-live", "refresh-live", nowSec() + 3600);
    assert.equal(readKimiCodeAccessToken(), "access-live");
    assert.equal(resolveKimiApiKey(KIMI_CODE_CREDENTIAL_API_KEY), "access-live");
    assert.equal(resolveKimiApiKey("$KIMI_API_KEY"), "access-live");
    process.env.KIMI_API_KEY = "env-key";
    assert.equal(resolveKimiApiKey(KIMI_CODE_CREDENTIAL_API_KEY), "env-key");
  });
});

describe("kimi-code credential refresh", () => {
  it("refreshes in place with an atomic write and releases kimi-code's lock", async () => {
    const path = writeCred(GLOBAL_NAME, "access-0", "refresh-0", nowSec() - 10);
    const seen: string[] = [];
    globalThis.fetch = (async (url: string | URL, init?: RequestInit) => {
      seen.push(String(url));
      assert.equal(String(url), `${GLOBAL_HOST}/api/oauth/token`);
      assert.equal(new URLSearchParams(String(init?.body)).get("refresh_token"), "refresh-0");
      return new Response(
        JSON.stringify({
          access_token: "access-1",
          refresh_token: "refresh-1",
          expires_in: 900,
          scope: "",
          token_type: "Bearer",
        }),
        { status: 200 },
      );
    }) as typeof fetch;

    assert.equal(await refreshKimiAuthToken("access-0"), "access-1");
    assert.equal(seen.length, 1);
    const stored = JSON.parse(readFileSync(path, "utf8"));
    assert.equal(stored.access_token, "access-1");
    assert.equal(stored.refresh_token, "refresh-1");
    assert.ok(stored.expires_at > nowSec());
    // The write records the non-secret endpoint binding for future reads.
    assert.deepEqual(stored.endpoint, { oauthHost: GLOBAL_HOST, baseUrl: GLOBAL_BASE });
    assert.equal(statSync(path).mode & 0o777, 0o600);
    assert.deepEqual(
      readdirSync(join(home, "credentials")).filter((n) => n.includes(".tmp.")),
      [],
    );
    assert.ok(!existsSync(join(home, "oauth", `${GLOBAL_NAME}.lock`)), "lock released");
    // Nothing copied into pi's store.
    const authPath = join(process.env.PI_CODING_AGENT_DIR!, "auth.json");
    if (existsSync(authPath)) assert.deepEqual(JSON.parse(readFileSync(authPath, "utf8")), {});
  });

  it("waits on kimi-code's lock and adopts the token kimi-code rotated meanwhile", async () => {
    writeCred(GLOBAL_NAME, "access-0", "refresh-0", nowSec() - 10);
    // Take the lock exactly as kimi-code's OAuthManager does.
    const target = join(home, "oauth", GLOBAL_NAME);
    mkdirSync(join(home, "oauth"), { recursive: true });
    writeFileSync(target, "", { flag: "a" });
    const release = await acquireFileLock(target, { stale: 5_000, realpath: false });
    let fetches = 0;
    globalThis.fetch = (async () => {
      fetches++;
      return new Response("{}", { status: 500 });
    }) as typeof fetch;

    let settled = false;
    const pending = refreshKimiAuthToken("access-0").finally(() => {
      settled = true;
    });
    await new Promise((r) => setTimeout(r, 700));
    assert.equal(settled, false, "pi must block while kimi-code holds the lock");
    // kimi-code finishes its own refresh (rotating the refresh token) and releases.
    writeCred(GLOBAL_NAME, "access-cli", "refresh-cli", nowSec() + 900);
    await release();
    assert.equal(await pending, "access-cli");
    assert.equal(fetches, 0, "pi must not spend the rotated refresh token");
    assert.equal(
      JSON.parse(readFileSync(join(home, "credentials", `${GLOBAL_NAME}.json`), "utf8"))
        .refresh_token,
      "refresh-cli",
    );
  });

  it("makes no request and adopts nothing when the credential is bound to a different endpoint", async () => {
    // A credential whose recorded binding differs from the configured
    // endpoints must not be refreshed (the refresh token would go to the
    // ambient host) and must not be adopted as a peer.
    writeCred(GLOBAL_NAME, "access-0", "refresh-0", nowSec() - 10);
    const path = join(home, "credentials", `${GLOBAL_NAME}.json`);
    const stored = JSON.parse(readFileSync(path, "utf8"));
    stored.endpoint = {
      oauthHost: "https://auth.example.com",
      baseUrl: "https://api.example.com/v1",
    };
    writeFileSync(path, JSON.stringify(stored));

    let fetches = 0;
    globalThis.fetch = (async () => {
      fetches++;
      return new Response("{}", { status: 200 });
    }) as typeof fetch;

    assert.equal(await refreshKimiAuthToken("access-0"), null);
    assert.equal(fetches, 0, "no HTTP request on a mismatched custom endpoint");
    assert.equal(readKimiCodeAccessToken(), null);
  });

  it("posts the refresh token only to the credential-bound OAuth host", async () => {
    const path = writeCred(GLOBAL_NAME, "access-0", "refresh-0", nowSec() - 10);
    const stored = JSON.parse(readFileSync(path, "utf8"));
    stored.endpoint = {
      oauthHost: "https://auth.example.com",
      baseUrl: "https://api.example.com/v1",
    };
    writeFileSync(path, JSON.stringify(stored));
    const seen: string[] = [];
    globalThis.fetch = (async (url: string | URL) => {
      seen.push(String(url));
      return new Response(
        JSON.stringify({
          access_token: "x",
          refresh_token: "y",
          expires_in: 900,
          scope: "",
          token_type: "Bearer",
        }),
        { status: 200 },
      );
    }) as typeof fetch;
    // Switch the configured endpoints away from the credential's binding:
    // the credential is rejected, so nothing is posted anywhere.
    process.env.KIMI_CODE_OAUTH_HOST = "https://auth.other.example";
    process.env.KIMI_CODE_BASE_URL = "https://api.other.example";
    assert.equal(await refreshKimiAuthToken("access-0"), null);
    assert.deepEqual(seen, []);
  });
});

describe("kimi-code /me binding probe", () => {
  it("treats only HTTP 2xx as valid", async () => {
    for (const [status, body] of [
      [200, "{}"],
      [204, null],
    ] as const) {
      globalThis.fetch = (async () => new Response(body, { status })) as typeof fetch;
      assert.equal(await isKimiCredentialRegionValid("token"), true, `status ${status}`);
    }
    for (const status of [401, 403, 404, 500, 503]) {
      globalThis.fetch = (async () => new Response("{}", { status })) as typeof fetch;
      assert.equal(await isKimiCredentialRegionValid("token"), false, `status ${status}`);
    }
  });

  it("fails closed on network errors and timeouts", async () => {
    globalThis.fetch = (async () => {
      throw new Error("network down");
    }) as typeof fetch;
    assert.equal(await isKimiCredentialRegionValid("token"), false);
    globalThis.fetch = (async () =>
      new Promise<Response>((_resolve, reject) =>
        setTimeout(() => reject(new Error("timeout")), 10),
      )) as typeof fetch;
    assert.equal(await isKimiCredentialRegionValid("token"), false);
  });

  it("probes the base URL of the current binding", async () => {
    let url = "";
    globalThis.fetch = (async (requestUrl: string | URL) => {
      url = String(requestUrl);
      return new Response("{}", { status: 200 });
    }) as typeof fetch;
    assert.equal(await isKimiCredentialRegionValid("token"), true);
    assert.equal(url, `${GLOBAL_BASE}/me`);
  });
});
