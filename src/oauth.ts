// OAuth subsystem: device flow, refresh-with-retry, Kimi credential
// reuse, the login / refresh handlers wired into pi's OAuth interface, and
// the stream-level auth refresh used by the streaming handler.

import { createHash, randomBytes } from "node:crypto";
import {
  chmodSync,
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  statSync,
  unlinkSync,
  writeFileSync,
  writeSync,
} from "node:fs";
import os from "node:os";
import { basename, dirname, join } from "node:path";

import { lock as acquireFileLock } from "proper-lockfile";

import type { OAuthCredentials, OAuthLoginCallbacks } from "@earendil-works/pi-ai";
import * as piAgent from "@earendil-works/pi-coding-agent";

// Structural mirrors of pi's stored credential shapes. The exported names
// moved between pi versions (pi-coding-agent <=0.79 vs pi-ai >=0.80.8), so
// these are defined locally to type-check against either surface.
type StoredCredential = { type: string } & Record<string, unknown>;

export interface StoredOAuthCredential {
  type: "oauth";
  access: string;
  refresh: string;
  expires: number;
  /** Non-secret endpoint binding this credential was minted for. Absent on
   * pre-binding credentials: those are accepted only at the official
   * mainland default binding. */
  endpoint?: { oauthHost: string; baseUrl: string };
  [key: string]: unknown;
}

// pi renamed its auth storage surface in 0.80.8: the exported AuthStorage
// class (sync get/set under a file lock) was replaced by readStoredCredential
// for one-off reads, with no exported write path. Detect whichever the host
// pi provides so the extension keeps loading on both sides of the rename.
const piAgentRuntime = piAgent as unknown as {
  getAgentDir(): string;
  readStoredCredential?(providerId: string): StoredCredential | undefined;
  AuthStorage?: {
    create(): {
      get(provider: string): StoredCredential | undefined;
      set(provider: string, credential: StoredCredential): void;
    };
  };
};

export function readStoredOAuthCredential(providerId: string): StoredOAuthCredential | null {
  const credential = piAgentRuntime.readStoredCredential
    ? piAgentRuntime.readStoredCredential(providerId)
    : piAgentRuntime.AuthStorage?.create().get(providerId);
  return credential?.type === "oauth" ? (credential as StoredOAuthCredential) : null;
}

// Binding-match rule shared by pi's stored credential and the in-flight lock
// read: unbound legacy credentials count only at the official mainland
// default binding; bound credentials must match exactly.
function storedCredentialMatchesBinding(
  credential: StoredOAuthCredential | null,
  binding: KimiEndpointBinding,
): credential is StoredOAuthCredential {
  if (!credential) return false;
  if (!credential.endpoint) return isMainlandKimiEndpointBinding(binding);
  const endpoint = credential.endpoint;
  if (typeof endpoint.oauthHost !== "string" || typeof endpoint.baseUrl !== "string") return false;
  return kimiEndpointBindingsEqual(
    {
      oauthHost: canonicalizeKimiEndpointUrl(endpoint.oauthHost),
      baseUrl: canonicalizeKimiEndpointUrl(endpoint.baseUrl),
    },
    binding,
  );
}

// Binding-checked read of pi's stored credential: a credential recorded for a
// different (oauthHost, baseUrl) pair is never handed out. Credentials written
// before binding metadata existed are accepted only at the official mainland
// default binding; anywhere else they are ignored so the user gets a fresh
// login instead of a token sent to the wrong endpoint.
export function readBoundStoredOAuthCredential(
  providerId: string,
  binding: KimiEndpointBinding,
): StoredOAuthCredential | null {
  const credential = readStoredOAuthCredential(providerId);
  return storedCredentialMatchesBinding(credential, binding) ? credential : null;
}

// Mutual exclusion with pi's own credential writes: use the same library
// (proper-lockfile) on the same file pi's FileAuthStorageBackend locks, with
// the same options. The shared implementation keeps the lock mtime fresh
// while held, recovers stale locks from crashed processes, and retries for
// ~40s so a live holder running a slow network refresh inside the lock is
// waited out.
async function acquireSharedFileLock(
  path: string,
  signal: AbortSignal | undefined,
  options: { maxRetries: number; stale: number; minTimeout: number; maxTimeout: number },
): Promise<() => Promise<void>> {
  for (let attempt = 0; ; attempt++) {
    signal?.throwIfAborted();
    try {
      return await acquireFileLock(path, {
        realpath: false,
        stale: options.stale,
        // Retry via the outer abortable sleep below. proper-lockfile's own
        // retry loop is not signal-aware and would otherwise ignore an abort
        // for the full configured retry window.
        retries: 0,
      });
    } catch (error) {
      const code =
        typeof error === "object" && error !== null && "code" in error
          ? String((error as { code?: unknown }).code)
          : undefined;
      if (code !== "ELOCKED" || attempt >= options.maxRetries) throw error;
      const baseDelay = Math.min(options.minTimeout * 2 ** attempt, options.maxTimeout);
      await sleep(baseDelay * (1 + Math.random()), signal);
    }
  }
}

async function acquireAuthFileLock(
  authPath: string,
  signal?: AbortSignal,
): Promise<() => Promise<void>> {
  return acquireSharedFileLock(authPath, signal, {
    maxRetries: 10,
    stale: 30_000,
    minTimeout: 100,
    maxTimeout: 10_000,
  });
}

async function acquireKimiCodeRefreshLock(
  credentialPath: string,
  signal?: AbortSignal,
): Promise<() => Promise<void>> {
  if (process.platform === "win32" || process.env.KIMI_DISABLE_OAUTH_LOCK === "1") {
    return async () => {};
  }
  // Derive the lock target from the discovered credential filename so we share
  // the CLI's lock for env-specific credential files
  // (`oauth/kimi-code-env-<hash>`), not just the legacy `oauth/kimi-code`.
  const lockName = basename(credentialPath, ".json");
  const target = join(getKimiCodeHome(), "oauth", lockName);
  mkdirSync(dirname(target), { recursive: true, mode: 0o700 });
  writeFileSync(target, "", { encoding: "utf-8", flag: "a" });
  return acquireSharedFileLock(target, signal, {
    maxRetries: 120,
    stale: 5_000,
    minTimeout: 500,
    maxTimeout: 1_000,
  });
}

interface LockedOAuthCredential {
  credential: StoredOAuthCredential | null;
  store(credential: StoredOAuthCredential): void;
  release(): Promise<void>;
}

async function lockStoredOAuthCredential(
  providerId: string,
  signal?: AbortSignal,
): Promise<LockedOAuthCredential> {
  // Hold the same lock Pi uses across the complete read-refresh-write
  // transaction. Kimi rotates refresh tokens, so locking only the write lets
  // concurrent Pi processes exchange the same token twice.
  const authPath = join(piAgentRuntime.getAgentDir(), "auth.json");
  mkdirSync(dirname(authPath), { recursive: true, mode: 0o700 });
  if (!existsSync(authPath)) {
    writeFileSync(authPath, "{}", { encoding: "utf-8", mode: 0o600 });
    chmodSync(authPath, 0o600);
  }
  const release = await acquireAuthFileLock(authPath, signal);
  let data: Record<string, unknown> = {};
  try {
    const parsed = JSON.parse(readFileSync(authPath, "utf-8")) as unknown;
    if (typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)) {
      data = parsed as Record<string, unknown>;
    }
  } catch {
    // Missing or unreadable auth.json — treat it as an empty store.
  }
  const stored = data[providerId] as StoredCredential | undefined;
  return {
    credential: stored?.type === "oauth" ? (stored as unknown as StoredOAuthCredential) : null,
    store(credential) {
      data[providerId] = credential;
      writeFileSync(authPath, JSON.stringify(data, null, 2), {
        encoding: "utf-8",
        mode: 0o600,
      });
      chmodSync(authPath, 0o600);
    },
    release,
  };
}

import {
  CLIENT_ID,
  KIMI_MAINLAND_ENDPOINT_BINDING,
  KIMI_REGION_PROFILES,
  type KimiEndpointBinding,
  type KimiRegion,
  PROVIDER_ID,
  RETRYABLE_REFRESH_STATUSES,
  canonicalizeKimiEndpointUrl,
  getBaseUrl,
  getKimiEndpointBinding,
  getOAuthHost,
  isMainlandKimiEndpointBinding,
  kimiEndpointBindingsEqual,
  normalizeKimiBaseV1,
} from "./constants.ts";
import { getCommonHeaders } from "./device.ts";
import { type KimiOAuthCredentials, discoverKimiModelMetadata } from "./models.ts";

// =============================================================================
// Device flow + token endpoint
// =============================================================================

export interface DeviceAuthorization {
  user_code: string;
  device_code: string;
  verification_uri: string;
  verification_uri_complete: string;
  expires_in: number;
  interval: number;
}

interface TokenResponse {
  access_token: string;
  refresh_token: string;
  expires_in: number;
  scope: string;
  token_type: string;
}

export async function requestDeviceAuthorization(): Promise<DeviceAuthorization> {
  const response = await fetch(`${getOAuthHost()}/api/oauth/device_authorization`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      ...getCommonHeaders(),
    },
    body: new URLSearchParams({
      client_id: CLIENT_ID,
    }),
  });

  if (!response.ok) {
    const text = await response.text().catch(() => "");
    throw new Error(`Device authorization failed: ${response.status} ${text}`);
  }

  const data = (await response.json()) as {
    user_code?: string;
    device_code?: string;
    verification_uri?: string;
    verification_uri_complete?: string;
    expires_in?: number;
    interval?: number;
  };

  const verificationUrl = data.verification_uri_complete || data.verification_uri;
  if (!data.user_code || !data.device_code || !verificationUrl) {
    throw new Error("Invalid device authorization response");
  }

  return {
    user_code: data.user_code,
    device_code: data.device_code,
    verification_uri: data.verification_uri || verificationUrl,
    verification_uri_complete: verificationUrl,
    expires_in: data.expires_in || 1800,
    interval: data.interval || 5,
  };
}

export async function requestDeviceToken(
  auth: DeviceAuthorization,
): Promise<TokenResponse | "slow_down" | null> {
  const response = await fetch(`${getOAuthHost()}/api/oauth/token`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      ...getCommonHeaders(),
    },
    body: new URLSearchParams({
      client_id: CLIENT_ID,
      device_code: auth.device_code,
      grant_type: "urn:ietf:params:oauth:grant-type:device_code",
    }),
  });

  if (response.status === 200) {
    const data = (await response.json()) as TokenResponse;
    if (data.access_token && data.refresh_token) {
      return data;
    }
    throw new Error("Token response missing required fields");
  }

  if (response.status === 400) {
    const data = (await response.json()) as { error?: string; error_description?: string };
    if (data.error === "authorization_pending") {
      return null;
    }
    if (data.error === "slow_down") {
      return "slow_down";
    }
    if (data.error === "expired_token") {
      throw new Error("expired_token");
    }
    throw new Error(`Token request failed: ${data.error_description || data.error || "unknown"}`);
  }

  const text = await response.text().catch(() => "");
  throw new Error(`Token request failed: ${response.status} ${text}`);
}

interface RefreshAccessTokenOptions {
  maxRetries?: number;
  signal?: AbortSignal;
  sleep?: (ms: number) => Promise<void>;
  /** The OAuth host that minted the refresh token. A refresh token is only
   * ever posted to its own host, never to an ambient override. Defaults to
   * the configured host for direct/test callers. */
  oauthHost?: string;
}

export const KIMI_LOGIN_REQUIRED_MESSAGE =
  "Kimi Code authorization is no longer valid. Sign in again with /login kimi-coding.";

export class KimiLoginRequiredError extends Error {
  constructor() {
    super(KIMI_LOGIN_REQUIRED_MESSAGE);
    this.name = "KimiLoginRequiredError";
  }
}

function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  if (!signal) return new Promise((resolve) => setTimeout(resolve, ms));
  signal.throwIfAborted();
  return new Promise((resolve, reject) => {
    const onAbort = () => {
      clearTimeout(timeout);
      reject(signal.reason);
    };
    const timeout = setTimeout(() => {
      signal.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    signal.addEventListener("abort", onAbort, { once: true });
  });
}

export async function refreshAccessToken(
  refreshToken: string,
  options: RefreshAccessTokenOptions = {},
): Promise<TokenResponse> {
  const maxRetries = options.maxRetries ?? 3;
  const wait = options.sleep ?? ((ms: number) => sleep(ms, options.signal));
  const oauthHost = canonicalizeKimiEndpointUrl(options.oauthHost ?? getOAuthHost());
  let lastError: unknown;

  for (let attempt = 0; attempt < maxRetries; attempt++) {
    try {
      options.signal?.throwIfAborted();
      const response = await fetch(`${oauthHost}/api/oauth/token`, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          ...getCommonHeaders(),
        },
        body: new URLSearchParams({
          client_id: CLIENT_ID,
          grant_type: "refresh_token",
          refresh_token: refreshToken,
        }),
        signal: options.signal,
      });

      if (!response.ok) {
        const text = await response.text().catch(() => "");
        let errorCode = "";
        try {
          const body = JSON.parse(text) as { error?: unknown };
          if (typeof body.error === "string") errorCode = body.error;
        } catch {
          // Non-JSON OAuth errors are classified by status below.
        }
        if (response.status === 401 || response.status === 403 || errorCode === "invalid_grant") {
          throw new KimiLoginRequiredError();
        }
        if (RETRYABLE_REFRESH_STATUSES.has(response.status)) {
          throw new Error(`Token refresh retryable: ${response.status} ${text}`);
        }
        throw new Error(`Token refresh failed: ${response.status} ${text}`);
      }

      const data = (await response.json()) as TokenResponse;
      if (!data.access_token || !data.refresh_token) {
        throw new Error("Token refresh response missing required fields");
      }

      return data;
    } catch (error) {
      if (options.signal?.aborted) throw options.signal.reason;
      lastError = error;
      const message = error instanceof Error ? error.message : String(error);
      if (error instanceof KimiLoginRequiredError) throw error;
      if (message.startsWith("Token refresh failed:")) throw error;
      if (attempt < maxRetries - 1) {
        await wait(2 ** attempt * 1000);
        continue;
      }
    }
  }

  throw new Error("Token refresh failed after retries.", { cause: lastError });
}

// =============================================================================
// Reuse existing Kimi credentials
//
// Users who already ran the upstream Kimi Code CLI and signed in have a valid
// OAuth token under `$KIMI_CODE_HOME/credentials/kimi-code.json` (defaults to
// `~/.kimi-code/...`). We also keep read-only support for legacy kimi-cli
// credentials under `$KIMI_SHARE_DIR/credentials/kimi-code.json` (defaults to
// `~/.kimi/...`). Loading either lets users skip the device-flow dance.
// =============================================================================

interface KimiCliCredentialsFile {
  access_token?: string;
  refresh_token?: string;
  expires_at?: number; // Unix seconds (upstream convention)
  scope?: string;
  token_type?: string;
  expires_in?: number;
  /** Non-secret binding of the endpoints this credential was minted for.
   * Written by this extension; the upstream CLI ignores unknown fields. */
  endpoint?: { oauthHost?: string; baseUrl?: string };
}

function getKimiCodeHome(): string {
  return process.env.KIMI_CODE_HOME || join(os.homedir(), ".kimi-code");
}

function getKimiShareDir(): string {
  return process.env.KIMI_SHARE_DIR || join(os.homedir(), ".kimi");
}

// Which on-disk slot a credential read/write targets, and the binding it must
// match. `derived` is the exact slot hashed from the current binding (an
// unbound file there inherits the binding encoded in its filename); the two
// legacy kinds exist only at the official mainland binding.
export interface KimiCredentialSelection {
  path: string;
  binding: KimiEndpointBinding;
  kind: "derived" | "fixed-legacy" | "share-legacy";
}

// Mirrors kimi-code's resolveKimiCodeOAuthKey (packages/oauth/src/managed-kimi-code.ts):
// the default mainland endpoints share the `kimi-code` slot; any other
// (oauthHost, baseUrl) pair gets `kimi-code-env-<sha256(json)[:16]>`. The
// digest input is the canonical pair, so a credential file created by the
// upstream CLI for the same endpoints resolves to the same slot. Exported for
// tests.
export function resolveKimiCodeCredentialName(
  oauthHost: string = getOAuthHost(),
  baseUrl: string = normalizeKimiBaseV1(getBaseUrl()),
): string {
  const host = canonicalizeKimiEndpointUrl(oauthHost);
  const base = canonicalizeKimiEndpointUrl(baseUrl);
  if (
    host === KIMI_MAINLAND_ENDPOINT_BINDING.oauthHost &&
    base === KIMI_MAINLAND_ENDPOINT_BINDING.baseUrl
  ) {
    return "kimi-code";
  }
  const digest = createHash("sha256")
    .update(JSON.stringify({ oauthHost: host, baseUrl: base }))
    .digest("hex")
    .slice(0, 16);
  return `kimi-code-env-${digest}`;
}

// Exact-slot selection. There is deliberately no newest-env fallback: a
// token minted for one endpoint pair must never be picked up for another.
// Exported for tests.
export function selectKimiCodeCredential(
  binding: KimiEndpointBinding = getKimiEndpointBinding(),
): KimiCredentialSelection {
  const credentialsDir = join(getKimiCodeHome(), "credentials");
  const derived = join(
    credentialsDir,
    `${resolveKimiCodeCredentialName(binding.oauthHost, binding.baseUrl)}.json`,
  );
  if (existsSync(derived)) return { path: derived, binding, kind: "derived" };
  if (isMainlandKimiEndpointBinding(binding)) {
    const legacy = join(credentialsDir, "kimi-code.json");
    if (existsSync(legacy)) {
      return { path: legacy, binding: KIMI_MAINLAND_ENDPOINT_BINDING, kind: "fixed-legacy" };
    }
    const shareLegacy = join(getKimiShareDir(), "credentials", "kimi-code.json");
    if (existsSync(shareLegacy)) {
      return { path: shareLegacy, binding: KIMI_MAINLAND_ENDPOINT_BINDING, kind: "share-legacy" };
    }
  }
  // Nothing on disk: the derived slot for the current binding is where a
  // fresh login lands.
  return { path: derived, binding, kind: "derived" };
}

// The live kimi-code credential file, shared in place with the CLI (never
// copied): only the exact slot for the current binding, or — at the official
// mainland binding — the fixed legacy file. Exported for tests.
export function discoverKimiCodeCredentialPath(): string {
  return selectKimiCodeCredential().path;
}

// With no region from pi config or KIMI_CODE_REGION, follow the kimi-code
// login: the region whose credential slot was written most recently, so the
// endpoints pi calls match the token it reuses. Exported for index.ts/tests.
export function inferKimiCodeLoginRegion(): KimiRegion | null {
  if (process.env.KIMI_CODE_REGION?.trim()) return null;
  const credentialsDir = join(getKimiCodeHome(), "credentials");
  let best: { region: KimiRegion; mtimeMs: number } | null = null;
  for (const region of Object.keys(KIMI_REGION_PROFILES) as KimiRegion[]) {
    const { apiBase, oauthHost } = KIMI_REGION_PROFILES[region];
    const name = resolveKimiCodeCredentialName(oauthHost, `${apiBase}/coding/v1`);
    try {
      const { mtimeMs } = statSync(join(credentialsDir, `${name}.json`));
      if (!best || mtimeMs > best.mtimeMs) best = { region, mtimeMs };
    } catch {
      // slot absent
    }
  }
  return best?.region ?? null;
}

// The binding a credential file effectively carries: its recorded endpoint,
// or — for files written before binding metadata — the binding its slot
// encodes. A file whose effective binding differs from the selection's is
// never used.
function credentialFileBinding(
  data: KimiCliCredentialsFile,
  selection: KimiCredentialSelection,
): KimiEndpointBinding | null {
  const endpoint = data.endpoint;
  if (endpoint !== undefined) {
    if (typeof endpoint.oauthHost !== "string" || typeof endpoint.baseUrl !== "string") {
      return null;
    }
    return {
      oauthHost: canonicalizeKimiEndpointUrl(endpoint.oauthHost),
      baseUrl: canonicalizeKimiEndpointUrl(endpoint.baseUrl),
    };
  }
  return selection.kind === "derived" ? selection.binding : KIMI_MAINLAND_ENDPOINT_BINDING;
}

function readKimiCliCredentials(
  selection: KimiCredentialSelection = selectKimiCodeCredential(),
): KimiCliCredentialsFile | null {
  try {
    if (!existsSync(selection.path)) return null;
    const data = JSON.parse(readFileSync(selection.path, "utf-8")) as KimiCliCredentialsFile;
    if (!data.access_token || !data.refresh_token) return null;
    const binding = credentialFileBinding(data, selection);
    if (!binding || !kimiEndpointBindingsEqual(binding, selection.binding)) return null;
    return data;
  } catch {
    return null;
  }
}

// Runtime reuse (no auth.json seeding): the kimi-code credential translated to
// the access token pi sends. Exported for the stream, tools, and usage paths.
export function readKimiCodeAccessToken(): string | null {
  return readKimiCliCredentials()?.access_token?.trim() || null;
}

// Same write protocol as kimi-code's FileTokenStorage.save: temp file in the
// same dir, fsync, chmod 0600, rename — readers never see a partial file.
// Every write records the binding the credential was minted for.
function writeKimiCodeCredentials(
  access: string,
  refresh: string,
  expiresMs: number,
  selection: KimiCredentialSelection = selectKimiCodeCredential(),
): void {
  const path = selection.path;
  const dir = dirname(path);
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const data: KimiCliCredentialsFile = {
    access_token: access,
    refresh_token: refresh,
    expires_at: Math.floor(expiresMs / 1000),
    scope: "",
    token_type: "Bearer",
    expires_in: Math.max(0, Math.floor((expiresMs - Date.now()) / 1000)),
    endpoint: { ...selection.binding },
  };
  const tmp = `${path}.tmp.${process.pid}.${randomBytes(4).toString("hex")}`;
  const bytes = Buffer.from(`${JSON.stringify(data, null, 2)}\n`, "utf-8");
  const fd = openSync(tmp, "w", 0o600);
  try {
    let written = 0;
    while (written < bytes.length) written += writeSync(fd, bytes, written);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  try {
    chmodSync(tmp, 0o600);
    renameSync(tmp, path);
  } catch (error) {
    try {
      unlinkSync(tmp);
    } catch {
      // ignore
    }
    throw error;
  }
}

interface LockedKimiCodeCredentials {
  credential: KimiCliCredentialsFile | null;
  /** The path+binding snapshot this lock covers; reuse it for every read and
   * write-back in the transaction so a mid-flight env change cannot redirect
   * tokens to another endpoint. */
  selection: KimiCredentialSelection;
  store(access: string, refresh: string, expiresMs: number): void;
  release(): Promise<void>;
}

async function lockKimiCodeCredentials(signal?: AbortSignal): Promise<LockedKimiCodeCredentials> {
  // Resolve the file and binding once so lock, read, and write-back all target
  // the same slot kimi-code locks (`oauth/<name>` → `oauth/<name>.lock`).
  const selection = selectKimiCodeCredential();
  const release = await acquireKimiCodeRefreshLock(selection.path, signal);
  const credential = readKimiCliCredentials(selection);
  return {
    credential,
    selection,
    store: (access, refresh, expiresMs) =>
      writeKimiCodeCredentials(access, refresh, expiresMs, selection),
    release,
  };
}

// Tokens are region-bound, and the credential records which OAuth host minted
// them. Only a credential whose binding exactly matches the endpoints pi is
// configured to call is reused or refreshed; the probe below fails closed —
// only an explicit 2xx proves the token is usable, because a network error or
// a non-2xx means the token may be bound to a different deployment.
// Exported for tests.
export async function isKimiCredentialRegionValid(
  accessToken: string,
  baseUrl: string = normalizeKimiBaseV1(getBaseUrl()),
): Promise<boolean> {
  const meUrl = `${baseUrl}/me`;
  try {
    const response = await fetch(meUrl, {
      headers: { ...getCommonHeaders(), Authorization: `Bearer ${accessToken}` },
      signal: AbortSignal.timeout(5_000),
    });
    return response.ok;
  } catch {
    return false;
  }
}

async function tryReuseKimiCliCredentials(
  callbacks: OAuthLoginCallbacks,
): Promise<KimiOAuthCredentials | null> {
  const selection = selectKimiCodeCredential();
  const data = readKimiCliCredentials(selection);
  if (!data) return null;

  const expiresAtMs = typeof data.expires_at === "number" ? data.expires_at * 1000 : 0;
  // 60s safety buffer so we don't hand pi a token that flips to expired
  // between this returning and the first API call.
  const stillFresh = expiresAtMs > Date.now() + 60_000;

  callbacks.onProgress?.("Found existing Kimi credentials, reusing them.");

  if (stillFresh) {
    if (!(await isKimiCredentialRegionValid(data.access_token!, selection.binding.baseUrl))) {
      callbacks.onProgress?.(
        "Existing Kimi credentials are not valid for the configured endpoints, starting a fresh login.",
      );
      return null;
    }
    const extras = await discoverKimiModelMetadata(data.access_token!);
    return {
      access: data.access_token!,
      refresh: data.refresh_token!,
      expires: expiresAtMs,
      // pi persists the returned object verbatim into auth.json: record the
      // binding with it so a later bound read accepts this credential.
      endpoint: { ...selection.binding },
      ...extras,
    };
  }

  callbacks.onProgress?.("Kimi access token expired, refreshing.");
  try {
    // Post the refresh token only to the host that minted it.
    const token = await refreshAccessToken(data.refresh_token!, {
      oauthHost: selection.binding.oauthHost,
    });
    // Probe before persisting: a token that fails the binding check must not
    // be written into the shared CLI credential file, or a later CLI-side
    // reuse (or the next /login) would pick up a token that 401s.
    if (!(await isKimiCredentialRegionValid(token.access_token, selection.binding.baseUrl))) {
      callbacks.onProgress?.(
        "Refreshed Kimi credentials are not valid for the configured endpoints, starting a fresh login.",
      );
      return null;
    }
    const expiresMs = Date.now() + token.expires_in * 1000;
    writeKimiCodeCredentials(token.access_token, token.refresh_token, expiresMs, selection);
    const extras = await discoverKimiModelMetadata(token.access_token);
    return {
      access: token.access_token,
      refresh: token.refresh_token,
      expires: expiresMs,
      // pi persists the returned object verbatim into auth.json: record the
      // binding with it so a later bound read accepts this credential.
      endpoint: { ...selection.binding },
      ...extras,
    };
  } catch {
    callbacks.onProgress?.("Refresh of Kimi token failed, falling back to device flow.");
    return null;
  }
}

// =============================================================================
// OAuth login / refresh for extension registration
// =============================================================================

export async function loginKimiCode(callbacks: OAuthLoginCallbacks): Promise<KimiOAuthCredentials> {
  const reused = await tryReuseKimiCliCredentials(callbacks);
  if (reused) return reused;

  // Keep trying until we get a token (handles expired device codes)
  while (true) {
    const auth = await requestDeviceAuthorization();

    callbacks.onAuth({
      url: auth.verification_uri_complete,
      instructions: `Please visit the URL to authorize. Your code: ${auth.user_code}`,
    });

    let interval = Math.max(auth.interval, 1) * 1000;
    const expiresAt = Date.now() + auth.expires_in * 1000;

    let token: TokenResponse | null = null;
    let printedWaiting = false;

    while (Date.now() < expiresAt) {
      try {
        const result = await requestDeviceToken(auth);
        if (result === "slow_down") {
          interval += 5000;
        } else {
          token = result;
          if (token) break;
        }
      } catch (error) {
        if (error instanceof Error && error.message === "expired_token") {
          // Device code expired, restart the flow
          if (callbacks.onProgress) {
            callbacks.onProgress("Device code expired, restarting...");
          }
          break;
        }
        throw error;
      }

      if (!printedWaiting) {
        if (callbacks.onProgress) {
          callbacks.onProgress("Waiting for authorization...");
        }
        printedWaiting = true;
      }

      // Check for abort
      if (callbacks.signal?.aborted) {
        throw new Error("Authorization aborted");
      }

      await new Promise((resolve) => setTimeout(resolve, interval));
    }

    if (token) {
      const expiresMs = Date.now() + token.expires_in * 1000;
      // A fresh login mints a credential for the endpoints configured right
      // now; record the binding with it in the exact derived slot.
      const selection = selectKimiCodeCredential();
      writeKimiCodeCredentials(token.access_token, token.refresh_token, expiresMs, selection);
      const extras = await discoverKimiModelMetadata(token.access_token);
      return {
        access: token.access_token,
        refresh: token.refresh_token,
        expires: expiresMs,
        // pi persists the returned object verbatim into auth.json: record the
        // binding with it so a later bound read accepts this credential.
        endpoint: { ...selection.binding },
        ...extras,
      };
    }

    // If we get here without a token, the device code expired - loop will retry
  }
}

export async function refreshKimiCodeToken(
  _credentials: OAuthCredentials,
): Promise<KimiOAuthCredentials> {
  // pi may hand us a credential written before binding metadata existed, or
  // one bound to a different endpoint pair than pi is configured for now; the
  // store — checked against the current binding — is authoritative.
  const binding = getKimiEndpointBinding();
  // Every return below carries this exact binding: pi persists the object a
  // refresh returns verbatim into auth.json.
  const piStored = readBoundStoredOAuthCredential(PROVIDER_ID, binding);
  const kimiLocked = await lockKimiCodeCredentials();
  try {
    if (!piStored) {
      // No binding-valid pi credential: refresh the kimi-code CLI credential
      // for this endpoint pair instead, if there is one.
      const kimiCred = kimiLocked.credential;
      if (!kimiCred?.refresh_token) throw new KimiLoginRequiredError();
      const kimiExpiresMs = (kimiCred.expires_at ?? 0) * 1000;
      if (kimiCred.access_token && Date.now() < kimiExpiresMs) {
        const extras = await discoverKimiModelMetadata(kimiCred.access_token);
        return {
          access: kimiCred.access_token,
          refresh: kimiCred.refresh_token,
          expires: kimiExpiresMs,
          endpoint: { ...binding },
          ...extras,
        };
      }
      let token: Awaited<ReturnType<typeof refreshAccessToken>>;
      try {
        token = await refreshAccessToken(kimiCred.refresh_token, {
          oauthHost: binding.oauthHost,
        });
      } catch (error) {
        // Lock-disabled platforms coordinate only through the sidecar: a peer
        // may have rotated it while this process was exchanging the stale
        // refresh token. Adopt the newer credential when it is bound to this
        // endpoint pair; otherwise surface the original failure.
        await sleep(100);
        const peerCredential = readKimiCliCredentials(kimiLocked.selection);
        const peerAccess = peerCredential?.access_token;
        const peerRefresh = peerCredential?.refresh_token;
        const peerExpiresMs = (peerCredential?.expires_at ?? 0) * 1000;
        if (
          peerAccess !== undefined &&
          peerRefresh !== undefined &&
          peerAccess !== kimiCred.access_token &&
          Date.now() < peerExpiresMs
        ) {
          const extras = await discoverKimiModelMetadata(peerAccess);
          return {
            access: peerAccess,
            refresh: peerRefresh,
            expires: peerExpiresMs,
            endpoint: { ...binding },
            ...extras,
          };
        }
        throw error;
      }
      const expiresMs = Date.now() + token.expires_in * 1000;
      kimiLocked.store(token.access_token, token.refresh_token, expiresMs);
      const extras = await discoverKimiModelMetadata(token.access_token);
      return {
        access: token.access_token,
        refresh: token.refresh_token,
        expires: expiresMs,
        endpoint: { ...binding },
        ...extras,
      };
    }
    const initialKimiCred = kimiLocked.credential;
    const initialKimiExpiresMs = (initialKimiCred?.expires_at ?? 0) * 1000;
    const peerHasNewerValidAccess =
      initialKimiCred?.access_token !== undefined &&
      initialKimiCred.access_token !== piStored.access &&
      Date.now() < initialKimiExpiresMs;
    const activeRefreshToken = peerHasNewerValidAccess
      ? initialKimiCred.refresh_token!
      : piStored.refresh;
    const activeAccessToken = peerHasNewerValidAccess
      ? initialKimiCred.access_token!
      : piStored.access;
    if (peerHasNewerValidAccess && initialKimiCred.refresh_token !== piStored.refresh) {
      const extras = await discoverKimiModelMetadata(activeAccessToken);
      return {
        access: activeAccessToken,
        refresh: activeRefreshToken,
        expires: initialKimiExpiresMs,
        endpoint: { ...binding },
        ...extras,
      };
    }
    let token: Awaited<ReturnType<typeof refreshAccessToken>>;
    try {
      token = await refreshAccessToken(activeRefreshToken, { oauthHost: binding.oauthHost });
    } catch (error) {
      // Lock-disabled platforms (Windows / KIMI_DISABLE_OAUTH_LOCK=1) use
      // storage re-read as the only coordinator. A peer may have rotated the
      // shared sidecar while this process was exchanging the old refresh
      // token; recover from that newer valid credential instead of surfacing
      // the stale-token invalid_grant as a login failure. Only a credential
      // bound to this endpoint pair is adopted.
      await sleep(100);
      const peerCredential = readKimiCliCredentials(kimiLocked.selection);
      const peerAccess = peerCredential?.access_token;
      const peerRefresh = peerCredential?.refresh_token;
      const peerExpiresMs = (peerCredential?.expires_at ?? 0) * 1000;
      if (
        peerAccess !== undefined &&
        peerRefresh !== undefined &&
        peerAccess !== piStored.access &&
        Date.now() < peerExpiresMs
      ) {
        const extras = await discoverKimiModelMetadata(peerAccess);
        return {
          access: peerAccess,
          refresh: peerRefresh,
          expires: peerExpiresMs,
          endpoint: { ...binding },
          ...extras,
        };
      }
      throw error;
    }
    const expiresMs = Date.now() + token.expires_in * 1000;
    const kimiCredentialAfterRefresh = readKimiCliCredentials(kimiLocked.selection);
    const peerAccess = kimiCredentialAfterRefresh?.access_token;
    const peerRefresh = kimiCredentialAfterRefresh?.refresh_token;
    const peerExpiresMs = (kimiCredentialAfterRefresh?.expires_at ?? 0) * 1000;
    const accessToken =
      peerAccess !== undefined && peerAccess !== activeAccessToken && Date.now() < peerExpiresMs
        ? peerAccess
        : token.access_token;
    const refreshToken = accessToken === peerAccess ? peerRefresh! : token.refresh_token;
    const effectiveExpiresMs = accessToken === peerAccess ? peerExpiresMs : expiresMs;
    if (accessToken !== peerAccess) {
      kimiLocked.store(accessToken, refreshToken, effectiveExpiresMs);
    }
    const extras = await discoverKimiModelMetadata(accessToken);
    return {
      access: accessToken,
      refresh: refreshToken,
      expires: effectiveExpiresMs,
      endpoint: { ...binding },
      ...extras,
    };
  } finally {
    await kimiLocked.release().catch(() => {});
  }
}

// =============================================================================
// Stream-level auth refresh: recover from server-side token invalidation
//
// pi-coding-agent only refreshes an OAuth token when the locally cached
// `expires` is in the past. If the server rotates/revokes the access token
// before that (common with short-lived session tokens), every request keeps
// returning 401. The streaming handler invokes refreshKimiAuthToken on the
// first auth error to force a refresh and persist the new credentials, and
// retry once.
// =============================================================================

export function getKimiApiKey(credentials: OAuthCredentials): string {
  // pi hands this whatever credential its own storage holds, which may have
  // been minted for endpoints the process is no longer configured for. A
  // token bound to a different endpoint pair must never leave for the
  // configured endpoints (AC-1.5): fail closed into a re-login error instead
  // of an unauthenticated request. Unbound pre-binding credentials count
  // only at the official mainland default binding.
  const endpoint = (credentials as Partial<StoredOAuthCredential>).endpoint;
  if (endpoint === undefined) {
    if (isMainlandKimiEndpointBinding(getKimiEndpointBinding())) return credentials.access;
  } else if (
    typeof endpoint.oauthHost === "string" &&
    typeof endpoint.baseUrl === "string" &&
    kimiEndpointBindingsEqual(
      {
        oauthHost: canonicalizeKimiEndpointUrl(endpoint.oauthHost),
        baseUrl: canonicalizeKimiEndpointUrl(endpoint.baseUrl),
      },
      getKimiEndpointBinding(),
    )
  ) {
    return credentials.access;
  }
  throw new KimiLoginRequiredError();
}

export function isKimiAuthErrorMessage(message: unknown): boolean {
  const text = String(message ?? "").toLowerCase();
  const isMembershipPermissionError =
    text.includes("current subscription does not have access to k3") ||
    text.includes("current plan supports only kimi-k3 up to 256k context") ||
    text.includes("current subscription does not have access to kimi-for-coding-highspeed");
  if (isMembershipPermissionError) return false;
  return (
    /\b401\b/.test(text) ||
    text.includes("unauthorized") ||
    text.includes("incorrect api key") ||
    text.includes("invalid api key") ||
    // Kimi's production 401 body: "The API Key appears to be invalid or may
    // have expired..." with type "invalid_authentication_error". Neither
    // contains the substrings above, so without these the digit fallback is
    // the only match and vanishes when a transport strips the status prefix.
    text.includes("api key appears to be invalid") ||
    text.includes("invalid_authentication_error")
  );
}

export async function refreshKimiAuthToken(
  currentKey: string,
  options: { signal?: AbortSignal } = {},
): Promise<string | null> {
  // Snapshot the endpoint binding for the whole transaction: every read,
  // refresh, and write-back below is scoped to this pair.
  const binding = getKimiEndpointBinding();
  let locked: LockedOAuthCredential | undefined;
  let kimiLocked: LockedKimiCodeCredentials | undefined;
  try {
    locked = await lockStoredOAuthCredential(PROVIDER_ID, options.signal);
    const piOAuth = storedCredentialMatchesBinding(locked.credential, binding)
      ? locked.credential
      : null;

    if (piOAuth) {
      if (piOAuth.access !== currentKey && Date.now() < piOAuth.expires) {
        return piOAuth.access;
      }

      let refreshed: Awaited<ReturnType<typeof refreshAccessToken>>;
      kimiLocked = await lockKimiCodeCredentials(options.signal);
      try {
        refreshed = await refreshAccessToken(piOAuth.refresh, {
          signal: options.signal,
          oauthHost: binding.oauthHost,
        });
      } catch (error) {
        const kimiCred = readKimiCliCredentials(kimiLocked.selection);
        if (!kimiCred?.refresh_token || kimiCred.refresh_token === piOAuth.refresh) throw error;
        const kimiExpiresMs = (kimiCred.expires_at ?? 0) * 1000;
        if (kimiCred.access_token !== currentKey && Date.now() < kimiExpiresMs) {
          const recovered: StoredOAuthCredential = {
            ...piOAuth,
            type: "oauth",
            access: kimiCred.access_token!,
            refresh: kimiCred.refresh_token,
            expires: kimiExpiresMs,
            endpoint: { ...binding },
          };
          locked.store(recovered);
          return recovered.access;
        }
        refreshed = await refreshAccessToken(kimiCred.refresh_token, {
          signal: options.signal,
          oauthHost: binding.oauthHost,
        });
      }

      const newExpiresMs = Date.now() + refreshed.expires_in * 1000;
      const kimiCredentialAfterRefresh = readKimiCliCredentials(kimiLocked.selection);
      const peerAccess = kimiCredentialAfterRefresh?.access_token;
      const peerExpiresMs = (kimiCredentialAfterRefresh?.expires_at ?? 0) * 1000;
      const peerIsNewerValid =
        peerAccess !== undefined && peerAccess !== currentKey && Date.now() < peerExpiresMs;
      if (peerIsNewerValid) {
        const peerCred: StoredOAuthCredential = {
          ...piOAuth,
          type: "oauth",
          access: peerAccess,
          refresh: kimiCredentialAfterRefresh!.refresh_token!,
          expires: peerExpiresMs,
          endpoint: { ...binding },
        };
        locked.store(peerCred);
        return peerCred.access;
      }
      kimiLocked.store(refreshed.access_token, refreshed.refresh_token, newExpiresMs);
      const newCred: StoredOAuthCredential = {
        ...piOAuth,
        type: "oauth",
        access: refreshed.access_token,
        refresh: refreshed.refresh_token,
        expires: newExpiresMs,
        endpoint: { ...binding },
      };
      locked.store(newCred);
      return newCred.access;
    }

    kimiLocked = await lockKimiCodeCredentials(options.signal);
    const kimiCred = kimiLocked.credential;
    if (!kimiCred) {
      return null;
    }

    const kimiExpiresMs = (kimiCred.expires_at ?? 0) * 1000;
    if (kimiCred.access_token !== currentKey && Date.now() < kimiExpiresMs) {
      return kimiCred.access_token!;
    }

    const refreshed = await refreshAccessToken(kimiCred.refresh_token!, {
      signal: options.signal,
      oauthHost: binding.oauthHost,
    });
    const newExpiresMs = Date.now() + refreshed.expires_in * 1000;
    const kimiCredentialAfterRefresh = readKimiCliCredentials(kimiLocked.selection);
    const peerAccess = kimiCredentialAfterRefresh?.access_token;
    const peerExpiresMs = (kimiCredentialAfterRefresh?.expires_at ?? 0) * 1000;
    if (peerAccess !== undefined && peerAccess !== currentKey && Date.now() < peerExpiresMs) {
      return peerAccess;
    }
    kimiLocked.store(refreshed.access_token, refreshed.refresh_token, newExpiresMs);
    return refreshed.access_token;
  } catch (err) {
    if (options.signal?.aborted) return null;
    if (err instanceof KimiLoginRequiredError) {
      console.error(`[kimi-coding] ${KIMI_LOGIN_REQUIRED_MESSAGE}`);
    } else {
      console.error("[kimi-coding] auth refresh failed:", err);
    }
    return null;
  } finally {
    if (kimiLocked) {
      await kimiLocked.release().catch(() => {});
    }
    if (locked) {
      await locked.release().catch(() => {});
    }
  }
}
