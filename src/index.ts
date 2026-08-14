interface Env {
  DB: D1Database;
}

interface RelayConfig {
  instance_id: string;
  secret_cipher: string;
  secret_iv: string;
  secret_salt: string;
  pull_hash: string;
  pull_salt: string;
  admin_hash: string;
  admin_salt: string;
  last_success_at: string | null;
  last_error: string | null;
  provider_count: number;
}

interface SecretConfig {
  cch_url: string;
  cch_api_key: string;
}

interface RemoteProvider {
  id: number;
  url: string;
  providerType?: string;
  provider_type?: string;
}

const SERVICE = "monitrex-cch-relay";
const VERSION = "0.1.0";
const PROTOCOL_VERSION = 1;
const PRIVACY_VERSION = 1;
const SCHEMA_VERSION = 1;
const MAX_RESPONSE_BYTES = 5 * 1024 * 1024;

const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS relay_config (
  singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
  instance_id TEXT NOT NULL,
  secret_cipher TEXT NOT NULL,
  secret_iv TEXT NOT NULL,
  secret_salt TEXT NOT NULL,
  pull_hash TEXT NOT NULL,
  pull_salt TEXT NOT NULL,
  admin_hash TEXT NOT NULL,
  admin_salt TEXT NOT NULL,
  last_success_at TEXT,
  last_error TEXT,
  provider_count INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL
);`;

function json(data: unknown, status = 200): Response {
  return Response.json(data, {
    status,
    headers: {
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
    },
  });
}

function html(body: string, status = 200): Response {
  return new Response(body, {
    status,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
      "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
      "x-content-type-options": "nosniff",
      "x-frame-options": "DENY",
    },
  });
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function base64ToBytes(value: string): Uint8Array {
  const binary = atob(value);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

function randomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

function buffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.slice().buffer as ArrayBuffer;
}

async function digest(value: string, salt: Uint8Array): Promise<string> {
  const encoded = new TextEncoder().encode(value);
  const data = new Uint8Array(salt.length + encoded.length);
  data.set(salt);
  data.set(encoded, salt.length);
  return bytesToBase64(new Uint8Array(await crypto.subtle.digest("SHA-256", buffer(data))));
}

function constantTimeEqual(left: string, right: string): boolean {
  const length = Math.max(left.length, right.length);
  let mismatch = left.length ^ right.length;
  for (let i = 0; i < length; i += 1) {
    mismatch |= (left.charCodeAt(i) || 0) ^ (right.charCodeAt(i) || 0);
  }
  return mismatch === 0;
}

async function deriveKey(token: string, salt: Uint8Array): Promise<CryptoKey> {
  const material = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(token),
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: buffer(salt), iterations: 150_000, hash: "SHA-256" },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

async function encryptSecrets(secrets: SecretConfig, token: string) {
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const key = await deriveKey(token, salt);
  const plain = new TextEncoder().encode(JSON.stringify(secrets));
  const cipher = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: buffer(iv) },
    key,
    buffer(plain),
  );
  return {
    cipher: bytesToBase64(new Uint8Array(cipher)),
    iv: bytesToBase64(iv),
    salt: bytesToBase64(salt),
  };
}

async function decryptSecrets(config: RelayConfig, token: string): Promise<SecretConfig> {
  const key = await deriveKey(token, base64ToBytes(config.secret_salt));
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: buffer(base64ToBytes(config.secret_iv)) },
    key,
    buffer(base64ToBytes(config.secret_cipher)),
  );
  return JSON.parse(new TextDecoder().decode(plain)) as SecretConfig;
}

async function ensureSchema(env: Env): Promise<void> {
  await env.DB.prepare(SCHEMA_SQL).run();
}

async function config(env: Env): Promise<RelayConfig | null> {
  await ensureSchema(env);
  return env.DB.prepare(
    `SELECT instance_id, secret_cipher, secret_iv, secret_salt,
            pull_hash, pull_salt, admin_hash, admin_salt,
            last_success_at, last_error, provider_count
     FROM relay_config WHERE singleton = 1`,
  ).first<RelayConfig>();
}

function bearer(request: Request): string {
  const value = request.headers.get("authorization") || "";
  return value.startsWith("Bearer ") ? value.slice(7).trim() : "";
}

async function tokenMatches(token: string, expected: string, salt: string): Promise<boolean> {
  if (!token) return false;
  return constantTimeEqual(await digest(token, base64ToBytes(salt)), expected);
}

function normalizeCchUrl(raw: string): string {
  const url = new URL(raw.trim());
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.search || url.hash) {
    throw new Error("CCH URL must be an http(s) origin without credentials, query, or fragment");
  }
  return url.toString().replace(/\/$/, "");
}

function endpointIdentity(raw: string): { host: string; path: string } | null {
  try {
    const url = new URL(raw.trim());
    if (!['http:', 'https:'].includes(url.protocol)) return null;
    const defaultPort = (url.protocol === 'http:' && url.port === '80') ||
      (url.protocol === 'https:' && url.port === '443');
    const host = `${url.hostname.toLowerCase().replace(/\.$/, "")}${url.port && !defaultPort ? `:${url.port}` : ""}`;
    const path = url.pathname.replace(/\/+$/, "") || "/";
    return host && host.length <= 255 && path.length <= 512 ? { host, path } : null;
  } catch {
    return null;
  }
}

function rows(value: unknown): Record<string, unknown>[] {
  if (Array.isArray(value)) return value.filter(isRecord);
  if (isRecord(value) && Array.isArray(value.items)) return value.items.filter(isRecord);
  return [];
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function number(value: unknown): number | null {
  const parsed = typeof value === "number" ? value : typeof value === "string" ? Number(value) : NaN;
  return Number.isFinite(parsed) ? parsed : null;
}

function count(value: unknown): number {
  return Math.max(0, Math.floor(number(value) ?? 0));
}

async function cchGet(baseUrl: string, apiKey: string, path: string): Promise<unknown> {
  const response = await fetch(`${baseUrl}${path}`, {
    headers: { accept: "application/json", authorization: `Bearer ${apiKey}` },
    signal: AbortSignal.timeout(25_000),
  });
  if (!response.ok) throw new Error(`CCH returned HTTP ${response.status}`);
  const raw = await response.text();
  if (raw.length > MAX_RESPONSE_BYTES) throw new Error("CCH response exceeded 5 MiB");
  return JSON.parse(raw) as unknown;
}

function availabilityMap(value: unknown, collectedAt: Date): Map<number, unknown[]> {
  const result = new Map<number, unknown[]>();
  if (!isRecord(value) || !Array.isArray(value.providers)) return result;
  for (const provider of value.providers.filter(isRecord)) {
    const providerId = number(provider.providerId);
    if (!providerId || !Number.isSafeInteger(providerId)) continue;
    const buckets: unknown[] = [];
    const timeBuckets = Array.isArray(provider.timeBuckets) ? provider.timeBuckets.filter(isRecord) : [];
    for (const bucket of timeBuckets.slice(0, 24)) {
      const start = new Date(String(bucket.bucketStart || ""));
      const reportedEnd = new Date(String(bucket.bucketEnd || ""));
      if (!Number.isFinite(start.valueOf()) || !Number.isFinite(reportedEnd.valueOf())) continue;
      const end = new Date(Math.min(reportedEnd.valueOf(), collectedAt.valueOf()));
      if (start >= end || end.valueOf() - start.valueOf() > 86_400_000) continue;
      const requestCount = count(bucket.totalRequests);
      const successCount = Math.min(count(bucket.greenCount), requestCount);
      const failureCount = Math.min(count(bucket.redCount), requestCount - successCount);
      buckets.push({
        bucket_start: start.toISOString(),
        bucket_end: end.toISOString(),
        request_count: requestCount,
        success_count: successCount,
        failure_count: failureCount,
      });
    }
    result.set(providerId, buckets);
  }
  return result;
}

function leaderboardMap(value: unknown): Map<number, Record<string, unknown>> {
  const result = new Map<number, Record<string, unknown>>();
  for (const item of rows(value)) {
    const providerId = number(item.providerId);
    if (providerId && Number.isSafeInteger(providerId)) result.set(providerId, item);
  }
  return result;
}

function optionalNonnegative(value: unknown): number | null {
  const parsed = number(value);
  return parsed !== null && parsed >= 0 ? parsed : null;
}

function metrics(
  providerId: number,
  providerRows: Map<number, Record<string, unknown>>,
  cacheRows: Map<number, Record<string, unknown>>,
) {
  const provider = providerRows.get(providerId);
  const cache = cacheRows.get(providerId);
  const successRate = number(provider?.successRate);
  const eligible = count(cache?.totalInputTokens);
  return {
    request_count: count(provider?.totalRequests),
    success_rate: successRate !== null && successRate >= 0 && successRate <= 1 ? successRate : null,
    avg_ttfb_ms: optionalNonnegative(provider?.avgTtftMs) ?? optionalNonnegative(provider?.avgTtfbMs),
    avg_tps: optionalNonnegative(provider?.avgTokensPerSecond),
    cache_request_count: count(cache?.totalRequests),
    cache_read_tokens: Math.min(count(cache?.cacheReadTokens), eligible),
    cache_eligible_tokens: eligible,
  };
}

async function collect(secrets: SecretConfig, instanceId: string) {
  const collectedAt = new Date();
  const start = new Date(collectedAt.valueOf() - 24 * 60 * 60 * 1000).toISOString();
  const end = collectedAt.toISOString();
  const query = new URLSearchParams({
    startTime: start,
    endTime: end,
    bucketSizeMinutes: "60",
    maxBuckets: "24",
    includeDisabled: "true",
  });
  const [providerEnvelope, availabilityValue, providerValue, cacheValue] = await Promise.all([
    cchGet(secrets.cch_url, secrets.cch_api_key, "/api/v1/providers"),
    cchGet(secrets.cch_url, secrets.cch_api_key, `/api/availability?${query}`),
    cchGet(secrets.cch_url, secrets.cch_api_key, "/api/leaderboard?period=daily&scope=provider"),
    cchGet(secrets.cch_url, secrets.cch_api_key, "/api/leaderboard?period=daily&scope=providerCacheHitRate"),
  ]);
  const providerItems = isRecord(providerEnvelope) && Array.isArray(providerEnvelope.items)
    ? providerEnvelope.items.filter(isRecord)
    : [];
  const availability = availabilityMap(availabilityValue, collectedAt);
  const providerRows = leaderboardMap(providerValue);
  const cacheRows = leaderboardMap(cacheValue);
  const seen = new Set<number>();
  const providers = [];
  for (const raw of providerItems.slice(0, 500)) {
    const provider = raw as unknown as RemoteProvider;
    const providerId = number(provider.id);
    const providerType = String(provider.providerType ?? provider.provider_type ?? "");
    const endpoint = endpointIdentity(String(provider.url ?? ""));
    if (!providerId || !Number.isSafeInteger(providerId) || seen.has(providerId) || !endpoint ||
        !/^[A-Za-z0-9_-]{1,64}$/.test(providerType)) continue;
    seen.add(providerId);
    providers.push({
      cch_provider_id: providerId,
      provider_type: providerType,
      website_host: null,
      endpoint_host: endpoint.host,
      endpoint_path: endpoint.path,
      availability: availability.get(providerId) || [],
      metrics: metrics(providerId, providerRows, cacheRows),
    });
  }
  return {
    schema_version: SCHEMA_VERSION,
    protocol_version: PROTOCOL_VERSION,
    privacy_version: PRIVACY_VERSION,
    source_ref: instanceId,
    collected_at: collectedAt.toISOString(),
    providers,
  };
}

function safeError(error: unknown): string {
  const message = error instanceof Error ? error.message : "unknown error";
  return message.replace(/[\r\n\t]/g, " ").slice(0, 300);
}

async function aggregate(request: Request, env: Env): Promise<Response> {
  const current = await config(env);
  if (!current) return json({ error: "relay is not configured" }, 503);
  const token = bearer(request);
  if (!(await tokenMatches(token, current.pull_hash, current.pull_salt))) {
    return json({ error: "invalid pull token" }, 401);
  }
  try {
    const secrets = await decryptSecrets(current, token);
    const batch = await collect(secrets, current.instance_id);
    await env.DB.prepare(
      `UPDATE relay_config SET last_success_at = ?, last_error = NULL,
       provider_count = ?, updated_at = ? WHERE singleton = 1`,
    ).bind(batch.collected_at, batch.providers.length, new Date().toISOString()).run();
    return json(batch);
  } catch (error) {
    await env.DB.prepare(
      "UPDATE relay_config SET last_error = ?, updated_at = ? WHERE singleton = 1",
    ).bind(safeError(error), new Date().toISOString()).run();
    return json({ error: "CCH collection failed" }, 502);
  }
}

async function readBody(request: Request): Promise<Record<string, string>> {
  const contentType = request.headers.get("content-type") || "";
  if (contentType.includes("application/json")) {
    const value = await request.json<Record<string, unknown>>();
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, String(item ?? "")]));
  }
  const form = await request.formData();
  const result: Record<string, string> = {};
  form.forEach((value, key) => {
    result[key] = String(value);
  });
  return result;
}

async function saveConfig(request: Request, env: Env): Promise<Response> {
  const body = await readBody(request);
  const existing = await config(env);
  if (existing && !(await tokenMatches(body.current_admin_token || "", existing.admin_hash, existing.admin_salt))) {
    return json({ error: "invalid admin token" }, 401);
  }
  const cchUrl = normalizeCchUrl(body.cch_url || "");
  const cchApiKey = (body.cch_api_key || "").trim();
  const pullToken = body.pull_token || "";
  const adminToken = body.admin_token || "";
  if (cchApiKey.length < 8 || pullToken.length < 16 || adminToken.length < 16 || pullToken === adminToken) {
    return json({ error: "CCH key and two different tokens are required; tokens need at least 16 characters" }, 400);
  }
  await cchGet(cchUrl, cchApiKey, "/api/v1/providers");
  const encrypted = await encryptSecrets({ cch_url: cchUrl, cch_api_key: cchApiKey }, pullToken);
  const pullSalt = randomBytes(16);
  const adminSalt = randomBytes(16);
  const now = new Date().toISOString();
  await env.DB.prepare(
    `INSERT INTO relay_config (
       singleton, instance_id, secret_cipher, secret_iv, secret_salt,
       pull_hash, pull_salt, admin_hash, admin_salt, provider_count, updated_at
     ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)
     ON CONFLICT(singleton) DO UPDATE SET
       secret_cipher = excluded.secret_cipher, secret_iv = excluded.secret_iv,
       secret_salt = excluded.secret_salt, pull_hash = excluded.pull_hash,
       pull_salt = excluded.pull_salt, admin_hash = excluded.admin_hash,
       admin_salt = excluded.admin_salt, last_error = NULL, updated_at = excluded.updated_at`,
  ).bind(
    existing?.instance_id || crypto.randomUUID(),
    encrypted.cipher,
    encrypted.iv,
    encrypted.salt,
    await digest(pullToken, pullSalt),
    bytesToBase64(pullSalt),
    await digest(adminToken, adminSalt),
    bytesToBase64(adminSalt),
    now,
  ).run();
  return json({ ok: true, configured: true });
}

async function adminState(request: Request, env: Env): Promise<Response> {
  const current = await config(env);
  if (!current) return json({ configured: false });
  if (!(await tokenMatches(bearer(request), current.admin_hash, current.admin_salt))) {
    return json({ error: "invalid admin token" }, 401);
  }
  return json({
    configured: true,
    instance_id: current.instance_id,
    last_success_at: current.last_success_at,
    last_error: current.last_error,
    provider_count: current.provider_count,
  });
}

async function clearConfig(request: Request, env: Env): Promise<Response> {
  const body = await readBody(request);
  const current = await config(env);
  if (!current || !(await tokenMatches(body.admin_token || bearer(request), current.admin_hash, current.admin_salt))) {
    return json({ error: "invalid admin token" }, 401);
  }
  await env.DB.prepare("DELETE FROM relay_config WHERE singleton = 1").run();
  return json({ ok: true, configured: false });
}

function setupPage(configured: boolean): Response {
  return html(`<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>MoniTrex CCH Relay</title><style>
:root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;background:#09090b;color:#d4d4d8;font:14px/1.55 system-ui,sans-serif}main{max-width:760px;margin:0 auto;padding:32px 20px 64px}h1{font-size:22px;color:#fafafa;margin:0 0 8px}h2{font-size:15px;color:#f4f4f5;margin:28px 0 10px}.status{border-left:3px solid ${configured ? "#00e052" : "#f59e0b"};padding:8px 12px;background:#18181b}label{display:block;margin:12px 0 5px;color:#a1a1aa}input{width:100%;border:1px solid #3f3f46;background:#09090b;color:#fafafa;border-radius:6px;padding:10px 11px;font:inherit}button{border:1px solid #52525b;background:#f4f4f5;color:#18181b;border-radius:6px;padding:9px 14px;font-weight:600;cursor:pointer}.danger{background:transparent;color:#ff5454;border-color:#7f1d1d}.grid{display:grid;grid-template-columns:1fr 1fr;gap:0 12px}.note{color:#71717a;font-size:12px}code{font-family:ui-monospace,monospace;color:#a1a1aa}@media(max-width:600px){.grid{grid-template-columns:1fr}}
</style></head><body><main><h1>MoniTrex CCH Relay</h1>
<p class="status">${configured ? "Relay 已配置。重新配置需要当前 ADMIN_TOKEN。" : "Relay 尚未配置。提交后凭据不会再次显示。"}</p>
<h2>${configured ? "替换配置" : "首次配置"}</h2>
<form id="config"><label>CCH URL</label><input name="cch_url" type="url" required placeholder="https://cch.example.com">
<label>CCH API Key</label><input name="cch_api_key" type="password" required autocomplete="off">
<div class="grid"><div><label>PULL_TOKEN</label><input name="pull_token" type="password" minlength="16" required autocomplete="new-password"></div>
<div><label>新的 ADMIN_TOKEN</label><input name="admin_token" type="password" minlength="16" required autocomplete="new-password"></div></div>
${configured ? '<label>当前 ADMIN_TOKEN</label><input name="current_admin_token" type="password" minlength="16" required autocomplete="current-password">' : ""}
<p class="note">PULL_TOKEN 用于 MoniTrex 拉取；ADMIN_TOKEN 只用于管理。请使用两个不同的随机值。</p><button>验证 CCH 并保存</button></form>
${configured ? '<h2>清除 Relay</h2><form id="clear"><label>ADMIN_TOKEN</label><input name="admin_token" type="password" minlength="16" required autocomplete="current-password"><p class="note">清除后 D1 中的加密 CCH 配置、令牌摘要和状态都会删除。</p><button class="danger">清除 Relay 配置</button></form>' : ""}
<p id="result" class="status" hidden></p><script>
async function send(form,path){const out=document.querySelector('#result');out.hidden=false;out.textContent='处理中...';try{const response=await fetch(path,{method:'POST',body:new FormData(form)});const data=await response.json();if(!response.ok)throw new Error(data.error||('HTTP '+response.status));out.textContent=data.ok?'操作完成，请刷新页面。':JSON.stringify(data)}catch(error){out.textContent='操作失败：'+error.message}}
document.querySelector('#config').addEventListener('submit',event=>{event.preventDefault();send(event.target,'/v1/admin/config')});
document.querySelector('#clear')?.addEventListener('submit',event=>{event.preventDefault();if(confirm('确定清除 Relay 配置？'))send(event.target,'/v1/admin/clear')});
</script></main></body></html>`);
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    try {
      const url = new URL(request.url);
      if (request.method === "GET" && url.pathname === "/.well-known/monitrex") {
        const current = await config(env);
        return json({
          service: SERVICE,
          version: VERSION,
          protocol: PROTOCOL_VERSION,
          privacy_version: PRIVACY_VERSION,
          configured: Boolean(current),
          instance_id: current?.instance_id ?? null,
          provider_count: current?.provider_count ?? 0,
          last_success_at: current?.last_success_at ?? null,
        });
      }
      if (request.method === "GET" && (url.pathname === "/" || url.pathname === "/setup")) {
        return setupPage(Boolean(await config(env)));
      }
      if (request.method === "GET" && url.pathname === "/v1/aggregate") return aggregate(request, env);
      if (request.method === "GET" && url.pathname === "/v1/admin/state") return adminState(request, env);
      if (request.method === "POST" && url.pathname === "/v1/admin/config") return saveConfig(request, env);
      if (request.method === "POST" && url.pathname === "/v1/admin/clear") return clearConfig(request, env);
      return json({ error: "not found" }, 404);
    } catch (error) {
      return json({ error: safeError(error) }, 400);
    }
  },
};
