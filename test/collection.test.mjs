import assert from "node:assert/strict";
import { after, test } from "node:test";
import relay from "../src/index.ts";

const originalFetch = globalThis.fetch;
after(() => { globalThis.fetch = originalFetch; });
const pullToken = "TEST_PULL_TOKEN_123456789";
const adminToken = "TEST_ADMIN_TOKEN_12345678";
const providerId = "01a13955-6889-7a77-a89d-63171f56feb9";
const origin = "https://private-cch.example.test";

function database() {
  let config = null;
  return { prepare(sql) {
    let values = [];
    return {
      bind(...args) { values = args; return this; },
      async first() { return config; },
      async run() {
        if (sql.includes("INSERT INTO relay_config")) {
          const [instance_id, secret_cipher, secret_iv, secret_salt,
            pull_hash, pull_salt, admin_hash, admin_salt] = values;
          config = { instance_id, secret_cipher, secret_iv, secret_salt,
            pull_hash, pull_salt, admin_hash, admin_salt, provider_count: 0 };
        } else if (sql.includes("SET last_success_at")) {
          config.last_success_at = values[0];
          config.provider_count = values[1];
        }
      },
    };
  } };
}

function configure(env, sourceType) {
  return relay.fetch(new Request("https://relay.example/v1/admin/config", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ source_type: sourceType, cch_url: origin,
      cch_api_key: "TEST_CCH_MANAGEMENT_KEY", pull_token: pullToken, admin_token: adminToken }),
  }), env);
}

async function aggregate(env) {
  const response = await relay.fetch(new Request("https://relay.example/v1/aggregate", {
    headers: { authorization: `Bearer ${pullToken}` },
  }), env);
  const data = await response.json();
  assert.equal(response.status, 200, JSON.stringify(data));
  return data;
}

test("CCHP maps organization, provider UUIDs, hourly and model metrics without multiplying endpoints", async () => {
  const seenPaths = [];
  let denied = false;
  globalThis.fetch = async (input, init) => {
    const url = new URL(input);
    assert.equal(url.origin, origin);
    assert.equal(init.headers.authorization, "Bearer TEST_CCH_MANAGEMENT_KEY");
    seenPaths.push(url.pathname);
    if (denied && url.pathname.includes("/usage/")) return Response.json({}, { status: 403 });
    if (url.pathname === "/api/account/me") return Response.json({
      activeOrganizationId: "org-1", tokenKind: "management-api", user: { email: "private@example.test" },
    });
    if (url.pathname === "/api/account/orgs/org-1/providers") return Response.json({
      providers: [{ id: providerId, name: "PRIVATE_PROVIDER_NAME", notes: "PRIVATE_NOTES" }],
    });
    if (url.pathname.endsWith("/endpoints")) return Response.json({ endpoints: [
      { base_url: "https://old.example.com", status: "disabled" },
      { base_url: "https://api.example.com/v1/", status: "active" },
      { base_url: "https://api.example.com/other", status: "active" },
    ] });
    if (url.pathname.endsWith("/by-provider")) {
      assert.match(url.searchParams.get("start"), /T00:00:00\.000Z$/);
      return Response.json({ items: [{ providerId, requests: 13, succeeded: 9, failed: 1,
        inputTokens: 1000, cacheReadTokens: 400, cacheWriteTokens: 200,
        avgTtftMs: 125, avgTpsMilli: 42500 }] });
    }
    if (url.pathname.endsWith("/leaderboard")) return Response.json({ total: 1, entries: [{
      id: providerId, name: "PRIVATE_PROVIDER_NAME", children: [{
        model: "gpt-6.1-sol", requests: 13, successRate: 0.9,
        inputTokens: 1000, cachedTokens: 400, cacheWriteTokens: 200, avgTtftMs: 125,
      }], keyChildren: [{ name: "PRIVATE_KEY_NAME" }],
    }] });
    if (url.pathname.endsWith("/timeseries")) {
      assert.equal(url.searchParams.get("groupBy"), "provider");
      const bucket = new Date(Date.now() - 3_600_000);
      bucket.setUTCMinutes(0, 0, 0);
      return Response.json({ buckets: [{ groupId: providerId, groupKey: "PRIVATE_PROVIDER_NAME",
        bucket: bucket.toISOString(), requests: 13, succeeded: 9, failed: 1 }] });
    }
    assert.fail(`Unexpected request ${url.pathname}`);
  };
  const env = { DB: database() };
  assert.equal((await configure(env, "cchp")).status, 200);
  const batch = await aggregate(env);
  assert.equal(batch.schema_version, 2);
  assert.equal(batch.protocol_version, 2);
  assert.equal(batch.privacy_version, 2);
  assert.equal(batch.providers.length, 1);
  const provider = batch.providers[0];
  assert.ok(Number.isSafeInteger(provider.cch_provider_id));
  assert.ok(provider.cch_provider_id >= 2 ** 52);
  assert.equal(provider.provider_type, "cchp");
  assert.equal(provider.endpoint_host, "api.example.com");
  assert.equal(provider.endpoint_path, "/v1");
  assert.deepEqual(provider.metrics, {
    request_count: 13, success_rate: 0.9, avg_ttfb_ms: 125, avg_tps: 42.5,
    cache_request_count: 13, cache_read_tokens: 400, cache_eligible_tokens: 1000,
  });
  assert.deepEqual(provider.model_metrics, [{
    model_name: "gpt-6.1-sol", request_count: 13, success_rate: 0.9, avg_ttfb_ms: 125,
    avg_tps: null, cache_request_count: 13, cache_read_tokens: 400, cache_eligible_tokens: 1000,
  }]);
  assert.equal(provider.availability.length, 1);
  assert.equal(provider.availability[0].request_count, 13);
  assert.equal(provider.availability[0].success_count, 9);
  assert.equal(provider.availability[0].failure_count, 1);
  const next = await aggregate(env);
  assert.equal(next.source_ref, batch.source_ref);
  assert.equal(next.providers[0].cch_provider_id, provider.cch_provider_id);
  for (const secret of [origin, providerId, "PRIVATE_PROVIDER_NAME", "PRIVATE_NOTES", "PRIVATE_KEY_NAME",
    "private@example.test", "TEST_CCH_MANAGEMENT_KEY"]) {
    assert.equal(JSON.stringify(batch).includes(secret), false, `leaked ${secret}`);
  }
  assert.equal(seenPaths.includes("/api/v1/providers"), false);
  denied = true;
  const deniedResponse = await configure({ DB: database() }, "cchp");
  assert.equal(deniedResponse.status, 400);
  assert.match((await deniedResponse.json()).error, /HTTP 403.*usage:read/);
});

test("existing setup requests still select the legacy CCH collector", async () => {
  globalThis.fetch = async (input) => {
    const url = new URL(input);
    if (url.pathname === "/api/v1/providers") return Response.json({ items: [{
      id: 17, url: "https://api.example.com/v1/messages", providerType: "claude",
    }] });
    if (url.pathname === "/api/availability") return Response.json({ providers: [] });
    if (url.pathname === "/api/leaderboard") return Response.json({ items: [{
      providerId: 17, totalRequests: 10, successRate: 0.9, avgTtftMs: 125,
      avgTokensPerSecond: 42, totalInputTokens: 1000, cacheReadTokens: 400,
      modelStats: [{ model: "gpt-6.1-sol", totalRequests: 10, successRate: 0.9,
        avgTtftMs: 125, avgTokensPerSecond: 42, totalInputTokens: 1000, cacheReadTokens: 400 }],
    }] });
    assert.fail(`Unexpected legacy request ${url.pathname}`);
  };
  const env = { DB: database() };
  assert.equal((await configure(env)).status, 200);
  const batch = await aggregate(env);
  assert.equal(batch.providers[0].cch_provider_id, 17);
  assert.equal(batch.providers[0].metrics.avg_tps, 42);
  assert.equal(batch.providers[0].model_metrics[0].avg_tps, 42);
});

function cchpFixture({ empty = false, truncated = false, modelCount = 1 } = {}) {
  const children = Array.from({ length: modelCount }, (_, index) => ({
    model: `synthetic-model-${index}`, requests: 1, successRate: 1,
    inputTokens: 100, cachedTokens: 50, avgTtftMs: 0,
  }));
  return async (input) => {
    const path = new URL(input).pathname;
    if (path === "/api/account/me") return Response.json({ tokenKind: "management-api", activeOrganizationId: "org-1" });
    if (path === "/api/account/orgs/org-1/providers") return Response.json({
      providers: empty ? [] : [{ id: providerId }],
    });
    if (path.endsWith("/endpoints")) return Response.json({ endpoints: [
      { base_url: "https://api.example.com/v1", status: "active" },
    ] });
    if (path.endsWith("/by-provider")) return Response.json({ items: empty ? [] : [{
      providerId, requests: modelCount, succeeded: modelCount, failed: 0,
      inputTokens: modelCount * 100, cacheReadTokens: modelCount * 50,
    }] });
    if (path.endsWith("/leaderboard")) return Response.json({
      total: empty ? 0 : truncated ? 2 : 1,
      entries: empty ? [] : [{ id: providerId, children }],
    });
    if (path.endsWith("/timeseries")) return Response.json({ buckets: [] });
    assert.fail(`Unexpected fixture request ${path}`);
  };
}

test("CCHP accepts an empty source without inventing metrics", async () => {
  globalThis.fetch = cchpFixture({ empty: true });
  const env = { DB: database() };
  assert.equal((await configure(env, "cchp")).status, 200);
  assert.deepEqual((await aggregate(env)).providers, []);
});

test("CCHP retains all 50 returned model rows and preserves missing timing samples", async () => {
  globalThis.fetch = cchpFixture({ modelCount: 50 });
  const env = { DB: database() };
  assert.equal((await configure(env, "cchp")).status, 200);
  const provider = (await aggregate(env)).providers[0];
  assert.equal(provider.model_metrics.length, 50);
  assert.equal(provider.model_metrics.reduce((n, model) => n + model.request_count, 0), 50);
  assert.equal(provider.metrics.avg_tps, null);
  assert.equal(provider.metrics.avg_ttfb_ms, null);
  assert.ok(provider.model_metrics.every(model => model.avg_ttfb_ms === null && model.avg_tps === null));
});

test("CCHP does not save a source when its supplier leaderboard is truncated", async () => {
  globalThis.fetch = cchpFixture({ truncated: true });
  const env = { DB: database() };
  const response = await configure(env, "cchp");
  assert.equal(response.status, 400);
  assert.match((await response.json()).error, /provider leaderboard is truncated/);
  const metadata = await relay.fetch(new Request("https://relay.example/.well-known/monitrex"), env);
  assert.equal((await metadata.json()).configured, false);
});
