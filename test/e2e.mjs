import assert from "node:assert/strict";

const relay = "http://127.0.0.1:18766";
const pullToken = "MOCK_PULL_TOKEN_123456789";
const adminToken = "MOCK_ADMIN_TOKEN_12345678";

const before = await fetch(`${relay}/.well-known/monitrex`).then((response) => response.json());
assert.equal(before.service, "monitrex-cch-relay");
assert.equal(before.configured, false);

const form = new FormData();
form.set("cch_url", "http://127.0.0.1:18765");
form.set("cch_api_key", "MOCK_CCH_KEY");
form.set("pull_token", pullToken);
form.set("admin_token", adminToken);
const configured = await fetch(`${relay}/v1/admin/config`, { method: "POST", body: form });
assert.equal(configured.status, 200);

const unauthorized = await fetch(`${relay}/v1/aggregate`, {
  headers: { authorization: "Bearer invalid" },
});
assert.equal(unauthorized.status, 401);

const aggregateResponse = await fetch(`${relay}/v1/aggregate`, {
  headers: { authorization: `Bearer ${pullToken}` },
});
assert.equal(aggregateResponse.status, 200);
const aggregate = await aggregateResponse.json();
assert.deepEqual(Object.keys(aggregate).sort(), [
  "collected_at",
  "privacy_version",
  "protocol_version",
  "providers",
  "schema_version",
  "source_ref",
]);
assert.deepEqual(Object.keys(aggregate.providers[0]).sort(), [
  "availability",
  "cch_provider_id",
  "endpoint_host",
  "endpoint_path",
  "metrics",
  "provider_type",
  "website_host",
]);
assert.equal(aggregate.providers[0].endpoint_host, "api.example.com");
assert.equal(aggregate.providers[0].website_host, null);
assert.equal(aggregate.providers[0].metrics.avg_ttfb_ms, 125);
const encoded = JSON.stringify(aggregate);
for (const secret of ["PRIVATE_PROVIDER_NAME", "PRIVATE_UPSTREAM_KEY", "PRIVATE_GROUP", "MOCK_CCH_KEY", "127.0.0.1:18765"]) {
  assert.equal(encoded.includes(secret), false, `aggregate leaked ${secret}`);
}

const state = await fetch(`${relay}/v1/admin/state`, {
  headers: { authorization: `Bearer ${adminToken}` },
}).then((response) => response.json());
assert.equal(state.configured, true);
assert.equal(state.provider_count, 1);

const clear = new FormData();
clear.set("admin_token", adminToken);
const cleared = await fetch(`${relay}/v1/admin/clear`, { method: "POST", body: clear });
assert.equal(cleared.status, 200);
const after = await fetch(`${relay}/.well-known/monitrex`).then((response) => response.json());
assert.equal(after.configured, false);

process.stdout.write("relay e2e: ok\n");
