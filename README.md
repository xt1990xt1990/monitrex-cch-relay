# MoniTrex CCH Relay

Deploy a small relay in the CCH or CCHP owner's Cloudflare account. The relay reads aggregate APIs and exposes a restricted provider-level snapshot to MoniTrex.

[Deploy to Cloudflare](https://deploy.workers.cloudflare.com/?url=https://github.com/xt1990xt1990/monitrex-cch-relay)

## Setup

1. Deploy the Worker and open its `/setup` page.
2. Select **CCH** or **CCHP**, then enter the console URL, API credential, a random `PULL_TOKEN`, and a separate random `ADMIN_TOKEN`.
3. Give the Worker URL and `PULL_TOKEN` to the MoniTrex administrator.

The CCH URL and API key are encrypted before they are stored in D1. The encryption key is derived from `PULL_TOKEN`; the token itself is not stored. `ADMIN_TOKEN` is used only to view state, replace configuration, or clear the relay.

### CCHP

Use the **console** URL and an organization-bound **management API Token**, created under
Account & Security → Management API Tokens. Grant `provider:read`, `usage:read`, and
`usage:inspect`; an LLM key cannot read these APIs. The organization is read from
`/api/account/me`, so no organization header or ID needs to be entered. Saving a CCHP
configuration checks the aggregate APIs before replacing the existing settings.

The collector uses the provider catalog, provider endpoints, daily provider totals,
provider leaderboard with model children, and hourly provider timeseries. Each supplier
is emitted once even if it has multiple endpoints. Its first active valid endpoint
(or first valid disabled endpoint) supplies the matching identity. UUIDs become stable
positive numeric IDs; original UUIDs are not exported. A supplier with no valid endpoint
cannot be matched and is omitted.

Daily metrics use UTC midnight through collection time; availability uses 24 hourly
buckets including the current partial hour. Success rate follows CCHP's health formula
`succeeded / (succeeded + failed)`, which excludes caller-caused failures. Input tokens
already include cache reads/writes and must not be added again. MoniTrex cache hit rate
uses read tokens divided by all input tokens, rather than CCHP's separate cache coefficient.

CCHP's leaderboard supplies up to 100 providers and 50 model rows per supplier. A
truncated provider leaderboard fails collection rather than publishing partial provider
coverage. Model rows follow the API's 50-row cap. Model TPS is unavailable in that API
and remains `null`; provider TPS converts `avgTpsMilli` to tokens/s. Collection uses
five requests plus one per supplier; the deployment's Cloudflare subrequest allowance
must cover that count.

The integration targets CCHP `1.0.13` API shapes. Official setup and credential guidance:
[management tokens](https://cch-plus.com/zh-CN/docs/operations/management-tokens),
[provider endpoints](https://cch-plus.com/zh-CN/docs/providers/endpoints).

## Data boundary

The relay returns only:

- a random relay instance ID and collection time;
- CCH provider numeric ID and protocol type;
- provider API endpoint host, port, and path;
- hourly provider-level availability;
- daily request, success, TTFB, TPS, and cache aggregates split by model.

It has no response fields for the CCH URL, CCH origin address, CCH API key, provider display name, upstream key, masked key, group tag, account, request body, response body, or individual usage logs.

If a provider endpoint itself is an IP address, that endpoint IP is included so MoniTrex can match the provider. It is not the CCH origin address.

## Upgrade

Version 0.2 adds model-level daily aggregates. Existing deployments can upgrade in place: keep the
same Worker name and D1 binding, update the source, and deploy again. The encrypted CCH settings,
tokens, and stable instance ID remain in the existing D1 database; no setup form needs to be
submitted again.

Version 0.3 adds CCHP collection and keeps the v2 output protocol. Existing CCH settings
continue to work. To migrate a relay to CCHP, upgrade the Worker in place and submit its
setup form with **CCHP** selected and the new console URL/management Token. Keep the
Worker name, D1 binding, `PULL_TOKEN`, and `ADMIN_TOKEN` to retain the same source identity
and MoniTrex connection. Then run an immediate sync in MoniTrex.

## Validation

Run `npm test`, `npm run typecheck`, and `npm run build`. Tests use isolated synthetic
CCH/CCHP responses and do not contact a production service.

## Removal

Open `/setup`, enter `ADMIN_TOKEN`, and use **Clear relay configuration**. You may then delete the Worker and its D1 database from the Cloudflare dashboard. Removing the source in MoniTrex stops polling and deletes the imported CCH source data there.
