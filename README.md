# MoniTrex CCH Relay

Deploy a small relay in the CCH owner's Cloudflare account. The relay reads CCH aggregate APIs and exposes a restricted provider-level snapshot to MoniTrex.

[Deploy to Cloudflare](https://deploy.workers.cloudflare.com/?url=https://github.com/xt1990xt1990/monitrex-cch-relay)

## Setup

1. Deploy the Worker and open its `/setup` page.
2. Enter the CCH URL, CCH API key, a random `PULL_TOKEN`, and a separate random `ADMIN_TOKEN`.
3. Give the Worker URL and `PULL_TOKEN` to the MoniTrex administrator.

The CCH URL and API key are encrypted before they are stored in D1. The encryption key is derived from `PULL_TOKEN`; the token itself is not stored. `ADMIN_TOKEN` is used only to view state, replace configuration, or clear the relay.

## Data boundary

The relay returns only:

- a random relay instance ID and collection time;
- CCH provider numeric ID and protocol type;
- provider API endpoint host, port, and path;
- hourly availability plus daily request, success, TTFB, TPS, and cache aggregates.

It has no response fields for the CCH URL, CCH origin address, CCH API key, provider display name, upstream key, masked key, group tag, account, request body, response body, or individual usage logs.

If a provider endpoint itself is an IP address, that endpoint IP is included so MoniTrex can match the provider. It is not the CCH origin address.

## Removal

Open `/setup`, enter `ADMIN_TOKEN`, and use **Clear relay configuration**. You may then delete the Worker and its D1 database from the Cloudflare dashboard. Removing the source in MoniTrex stops polling and deletes the imported CCH source data there.
