import http from "node:http";

const provider = {
  id: 17,
  name: "PRIVATE_PROVIDER_NAME",
  url: "https://api.example.com/v1/messages",
  websiteUrl: "https://private.example.com",
  providerType: "claude",
  apiKey: "PRIVATE_UPSTREAM_KEY",
  groupTag: "PRIVATE_GROUP",
};

const server = http.createServer((request, response) => {
  if (request.headers.authorization !== "Bearer MOCK_CCH_KEY") {
    response.writeHead(401).end(JSON.stringify({ error: "unauthorized" }));
    return;
  }
  response.setHeader("content-type", "application/json");
  const url = new URL(request.url, "http://127.0.0.1");
  if (url.pathname === "/api/v1/providers") {
    response.end(JSON.stringify({ items: [provider] }));
    return;
  }
  if (url.pathname === "/api/availability") {
    const end = new Date();
    const start = new Date(end.valueOf() - 3_600_000);
    response.end(JSON.stringify({
      providers: [{
        providerId: 17,
        timeBuckets: [{
          bucketStart: start.toISOString(),
          bucketEnd: end.toISOString(),
          totalRequests: 10,
          greenCount: 9,
          redCount: 1,
        }],
      }],
    }));
    return;
  }
  if (url.pathname === "/api/leaderboard" && url.searchParams.get("scope") === "provider") {
    response.end(JSON.stringify({ items: [{
      providerId: 17,
      totalRequests: 10,
      successRate: 0.9,
      avgTtftMs: 125,
      avgTokensPerSecond: 42,
    }] }));
    return;
  }
  if (url.pathname === "/api/leaderboard") {
    response.end(JSON.stringify({ items: [{
      providerId: 17,
      totalRequests: 5,
      totalInputTokens: 1000,
      cacheReadTokens: 400,
    }] }));
    return;
  }
  response.writeHead(404).end(JSON.stringify({ error: "not found" }));
});

server.listen(18765, "127.0.0.1", () => {
  process.stdout.write("mock-cch ready on 18765\n");
});
