import assert from "node:assert/strict";
import test from "node:test";
import { analyzeInfrastructure } from "../dist/infrastructure.js";

test("analyzeInfrastructure infers providers from passive DNS, reverse DNS, headers, and stack evidence", async () => {
  const result = await analyzeInfrastructure(
    new URL("https://www.example.com/"),
    {
      server: "cloudflare",
      "x-amz-cf-id": "example-cloudfront-id",
    },
    [
      {
        name: "Vercel",
        category: "hosting",
        evidence: "Detected from x-vercel-id response header",
        version: null,
        confidence: "high",
        detection: "observed",
      },
    ],
    {
      resolveCname: async () => ["example.azurefd.net"],
      resolve4: async () => ["203.0.113.10"],
      resolve6: async () => [],
      reverse: async () => ["server.compute.amazonaws.com"],
    },
  );

  assert.deepEqual(result.addresses, ["203.0.113.10"]);
  assert.deepEqual(result.cnameTargets, ["example.azurefd.net"]);
  assert.deepEqual(result.reverseDns, ["server.compute.amazonaws.com"]);

  const providers = result.providers.map((signal) => signal.provider);
  assert.ok(providers.includes("Cloudflare"));
  assert.ok(providers.includes("AWS / CloudFront"));
  assert.ok(providers.includes("Microsoft Azure"));
  assert.ok(providers.includes("Vercel"));
  assert.match(result.summary, /Passive infrastructure evidence points to/);
});
