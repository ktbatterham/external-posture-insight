import assert from "node:assert/strict";
import { performance } from "node:perf_hooks";
import test from "node:test";
import { evaluateDetectionPacks } from "../dist/detectionPacks/evaluator.js";
import { FIRST_PARTY_DETECTION_PACKS } from "../dist/detectionPacks/edgeProviders.js";
import { detectTechnologies } from "../dist/technology-detection.js";
import { analyzeWafFingerprint } from "../dist/wafFingerprint.js";

test("first-party edge detection pack produces deterministic provider matches", () => {
  const matches = evaluateDetectionPacks(
    {
      headers: {
        "cf-ray": "abc-LHR",
        "x-cache": "HIT, fastly",
        "x-akamai-transformed": "9 123 0 pmb=mRUM,2",
        "x-amz-cf-id": "cloudfront-request-id",
      },
      body: "",
    },
    FIRST_PARTY_DETECTION_PACKS,
  );

  assert.deepEqual(
    matches.map((match) => match.ruleId),
    ["edge.cloudflare", "edge.akamai", "edge.fastly", "edge.aws-cloudfront"],
  );
  assert.deepEqual(
    matches.map((match) => match.provider),
    ["Cloudflare", "Akamai", "Fastly", "AWS CloudFront / WAF"],
  );
});

test("CloudFront pack matches retain internal provenance across infrastructure signals", () => {
  const matches = evaluateDetectionPacks(
    {
      headers: {
        "x-amz-cf-id": "cloudfront-request-id",
        "x-amz-cf-pop": "LHR62-P1",
      },
      body: "",
    },
    FIRST_PARTY_DETECTION_PACKS,
  ).filter((match) => match.provider === "AWS CloudFront / WAF");

  assert.deepEqual(
    matches.map(({ packId, packVersion, ruleId }) => ({ packId, packVersion, ruleId })),
    [
      {
        packId: "securl.first-party.edge-providers",
        packVersion: "1.0.0",
        ruleId: "edge.aws-cloudfront",
      },
      {
        packId: "securl.first-party.edge-providers",
        packVersion: "1.0.0",
        ruleId: "edge.aws-cloudfront-pop",
      },
    ],
  );
  assert.deepEqual(matches[0].outputs.infrastructureWaf, {
    provider: "AWS WAF / CloudFront",
    confidence: "medium",
    evidence: "Observed AWS CloudFront edge headers.",
  });
});

test("bundled detection-pack evaluation stays bounded for repeated CloudFront matches", () => {
  const snapshot = {
    headers: {
      "x-amz-cf-id": "cloudfront-request-id",
      "x-amz-cf-pop": "LHR62-P1",
      server: "CloudFront",
    },
    body: "",
  };
  const startedAt = performance.now();
  for (let index = 0; index < 10_000; index += 1) {
    evaluateDetectionPacks(snapshot, FIRST_PARTY_DETECTION_PACKS);
  }
  const elapsedMs = performance.now() - startedAt;

  assert.ok(elapsedMs < 1_000, `expected 10,000 pack evaluations below 1s, took ${elapsedMs}ms`);
});

test("edge detection pack keeps WAF output equivalent for migrated providers", () => {
  const cloudflare = analyzeWafFingerprint(
    new URL("https://example.com/"),
    { "cf-ray": "abc-LHR" },
    null,
    [],
  );
  const akamai = analyzeWafFingerprint(
    new URL("https://example.com/"),
    {},
    "Reference #18.abc123.akamai",
    [],
  );
  const fastly = analyzeWafFingerprint(
    new URL("https://example.com/"),
    { "x-served-by": "cache-lhr-egll1980023-LHR" },
    null,
    [],
  );
  const cloudfrontHeader = analyzeWafFingerprint(
    new URL("https://example.com/"),
    { "x-amz-cf-id": "cloudfront-request-id" },
    null,
    [],
  );
  const cloudfrontServer = analyzeWafFingerprint(
    new URL("https://example.com/"),
    { server: "CloudFront" },
    null,
    [],
  );

  assert.deepEqual(cloudflare.providers, [
    {
      name: "Cloudflare",
      confidence: "high",
      detection: "observed",
      evidence: "Observed cf-ray / Cloudflare edge headers.",
    },
  ]);
  assert.deepEqual(akamai.providers, [
    {
      name: "Akamai",
      confidence: "high",
      detection: "observed",
      evidence: "Observed Akamai edge headers or block-page signatures.",
    },
  ]);
  assert.deepEqual(fastly.providers, [
    {
      name: "Fastly",
      confidence: "medium",
      detection: "observed",
      evidence: "Observed Fastly cache headers.",
    },
  ]);
  assert.deepEqual(cloudfrontHeader.providers, [
    {
      name: "AWS CloudFront / WAF",
      confidence: "medium",
      detection: "observed",
      evidence: "Observed CloudFront edge headers.",
    },
  ]);
  assert.deepEqual(cloudfrontServer.providers, [
    {
      name: "AWS CloudFront / WAF",
      confidence: "medium",
      detection: "observed",
      evidence: "Observed CloudFront edge headers.",
    },
  ]);
});

test("edge detection pack keeps technology output equivalent for migrated header providers", () => {
  assert.deepEqual(
    detectTechnologies({ "cf-cache-status": "DYNAMIC" }, new URL("https://example.com/")),
    [
      {
        name: "Cloudflare",
        category: "network",
        evidence: "Observed in Cloudflare response headers",
        version: null,
        confidence: "high",
        detection: "observed",
      },
      {
        name: "HTTPS",
        category: "security",
        evidence: "Derived from final URL",
        version: null,
        confidence: "high",
        detection: "observed",
      },
    ],
  );
  assert.deepEqual(
    detectTechnologies({ "x-cache": "HIT, fastly" }, new URL("https://example.com/")),
    [
      {
        name: "Fastly",
        category: "network",
        evidence: "Observed in X-Cache header",
        version: null,
        confidence: "high",
        detection: "observed",
      },
      {
        name: "HTTPS",
        category: "security",
        evidence: "Derived from final URL",
        version: null,
        confidence: "high",
        detection: "observed",
      },
    ],
  );
  assert.deepEqual(
    detectTechnologies({ "x-amz-cf-id": "cloudfront-request-id" }, new URL("https://example.com/")),
    [
      {
        name: "Amazon CloudFront",
        category: "network",
        evidence: "Observed in CloudFront response headers",
        version: null,
        confidence: "high",
        detection: "observed",
      },
      {
        name: "HTTPS",
        category: "security",
        evidence: "Derived from final URL",
        version: null,
        confidence: "high",
        detection: "observed",
      },
    ],
  );
});

test("edge detection pack does not override richer Server-header technology evidence", () => {
  assert.deepEqual(
    detectTechnologies({ server: "cloudflare" }, new URL("https://example.com/")),
    [
      {
        name: "Cloudflare",
        category: "network",
        evidence: "Observed in Server header",
        version: "cloudflare",
        confidence: "high",
        detection: "observed",
      },
      {
        name: "HTTPS",
        category: "security",
        evidence: "Derived from final URL",
        version: null,
        confidence: "high",
        detection: "observed",
      },
    ],
  );
});
