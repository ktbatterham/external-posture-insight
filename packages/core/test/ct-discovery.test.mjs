import assert from "node:assert/strict";
import test from "node:test";
import { detectEdgeProvider } from "../dist/ctDiscovery.js";

test("CT sampling preserves CloudFront edge-provider output through the detection pack", () => {
  assert.equal(
    detectEdgeProvider({ "x-amz-cf-id": "cloudfront-request-id" }, ""),
    "AWS WAF / CloudFront",
  );
  assert.equal(
    detectEdgeProvider({ server: "CloudFront" }, ""),
    "AWS WAF / CloudFront",
  );
});

test("CT sampling preserves existing provider precedence over CloudFront", () => {
  assert.equal(
    detectEdgeProvider(
      {
        "cf-ray": "abc-LHR",
        "x-amz-cf-id": "cloudfront-request-id",
      },
      "",
    ),
    "Cloudflare",
  );
});
