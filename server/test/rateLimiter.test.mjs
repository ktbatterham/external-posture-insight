import assert from "node:assert/strict";
import test from "node:test";
import { createRateLimiter } from "../rateLimiter.mjs";

test("in-memory limiter blocks after threshold and returns retry-after", async () => {
  const limiter = createRateLimiter({
    backend: "in-memory",
    windowMs: 2000,
    maxRequests: 2,
    maxBuckets: 10,
  });

  const one = await limiter.check("198.51.100.1");
  const two = await limiter.check("198.51.100.1");
  const three = await limiter.check("198.51.100.1");

  assert.equal(one.limited, false);
  assert.equal(two.limited, false);
  assert.equal(three.limited, true);
  assert.equal(three.retryAfterSeconds, 2);
});

test("upstash limiter marks request as limited when count exceeds threshold", async () => {
  const originalFetch = globalThis.fetch;
  const originalNow = Date.now;

  try {
    globalThis.fetch = async () => ({
      ok: true,
      async json() {
        return [{ result: 3 }, { result: "OK" }];
      },
    });
    Date.now = () => 1_000_000;

    const limiter = createRateLimiter({
      backend: "upstash",
      windowMs: 60_000,
      maxRequests: 2,
      upstashUrl: "https://example.upstash.io",
      upstashToken: "token",
    });

    const result = await limiter.check("198.51.100.2");
    assert.equal(result.limited, true);
    assert.ok(result.retryAfterSeconds >= 1);
    assert.ok(result.retryAfterSeconds <= 60);
  } finally {
    globalThis.fetch = originalFetch;
    Date.now = originalNow;
  }
});

test("upstash limiter fails open and logs when backend call fails", async () => {
  const originalFetch = globalThis.fetch;

  try {
    const logs = [];
    globalThis.fetch = async () => ({
      ok: false,
      status: 503,
      async json() {
        return {};
      },
    });

    const limiter = createRateLimiter({
      backend: "upstash",
      windowMs: 30_000,
      maxRequests: 1,
      upstashUrl: "https://example.upstash.io",
      upstashToken: "token",
      log: (...args) => logs.push(args),
    });

    const result = await limiter.check("198.51.100.3");
    assert.equal(result.limited, false);
    assert.ok(result.retryAfterSeconds >= 1);
    assert.ok(logs.some((entry) => entry[1] === "rate_limit_backend_error"));
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("upstash limiter fails open for malformed payload", async () => {
  const originalFetch = globalThis.fetch;

  try {
    globalThis.fetch = async () => ({
      ok: true,
      async json() {
        return [{ result: "not-a-number" }];
      },
    });

    const limiter = createRateLimiter({
      backend: "upstash",
      windowMs: 30_000,
      maxRequests: 1,
      upstashUrl: "https://example.upstash.io",
      upstashToken: "token",
      log: () => {},
    });

    const result = await limiter.check("198.51.100.4");
    assert.equal(result.limited, false);
    assert.ok(result.retryAfterSeconds >= 1);
  } finally {
    globalThis.fetch = originalFetch;
  }
});
