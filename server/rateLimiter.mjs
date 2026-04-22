const DEFAULT_PREFIX = "epi:rate-limit";

function createInMemoryRateLimiter({ windowMs, maxRequests, maxBuckets = 20000 }) {
  const buckets = new Map();

  const sweep = () => {
    const now = Date.now();
    for (const [clientId, timestamps] of buckets.entries()) {
      const recent = timestamps.filter((timestamp) => now - timestamp < windowMs);
      if (recent.length) {
        buckets.set(clientId, recent);
      } else {
        buckets.delete(clientId);
      }
    }
  };

  setInterval(sweep, windowMs).unref();

  return {
    backend: "in-memory",
    distributed: false,
    async check(clientId) {
      const now = Date.now();
      if (!buckets.has(clientId) && buckets.size >= maxBuckets) {
        sweep();
        if (!buckets.has(clientId) && buckets.size >= maxBuckets) {
          const oldestClient = buckets.keys().next().value;
          if (oldestClient) {
            buckets.delete(oldestClient);
          }
        }
      }

      const current = buckets.get(clientId) || [];
      const recent = current.filter((timestamp) => now - timestamp < windowMs);
      recent.push(now);
      buckets.set(clientId, recent);
      return {
        limited: recent.length > maxRequests,
        retryAfterSeconds: Math.max(1, Math.ceil(windowMs / 1000)),
      };
    },
  };
}

function createUpstashRateLimiter({ windowMs, maxRequests, upstashUrl, upstashToken, prefix = DEFAULT_PREFIX, log }) {
  const normalizedBaseUrl = upstashUrl.replace(/\/+$/, "");

  return {
    backend: "upstash",
    distributed: true,
    async check(clientId) {
      const now = Date.now();
      const bucketStart = Math.floor(now / windowMs) * windowMs;
      const key = `${prefix}:${bucketStart}:${clientId}`;
      const bucketEnd = bucketStart + windowMs;
      const retryAfterSeconds = Math.max(1, Math.ceil((bucketEnd - now) / 1000));

      try {
        const response = await fetch(`${normalizedBaseUrl}/pipeline`, {
          method: "POST",
          headers: {
            Authorization: `Bearer ${upstashToken}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify([
            ["INCR", key],
            ["PEXPIRE", key, String(windowMs), "NX"],
          ]),
        });

        if (!response.ok) {
          throw new Error(`Upstash pipeline request failed with status ${response.status}.`);
        }

        const payload = await response.json();
        const count = Number(payload?.[0]?.result);
        if (!Number.isFinite(count)) {
          throw new Error("Unexpected Upstash pipeline response shape.");
        }

        return {
          limited: count > maxRequests,
          retryAfterSeconds,
        };
      } catch (error) {
        if (typeof log === "function") {
          log("error", "rate_limit_backend_error", {
            backend: "upstash",
            message: error instanceof Error ? error.message : String(error),
          });
        }

        // Fail open to preserve API availability if the limiter backend is briefly unavailable.
        return {
          limited: false,
          retryAfterSeconds,
        };
      }
    },
  };
}

export function createRateLimiter(options) {
  const {
    backend,
    windowMs,
    maxRequests,
    maxBuckets,
    upstashUrl,
    upstashToken,
    prefix,
    log,
  } = options;

  if (backend === "upstash") {
    return createUpstashRateLimiter({
      windowMs,
      maxRequests,
      upstashUrl,
      upstashToken,
      prefix,
      log,
    });
  }

  return createInMemoryRateLimiter({
    windowMs,
    maxRequests,
    maxBuckets,
  });
}
