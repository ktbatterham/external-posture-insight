import fs from "node:fs";
import http from "node:http";
import dns from "node:dns/promises";
import net from "node:net";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath, URL } from "node:url";
import { createRateLimiter } from "./rateLimiter.mjs";
import {
  analyzeUrl,
  formatErrorMessage,
  isPrivateAddress,
  isLocalHostname,
} from "../packages/core/dist/index.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, "..");
const distDir = path.join(projectRoot, "dist");
const publicDir = path.join(projectRoot, "public");
const port = Number(process.env.PORT || 8787);
const isProduction = process.env.NODE_ENV === "production";
const apiKey = process.env.API_KEY || "";
const allowUnauthenticated = process.env.ALLOW_UNAUTHENTICATED === "true";
const trustProxy = process.env.TRUST_PROXY === "true";
const deploymentMode = process.env.DEPLOYMENT_MODE === "multi-instance" ? "multi-instance" : "single-instance";
const DEFAULT_RATE_LIMIT_WINDOW_MS = 15 * 60 * 1000;
const DEFAULT_RATE_LIMIT_MAX_REQUESTS = 30;
const DEFAULT_TARGET_RATE_LIMIT_WINDOW_MS = 15 * 60 * 1000;
const DEFAULT_TARGET_RATE_LIMIT_MAX_REQUESTS = 10;
const DEFAULT_ABUSE_ALERT_WINDOW_MS = 10 * 60 * 1000;
const DEFAULT_ABUSE_ALERT_THRESHOLD = 25;
const RATE_LIMIT_MAX_BUCKETS = 20000;
const configuredRateLimitBackend = (process.env.RATE_LIMIT_BACKEND || "").trim().toLowerCase();
const rateLimitBackend = configuredRateLimitBackend || (deploymentMode === "multi-instance" ? "upstash" : "in-memory");
const RATE_LIMIT_WINDOW_MS = (() => {
  const raw = Number(process.env.RATE_LIMIT_WINDOW_MS || DEFAULT_RATE_LIMIT_WINDOW_MS);
  if (!Number.isFinite(raw) || raw < 1000) {
    return DEFAULT_RATE_LIMIT_WINDOW_MS;
  }
  return Math.floor(raw);
})();
const RATE_LIMIT_MAX_REQUESTS = (() => {
  const raw = Number(process.env.RATE_LIMIT_MAX_REQUESTS || DEFAULT_RATE_LIMIT_MAX_REQUESTS);
  if (!Number.isFinite(raw) || raw < 1) {
    return DEFAULT_RATE_LIMIT_MAX_REQUESTS;
  }
  return Math.floor(raw);
})();
const TARGET_RATE_LIMIT_WINDOW_MS = (() => {
  const raw = Number(process.env.TARGET_RATE_LIMIT_WINDOW_MS || DEFAULT_TARGET_RATE_LIMIT_WINDOW_MS);
  if (!Number.isFinite(raw) || raw < 1000) {
    return DEFAULT_TARGET_RATE_LIMIT_WINDOW_MS;
  }
  return Math.floor(raw);
})();
const TARGET_RATE_LIMIT_MAX_REQUESTS = (() => {
  const raw = Number(process.env.TARGET_RATE_LIMIT_MAX_REQUESTS || DEFAULT_TARGET_RATE_LIMIT_MAX_REQUESTS);
  if (!Number.isFinite(raw) || raw < 1) {
    return DEFAULT_TARGET_RATE_LIMIT_MAX_REQUESTS;
  }
  return Math.floor(raw);
})();
const API_KEY_FINGERPRINT_SALT = process.env.API_KEY_FINGERPRINT_SALT || "epi-api-key-fingerprint-v1";
const ABUSE_ALERT_WINDOW_MS = (() => {
  const raw = Number(process.env.ABUSE_ALERT_WINDOW_MS || DEFAULT_ABUSE_ALERT_WINDOW_MS);
  if (!Number.isFinite(raw) || raw < 1000) {
    return DEFAULT_ABUSE_ALERT_WINDOW_MS;
  }
  return Math.floor(raw);
})();
const ABUSE_ALERT_THRESHOLD = (() => {
  const raw = Number(process.env.ABUSE_ALERT_THRESHOLD || DEFAULT_ABUSE_ALERT_THRESHOLD);
  if (!Number.isFinite(raw) || raw < 1) {
    return DEFAULT_ABUSE_ALERT_THRESHOLD;
  }
  return Math.floor(raw);
})();
const upstashRestUrl = (process.env.UPSTASH_REDIS_REST_URL || "").trim();
const upstashRestToken = (process.env.UPSTASH_REDIS_REST_TOKEN || "").trim();
const abuseSignalBuckets = new Map();

const log = (level, event, details = {}) => {
  const payload = {
    level,
    event,
    time: new Date().toISOString(),
    ...details,
  };

  const line = JSON.stringify(payload);
  if (level === "error" || level === "warn") {
    console.error(line);
    return;
  }
  console.log(line);
};

function getClientIp(request) {
  if (trustProxy && shouldTrustForwardedHeaders(request)) {
    const forwarded = request.headers["x-forwarded-for"];
    const candidate = Array.isArray(forwarded) ? forwarded[0] : forwarded;
    if (typeof candidate === "string" && candidate.trim()) {
      return candidate.split(",")[0].trim();
    }
  }

  const remoteAddress = request.socket.remoteAddress || "";
  return remoteAddress.startsWith("::ffff:") ? remoteAddress.slice(7) : remoteAddress;
}

function shouldTrustForwardedHeaders(request) {
  const remoteAddress = request.socket.remoteAddress || "";
  const normalized = remoteAddress.startsWith("::ffff:") ? remoteAddress.slice(7) : remoteAddress;
  if (!normalized) {
    return false;
  }

  if (isLocalHostname(normalized)) {
    return true;
  }

  if (net.isIP(normalized)) {
    return !isPublicIp(normalized);
  }

  return false;
}

function isPublicIp(ip) {
  return net.isIP(ip) !== 0 && !isPrivateAddress(ip);
}

async function assertPublicHttpUrl(rawTarget) {
  if (!rawTarget.trim()) {
    throw new Error("Enter a URL to scan.");
  }

  const normalizedTarget = /^https?:\/\//i.test(rawTarget) ? rawTarget : `https://${rawTarget}`;
  const targetUrl = new URL(normalizedTarget);

  if (!["http:", "https:"].includes(targetUrl.protocol)) {
    throw new Error("Only http and https URLs are supported.");
  }

  if (targetUrl.username || targetUrl.password) {
    throw new Error("URLs with embedded credentials are not supported.");
  }

  const hostname = targetUrl.hostname.toLowerCase();
  if (isLocalHostname(hostname)) {
    throw new Error("Localhost and private network targets are not allowed.");
  }

  if (net.isIP(hostname)) {
    if (!isPublicIp(hostname)) {
      throw new Error("Private or local network targets are not allowed.");
    }
    return targetUrl;
  }

  const records = await dns.lookup(hostname, { all: true });
  if (!records.length || records.some((record) => !isPublicIp(record.address))) {
    throw new Error("Target must resolve to a public IP address.");
  }

  return targetUrl;
}

function getPresentedApiKey(request) {
  const candidate = request.headers["x-api-key"];
  if (Array.isArray(candidate)) {
    return candidate[0] || "";
  }
  return typeof candidate === "string" ? candidate : "";
}

function tokenFingerprint(token) {
  return crypto.pbkdf2Sync(token, API_KEY_FINGERPRINT_SALT, 120000, 12, "sha256").toString("hex");
}

function getRequesterScope(clientIp, presentedApiKey) {
  if (apiKey && presentedApiKey) {
    return `api-key:${tokenFingerprint(presentedApiKey)}`;
  }
  return `ip:${clientIp || "unknown"}`;
}

function parseTargetHostForQuota(rawTarget) {
  if (!rawTarget.trim()) {
    return null;
  }

  try {
    const normalized = /^https?:\/\//i.test(rawTarget) ? rawTarget : `https://${rawTarget}`;
    const parsed = new URL(normalized);
    if (!["http:", "https:"].includes(parsed.protocol)) {
      return null;
    }
    return parsed.hostname.toLowerCase();
  } catch {
    return null;
  }
}

function recordAbuseSignal(signalType, details = {}) {
  const now = Date.now();
  const current = abuseSignalBuckets.get(signalType) || [];
  const recent = current.filter((timestamp) => now - timestamp < ABUSE_ALERT_WINDOW_MS);
  recent.push(now);
  abuseSignalBuckets.set(signalType, recent);

  log("warn", signalType, details);

  if (
    recent.length === ABUSE_ALERT_THRESHOLD
    || (recent.length > ABUSE_ALERT_THRESHOLD && recent.length % ABUSE_ALERT_THRESHOLD === 0)
  ) {
    log("error", "abuse_alert_threshold_reached", {
      signalType,
      count: recent.length,
      threshold: ABUSE_ALERT_THRESHOLD,
      windowMs: ABUSE_ALERT_WINDOW_MS,
    });
  }
}

function sendJson(response, statusCode, payload) {
  response.writeHead(statusCode, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
  });
  response.end(JSON.stringify(payload));
}

function sendRateLimited(response, retryAfterSeconds, message = "Too many analysis requests from this client. Please try again later.") {
  response.writeHead(429, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "Retry-After": String(retryAfterSeconds),
  });
  response.end(JSON.stringify({
    error: message,
  }));
}

const rateLimiter = createRateLimiter({
  backend: rateLimitBackend,
  windowMs: RATE_LIMIT_WINDOW_MS,
  maxRequests: RATE_LIMIT_MAX_REQUESTS,
  maxBuckets: RATE_LIMIT_MAX_BUCKETS,
  upstashUrl: upstashRestUrl,
  upstashToken: upstashRestToken,
  prefix: "epi:rate-limit:requester",
  log,
});

const targetRateLimiter = createRateLimiter({
  backend: rateLimitBackend,
  windowMs: TARGET_RATE_LIMIT_WINDOW_MS,
  maxRequests: TARGET_RATE_LIMIT_MAX_REQUESTS,
  maxBuckets: RATE_LIMIT_MAX_BUCKETS,
  upstashUrl: upstashRestUrl,
  upstashToken: upstashRestToken,
  prefix: "epi:rate-limit:target",
  log,
});

function getMimeType(filePath) {
  const ext = path.extname(filePath);
  switch (ext) {
    case ".html":
      return "text/html; charset=utf-8";
    case ".js":
      return "application/javascript; charset=utf-8";
    case ".css":
      return "text/css; charset=utf-8";
    case ".json":
      return "application/json; charset=utf-8";
    case ".svg":
      return "image/svg+xml";
    case ".png":
      return "image/png";
    case ".ico":
      return "image/x-icon";
    default:
      return "application/octet-stream";
  }
}

function resolveStaticPath(baseDir, requestPath) {
  const trimmed = requestPath.replace(/^\/+/, "");
  const decoded = (() => {
    try {
      return decodeURIComponent(trimmed);
    } catch {
      return trimmed;
    }
  })();
  const normalizedRequest = path.normalize(decoded || "index.html");
  if (normalizedRequest.startsWith("..") || path.isAbsolute(normalizedRequest)) {
    return null;
  }

  const resolved = path.resolve(baseDir, normalizedRequest);
  const baseWithSep = baseDir.endsWith(path.sep) ? baseDir : `${baseDir}${path.sep}`;
  if (resolved !== baseDir && !resolved.startsWith(baseWithSep)) {
    return null;
  }

  return resolved;
}

function serveStatic(requestPath, method, response) {
  const cleanPath = requestPath === "/" ? "/index.html" : requestPath;
  const staticTarget = resolveStaticPath(distDir, cleanPath);
  const publicTarget = resolveStaticPath(publicDir, cleanPath);
  const fallbackTarget = path.join(distDir, "index.html");

  if (!staticTarget || !publicTarget) {
    response.writeHead(400, { "Content-Type": "text/plain; charset=utf-8" });
    response.end("Invalid request path.");
    return;
  }

  const preferredPath = fs.existsSync(staticTarget)
    ? staticTarget
    : fs.existsSync(publicTarget)
      ? publicTarget
      : fs.existsSync(fallbackTarget)
        ? fallbackTarget
        : null;

  if (!preferredPath) {
    response.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
    response.end("Frontend build not found. Run `npm run build` for a production preview.");
    return;
  }

  const connectSources = ["'self'"];
  if (!isProduction) {
    connectSources.push("http://127.0.0.1:8787", "http://localhost:8787");
  }

  response.writeHead(200, {
    "Content-Type": getMimeType(preferredPath),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": `default-src 'self'; img-src 'self' data: blob: https:; style-src 'self' 'unsafe-inline'; script-src 'self'; font-src 'self' data:; connect-src ${connectSources.join(" ")};`,
  });
  if (method === "HEAD") {
    response.end();
    return;
  }
  fs.createReadStream(preferredPath).pipe(response);
}

const server = http.createServer(async (request, response) => {
  const rawRequestPath = (request.url || "/").split("?")[0] || "/";
  const requestUrl = new URL(request.url || "/", `http://${request.headers.host}`);

  if (requestUrl.pathname === "/api/health") {
    sendJson(response, 200, {
      ok: true,
      now: new Date().toISOString(),
      deploymentMode,
      rateLimit: {
        backend: targetRateLimiter.backend,
        distributed: targetRateLimiter.distributed,
        requester: {
          maxRequests: RATE_LIMIT_MAX_REQUESTS,
          windowMs: RATE_LIMIT_WINDOW_MS,
        },
        target: {
          maxRequests: TARGET_RATE_LIMIT_MAX_REQUESTS,
          windowMs: TARGET_RATE_LIMIT_WINDOW_MS,
        },
      },
      abuseAlerting: {
        threshold: ABUSE_ALERT_THRESHOLD,
        windowMs: ABUSE_ALERT_WINDOW_MS,
      },
    });
    return;
  }

  if (requestUrl.pathname === "/api/analyze") {
    if (request.method !== "GET" && request.method !== "HEAD") {
      response.writeHead(405, {
        "Content-Type": "application/json; charset=utf-8",
        "Allow": "GET, HEAD",
      });
      response.end(JSON.stringify({ error: "Method not allowed. Use GET or HEAD." }));
      return;
    }

    const clientIp = getClientIp(request) || "unknown";
    const presentedApiKey = getPresentedApiKey(request);
    const requesterScope = getRequesterScope(clientIp, presentedApiKey);
    if (apiKey && presentedApiKey !== apiKey) {
      recordAbuseSignal("api_key_rejected", {
        clientIp,
        path: requestUrl.pathname,
      });
      sendJson(response, 401, {
        error: "A valid API key is required to analyze targets from this deployment.",
      });
      return;
    }

    const rateLimitState = await rateLimiter.check(requesterScope);
    if (rateLimitState.limited) {
      recordAbuseSignal("rate_limit_exceeded", {
        clientIp,
        requesterScope,
        path: requestUrl.pathname,
      });
      sendRateLimited(response, rateLimitState.retryAfterSeconds);
      return;
    }

    try {
      const target = requestUrl.searchParams.get("url") || "";
      const targetHost = parseTargetHostForQuota(target);
      if (targetHost) {
        const targetScope = `${requesterScope}:${targetHost}`;
        const targetRateLimitState = await targetRateLimiter.check(targetScope);
        if (targetRateLimitState.limited) {
          recordAbuseSignal("target_quota_exceeded", {
            clientIp,
            requesterScope,
            targetHost,
            path: requestUrl.pathname,
          });
          sendRateLimited(
            response,
            targetRateLimitState.retryAfterSeconds,
            "Too many analysis requests for this target from this client. Please try again later.",
          );
          return;
        }
      }

      const validatedTarget = await assertPublicHttpUrl(target);
      log("info", "analysis_requested", {
        clientIp,
        requesterScope,
        target: validatedTarget.toString(),
      });
      const result = await analyzeUrl(validatedTarget.toString());
      sendJson(response, 200, result);
    } catch (error) {
      log("warn", "analysis_failed", {
        message: formatErrorMessage(error),
        clientIp,
        target: requestUrl.searchParams.get("url") || "",
      });
      sendJson(response, 400, {
        error: "Unable to analyze that target. Please check the URL and try again.",
      });
    }
    return;
  }

  if (request.method === "GET" || request.method === "HEAD") {
    serveStatic(rawRequestPath, request.method, response);
    return;
  }

  response.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
  response.end("Not found");
});

if (!apiKey) {
  if (isProduction && !allowUnauthenticated) {
    log("error", "server_start_blocked", {
      reason: "API_KEY missing and ALLOW_UNAUTHENTICATED was not explicitly enabled.",
    });
    process.exit(1);
  }

  log("warn", "unauthenticated_mode", {
    production: isProduction,
    explicitOptIn: allowUnauthenticated,
  });
}

if (trustProxy) {
  log("warn", "trusted_proxy_mode", {
    message: "TRUST_PROXY is enabled; forwarded client IP attribution is only accepted when the direct peer is private/local.",
  });
}

if (isProduction && deploymentMode === "multi-instance" && rateLimiter.backend !== "upstash") {
  log("error", "server_start_blocked", {
    reason: "DEPLOYMENT_MODE=multi-instance requires RATE_LIMIT_BACKEND=upstash.",
  });
  process.exit(1);
}

if (rateLimiter.backend !== targetRateLimiter.backend) {
  log("error", "server_start_blocked", {
    reason: "Requester and target rate limiter backends must match.",
  });
  process.exit(1);
}

if (
  (rateLimiter.backend === "upstash" || targetRateLimiter.backend === "upstash")
  && (!upstashRestUrl || !upstashRestToken)
) {
  log("error", "server_start_blocked", {
    reason: "RATE_LIMIT_BACKEND=upstash requires UPSTASH_REDIS_REST_URL and UPSTASH_REDIS_REST_TOKEN.",
  });
  process.exit(1);
}

server.listen(port, () => {
  log("info", "server_started", {
    port,
    url: `http://127.0.0.1:${port}`,
    production: isProduction,
    authenticated: Boolean(apiKey),
    allowUnauthenticated,
    trustProxy,
    deploymentMode,
    rateLimitBackend: targetRateLimiter.backend,
    distributedRateLimit: targetRateLimiter.distributed,
    requesterRateLimit: {
      maxRequests: RATE_LIMIT_MAX_REQUESTS,
      windowMs: RATE_LIMIT_WINDOW_MS,
    },
    targetRateLimit: {
      maxRequests: TARGET_RATE_LIMIT_MAX_REQUESTS,
      windowMs: TARGET_RATE_LIMIT_WINDOW_MS,
    },
    abuseAlerting: {
      threshold: ABUSE_ALERT_THRESHOLD,
      windowMs: ABUSE_ALERT_WINDOW_MS,
    },
  });
});
