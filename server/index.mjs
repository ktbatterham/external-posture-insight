import fs from "node:fs";
import http from "node:http";
import dns from "node:dns/promises";
import net from "node:net";
import path from "node:path";
import { fileURLToPath, URL } from "node:url";
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
const allowInMemoryRateLimitInMultiInstance = process.env.ALLOW_INMEMORY_RATE_LIMITER_IN_MULTI_INSTANCE === "true";
const RATE_LIMIT_WINDOW_MS = 15 * 60 * 1000;
const RATE_LIMIT_MAX_REQUESTS = 30;
const RATE_LIMIT_MAX_BUCKETS = 20000;
const rateLimitBuckets = new Map();

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

function rateLimitExceeded(clientIp) {
  const now = Date.now();
  if (!rateLimitBuckets.has(clientIp) && rateLimitBuckets.size >= RATE_LIMIT_MAX_BUCKETS) {
    sweepRateLimitBuckets();
    if (!rateLimitBuckets.has(clientIp) && rateLimitBuckets.size >= RATE_LIMIT_MAX_BUCKETS) {
      const oldestClient = rateLimitBuckets.keys().next().value;
      if (oldestClient) {
        rateLimitBuckets.delete(oldestClient);
      }
    }
  }
  const current = rateLimitBuckets.get(clientIp) || [];
  const recent = current.filter((timestamp) => now - timestamp < RATE_LIMIT_WINDOW_MS);
  recent.push(now);
  rateLimitBuckets.set(clientIp, recent);
  return recent.length > RATE_LIMIT_MAX_REQUESTS;
}

function sweepRateLimitBuckets() {
  const now = Date.now();
  for (const [clientIp, timestamps] of rateLimitBuckets.entries()) {
    const recent = timestamps.filter((timestamp) => now - timestamp < RATE_LIMIT_WINDOW_MS);
    if (recent.length) {
      rateLimitBuckets.set(clientIp, recent);
    } else {
      rateLimitBuckets.delete(clientIp);
    }
  }
}

setInterval(sweepRateLimitBuckets, RATE_LIMIT_WINDOW_MS).unref();

function sendJson(response, statusCode, payload) {
  response.writeHead(statusCode, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
  });
  response.end(JSON.stringify(payload));
}

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
        backend: "in-memory",
        maxRequests: RATE_LIMIT_MAX_REQUESTS,
        windowMs: RATE_LIMIT_WINDOW_MS,
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
    if (apiKey && getPresentedApiKey(request) !== apiKey) {
      log("warn", "api_key_rejected", {
        clientIp,
        path: requestUrl.pathname,
      });
      sendJson(response, 401, {
        error: "A valid API key is required to analyze targets from this deployment.",
      });
      return;
    }

    if (rateLimitExceeded(clientIp)) {
      log("warn", "rate_limit_exceeded", {
        clientIp,
        path: requestUrl.pathname,
      });
      sendJson(response, 429, {
        error: "Too many analysis requests from this client. Please try again later.",
      });
      return;
    }

    try {
      const target = requestUrl.searchParams.get("url") || "";
      const validatedTarget = await assertPublicHttpUrl(target);
      log("info", "analysis_requested", {
        clientIp,
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

if (isProduction && deploymentMode === "multi-instance" && !allowInMemoryRateLimitInMultiInstance) {
  log("error", "server_start_blocked", {
    reason: "DEPLOYMENT_MODE=multi-instance requires a distributed limiter. In-memory limiter is blocked by default.",
    overrideEnv: "ALLOW_INMEMORY_RATE_LIMITER_IN_MULTI_INSTANCE=true",
  });
  process.exit(1);
}

if (isProduction && deploymentMode === "multi-instance" && allowInMemoryRateLimitInMultiInstance) {
  log("warn", "multi_instance_inmemory_limiter_override", {
    message: "In-memory rate limiting override is enabled in multi-instance mode. This is not safe for sustained public traffic.",
  });
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
    rateLimitBackend: "in-memory",
  });
});
