import fs from "node:fs";
import http from "node:http";
import dns from "node:dns/promises";
import net from "node:net";
import path from "node:path";
import { fileURLToPath, URL } from "node:url";
import { analyzeUrl, formatErrorMessage } from "../packages/core/dist/index.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, "..");
const distDir = path.join(projectRoot, "dist");
const publicDir = path.join(projectRoot, "public");
const port = Number(process.env.PORT || 8787);
const RATE_LIMIT_WINDOW_MS = 15 * 60 * 1000;
const RATE_LIMIT_MAX_REQUESTS = 30;
const rateLimitBuckets = new Map();

function getClientIp(request) {
  const forwarded = request.headers["x-forwarded-for"];
  const candidate = Array.isArray(forwarded) ? forwarded[0] : forwarded;
  if (typeof candidate === "string" && candidate.trim()) {
    return candidate.split(",")[0].trim();
  }

  const remoteAddress = request.socket.remoteAddress || "";
  return remoteAddress.startsWith("::ffff:") ? remoteAddress.slice(7) : remoteAddress;
}

function isPrivateIpv4(ip) {
  const octets = ip.split(".").map((part) => Number(part));
  if (octets.length !== 4 || octets.some((value) => Number.isNaN(value))) {
    return true;
  }

  return (
    octets[0] === 10 ||
    octets[0] === 127 ||
    (octets[0] === 169 && octets[1] === 254) ||
    (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) ||
    (octets[0] === 192 && octets[1] === 168) ||
    (octets[0] === 100 && octets[1] >= 64 && octets[1] <= 127) ||
    octets[0] === 0
  );
}

function isPrivateIpv6(ip) {
  const normalized = ip.toLowerCase();
  return (
    normalized === "::1" ||
    normalized === "::" ||
    normalized.startsWith("fc") ||
    normalized.startsWith("fd") ||
    normalized.startsWith("fe80:") ||
    normalized.startsWith("fec0:")
  );
}

function isPublicIp(ip) {
  const family = net.isIP(ip);
  if (family === 4) {
    return !isPrivateIpv4(ip);
  }
  if (family === 6) {
    return !isPrivateIpv6(ip);
  }
  return false;
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

  const hostname = targetUrl.hostname.toLowerCase();
  if (hostname === "localhost" || hostname.endsWith(".localhost")) {
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

function rateLimitExceeded(clientIp) {
  const now = Date.now();
  const current = rateLimitBuckets.get(clientIp) || [];
  const recent = current.filter((timestamp) => now - timestamp < RATE_LIMIT_WINDOW_MS);
  recent.push(now);
  rateLimitBuckets.set(clientIp, recent);
  return recent.length > RATE_LIMIT_MAX_REQUESTS;
}

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

function serveStatic(requestPath, method, response) {
  const cleanPath = requestPath === "/" ? "/index.html" : requestPath;
  const staticTarget = path.join(distDir, cleanPath);
  const publicTarget = path.join(publicDir, cleanPath);
  const fallbackTarget = path.join(distDir, "index.html");
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

  response.writeHead(200, {
    "Content-Type": getMimeType(preferredPath),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": "default-src 'self'; img-src 'self' data: blob: https:; style-src 'self' 'unsafe-inline'; script-src 'self'; font-src 'self' data:; connect-src 'self' http://127.0.0.1:8787 http://localhost:8787;",
  });
  if (method === "HEAD") {
    response.end();
    return;
  }
  fs.createReadStream(preferredPath).pipe(response);
}

const server = http.createServer(async (request, response) => {
  const requestUrl = new URL(request.url || "/", `http://${request.headers.host}`);

  if (requestUrl.pathname === "/api/health") {
    sendJson(response, 200, { ok: true, now: new Date().toISOString() });
    return;
  }

  if (requestUrl.pathname === "/api/analyze") {
    const clientIp = getClientIp(request) || "unknown";
    if (rateLimitExceeded(clientIp)) {
      sendJson(response, 429, {
        error: "Too many analysis requests from this client. Please try again later.",
      });
      return;
    }

    try {
      const target = requestUrl.searchParams.get("url") || "";
      const validatedTarget = await assertPublicHttpUrl(target);
      const result = await analyzeUrl(validatedTarget.toString());
      sendJson(response, 200, result);
    } catch (error) {
      console.error("Analyze request failed", {
        message: formatErrorMessage(error),
        target: requestUrl.searchParams.get("url") || "",
      });
      sendJson(response, 400, {
        error: "Unable to analyze that target. Please check the URL and try again.",
      });
    }
    return;
  }

  if (request.method === "GET" || request.method === "HEAD") {
    serveStatic(requestUrl.pathname, request.method, response);
    return;
  }

  response.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
  response.end("Not found");
});

server.listen(port, () => {
  console.log(`Secure Header Insight API listening on http://127.0.0.1:${port}`);
});
