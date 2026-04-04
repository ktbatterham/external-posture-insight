import fs from "node:fs";
import http from "node:http";
import https from "node:https";
import dns from "node:dns/promises";
import path from "node:path";
import tls from "node:tls";
import { URL, fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, "..");
const distDir = path.join(projectRoot, "dist");
const publicDir = path.join(projectRoot, "public");
const port = Number(process.env.PORT || 8787);

const SECURITY_HEADERS = [
  {
    key: "strict-transport-security",
    label: "Strict-Transport-Security",
    description: "Forces browsers to keep using HTTPS after the first secure visit.",
    recommendation: "Set HSTS with at least 6 months max-age and includeSubDomains.",
  },
  {
    key: "content-security-policy",
    label: "Content-Security-Policy",
    description: "Reduces XSS and data injection risk by controlling allowed resource sources.",
    recommendation: "Add a CSP and avoid unsafe-inline / unsafe-eval where possible.",
  },
  {
    key: "x-frame-options",
    label: "X-Frame-Options",
    description: "Helps prevent clickjacking in framed pages.",
    recommendation: "Use DENY or SAMEORIGIN unless framing is intentionally required.",
  },
  {
    key: "x-content-type-options",
    label: "X-Content-Type-Options",
    description: "Stops MIME sniffing for mismatched content types.",
    recommendation: "Set X-Content-Type-Options to nosniff.",
  },
  {
    key: "referrer-policy",
    label: "Referrer-Policy",
    description: "Limits how much referral data leaves the site.",
    recommendation: "Use strict-origin-when-cross-origin or stricter.",
  },
  {
    key: "permissions-policy",
    label: "Permissions-Policy",
    description: "Restricts browser features such as camera and microphone access.",
    recommendation: "Disable unneeded browser capabilities with Permissions-Policy.",
  },
  {
    key: "cross-origin-opener-policy",
    label: "Cross-Origin-Opener-Policy",
    description: "Improves browsing context isolation against cross-window attacks.",
    recommendation: "Set COOP to same-origin for stronger isolation where compatible.",
  },
  {
    key: "cross-origin-resource-policy",
    label: "Cross-Origin-Resource-Policy",
    description: "Protects resources from being loaded by unintended origins.",
    recommendation: "Set CORP to same-origin or same-site when appropriate.",
  },
];

const REMEDIATION_TARGETS = {
  "strict-transport-security": "max-age=31536000; includeSubDomains; preload",
  "content-security-policy": "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'; upgrade-insecure-requests",
  "x-frame-options": "SAMEORIGIN",
  "x-content-type-options": "nosniff",
  "referrer-policy": "strict-origin-when-cross-origin",
  "permissions-policy": "camera=(), microphone=(), geolocation=(), browsing-topics=()",
  "cross-origin-opener-policy": "same-origin",
  "cross-origin-resource-policy": "same-origin",
};

const CRAWL_CANDIDATES = [
  { label: "Homepage", path: "/" },
  { label: "Login", path: "/login" },
  { label: "App", path: "/app" },
  { label: "Dashboard", path: "/dashboard" },
  { label: "Admin", path: "/admin" },
  { label: "API root", path: "/api" },
];

const EXPOSURE_PROBES = [
  { label: "Robots", path: "/robots.txt" },
  { label: "Sitemap", path: "/sitemap.xml" },
  { label: "Git metadata", path: "/.git/HEAD" },
  { label: "Environment file", path: "/.env" },
];

const API_SURFACE_PROBES = [
  { label: "API root", path: "/api" },
  { label: "GraphQL", path: "/graphql" },
  { label: "Versioned API", path: "/api/v1" },
];

const PAGE_PATH_PRIORITY_PATTERNS = [
  /\/login/i,
  /\/account/i,
  /\/dashboard/i,
  /\/admin/i,
  /\/app/i,
  /\/portal/i,
  /\/signin/i,
  /\/auth/i,
  /\/support/i,
  /\/contact/i,
  /\/security/i,
];

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

  response.writeHead(200, { "Content-Type": getMimeType(preferredPath) });
  if (method === "HEAD") {
    response.end();
    return;
  }
  fs.createReadStream(preferredPath).pipe(response);
}

function normalizeUrl(input) {
  let candidate = input.trim();
  if (!candidate) {
    throw new Error("Enter a URL to scan.");
  }

  if (!/^https?:\/\//i.test(candidate)) {
    candidate = `https://${candidate}`;
  }

  const normalized = new URL(candidate);
  if (!["http:", "https:"].includes(normalized.protocol)) {
    throw new Error("Only http and https URLs are supported.");
  }

  return normalized;
}

function headerValue(headers, name) {
  const value = headers[name];
  if (Array.isArray(value)) {
    return value.join(", ");
  }
  return value ?? null;
}

function parseSetCookie(setCookieHeaders) {
  return (setCookieHeaders || []).map((cookieLine) => {
    const parts = cookieLine.split(";").map((item) => item.trim());
    const [nameValue, ...attributes] = parts;
    const [rawName, ...rawValue] = nameValue.split("=");
    const attributeMap = Object.fromEntries(
      attributes.map((attribute) => {
        const [key, ...value] = attribute.split("=");
        return [key.toLowerCase(), value.join("=") || true];
      }),
    );

    const sameSiteValue = typeof attributeMap.samesite === "string"
      ? attributeMap.samesite
      : null;
    const sameSite = sameSiteValue
      ? sameSiteValue.charAt(0).toUpperCase() + sameSiteValue.slice(1).toLowerCase()
      : null;

    const issues = [];
    if (!attributeMap.secure) {
      issues.push("Missing Secure flag");
    }
    if (!attributeMap.httponly) {
      issues.push("Missing HttpOnly flag");
    }
    if (!sameSite) {
      issues.push("Missing SameSite attribute");
    } else if (sameSite === "None" && !attributeMap.secure) {
      issues.push("SameSite=None should be paired with Secure");
    }

    return {
      name: rawName,
      valuePreview: rawValue.join("="),
      secure: Boolean(attributeMap.secure),
      httpOnly: Boolean(attributeMap.httponly),
      sameSite,
      domain: typeof attributeMap.domain === "string" ? attributeMap.domain : null,
      path: typeof attributeMap.path === "string" ? attributeMap.path : null,
      expires: typeof attributeMap.expires === "string" ? attributeMap.expires : null,
      maxAge: typeof attributeMap["max-age"] === "string" ? attributeMap["max-age"] : null,
      issues,
      risk: issues.length >= 2 ? "high" : issues.length === 1 ? "medium" : "low",
    };
  });
}

function detectTechnologies(headers, finalUrl) {
  const technologies = [];
  const seen = new Set();

  const addTechnology = (name, category, evidence, version) => {
    const key = `${name}:${category}`;
    if (seen.has(key)) {
      return;
    }
    seen.add(key);
    technologies.push({ name, category, evidence, version: version || null });
  };

  const server = headerValue(headers, "server");
  const poweredBy = headerValue(headers, "x-powered-by");
  const cache = headerValue(headers, "cf-cache-status");

  if (server) {
    const serverLower = server.toLowerCase();
    if (serverLower.includes("cloudflare")) {
      addTechnology("Cloudflare", "network", "Detected from Server header", server);
    } else if (serverLower.includes("sucuri")) {
      addTechnology("Sucuri", "network", "Detected from Server header", server);
    } else if (serverLower.includes("akamai")) {
      addTechnology("Akamai", "network", "Detected from Server header", server);
    } else if (serverLower.includes("fastly")) {
      addTechnology("Fastly", "network", "Detected from Server header", server);
    } else if (serverLower.includes("nginx")) {
      addTechnology("Nginx", "server", "Detected from Server header", server);
    } else if (serverLower.includes("apache")) {
      addTechnology("Apache", "server", "Detected from Server header", server);
    } else if (serverLower.includes("caddy")) {
      addTechnology("Caddy", "server", "Detected from Server header", server);
    } else {
      addTechnology(server, "server", "Reported by Server header");
    }
  }

  if (poweredBy) {
    addTechnology(poweredBy, "frontend", "Detected from X-Powered-By header");
    const poweredByLower = poweredBy.toLowerCase();
    if (poweredByLower.includes("express")) {
      addTechnology("Express", "frontend", "Detected from X-Powered-By header");
    }
    if (poweredByLower.includes("next")) {
      addTechnology("Next.js", "frontend", "Detected from X-Powered-By header");
    }
  }

  if (headerValue(headers, "x-vercel-id")) {
    addTechnology("Vercel", "hosting", "Detected from X-Vercel-Id header");
  }
  if (headerValue(headers, "cf-ray") || cache) {
    addTechnology("Cloudflare", "network", "Detected from Cloudflare response headers");
  }
  if (headerValue(headers, "x-sucuri-id") || headerValue(headers, "x-sucuri-cache")) {
    addTechnology("Sucuri", "network", "Detected from Sucuri edge headers");
  }
  if (headerValue(headers, "x-akamai-transformed") || headerValue(headers, "akamai-cache-status")) {
    addTechnology("Akamai", "network", "Detected from Akamai response headers");
  }
  if (headerValue(headers, "x-served-by")?.toLowerCase().includes("cache-")) {
    addTechnology("Fastly", "network", "Detected from X-Served-By cache headers");
  }
  if (headerValue(headers, "server-timing")?.toLowerCase().includes("cdn-cache")) {
    addTechnology("CDN", "network", "Detected from Server-Timing header");
  }

  addTechnology(finalUrl.protocol === "https:" ? "HTTPS" : "HTTP", "security", "Derived from final URL");
  return technologies;
}

function analyzeHeaders(headers, isHttps) {
  const results = [];
  const issues = [];
  const strengths = [];
  const createIssue = (severity, area, title, detail, confidence = "high", source = "observed") => ({
    severity,
    area,
    title,
    detail,
    confidence,
    source,
  });

  for (const definition of SECURITY_HEADERS) {
    const value = headerValue(headers, definition.key);
    let status = value ? "present" : "missing";
    let severity = value ? "good" : "warning";
    let summary = value
      ? "Configured."
      : "Missing.";

    if (definition.key === "strict-transport-security" && value) {
      const lower = value.toLowerCase();
      const maxAgeMatch = lower.match(/max-age=(\d+)/);
      const maxAge = maxAgeMatch ? Number(maxAgeMatch[1]) : 0;
      if (maxAge < 15552000 || !lower.includes("includesubdomains")) {
        status = "warning";
        severity = "warning";
        summary = "Present, but the policy is weaker than recommended.";
        issues.push(
          createIssue(
            "warning",
            "transport",
            "HSTS could be stronger",
            "Increase max-age and include subdomains for better HTTPS protection.",
            "medium",
            "heuristic",
          ),
        );
      } else {
        strengths.push("Strong HSTS policy detected.");
      }
    }

    if (definition.key === "content-security-policy" && value) {
      const directives = Object.fromEntries(
        value
          .split(";")
          .map((directive) => directive.trim())
          .filter(Boolean)
          .map((directive) => {
            const [name, ...tokens] = directive.split(/\s+/);
            return [name.toLowerCase(), tokens.map((token) => token.toLowerCase())];
          }),
      );
      const scriptSources = directives["script-src"] || directives["default-src"] || [];
      if (scriptSources.includes("'unsafe-inline'") || scriptSources.includes("'unsafe-eval'")) {
        status = "warning";
        severity = "warning";
        summary = "Present, but allows unsafe script execution in script policies.";
        issues.push(
          createIssue(
            "warning",
            "headers",
            "CSP contains risky allowances",
            "unsafe-inline or unsafe-eval in script policies weakens CSP protections against XSS.",
            "high",
            "observed",
          ),
        );
      } else {
        strengths.push("CSP is present without obvious unsafe script allowances.");
      }
    }

    if (definition.key === "x-frame-options" && value) {
      const lower = value.toLowerCase();
      if (!["deny", "sameorigin"].includes(lower)) {
        status = "warning";
        severity = "warning";
        summary = "Present, but uses a less reliable policy.";
      }
    }

    if (definition.key === "referrer-policy" && value) {
      const lower = value
        .split(",")
        .map((part) => part.trim().toLowerCase())
        .filter(Boolean)
        .at(-1) || "";
      if (!["strict-origin", "strict-origin-when-cross-origin", "same-origin", "no-referrer"].includes(lower)) {
        status = "warning";
        severity = "warning";
        summary = "Present, but a stricter referrer policy is recommended.";
      }
    }

    if (!value) {
      issues.push(
        createIssue(
          definition.key === "permissions-policy" ? "info" : "warning",
          "headers",
          `${definition.label} is missing`,
          definition.recommendation,
          "high",
          "observed",
        ),
      );
    }

    results.push({
      ...definition,
      value,
      status,
      severity,
      summary,
    });
  }

  if (!isHttps) {
    issues.push(
      createIssue(
        "critical",
        "transport",
        "Site is not using HTTPS",
        "Traffic can be intercepted or modified in transit over plain HTTP.",
        "high",
        "observed",
      ),
    );
  }

  return { headers: results, issues, strengths };
}

function buildRawHeaders(headers) {
  return Object.fromEntries(
    Object.entries(headers)
      .filter(([, value]) => value !== undefined)
      .map(([key, value]) => [key, Array.isArray(value) ? value.join(", ") : String(value)]),
  );
}

function scoreAnalysis({ isHttps, headerResults, certificate, cookies, redirects }) {
  let score = 100;
  const headerPenalty = {
    "strict-transport-security": { missing: 10, warning: 4 },
    "content-security-policy": { missing: 12, warning: 4 },
    "x-frame-options": { missing: 5, warning: 2 },
    "x-content-type-options": { missing: 5, warning: 2 },
    "referrer-policy": { missing: 5, warning: 2 },
    "permissions-policy": { missing: 2, warning: 1 },
    "cross-origin-opener-policy": { missing: 2, warning: 1 },
    "cross-origin-resource-policy": { missing: 2, warning: 1 },
  };

  if (!isHttps) {
    score -= 35;
  }

  for (const header of headerResults) {
    const weights = headerPenalty[header.key] || { missing: 4, warning: 2 };
    if (header.status === "missing") {
      score -= weights.missing;
    }
    if (header.status === "warning") {
      score -= weights.warning;
    }
  }

  if (certificate.available) {
    if (!certificate.valid) {
      score -= 25;
    }
    if (certificate.protocol && /tlsv1(\.0|\.1)?$/i.test(certificate.protocol)) {
      score -= 15;
    }
    if ((certificate.daysRemaining ?? 365) <= 14) {
      score -= 10;
    }
  }

  for (const cookie of cookies) {
    if (!cookie.secure) score -= 6;
    if (!cookie.httpOnly) score -= 4;
    if (!cookie.sameSite) score -= 4;
  }

  if (redirects.length > 1) {
    score -= Math.min(redirects.length - 1, 4) * 2;
  }

  score = Math.max(0, Math.min(100, score));

  let grade = "F";
  if (score >= 97) grade = "A+";
  else if (score >= 90) grade = "A";
  else if (score >= 80) grade = "B";
  else if (score >= 70) grade = "C";
  else if (score >= 60) grade = "D";

  return { score, grade };
}

function buildRemediation(headerResults) {
  const requiredHeaders = headerResults
    .filter((header) => header.status !== "present")
    .map((header) => ({
      key: header.key,
      label: header.label,
      value: REMEDIATION_TARGETS[header.key],
    }))
    .filter((header) => header.value);

  if (!requiredHeaders.length) {
    return [];
  }

  const nginxLines = requiredHeaders.map(
    (header) => `add_header ${header.label} "${header.value}" always;`,
  );
  const apacheLines = requiredHeaders.map(
    (header) => `Header always set ${header.label} "${header.value}"`,
  );
  const cloudflareLines = requiredHeaders.map(
    (header) =>
      `secured.headers.set("${header.label}", "${header.value.replaceAll('"', '\\"')}");`,
  );
  const vercelLines = requiredHeaders.map((header) => `        { key: "${header.label}", value: "${header.value}" },`);
  const netlifyLines = requiredHeaders.map((header) => `  ${header.label}: ${header.value}`);
  const names = requiredHeaders.map((header) => header.label).join(", ");

  return [
    {
      platform: "nginx",
      title: "Nginx security headers",
      description: `Adds recommended headers for: ${names}.`,
      filename: "nginx.conf",
      snippet: [
        "server {",
        "  # ...existing config",
        ...nginxLines.map((line) => `  ${line}`),
        "}",
      ].join("\n"),
    },
    {
      platform: "apache",
      title: "Apache mod_headers rules",
      description: `Use inside your vhost or .htaccess where mod_headers is enabled.`,
      filename: ".htaccess",
      snippet: [
        "<IfModule mod_headers.c>",
        ...apacheLines.map((line) => `  ${line}`),
        "</IfModule>",
      ].join("\n"),
    },
    {
      platform: "cloudflare",
      title: "Cloudflare Worker response hardening",
      description: "Apply these headers in a Worker or edge response transform.",
      filename: "worker.js",
      snippet: [
        "export default {",
        "  async fetch(request, env, ctx) {",
        "    const response = await fetch(request);",
        "    const secured = new Response(response.body, response);",
        ...cloudflareLines.map((line) => `    ${line}`),
        "    return secured;",
        "  },",
        "};",
      ].join("\n"),
    },
    {
      platform: "vercel",
      title: "Vercel headers() config",
      description: "Paste into next.config.js or next.config.mjs.",
      filename: "next.config.js",
      snippet: [
        "export default {",
        "  async headers() {",
        "    return [",
        "      {",
        '        source: "/(.*)",',
        "        headers: [",
        ...vercelLines,
        "        ],",
        "      },",
        "    ];",
        "  },",
        "};",
      ].join("\n"),
    },
    {
      platform: "netlify",
      title: "Netlify _headers file",
      description: "Add this block to your Netlify `_headers` file.",
      filename: "_headers",
      snippet: [
        "/*",
        ...netlifyLines,
        "",
      ].join("\n"),
    },
  ];
}

function scanTls(targetUrl) {
  if (targetUrl.protocol !== "https:") {
    return Promise.resolve({
      available: false,
      valid: false,
      authorized: false,
      issuer: null,
      subject: null,
      validFrom: null,
      validTo: null,
      daysRemaining: null,
      protocol: null,
      cipher: null,
      fingerprint: null,
      subjectAltName: [],
      issues: ["TLS certificate data is only available for HTTPS targets."],
    });
  }

  return new Promise((resolve, reject) => {
    const socket = tls.connect({
      host: targetUrl.hostname,
      port: Number(targetUrl.port || 443),
      servername: targetUrl.hostname,
      rejectUnauthorized: false,
      timeout: 10000,
    });

    socket.once("secureConnect", () => {
      const certificate = socket.getPeerCertificate(true);
      const protocol = socket.getProtocol?.() || null;
      const cipherInfo = socket.getCipher?.();
      const validTo = certificate?.valid_to || null;
      const validFrom = certificate?.valid_from || null;
      const daysRemaining = validTo
        ? Math.ceil((new Date(validTo).getTime() - Date.now()) / (1000 * 60 * 60 * 24))
        : null;
      const subjectAltName = typeof certificate?.subjectaltname === "string"
        ? certificate.subjectaltname
            .split(",")
            .map((entry) => entry.trim().replace(/^DNS:/, ""))
        : [];
      const issues = [];

      if (!socket.authorized) {
        issues.push(socket.authorizationError || "Certificate is not trusted.");
      }
      if (daysRemaining !== null && daysRemaining <= 14) {
        issues.push("Certificate expires very soon.");
      }
      if (protocol && /tlsv1(\.0|\.1)?$/i.test(protocol)) {
        issues.push("TLS protocol is outdated.");
      }

      resolve({
        available: true,
        valid: Boolean(socket.authorized),
        authorized: Boolean(socket.authorized),
        issuer: certificate?.issuer?.O || certificate?.issuer?.CN || null,
        subject: certificate?.subject?.CN || null,
        validFrom,
        validTo,
        daysRemaining,
        protocol,
        cipher: cipherInfo?.name || null,
        fingerprint: certificate?.fingerprint256 || null,
        subjectAltName,
        issues,
      });

      socket.end();
    });

    socket.once("timeout", () => {
      socket.destroy(new Error("TLS handshake timed out."));
    });
    socket.once("error", reject);
  });
}

function requestOnce(targetUrl, method = "HEAD") {
  return requestWithHeaders(targetUrl, method);
}

function requestWithHeaders(targetUrl, method = "HEAD", extraHeaders = {}) {
  const isHttps = targetUrl.protocol === "https:";
  const transport = isHttps ? https : http;
  const startedAt = Date.now();

  return new Promise((resolve, reject) => {
    const request = transport.request(
      targetUrl,
      {
        method,
        rejectUnauthorized: false,
        headers: {
          "User-Agent": "SecureHeaderInsight/1.0",
          Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
          "Accept-Encoding": "identity",
          ...extraHeaders,
        },
      },
      (response) => {
        response.resume();
        resolve({
          statusCode: response.statusCode || 0,
          headers: response.headers,
          elapsedMs: Date.now() - startedAt,
        });
      },
    );

    request.on("error", reject);
    request.setTimeout(12000, () => {
      request.destroy(new Error("Request timed out."));
    });
    request.end();
  });
}

function requestText(targetUrl, extraHeaders = {}) {
  const isHttps = targetUrl.protocol === "https:";
  const transport = isHttps ? https : http;

  return new Promise((resolve, reject) => {
    const request = transport.request(
      targetUrl,
      {
        method: "GET",
        rejectUnauthorized: false,
        headers: {
          "User-Agent": "SecureHeaderInsight/1.0",
          Accept: "text/plain,text/*;q=0.9,*/*;q=0.1",
          "Accept-Encoding": "identity",
          ...extraHeaders,
        },
      },
      (response) => {
        let body = "";
        response.setEncoding("utf8");
        response.on("data", (chunk) => {
          body += chunk;
          if (body.length > 64_000) {
            body = body.slice(0, 64_000);
          }
        });
        response.on("end", () => {
          resolve({
            statusCode: response.statusCode || 0,
            headers: response.headers,
            body,
          });
        });
      },
    );

    request.on("error", reject);
    request.setTimeout(12000, () => {
      request.destroy(new Error("Request timed out."));
    });
    request.end();
  });
}

function normalizeHtmlSignature(body) {
  return body
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .toLowerCase()
    .slice(0, 280);
}

function getHtmlTitle(body) {
  const match = body.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  return match ? match[1].replace(/\s+/g, " ").trim() : null;
}

function extractHtmlTitle(body) {
  const title = getHtmlTitle(body);
  return title ? title.toLowerCase() : null;
}

function classifyHtmlApiFallback(probePath, finalUrl, resolvedUrl, body, homepageSignature, homepageTitle) {
  const looksLikeHtml = /<html[\s>]|<!doctype html/i.test(body);
  if (!looksLikeHtml) {
    return false;
  }

  if (resolvedUrl.origin === finalUrl.origin && resolvedUrl.pathname === finalUrl.pathname) {
    return true;
  }

  const probeSegments = probePath.split("/").filter(Boolean);
  const resolvedSegments = resolvedUrl.pathname.split("/").filter(Boolean);
  if (!resolvedSegments.length && probeSegments.length) {
    return true;
  }

  const bodySignature = normalizeHtmlSignature(body);
  const bodyTitle = extractHtmlTitle(body);
  return Boolean(
    homepageSignature &&
      bodySignature &&
      (bodySignature === homepageSignature ||
        (homepageTitle && bodyTitle && homepageTitle === bodyTitle)),
  );
}

function isAccessDeniedHtml(headers, body) {
  const server = (headerValue(headers, "server") || "").toLowerCase();
  const bodyText = body.toLowerCase();
  const title = extractHtmlTitle(body) || "";

  if (
    server.includes("sucuri") ||
    bodyText.includes("website security - access denied") ||
    bodyText.includes("access denied") ||
    bodyText.includes("request blocked") ||
    title.includes("access denied")
  ) {
    return true;
  }

  return false;
}

async function fetchWithRedirects(initialUrl, redirectLimit = 5) {
  const redirects = [];
  let currentUrl = initialUrl;
  let response = await requestOnce(currentUrl, "HEAD");

  if (response.statusCode === 405 || response.statusCode === 403) {
    response = await requestOnce(currentUrl, "GET");
  }

  while (
    [301, 302, 303, 307, 308].includes(response.statusCode) &&
    headerValue(response.headers, "location") &&
    redirects.length < redirectLimit
  ) {
    const location = headerValue(response.headers, "location");
    redirects.push({
      url: currentUrl.toString(),
      statusCode: response.statusCode,
      location,
      secure: currentUrl.protocol === "https:",
    });
    currentUrl = new URL(location, currentUrl);
    response = await requestOnce(currentUrl, "HEAD");
    if (response.statusCode === 405 || response.statusCode === 403) {
      response = await requestOnce(currentUrl, "GET");
    }
  }

  redirects.push({
    url: currentUrl.toString(),
    statusCode: response.statusCode,
    location: null,
    secure: currentUrl.protocol === "https:",
  });

  return {
    finalUrl: currentUrl,
    redirects,
    response,
  };
}

function parseSecurityTxt(raw, url) {
  const fields = {
    contact: [],
    policy: [],
    acknowledgments: [],
    encryption: [],
    hiring: [],
    preferredLanguages: [],
    canonical: [],
  };
  const issues = [];

  for (const line of raw.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) {
      continue;
    }
    const match = trimmed.match(/^([^:]+):\s*(.+)$/);
    if (!match) {
      continue;
    }
    const [, key, value] = match;
    const normalizedKey = key.toLowerCase();
    if (normalizedKey === "contact") fields.contact.push(value);
    if (normalizedKey === "expires") fields.expires = value;
    if (normalizedKey === "policy") fields.policy.push(value);
    if (normalizedKey === "acknowledgments") fields.acknowledgments.push(value);
    if (normalizedKey === "encryption") fields.encryption.push(value);
    if (normalizedKey === "hiring") fields.hiring.push(value);
    if (normalizedKey === "preferred-languages") fields.preferredLanguages.push(value);
    if (normalizedKey === "canonical") fields.canonical.push(value);
  }

  if (!fields.contact.length) {
    issues.push("No Contact field found.");
  }
  if (!fields.expires) {
    issues.push("No Expires field found.");
  }
  if (fields.canonical.length && !fields.canonical.includes(url.toString())) {
    issues.push("Canonical field does not include the discovered security.txt URL.");
  }

  return {
    status: issues.length && !raw.includes("Contact:") ? "invalid" : "present",
    url: url.toString(),
    contact: fields.contact,
    expires: fields.expires || null,
    policy: fields.policy,
    acknowledgments: fields.acknowledgments,
    encryption: fields.encryption,
    hiring: fields.hiring,
    preferredLanguages: fields.preferredLanguages,
    canonical: fields.canonical,
    raw: raw.trim() || null,
    issues,
  };
}

async function fetchSecurityTxt(finalUrl) {
  const candidates = [
    new URL("/.well-known/security.txt", finalUrl.origin),
    new URL("/security.txt", finalUrl.origin),
  ];

  for (const candidate of candidates) {
    try {
      const response = await requestText(candidate);
      if (response.statusCode >= 200 && response.statusCode < 300 && response.body.trim()) {
        return parseSecurityTxt(response.body, candidate);
      }
    } catch {
      // Continue to the fallback path.
    }
  }

  return {
    status: "missing",
    url: null,
    contact: [],
    expires: null,
    policy: [],
    acknowledgments: [],
    encryption: [],
    hiring: [],
    preferredLanguages: [],
    canonical: [],
    raw: null,
    issues: ["No security.txt file found at /.well-known/security.txt or /security.txt."],
  };
}

function getAttribute(tag, attribute) {
  const match = tag.match(new RegExp(`${attribute}\\s*=\\s*["']([^"']+)["']`, "i"));
  return match ? match[1] : null;
}

function unique(values) {
  return [...new Set(values.filter(Boolean))];
}

function isLikelyPagePath(pathname) {
  if (!pathname || pathname === "/") {
    return false;
  }

  return !/\.(?:css|js|mjs|json|xml|txt|ico|png|jpe?g|gif|svg|webp|avif|woff2?|ttf|eot|map|pdf|zip|gz|mp4|webm)$/i.test(
    pathname,
  );
}

function scorePagePath(pathname) {
  return PAGE_PATH_PRIORITY_PATTERNS.reduce((score, pattern, index) => {
    if (pattern.test(pathname)) {
      return score + (PAGE_PATH_PRIORITY_PATTERNS.length - index) * 10;
    }
    return score;
  }, pathname.split("/").filter(Boolean).length <= 2 ? 5 : 0);
}

function normalizeDiscoveredPath(value, finalUrl) {
  if (!value || /^(mailto|tel|javascript):/i.test(value)) {
    return null;
  }

  try {
    const resolved = new URL(value, finalUrl);
    if (resolved.origin !== finalUrl.origin || !isLikelyPagePath(resolved.pathname)) {
      return null;
    }

    const normalizedPath = `${resolved.pathname}${resolved.search}`;
    return normalizedPath.length <= 120 ? normalizedPath : resolved.pathname;
  } catch {
    return null;
  }
}

function rankDiscoveredPaths(paths) {
  return unique(paths)
    .sort((left, right) => scorePagePath(right) - scorePagePath(left))
    .slice(0, 10);
}

function addDetectedTechnology(target, seen, name, category, evidence, version) {
  const key = `${name}:${category}`;
  if (seen.has(key)) {
    return;
  }
  seen.add(key);
  target.push({ name, category, evidence, version: version || null });
}

function detectHtmlTechnologies(html, finalUrl, metaGenerator, externalScriptUrls, externalStylesheetUrls) {
  const technologies = [];
  const seen = new Set();
  const htmlLower = html.toLowerCase();
  const allUrls = [...externalScriptUrls, ...externalStylesheetUrls].map((url) => url.toLowerCase());
  const generator = metaGenerator?.toLowerCase() || "";

  if (generator.includes("wordpress") || htmlLower.includes("/wp-content/") || htmlLower.includes("/wp-includes/")) {
    addDetectedTechnology(technologies, seen, "WordPress", "frontend", "Detected from meta generator or wp-content assets");
  }
  if (generator.includes("drupal") || htmlLower.includes("drupalsettings") || htmlLower.includes("/sites/default/files/")) {
    addDetectedTechnology(technologies, seen, "Drupal", "frontend", "Detected from Drupal page markers");
  }
  if (generator.includes("joomla")) {
    addDetectedTechnology(technologies, seen, "Joomla", "frontend", "Detected from meta generator");
  }
  if (generator.includes("ghost")) {
    addDetectedTechnology(technologies, seen, "Ghost", "frontend", "Detected from meta generator");
  }
  if (generator.includes("webflow") || allUrls.some((url) => url.includes("webflow"))) {
    addDetectedTechnology(technologies, seen, "Webflow", "hosting", "Detected from Webflow assets or generator");
  }
  if (generator.includes("wix") || allUrls.some((url) => url.includes("wixstatic.com"))) {
    addDetectedTechnology(technologies, seen, "Wix", "hosting", "Detected from Wix assets or generator");
  }
  if (allUrls.some((url) => url.includes("static1.squarespace.com")) || generator.includes("squarespace")) {
    addDetectedTechnology(technologies, seen, "Squarespace", "hosting", "Detected from Squarespace assets or generator");
  }
  if (htmlLower.includes("/_next/") || htmlLower.includes("__next_data__")) {
    addDetectedTechnology(technologies, seen, "Next.js", "frontend", "Detected from Next.js page assets");
  }
  if (htmlLower.includes("/_nuxt/") || htmlLower.includes("__nuxt")) {
    addDetectedTechnology(technologies, seen, "Nuxt", "frontend", "Detected from Nuxt page assets");
  }
  if (allUrls.some((url) => url.includes("cdn.shopify.com")) || htmlLower.includes("shopify.theme")) {
    addDetectedTechnology(technologies, seen, "Shopify", "hosting", "Detected from Shopify assets");
  }
  if (allUrls.some((url) => url.includes("code.jquery.com")) || htmlLower.includes("jquery")) {
    addDetectedTechnology(technologies, seen, "jQuery", "frontend", "Detected from jQuery asset references");
  }
  if (allUrls.some((url) => url.includes("googletagmanager.com"))) {
    addDetectedTechnology(technologies, seen, "Google Tag Manager", "network", "Detected from third-party script domains");
  }
  if (allUrls.some((url) => url.includes("google-analytics.com") || url.includes("gtag/js"))) {
    addDetectedTechnology(technologies, seen, "Google Analytics", "network", "Detected from analytics asset references");
  }
  if (allUrls.some((url) => url.includes("app.usercentrics.eu"))) {
    addDetectedTechnology(technologies, seen, "Usercentrics", "security", "Detected from consent-management script");
  }
  if (allUrls.some((url) => url.includes("consent.cookiebot.com"))) {
    addDetectedTechnology(technologies, seen, "Cookiebot", "security", "Detected from consent-management script");
  }
  if (allUrls.some((url) => url.includes("js.hs-scripts.com"))) {
    addDetectedTechnology(technologies, seen, "HubSpot", "network", "Detected from HubSpot script references");
  }
  if (allUrls.some((url) => url.includes("cloudfront.net"))) {
    addDetectedTechnology(technologies, seen, "Amazon CloudFront", "network", "Detected from asset hosting domain");
  }
  if (finalUrl.hostname.endsWith(".pages.dev")) {
    addDetectedTechnology(technologies, seen, "Cloudflare Pages", "hosting", "Derived from final hostname");
  }

  return technologies;
}

function analyzeAiSurface(html, finalUrl, externalScriptUrls, firstPartyPaths) {
  const htmlLower = html.toLowerCase();
  const vendors = [];
  const seen = new Set();
  const addVendor = (name, evidence, category, confidence) => {
    const key = `${name}:${category}`;
    if (seen.has(key)) {
      return;
    }
    seen.add(key);
    vendors.push({ name, evidence, category, confidence });
  };

  const vendorMatchers = [
    {
      name: "Intercom Fin",
      pattern: /intercom.*fin|fin ai|intercom/i,
      evidence: "Detected from Intercom-related assets or markup",
      category: "support_automation",
      confidence: "medium",
    },
    {
      name: "Drift",
      pattern: /drift\.com|driftt/i,
      evidence: "Detected from Drift assets or widget markup",
      category: "support_automation",
      confidence: "high",
    },
    {
      name: "Zendesk AI",
      pattern: /zendesk|zopim/i,
      evidence: "Detected from Zendesk widget assets or markup",
      category: "support_automation",
      confidence: "medium",
    },
    {
      name: "HubSpot Chat",
      pattern: /hubspot|hs-scripts/i,
      evidence: "Detected from HubSpot assets or chat markup",
      category: "support_automation",
      confidence: "medium",
    },
    {
      name: "Salesforce Einstein",
      pattern: /einstein|salesforce ai/i,
      evidence: "Detected from Salesforce or Einstein signals",
      category: "ai_vendor",
      confidence: "medium",
    },
    {
      name: "Crisp",
      pattern: /crisp\.chat|crisp/i,
      evidence: "Detected from Crisp widget assets or markup",
      category: "support_automation",
      confidence: "high",
    },
    {
      name: "Freshchat",
      pattern: /freshchat|freshworks/i,
      evidence: "Detected from Freshchat assets or markup",
      category: "support_automation",
      confidence: "high",
    },
    {
      name: "OpenAI",
      pattern: /openai/i,
      evidence: "Detected from OpenAI-related assets or markup",
      category: "ai_vendor",
      confidence: "high",
    },
    {
      name: "Anthropic",
      pattern: /anthropic|claude/i,
      evidence: "Detected from Anthropic-related assets or markup",
      category: "ai_vendor",
      confidence: "high",
    },
    {
      name: "Google Gemini",
      pattern: /gemini|generativelanguage|vertex ai/i,
      evidence: "Detected from Google AI-related assets or markup",
      category: "ai_vendor",
      confidence: "medium",
    },
    {
      name: "Microsoft Copilot",
      pattern: /\bmicrosoft copilot\b|copilot for|copilot studio|copilot.microsoft/i,
      evidence: "Detected from Copilot-specific assets or markup",
      category: "assistant_ui",
      confidence: "medium",
    },
  ];

  const combinedSignals = `${htmlLower} ${externalScriptUrls.join(" ").toLowerCase()}`;
  for (const matcher of vendorMatchers) {
    if (matcher.pattern.test(combinedSignals)) {
      addVendor(matcher.name, matcher.evidence, matcher.category, matcher.confidence);
    }
  }

  const assistantVisible =
    /chat with (ai|our ai)|ask ai|ai assistant|virtual assistant|talk to our assistant|assistant for/i.test(htmlLower) ||
    /aria-label=["'][^"']*(chat with ai|ai assistant|ask ai|virtual assistant)[^"']*["']/i.test(html);

  const aiPageSignals = firstPartyPaths.filter((path) => /\/(ai|assistant|copilot|chat|ask-ai|automation)(\/|$)/i.test(path));
  const disclosures = [];

  if (/do not share sensitive|may be inaccurate|ai-generated|generative ai|assistant may/i.test(htmlLower)) {
    disclosures.push("The page appears to include AI usage or safety disclosure language.");
  }
  if (/privacy policy/i.test(htmlLower) && /ai/i.test(htmlLower)) {
    disclosures.push("AI-related language appears alongside privacy-policy content.");
  }

  const issues = [];
  const strengths = [];
  const automationOnly = vendors.length > 0 && vendors.every((vendor) => vendor.category === "support_automation");
  const highConfidenceAiSignals =
    assistantVisible ||
    vendors.some((vendor) => vendor.category === "ai_vendor" && vendor.confidence === "high") ||
    aiPageSignals.length > 0;

  if (assistantVisible || vendors.length || aiPageSignals.length) {
    strengths.push(
      automationOnly && !assistantVisible && !aiPageSignals.length
        ? "Public-facing support automation signals were detected passively."
        : "Public-facing AI or automation signals were detected passively.",
    );
  }
  if (highConfidenceAiSignals && !disclosures.length) {
    issues.push("AI-related signals were detected, but no obvious AI disclosure language was found on the fetched page.");
  } else if (automationOnly && !disclosures.length) {
    issues.push("Support automation signals were detected, but no obvious disclosure language was found on the fetched page.");
  }
  if (!assistantVisible && !vendors.length && !aiPageSignals.length) {
    strengths.push("No obvious public-facing AI assistant or automation surface was detected on the fetched page.");
  }

  return {
    detected: Boolean(assistantVisible || vendors.length || aiPageSignals.length),
    assistantVisible,
    aiPageSignals,
    vendors,
    discoveredPaths: aiPageSignals,
    disclosures,
    issues,
    strengths,
  };
}

function mergeTechnologies(...groups) {
  const merged = [];
  const seen = new Set();

  for (const group of groups) {
    for (const technology of group || []) {
      addDetectedTechnology(
        merged,
        seen,
        technology.name,
        technology.category,
        technology.evidence,
        technology.version,
      );
    }
  }

  return merged;
}

async function analyzeHtmlSecurity(finalUrl) {
  try {
    const response = await requestText(finalUrl);
    const contentType = headerValue(response.headers, "content-type") || "";
    if (!contentType.toLowerCase().includes("text/html")) {
      return {
        fetched: false,
        pageUrl: finalUrl.toString(),
        pageTitle: null,
        metaGenerator: null,
        forms: [],
        externalScriptDomains: [],
        externalStylesheetDomains: [],
        insecureResourceUrls: [],
        inlineScriptCount: 0,
        inlineStyleCount: 0,
        missingSriScriptUrls: [],
        firstPartyPaths: [],
        detectedTechnologies: [],
        aiSurface: {
          detected: false,
          assistantVisible: false,
          aiPageSignals: [],
          vendors: [],
          discoveredPaths: [],
          disclosures: [],
          issues: ["Primary response was not HTML, so AI surface inspection was skipped."],
          strengths: [],
        },
        issues: ["Primary response was not HTML, so page content inspection was skipped."],
        strengths: [],
      };
    }

    const html = response.body;
    const issues = [];
    const strengths = [];
    const pageTitle = getHtmlTitle(html);
    const metaGenerator = getAttribute(
      html.match(/<meta\b[^>]*name\s*=\s*["']generator["'][^>]*>/i)?.[0] || "",
      "content",
    );

    const formTags = [...html.matchAll(/<form\b[^>]*>([\s\S]*?)<\/form>/gi)];
    const forms = formTags.map(([fullTag, innerHtml]) => {
      const openTagMatch = fullTag.match(/<form\b[^>]*>/i);
      const openTag = openTagMatch ? openTagMatch[0] : fullTag;
      const action = getAttribute(openTag, "action");
      const method = (getAttribute(openTag, "method") || "GET").toUpperCase();
      const hasPasswordField = /<input\b[^>]*type\s*=\s*["']password["']/i.test(innerHtml);
      const resolvedAction = action ? new URL(action, finalUrl).toString() : finalUrl.toString();
      const insecureSubmission = resolvedAction.startsWith("http://");

      return {
        action,
        method,
        insecureSubmission,
        hasPasswordField,
      };
    });

    const scriptTags = [...html.matchAll(/<script\b[^>]*>/gi)].map((match) => match[0]);
    const linkTags = [...html.matchAll(/<link\b[^>]*>/gi)].map((match) => match[0]);
    const externalScriptUrls = scriptTags
      .map((tag) => getAttribute(tag, "src"))
      .filter(Boolean)
      .map((src) => new URL(src, finalUrl).toString());
    const externalStylesheetUrls = linkTags
      .filter((tag) => /\brel\s*=\s*["'][^"']*stylesheet/i.test(tag))
      .map((tag) => getAttribute(tag, "href"))
      .filter(Boolean)
      .map((href) => new URL(href, finalUrl).toString());
    const anchorTags = [...html.matchAll(/<a\b[^>]*>/gi)].map((match) => match[0]);
    const firstPartyPaths = rankDiscoveredPaths([
      ...anchorTags.map((tag) => normalizeDiscoveredPath(getAttribute(tag, "href"), finalUrl)),
      ...forms.map((form) => normalizeDiscoveredPath(form.action, finalUrl)),
    ]);
    const insecureResourceUrls = unique(
      [...externalScriptUrls, ...externalStylesheetUrls].filter((url) => url.startsWith("http://")),
    );
    const externalScriptDomains = unique(
      externalScriptUrls
        .map((url) => new URL(url).hostname)
        .filter((hostname) => hostname !== finalUrl.hostname),
    );
    const externalStylesheetDomains = unique(
      externalStylesheetUrls
        .map((url) => new URL(url).hostname)
        .filter((hostname) => hostname !== finalUrl.hostname),
    );
    const inlineScriptCount = [...html.matchAll(/<script\b(?![^>]*\bsrc=)[^>]*>[\s\S]*?<\/script>/gi)].length;
    const inlineStyleCount = [...html.matchAll(/<style\b[^>]*>[\s\S]*?<\/style>/gi)].length;
    const missingSriScriptUrls = scriptTags
      .filter((tag) => getAttribute(tag, "src"))
      .filter((tag) => {
        const src = getAttribute(tag, "src");
        const resolved = src ? new URL(src, finalUrl) : null;
        return resolved && resolved.hostname !== finalUrl.hostname && !getAttribute(tag, "integrity");
      })
      .map((tag) => new URL(getAttribute(tag, "src"), finalUrl).toString());

    if (forms.some((form) => form.hasPasswordField)) {
      strengths.push("Login-like form elements are present for passive inspection.");
    }
    if (forms.some((form) => form.insecureSubmission)) {
      issues.push("At least one form appears to submit over HTTP.");
    }
    if (insecureResourceUrls.length) {
      issues.push("The page references insecure HTTP resources.");
    }
    if (inlineScriptCount > 0) {
      issues.push(`Inline scripts detected (${inlineScriptCount}).`);
    }
    if (inlineStyleCount > 0) {
      issues.push(`Inline style blocks detected (${inlineStyleCount}).`);
    }
    if (missingSriScriptUrls.length) {
      issues.push("Some third-party scripts are missing Subresource Integrity attributes.");
    }
    if (firstPartyPaths.length) {
      strengths.push(`Discovered ${firstPartyPaths.length} same-origin navigation paths for low-noise follow-up scans.`);
    }
    if (!issues.length) {
      strengths.push("No obvious passive HTML transport/content risks detected on the fetched page.");
    }

    return {
      fetched: true,
      pageUrl: finalUrl.toString(),
      pageTitle,
      metaGenerator: metaGenerator || null,
      forms,
      externalScriptDomains,
      externalStylesheetDomains,
      insecureResourceUrls,
      inlineScriptCount,
      inlineStyleCount,
      missingSriScriptUrls,
      firstPartyPaths,
      detectedTechnologies: detectHtmlTechnologies(
        html,
        finalUrl,
        metaGenerator || null,
        externalScriptUrls,
        externalStylesheetUrls,
      ),
      aiSurface: analyzeAiSurface(html, finalUrl, externalScriptUrls, firstPartyPaths),
      issues,
      strengths,
    };
  } catch (error) {
    return {
      fetched: false,
      pageUrl: finalUrl.toString(),
      pageTitle: null,
      metaGenerator: null,
      forms: [],
      externalScriptDomains: [],
      externalStylesheetDomains: [],
      insecureResourceUrls: [],
      inlineScriptCount: 0,
      inlineStyleCount: 0,
      missingSriScriptUrls: [],
      firstPartyPaths: [],
      detectedTechnologies: [],
      aiSurface: {
        detected: false,
        assistantVisible: false,
        aiPageSignals: [],
        vendors: [],
        discoveredPaths: [],
        disclosures: [],
        issues: [error instanceof Error ? error.message : "AI surface inspection failed."],
        strengths: [],
      },
      issues: [error instanceof Error ? error.message : "HTML inspection failed."],
      strengths: [],
    };
  }
}

function parseRobotsSitemaps(body) {
  return unique(
    body
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter((line) => /^sitemap:/i.test(line))
      .map((line) => line.replace(/^sitemap:\s*/i, "").trim()),
  );
}

function parseSitemapPaths(xml, finalUrl) {
  return rankDiscoveredPaths(
    [...xml.matchAll(/<loc>([\s\S]*?)<\/loc>/gi)].map((match) =>
      normalizeDiscoveredPath(match[1].trim(), finalUrl),
    ),
  );
}

async function collectDiscoveryPaths(finalUrl, htmlSecurity) {
  const discoverySources = [];
  const discoveredPaths = [...(htmlSecurity.firstPartyPaths || [])];

  if (htmlSecurity.firstPartyPaths?.length) {
    discoverySources.push("page links");
  }

  const sitemapCandidates = [new URL("/sitemap.xml", finalUrl.origin).toString()];

  try {
    const robotsResponse = await requestText(new URL("/robots.txt", finalUrl.origin));
    if (robotsResponse.statusCode >= 200 && robotsResponse.statusCode < 300 && robotsResponse.body.trim()) {
      discoverySources.push("robots.txt");
      sitemapCandidates.push(...parseRobotsSitemaps(robotsResponse.body));
    }
  } catch {
    // Ignore robots fetch failures.
  }

  for (const sitemapCandidate of unique(sitemapCandidates).slice(0, 2)) {
    try {
      const sitemapUrl = new URL(sitemapCandidate, finalUrl);
      const response = await requestText(sitemapUrl);
      if (response.statusCode >= 200 && response.statusCode < 300 && response.body.includes("<loc>")) {
        discoveredPaths.push(...parseSitemapPaths(response.body, finalUrl));
        discoverySources.push(sitemapUrl.pathname === "/sitemap.xml" ? "sitemap.xml" : "robots.txt sitemap");
        break;
      }
    } catch {
      // Ignore sitemap fetch failures.
    }
  }

  return {
    paths: rankDiscoveredPaths(discoveredPaths),
    sources: unique(discoverySources),
  };
}

async function fetchPublicSignals(host) {
  const apexHost = host.startsWith("www.") ? host.slice(4) : host;
  const sourceUrl = `https://hstspreload.org/api/v2/status?domain=${encodeURIComponent(apexHost)}`;
  const fallback = {
    hstsPreload: {
      status: "unknown",
      summary: "Public HSTS preload status could not be determined.",
      sourceUrl,
    },
    issues: [],
    strengths: [],
  };

  try {
    const response = await requestText(new URL(sourceUrl), { Accept: "application/json" });
    if (response.statusCode < 200 || response.statusCode >= 300) {
      return fallback;
    }

    const payload = JSON.parse(response.body);
    const statusText = String(payload.status || payload.result || "").toLowerCase();
    const message = String(payload.message || payload.status || "").trim();
    const errors = Array.isArray(payload.errors) ? payload.errors : [];
    const errorText = errors
      .map((entry) => (typeof entry === "string" ? entry : entry?.message || JSON.stringify(entry)))
      .join(" ");

    let status = "not_preloaded";
    if (payload.preloaded === true || statusText.includes("preloaded")) {
      status = "preloaded";
    } else if (statusText.includes("pending")) {
      status = "pending";
    } else if (payload.preloadable === true || payload.eligible === true || statusText.includes("eligible")) {
      status = "eligible";
    } else if (!statusText && !errorText) {
      status = "unknown";
    }

    const summary =
      message && message.toLowerCase() !== "unknown"
        ? message
        : errorText ||
          (status === "not_preloaded"
            ? "The domain is not currently shown as preloaded in the public HSTS preload dataset."
            : "HSTS preload status retrieved from the public preload dataset.");
    const issues = [];
    const strengths = [];

    if (status === "preloaded") {
      strengths.push("Domain appears in the public HSTS preload program.");
    } else if (status === "pending") {
      strengths.push("Domain appears to have an HSTS preload submission pending.");
    } else if (status === "eligible") {
      issues.push("Domain may be eligible for HSTS preload but is not currently shown as preloaded.");
    } else if (status === "not_preloaded") {
      issues.push("Domain is not shown as preloaded in the public HSTS preload dataset.");
    }

    return {
      hstsPreload: {
        status,
        summary,
        sourceUrl,
      },
      issues,
      strengths,
    };
  } catch {
    return fallback;
  }
}

async function analyzeExposure(finalUrl) {
  const probes = [];
  const issues = [];
  const strengths = [];

  for (const probe of EXPOSURE_PROBES) {
    const probeUrl = new URL(probe.path, finalUrl.origin);
    try {
      let response;
      let resolvedUrl = probeUrl;

      if (probe.path === "/robots.txt" || probe.path === "/sitemap.xml") {
        const redirectData = await fetchWithRedirects(probeUrl, 3);
        response = redirectData.response;
        resolvedUrl = redirectData.finalUrl;
      } else {
        response = await requestOnce(probeUrl, "HEAD");
        if (response.statusCode === 405 || response.statusCode === 403) {
          response = await requestOnce(probeUrl, "GET");
        }
      }

      let finding = "safe";
      let detail = "Not exposed.";

      if (probe.path === "/robots.txt" || probe.path === "/sitemap.xml") {
        if (response.statusCode >= 200 && response.statusCode < 300) {
          finding = "interesting";
          detail =
            resolvedUrl.toString() === probeUrl.toString()
              ? "Public discovery file is available."
              : `Public discovery file is available after redirect to ${resolvedUrl.toString()}.`;
          strengths.push(`${probe.label} is published.`);
        } else if (response.statusCode === 401 || response.statusCode === 403) {
          finding = "interesting";
          detail = "Discovery file exists but is access-controlled.";
        } else {
          detail = "Discovery file not found.";
        }
      } else if (response.statusCode >= 200 && response.statusCode < 300) {
        finding = "exposed";
        detail = "Sensitive path returned a successful response.";
        issues.push(`${probe.label} may be exposed at ${probe.path}.`);
      } else if (response.statusCode === 401 || response.statusCode === 403) {
        finding = "interesting";
        detail = "Sensitive path exists but is access-controlled.";
        strengths.push(`${probe.label} appears access-controlled.`);
      }

      probes.push({
        label: probe.label,
        path: probe.path,
        statusCode: response.statusCode,
        finalUrl: resolvedUrl.toString(),
        finding,
        detail,
      });
    } catch (error) {
      probes.push({
        label: probe.label,
        path: probe.path,
        statusCode: 0,
        finalUrl: probeUrl.toString(),
        finding: "safe",
        detail: error instanceof Error ? error.message : "Probe failed.",
      });
    }
  }

  if (!issues.length) {
    strengths.push("No obvious high-signal sensitive files were openly exposed in the limited probe set.");
  }

  return {
    probes,
    issues,
    strengths,
  };
}

function parseCsvHeader(value) {
  return value
    ? value
        .split(",")
        .map((part) => part.trim())
        .filter(Boolean)
    : [];
}

async function analyzeCorsSecurity(finalUrl, responseHeaders) {
  let optionsResponse = { statusCode: 0, headers: {} };
  try {
    optionsResponse = await requestWithHeaders(finalUrl, "OPTIONS", {
      Origin: "https://security-posture-insight.local",
      "Access-Control-Request-Method": "POST",
      "Access-Control-Request-Headers": "content-type,authorization",
    });
  } catch {
    // Keep the default empty response if OPTIONS is blocked or errors out.
  }

  const mergedHeaders = {
    ...responseHeaders,
    ...optionsResponse.headers,
  };
  const allowedOrigin = headerValue(mergedHeaders, "access-control-allow-origin");
  const allowCredentials = headerValue(mergedHeaders, "access-control-allow-credentials");
  const allowMethods = parseCsvHeader(headerValue(mergedHeaders, "access-control-allow-methods"));
  const allowHeaders = parseCsvHeader(headerValue(mergedHeaders, "access-control-allow-headers"));
  const allowPrivateNetwork = headerValue(mergedHeaders, "access-control-allow-private-network");
  const vary = headerValue(mergedHeaders, "vary");
  const issues = [];
  const strengths = [];

  if (allowedOrigin === "*") {
    if (allowCredentials?.toLowerCase() === "true") {
      issues.push("CORS allows any origin while also allowing credentials.");
    } else {
      issues.push("CORS allows any origin.");
    }
  } else if (allowedOrigin) {
    strengths.push(`CORS is scoped to ${allowedOrigin}.`);
  }

  if (allowMethods.includes("PUT") || allowMethods.includes("DELETE") || allowMethods.includes("PATCH")) {
    issues.push(`Preflight allows elevated methods: ${allowMethods.join(", ")}.`);
  }
  if (allowHeaders.includes("*")) {
    issues.push("CORS allows any request header.");
  }
  if (allowPrivateNetwork?.toLowerCase() === "true") {
    issues.push("CORS allows private network access.");
  }
  if (allowedOrigin && allowedOrigin !== "*" && !(vary || "").toLowerCase().includes("origin")) {
    issues.push("CORS varies by origin but the response does not advertise Vary: Origin.");
  }
  if (!allowedOrigin) {
    strengths.push("No permissive CORS policy detected on the scanned page.");
  }

  return {
    allowedOrigin,
    allowCredentials,
    allowMethods,
    allowHeaders,
    allowPrivateNetwork,
    vary,
    optionsStatus: optionsResponse.statusCode,
    issues,
    strengths,
  };
}

async function analyzeApiSurface(finalUrl) {
  const probes = [];
  const issues = [];
  const strengths = [];
  let homepageSignature = "";
  let homepageTitle = null;

  try {
    const homepageResponse = await requestText(finalUrl, {
      Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    });
    if (homepageResponse.statusCode >= 200 && homepageResponse.statusCode < 300) {
      homepageSignature = normalizeHtmlSignature(homepageResponse.body);
      homepageTitle = extractHtmlTitle(homepageResponse.body);
    }
  } catch {
    // Ignore homepage body fetch failures and continue with probe-only heuristics.
  }

  for (const probe of API_SURFACE_PROBES) {
    const targetUrl = new URL(probe.path, finalUrl.origin);
    try {
      let response = await requestText(targetUrl, {
        Accept: "application/json,text/plain;q=0.9,*/*;q=0.8",
      });
      let resolvedUrl = targetUrl;

      if ([301, 302, 303, 307, 308].includes(response.statusCode) && headerValue(response.headers, "location")) {
        const redirectData = await fetchWithRedirects(targetUrl, 2);
        resolvedUrl = redirectData.finalUrl;
        response = await requestText(resolvedUrl, {
          Accept: "application/json,text/plain;q=0.9,*/*;q=0.8",
        });
      }

      const contentType = headerValue(response.headers, "content-type");
      let classification = "absent";
      let detail = "Endpoint not found.";

      if (response.statusCode === 401 || response.statusCode === 403) {
        classification = "restricted";
        detail = "Endpoint exists but requires authorization or is blocked.";
        strengths.push(`${probe.label} appears access-controlled.`);
      } else if (response.statusCode === 404) {
        classification = "absent";
        detail = "Endpoint not found.";
      } else if (response.statusCode >= 500) {
        classification = "error";
        detail = "Endpoint triggered a server-side error, so the path exists or is handled but did not respond cleanly.";
      } else if (response.statusCode >= 200 && response.statusCode < 300) {
        if ((contentType || "").includes("application/json")) {
          classification = "public";
          detail = "Public JSON-style endpoint responded successfully.";
          issues.push(`${probe.label} appears publicly reachable at ${probe.path}.`);
        } else if ((contentType || "").includes("text/html") && isAccessDeniedHtml(response.headers, response.body)) {
          classification = "restricted";
          detail = "Endpoint response appears to be a web application firewall or access-denied page.";
          strengths.push(`${probe.label} appears blocked by edge protection.`);
        } else if (
          (contentType || "").includes("text/html") &&
          classifyHtmlApiFallback(
            probe.path,
            finalUrl,
            resolvedUrl,
            response.body,
            homepageSignature,
            homepageTitle,
          )
        ) {
          classification = "fallback";
          detail = "Endpoint appears to return the site's standard HTML page rather than an API response.";
        } else {
          classification = "interesting";
          detail = "Endpoint responded successfully but does not clearly look like JSON.";
        }
      } else if (response.statusCode >= 300 && response.statusCode < 400) {
        classification = "interesting";
        detail = "Endpoint redirected.";
      } else if (response.statusCode > 0) {
        classification = "interesting";
        detail = "Endpoint returned a non-success response that may still indicate application handling on this path.";
      }

      probes.push({
        label: probe.label,
        path: probe.path,
        statusCode: response.statusCode,
        finalUrl: resolvedUrl.toString(),
        classification,
        contentType,
        detail,
      });
    } catch (error) {
      probes.push({
        label: probe.label,
        path: probe.path,
        statusCode: 0,
        finalUrl: targetUrl.toString(),
        classification: "absent",
        contentType: null,
        detail: error instanceof Error ? error.message : "Probe failed.",
      });
    }
  }

  if (!issues.length) {
    strengths.push("No obviously public API endpoints were detected in the limited probe set.");
  }

  if (probes.some((probe) => probe.classification === "fallback")) {
    strengths.push("Some API-style paths appear to be frontend route fallbacks rather than exposed APIs.");
  }

  return {
    probes,
    issues,
    strengths,
  };
}

async function safeResolve(operation) {
  try {
    return await operation();
  } catch {
    return null;
  }
}

async function fetchMtaStsPolicy(host) {
  const policyHost = `mta-sts.${host}`;
  const policyUrl = new URL(`https://${policyHost}/.well-known/mta-sts.txt`);

  try {
    const response = await requestText(policyUrl);
    if (response.statusCode >= 200 && response.statusCode < 300 && response.body.trim()) {
      return {
        policyUrl: policyUrl.toString(),
        policy: response.body.trim(),
      };
    }
  } catch {
    // Ignore fetch failure and return a null policy below.
  }

  return {
    policyUrl: policyUrl.toString(),
    policy: null,
  };
}

async function analyzeDomainSecurity(host) {
  const apexHost = host.startsWith("www.") ? host.slice(4) : host;
  const candidateHosts = [...new Set([host, apexHost])];

  const [
    mxByHost,
    nsByHost,
    txtRootByHost,
    txtDmarcByHost,
    caaByHost,
    txtMtaStsByHost,
  ] = await Promise.all([
    Promise.all(candidateHosts.map((candidate) => safeResolve(() => dns.resolveMx(candidate)))),
    Promise.all(candidateHosts.map((candidate) => safeResolve(() => dns.resolveNs(candidate)))),
    Promise.all(candidateHosts.map((candidate) => safeResolve(() => dns.resolveTxt(candidate)))),
    Promise.all(candidateHosts.map((candidate) => safeResolve(() => dns.resolveTxt(`_dmarc.${candidate}`)))),
    Promise.all(candidateHosts.map((candidate) => safeResolve(() => dns.resolveCaa(candidate)))),
    Promise.all(candidateHosts.map((candidate) => safeResolve(() => dns.resolveTxt(`_mta-sts.${candidate}`)))),
  ]);

  const pickFirst = (values) => values.find((value) => value && value.length) || null;
  const mxRecordsRaw = pickFirst(mxByHost) || [];
  const nsRecordsRaw = pickFirst(nsByHost) || [];
  const txtRoot = pickFirst(txtRootByHost) || [];
  const txtDmarc = pickFirst(txtDmarcByHost) || [];
  const caaRaw = pickFirst(caaByHost) || [];
  const txtMtaSts = pickFirst(txtMtaStsByHost) || [];

  const mxRecords = (mxRecordsRaw || [])
    .sort((a, b) => a.priority - b.priority)
    .map((record) => `${record.priority} ${record.exchange}`);
  const nsRecords = nsRecordsRaw || [];
  const txtValues = (txtRoot || []).map((entry) => entry.join(""));
  const dmarcValues = (txtDmarc || []).map((entry) => entry.join(""));
  const mtaStsValues = (txtMtaSts || []).map((entry) => entry.join(""));
  const caaRecords = (caaRaw || []).flatMap((record) =>
    Object.entries(record)
      .filter(([key]) => key !== "critical")
      .map(([tag, value]) => `${tag} ${value}`),
  );
  const spf = txtValues.find((value) => value.toLowerCase().startsWith("v=spf1")) || null;
  const dmarc = dmarcValues.find((value) => value.toLowerCase().startsWith("v=dmarc1")) || null;
  const mtaStsDns = mtaStsValues.find((value) => value.toLowerCase().startsWith("v=stsv1")) || null;
  const mtaStsTargetHost = txtMtaStsByHost[0]?.length ? candidateHosts[0] : candidateHosts[1] || candidateHosts[0];
  const mtaStsPolicy = mtaStsDns ? await fetchMtaStsPolicy(mtaStsTargetHost) : { policyUrl: null, policy: null };

  const issues = [];
  const strengths = [];

  if (!mxRecords.length) {
    issues.push("No MX records found.");
  } else {
    strengths.push("MX records are published.");
  }

  if (!spf) {
    issues.push("No SPF record detected at the zone apex.");
  } else if (!spf.includes("-all") && !spf.includes("~all")) {
    issues.push("SPF record does not define an explicit all-mechanism.");
  } else {
    strengths.push("SPF is published.");
  }

  if (!dmarc) {
    issues.push("No DMARC record detected.");
  } else {
    if (!/p=(reject|quarantine)/i.test(dmarc)) {
      issues.push("DMARC policy is present but not enforcing quarantine or reject.");
    } else {
      strengths.push("DMARC is enforcing.");
    }
  }

  if (!caaRecords.length) {
    issues.push("No CAA records found.");
  } else {
    strengths.push("CAA records restrict which certificate authorities may issue for the domain.");
  }

  if (!mtaStsDns) {
    issues.push("No MTA-STS DNS policy record detected.");
  } else if (!mtaStsPolicy.policy) {
    issues.push("MTA-STS DNS record exists, but the HTTPS policy file could not be fetched.");
  } else {
    strengths.push("MTA-STS is published.");
  }

  return {
    host: apexHost,
    mxRecords,
    nsRecords,
    caaRecords,
    spf,
    dmarc,
    mtaSts: {
      dns: mtaStsDns,
      policyUrl: mtaStsPolicy.policyUrl,
      policy: mtaStsPolicy.policy,
    },
    issues,
    strengths,
  };
}

async function analyzeUrlCore(input, options = {}) {
  const { includeCertificate = true } = options;
  const normalizedUrl = input instanceof URL ? input : normalizeUrl(input);
  const requestData = await fetchWithRedirects(normalizedUrl);
  const certificate = includeCertificate
    ? await scanTls(requestData.finalUrl)
    : {
        available: false,
        valid: false,
        authorized: false,
        issuer: null,
        subject: null,
        validFrom: null,
        validTo: null,
        daysRemaining: null,
        protocol: null,
        cipher: null,
        fingerprint: null,
        subjectAltName: [],
        issues: [],
      };
  const rawHeaders = buildRawHeaders(requestData.response.headers);
  const { headers: headerResults, issues: headerIssues, strengths } = analyzeHeaders(
    requestData.response.headers,
    requestData.finalUrl.protocol === "https:",
  );
  const cookies = parseSetCookie(requestData.response.headers["set-cookie"]);
  const technologies = detectTechnologies(requestData.response.headers, requestData.finalUrl);
  const { score, grade } = scoreAnalysis({
    isHttps: requestData.finalUrl.protocol === "https:",
    headerResults,
    certificate,
    cookies,
    redirects: requestData.redirects,
  });

  const cookieIssues = cookies.flatMap((cookie) =>
    cookie.issues.map((detail) => ({
      severity: cookie.risk === "high" ? "warning" : "info",
      area: "cookies",
      title: `Cookie ${cookie.name} needs attention`,
      detail,
      confidence: "high",
      source: "observed",
    })),
  );

  const redirectIssues =
    requestData.redirects.length > 1
      ? [
          {
            severity: "info",
            area: "transport",
            title: "Redirect chain detected",
            detail: `This scan followed ${requestData.redirects.length - 1} redirect${requestData.redirects.length > 2 ? "s" : ""} before reaching the final URL.`,
            confidence: "high",
            source: "observed",
          },
        ]
      : [];

  const issues = [...headerIssues, ...cookieIssues, ...redirectIssues];
  if (certificate.issues.length) {
    issues.push(
      ...certificate.issues.map((detail) => ({
        severity: /outdated|not trusted|expires/i.test(detail) ? "warning" : "info",
        area: "certificate",
        title: "TLS certificate needs attention",
        detail,
        confidence: /expires/i.test(detail) ? "high" : "medium",
        source: "observed",
      })),
    );
  }

  const summary =
    grade === "A+"
      ? "Excellent baseline hardening."
      : grade === "A"
        ? "Strong setup with a few remaining improvements."
        : grade === "B"
          ? "Reasonably protected, but several headers or cookie controls can be improved."
          : "Security posture needs work before this would count as well hardened.";

  return {
    inputUrl: input instanceof URL ? input.toString() : input,
    normalizedUrl: normalizedUrl.toString(),
    finalUrl: requestData.finalUrl.toString(),
    host: requestData.finalUrl.hostname,
    scannedAt: new Date().toISOString(),
    responseTimeMs: requestData.response.elapsedMs,
    statusCode: requestData.response.statusCode,
    score,
    grade,
    summary,
    headers: headerResults,
    rawHeaders,
    cookies,
    technologies,
    certificate,
    redirects: requestData.redirects,
    issues,
    strengths,
    remediation: buildRemediation(headerResults),
  };
}

function toCandidateLabel(pathname) {
  if (pathname === "/") {
    return "Homepage";
  }

  const segments = pathname
    .split("?")[0]
    .split("/")
    .filter(Boolean)
    .map((segment) => decodeURIComponent(segment).replace(/[-_]+/g, " ").trim())
    .filter(Boolean);

  const uniqueSegments = segments.filter((segment, index) => {
    return index === 0 || segment.toLowerCase() !== segments[index - 1].toLowerCase();
  });

  const preferredSegments =
    uniqueSegments.length <= 2
      ? uniqueSegments
      : [uniqueSegments[0], uniqueSegments[uniqueSegments.length - 1]];

  const label = preferredSegments
    .map((segment) =>
      segment
        .split(/\s+/)
        .slice(0, 3)
        .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
        .join(" "),
    )
    .join(" / ");

  return label.length > 42 ? `${label.slice(0, 39).trimEnd()}...` : label;
}

function buildCrawlCandidates(result, discoveryPaths = []) {
  const finalUrl = new URL(result.finalUrl);
  const userPath = new URL(result.normalizedUrl).pathname || "/";
  const seen = new Set();

  return [
    { label: userPath === "/" ? "Homepage" : "Requested page", path: userPath },
    ...discoveryPaths.map((path) => ({ label: toCandidateLabel(path), path })),
    ...CRAWL_CANDIDATES,
  ]
    .map((candidate) => {
      const url = new URL(candidate.path, finalUrl.origin);
      return {
        label: candidate.label,
        path: url.pathname,
        url,
      };
    })
    .filter((candidate) => {
      const key = candidate.path;
      if (seen.has(key)) {
        return false;
      }
      seen.add(key);
      return true;
    })
    .slice(0, 6);
}

function summarizePageAnalysis(label, path, pageResult, rootHost) {
  const sameOrigin = new URL(pageResult.finalUrl).hostname === rootHost;
  return {
    label,
    path,
    finalUrl: pageResult.finalUrl,
    sameOrigin,
    statusCode: pageResult.statusCode,
    responseTimeMs: pageResult.responseTimeMs,
    score: sameOrigin ? pageResult.score : 0,
    grade: sameOrigin ? pageResult.grade : "Redirected",
    missingHeaders: sameOrigin ? pageResult.headers
      .filter((header) => header.status === "missing")
      .map((header) => header.label) : [],
    warningHeaders: sameOrigin ? pageResult.headers
      .filter((header) => header.status === "warning")
      .map((header) => header.label) : [],
    issueCount: sameOrigin ? pageResult.issues.length : 1,
  };
}

async function crawlRelatedPages(rootResult, discovery) {
  const candidates = buildCrawlCandidates(rootResult, discovery.paths);
  const rootHost = new URL(rootResult.finalUrl).hostname;
  const pages = [];

  for (const candidate of candidates) {
    try {
      const pageResult = await analyzeUrlCore(candidate.url, { includeCertificate: false });
      pages.push(summarizePageAnalysis(candidate.label, candidate.path, pageResult, rootHost));
    } catch {
      pages.push({
        label: candidate.label,
        path: candidate.path,
        finalUrl: candidate.url.toString(),
        sameOrigin: true,
        statusCode: 0,
        responseTimeMs: 0,
        score: 0,
        grade: "F",
        missingHeaders: SECURITY_HEADERS.map((header) => header.label),
        warningHeaders: [],
        issueCount: 1,
      });
    }
  }

  const comparablePages = pages.filter((page) => page.sameOrigin);

  const strongestPage = comparablePages.length
    ? comparablePages.reduce((best, page) => (page.score > best.score ? page : best), comparablePages[0]).label
    : null;
  const weakestPage = comparablePages.length
    ? comparablePages.reduce((worst, page) => (page.score < worst.score ? page : worst), comparablePages[0]).label
    : null;

  const headerMap = new Map();
  for (const page of comparablePages) {
    for (const header of SECURITY_HEADERS) {
      const status = page.missingHeaders.includes(header.label)
        ? "missing"
        : page.warningHeaders.includes(header.label)
          ? "warning"
          : "present";
      const existing = headerMap.get(header.label) || new Set();
      existing.add(status);
      headerMap.set(header.label, existing);
    }
  }

  const inconsistentHeaders = [...headerMap.entries()]
    .filter(([, states]) => states.size > 1)
    .map(([label]) => label);

  return {
    pages,
    strongestPage,
    weakestPage,
    inconsistentHeaders,
    discoverySources: discovery.sources,
  };
}

async function analyzeUrl(input) {
  const result = await analyzeUrlCore(input, { includeCertificate: true });
  const finalUrl = new URL(result.finalUrl);
  const htmlSecurity = await analyzeHtmlSecurity(finalUrl);
  const discovery = await collectDiscoveryPaths(finalUrl, htmlSecurity);
  const publicSignals = await fetchPublicSignals(result.host);

  return {
    ...result,
    technologies: mergeTechnologies(result.technologies, htmlSecurity.detectedTechnologies),
    crawl: await crawlRelatedPages(result, discovery),
    securityTxt: await fetchSecurityTxt(finalUrl),
    domainSecurity: await analyzeDomainSecurity(result.host),
    htmlSecurity,
    aiSurface: htmlSecurity.aiSurface,
    exposure: await analyzeExposure(finalUrl),
    corsSecurity: await analyzeCorsSecurity(finalUrl, result.rawHeaders),
    apiSurface: await analyzeApiSurface(finalUrl),
    publicSignals,
  };
}

const server = http.createServer(async (request, response) => {
  const requestUrl = new URL(request.url || "/", `http://${request.headers.host}`);

  if (requestUrl.pathname === "/api/health") {
    sendJson(response, 200, { ok: true, now: new Date().toISOString() });
    return;
  }

  if (requestUrl.pathname === "/api/analyze") {
    try {
      const target = requestUrl.searchParams.get("url") || "";
      const result = await analyzeUrl(target);
      sendJson(response, 200, result);
    } catch (error) {
      sendJson(response, 400, {
        error: error instanceof Error ? error.message : "Unable to analyze URL.",
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
