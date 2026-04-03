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
    const key = `${name}:${category}:${version || ""}`;
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
        issues.push({
          severity: "warning",
          area: "transport",
          title: "HSTS could be stronger",
          detail: "Increase max-age and include subdomains for better HTTPS protection.",
        });
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
        issues.push({
          severity: "warning",
          area: "headers",
          title: "CSP contains risky allowances",
          detail: "unsafe-inline or unsafe-eval in script policies weakens CSP protections against XSS.",
        });
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
      issues.push({
        severity: definition.key === "permissions-policy" ? "info" : "warning",
        area: "headers",
        title: `${definition.label} is missing`,
        detail: definition.recommendation,
      });
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
    issues.push({
      severity: "critical",
      area: "transport",
      title: "Site is not using HTTPS",
      detail: "Traffic can be intercepted or modified in transit over plain HTTP.",
    });
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

function requestText(targetUrl) {
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

function buildCrawlCandidates(result) {
  const finalUrl = new URL(result.finalUrl);
  const userPath = new URL(result.normalizedUrl).pathname || "/";
  const seen = new Set();

  return [
    { label: userPath === "/" ? "Homepage" : "Requested page", path: userPath },
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
    .slice(0, 5);
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

async function crawlRelatedPages(rootResult) {
  const candidates = buildCrawlCandidates(rootResult);
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
  };
}

async function analyzeUrl(input) {
  const result = await analyzeUrlCore(input, { includeCertificate: true });
  return {
    ...result,
    crawl: await crawlRelatedPages(result),
    securityTxt: await fetchSecurityTxt(new URL(result.finalUrl)),
    domainSecurity: await analyzeDomainSecurity(result.host),
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
