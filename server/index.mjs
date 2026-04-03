import fs from "node:fs";
import http from "node:http";
import https from "node:https";
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

async function analyzeUrl(input) {
  const normalizedUrl = normalizeUrl(input);
  const requestData = await fetchWithRedirects(normalizedUrl);
  const certificate = await scanTls(requestData.finalUrl);

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
    inputUrl: input,
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
