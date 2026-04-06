import http from "node:http";
import https from "node:https";
import dns from "node:dns/promises";
import net from "node:net";
import tls from "node:tls";
import { URL } from "node:url";
import * as cheerio from "cheerio";
import { fetchCtDiscovery } from "./ctDiscovery.js";
import { analyzeIdentityProvider } from "./identityProvider.js";
import type {
  AnalysisResult,
  AnalyzeTargetOptions,
  AiSurfaceInfo,
  CertificateResult,
  CorsSecurityInfo,
  DomainSecurityInfo,
  ExecutiveSummaryInfo,
  HtmlSecurityInfo,
  IssueConfidence,
  PublicSignalsInfo,
  RemediationSnippet,
  SecurityTxtInfo,
  TechnologyResult,
  ThirdPartyProvider,
} from "./types.js";

type ResponseHeaders = http.IncomingHttpHeaders;

const SCANNER_USER_AGENT = "ExternalPostureInsight/1.0";
const REQUEST_TIMEOUT_MS = 12_000;
const TLS_HANDSHAKE_TIMEOUT_MS = 10_000;
const TEXT_BODY_LIMIT = 256_000;
const HTML_SIGNATURE_LIMIT = 280;
const DISCOVERY_PATH_LIMIT = 10;
const SUMMARY_EVIDENCE_LIMIT = 3;
const CLIENT_EXPOSURE_EVIDENCE_LIMIT = 6;
const REDIRECT_LIMIT = 5;

// Deliberately disabled only for observational scanning so invalid or expired
// certificates can still be described. This must never be reused for
// authenticated or stateful application traffic.
const OBSERVATIONAL_TLS_OPTIONS = {
  rejectUnauthorized: false,
};

interface RequestHeadResult {
  statusCode: number;
  headers: ResponseHeaders;
  elapsedMs: number;
}

interface RequestTextResult {
  statusCode: number;
  headers: ResponseHeaders;
  body: string;
}

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

function shouldRetryOverHttp(error) {
  if (!(error instanceof Error)) {
    return false;
  }

  const message = error.message.toLowerCase();
  return (
    message.includes("socket hang up") ||
    message.includes("econnreset") ||
    message.includes("tls") ||
    message.includes("ssl") ||
    message.includes("wrong version number") ||
    message.includes("alert handshake failure")
  );
}

function formatErrorMessage(error) {
  if (error instanceof AggregateError && Array.isArray(error.errors) && error.errors.length) {
    const messages = error.errors
      .map((item) => (item instanceof Error ? item.message : String(item)))
      .filter(Boolean);
    if (messages.length) {
      return messages.join("; ");
    }
  }

  if (error instanceof Error && error.message) {
    return error.message;
  }

  return "Unable to analyze URL.";
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
  const seen = new Set<string>();

  const addTechnology = (name, category, evidence, version, confidence = "high", detection = "observed") => {
    const key = `${name}:${category}`;
    if (seen.has(key)) {
      return;
    }
    seen.add(key);
    technologies.push({
      name,
      category,
      evidence,
      version: version || null,
      confidence,
      detection,
    });
  };

  const server = headerValue(headers, "server");
  const poweredBy = headerValue(headers, "x-powered-by");
  const cache = headerValue(headers, "cf-cache-status");
  const via = headerValue(headers, "via");

  const classifyServerHeader = (value) => {
    const lower = value.toLowerCase();
    if (lower.includes("cloudflare")) {
      return { name: "Cloudflare", category: "network", version: value };
    }
    if (lower.includes("sucuri")) {
      return { name: "Sucuri", category: "network", version: value };
    }
    if (lower.includes("akamai")) {
      return { name: "Akamai", category: "network", version: value };
    }
    if (lower.includes("fastly")) {
      return { name: "Fastly", category: "network", version: value };
    }
    if (lower.includes("nginx")) {
      return { name: "Nginx", category: "server", version: value };
    }
    if (lower.includes("apache")) {
      return { name: "Apache", category: "server", version: value };
    }
    if (lower.includes("caddy")) {
      return { name: "Caddy", category: "server", version: value };
    }
    if (/(gtm|gateway|proxy|edge|cache|router|traffic)/.test(lower)) {
      return { name: value, category: "network", version: null };
    }
    return { name: value, category: "server", version: null };
  };

  const addViaSignals = (viaHeader) => {
    const hops = viaHeader
      .split(",")
      .map((part) => part.trim())
      .filter(Boolean)
      .map((part) => part.replace(/^\d+(?:\.\d+)?\s+/i, "").trim());

    for (const hop of hops) {
      if (!hop) {
        continue;
      }
      const lower = hop.toLowerCase();
      if (/(bbc-gtm|gtm|gateway|proxy|edge|cache|belfrage|varnish)/.test(lower)) {
        addTechnology(hop, "network", "Observed in Via response chain", null, "high", "observed");
      }
    }
  };

  if (server) {
    const classification = classifyServerHeader(server);
    addTechnology(classification.name, classification.category, "Observed in Server header", classification.version, "high", "observed");
  }

  if (via) {
    addViaSignals(via);
  }

  if (poweredBy) {
    addTechnology(poweredBy, "frontend", "Observed in X-Powered-By header", null, "high", "observed");
    const poweredByLower = poweredBy.toLowerCase();
    if (poweredByLower.includes("express")) {
      addTechnology("Express", "frontend", "Observed in X-Powered-By header", null, "high", "observed");
    }
    if (poweredByLower.includes("next")) {
      addTechnology("Next.js", "frontend", "Observed in X-Powered-By header", null, "high", "observed");
    }
  }

  if (headerValue(headers, "x-vercel-id")) {
    addTechnology("Vercel", "hosting", "Observed in X-Vercel-Id header", null, "high", "observed");
  }
  if (headerValue(headers, "x-amz-cf-id")) {
    addTechnology("Amazon CloudFront", "network", "Observed in CloudFront response headers", null, "high", "observed");
  }
  if (headerValue(headers, "x-cache")?.toLowerCase().includes("fastly")) {
    addTechnology("Fastly", "network", "Observed in X-Cache header", null, "high", "observed");
  }
  if (headerValue(headers, "x-cdn")) {
    addTechnology(headerValue(headers, "x-cdn"), "network", "Observed in X-CDN header", null, "high", "observed");
  }
  if (headerValue(headers, "x-envoy-upstream-service-time")) {
    addTechnology("Envoy", "network", "Observed in Envoy upstream timing header", null, "high", "observed");
  }
  if (headerValue(headers, "cf-ray") || cache) {
    addTechnology("Cloudflare", "network", "Observed in Cloudflare response headers", null, "high", "observed");
  }
  if (headerValue(headers, "x-sucuri-id") || headerValue(headers, "x-sucuri-cache")) {
    addTechnology("Sucuri", "network", "Observed in Sucuri edge headers", null, "high", "observed");
  }
  if (headerValue(headers, "x-akamai-transformed") || headerValue(headers, "akamai-cache-status")) {
    addTechnology("Akamai", "network", "Observed in Akamai response headers", null, "high", "observed");
  }
  if (headerValue(headers, "x-served-by")?.toLowerCase().includes("cache-")) {
    addTechnology("Fastly", "network", "Observed in X-Served-By cache headers", null, "high", "observed");
  }
  if (headerValue(headers, "server-timing")?.toLowerCase().includes("cdn-cache")) {
    addTechnology("CDN", "network", "Observed in Server-Timing header", null, "medium", "observed");
  }

  addTechnology(finalUrl.protocol === "https:" ? "HTTPS" : "HTTP", "security", "Derived from final URL", null, "high", "observed");
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
    owasp: [],
    mitre: [],
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

function classifyIssueTaxonomy(issue) {
  const text = `${issue.area} ${issue.title} ${issue.detail}`.toLowerCase();
  const owasp = [];
  const mitre = [];

  if (
    issue.area === "transport" ||
    issue.area === "certificate" ||
    text.includes("https") ||
    text.includes("tls") ||
    text.includes("certificate") ||
    text.includes("hsts") ||
    text.includes("secure flag")
  ) {
    owasp.push("A02 Cryptographic Failures");
  }

  if (
    issue.area === "headers" ||
    text.includes("missing") ||
    text.includes("csp") ||
    text.includes("referrer-policy") ||
    text.includes("permissions-policy") ||
    text.includes("cors") ||
    text.includes("samesite") ||
    text.includes("httponly") ||
    text.includes("secure flag")
  ) {
    owasp.push("A05 Security Misconfiguration");
  }

  if (
    text.includes("unsafe-inline") ||
    text.includes("unsafe-eval") ||
    text.includes("xss") ||
    text.includes("inline script")
  ) {
    owasp.push("A03 Injection");
  }

  if (
    text.includes("publicly reachable") ||
    text.includes("exposed") ||
    text.includes("authorization") ||
    text.includes("access-controlled")
  ) {
    owasp.push("A01 Broken Access Control");
  }

  if (issue.area === "cookies" || text.includes("cookie")) {
    owasp.push("A07 Identification and Authentication Failures");
  }

  if (
    text.includes("publicly reachable") ||
    text.includes("exposed") ||
    text.includes("site is not using https") ||
    text.includes("redirect chain")
  ) {
    mitre.push("Initial Access");
  }

  if (
    text.includes("missing") ||
    text.includes("version") ||
    text.includes("certificate") ||
    text.includes("cors") ||
    text.includes("header")
  ) {
    mitre.push("Reconnaissance");
  }

  if (text.includes("cookie") || text.includes("password")) {
    mitre.push("Credential Access");
  }

  if (text.includes("referrer") || text.includes("inline script") || text.includes("sri")) {
    mitre.push("Collection");
  }

  if (text.includes("httponly") || text.includes("samesite") || text.includes("secure flag")) {
    mitre.push("Defense Evasion");
  }

  return {
    ...issue,
    owasp: unique(owasp),
    mitre: unique(mitre),
  };
}

function scoreAnalysis({ isHttps, headerResults, certificate, cookies, redirects }) {
  let score = 100;
  const headerPenalty = {
    "strict-transport-security": { missing: 10, warning: 4 },
    "content-security-policy": { missing: 12, warning: 4 },
    "x-frame-options": { missing: 3, warning: 2 },
    "x-content-type-options": { missing: 4, warning: 2 },
    "referrer-policy": { missing: 3, warning: 2 },
    "permissions-policy": { missing: 1, warning: 1 },
    "cross-origin-opener-policy": { missing: 1, warning: 1 },
    "cross-origin-resource-policy": { missing: 1, warning: 1 },
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

  const scoredCookies = new Map();
  for (const cookie of cookies) {
    const expiresAt = cookie.expires ? Date.parse(cookie.expires) : NaN;
    if (!Number.isNaN(expiresAt) && expiresAt <= Date.now()) {
      continue;
    }

    const cookieKey = cookie.name.toLowerCase();
    const existing = scoredCookies.get(cookieKey);
    const candidate = existing
      ? {
          secure: existing.secure && cookie.secure,
          httpOnly: existing.httpOnly && cookie.httpOnly,
          sameSite: existing.sameSite && cookie.sameSite,
        }
      : {
          secure: cookie.secure,
          httpOnly: cookie.httpOnly,
          sameSite: cookie.sameSite,
        };
    scoredCookies.set(cookieKey, candidate);
  }

  let cookiePenalty = 0;
  for (const cookie of scoredCookies.values()) {
    const cookieName = cookie.name || "";
    const isLikelyPreferenceCookie = /(locale|lang|language|country|theme|consent|prefs?|preference|visitor|device|did)/i.test(cookieName);
    let perCookiePenalty = 0;
    if (!cookie.secure) perCookiePenalty += 1;
    if (!cookie.httpOnly && !isLikelyPreferenceCookie) perCookiePenalty += 1;
    if (!cookie.sameSite) perCookiePenalty += 1;
    cookiePenalty += Math.min(perCookiePenalty, 4);
  }
  score -= Math.min(cookiePenalty, 8);

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

function buildRemediation(headerResults): RemediationSnippet[] {
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

function scanTls(targetUrl: URL): Promise<CertificateResult> {
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
      ...OBSERVATIONAL_TLS_OPTIONS,
      timeout: TLS_HANDSHAKE_TIMEOUT_MS,
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

function requestOnce(targetUrl: URL, method = "HEAD"): Promise<RequestHeadResult> {
  return requestWithHeaders(targetUrl, method);
}

function requestWithHeaders(targetUrl: URL, method = "HEAD", extraHeaders = {}): Promise<RequestHeadResult> {
  const isHttps = targetUrl.protocol === "https:";
  const transport = isHttps ? https : http;
  const startedAt = Date.now();

  return new Promise((resolve, reject) => {
    const request = transport.request(
      targetUrl,
      {
        method,
        ...OBSERVATIONAL_TLS_OPTIONS,
        headers: {
          "User-Agent": SCANNER_USER_AGENT,
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
    request.setTimeout(REQUEST_TIMEOUT_MS, () => {
      request.destroy(new Error("Request timed out."));
    });
    request.end();
  });
}

function requestText(targetUrl: URL, extraHeaders = {}): Promise<RequestTextResult> {
  const isHttps = targetUrl.protocol === "https:";
  const transport = isHttps ? https : http;

  return new Promise((resolve, reject) => {
    const request = transport.request(
      targetUrl,
      {
        method: "GET",
        ...OBSERVATIONAL_TLS_OPTIONS,
        headers: {
          "User-Agent": SCANNER_USER_AGENT,
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
          if (body.length > TEXT_BODY_LIMIT) {
            body = body.slice(0, TEXT_BODY_LIMIT);
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
    request.setTimeout(REQUEST_TIMEOUT_MS, () => {
      request.destroy(new Error("Request timed out."));
    });
    request.end();
  });
}

function isPrivateIpv4(value: string) {
  const [first, second] = value.split(".").map((part) => Number(part));
  if ([first, second].some((part) => Number.isNaN(part))) {
    return false;
  }

  return (
    first === 10 ||
    first === 127 ||
    first === 0 ||
    (first === 100 && second >= 64 && second <= 127) ||
    (first === 169 && second === 254) ||
    (first === 172 && second >= 16 && second <= 31) ||
    (first === 192 && second === 168) ||
    (first === 198 && (second === 18 || second === 19))
  );
}

function isPrivateIpv6(value: string) {
  const normalized = value.toLowerCase();
  return (
    normalized === "::1" ||
    normalized === "::" ||
    normalized.startsWith("fc") ||
    normalized.startsWith("fd") ||
    normalized.startsWith("fe80:")
  );
}

function isLocalHostname(hostname: string) {
  const normalized = hostname.toLowerCase();
  return (
    normalized === "localhost" ||
    normalized.endsWith(".localhost") ||
    normalized.endsWith(".local") ||
    normalized.endsWith(".internal")
  );
}

function isPrivateAddress(value: string) {
  const ipVersion = net.isIP(value);
  if (ipVersion === 4) {
    return isPrivateIpv4(value);
  }
  if (ipVersion === 6) {
    return isPrivateIpv6(value);
  }
  return false;
}

async function assertPublicRedirectTarget(targetUrl: URL) {
  if (isLocalHostname(targetUrl.hostname) || isPrivateAddress(targetUrl.hostname)) {
    throw new Error(`Redirect target ${targetUrl.hostname} is not public and was blocked.`);
  }

  try {
    const lookups = await dns.lookup(targetUrl.hostname, { all: true });
    if (lookups.length && lookups.every((entry) => isPrivateAddress(entry.address))) {
      throw new Error(`Redirect target ${targetUrl.hostname} resolved only to private or loopback addresses and was blocked.`);
    }
  } catch (error) {
    if (error instanceof Error && error.message.includes("was blocked")) {
      throw error;
    }
  }
}

function normalizeHtmlSignature(body) {
  return body
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .toLowerCase()
    .slice(0, HTML_SIGNATURE_LIMIT);
}

function getHtmlTitle(body) {
  const match = body.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  return match ? match[1].replace(/\s+/g, " ").trim() : null;
}

function extractHtmlTitle(body) {
  const title = getHtmlTitle(body);
  return title ? title.toLowerCase() : null;
}

function summarizeEvidence<T>(values: Array<T | null | undefined | false>, limit = SUMMARY_EVIDENCE_LIMIT): T[] {
  return unique(values).slice(0, limit);
}

function extractRedactedMatch(pattern, html, transform = (value) => value) {
  const match = html.match(pattern);
  return match ? transform(match[0]) : null;
}

function redactToken(value, visible = 8) {
  if (!value || value.length <= visible * 2) {
    return value;
  }
  return `${value.slice(0, visible)}...${value.slice(-visible)}`;
}

function collectPassiveLeakSignals(html, finalUrl, metaGenerator, externalScriptUrls, externalStylesheetUrls) {
  const signals = [];
  const sourceMapReferences = summarizeEvidence([
    ...[...html.matchAll(/sourceMappingURL\s*=\s*([^\s"'<>]+)/gi)].map((match) => match[1]),
    ...externalScriptUrls.filter((url) => /\.map(?:$|[?#])/i.test(url)),
    ...externalStylesheetUrls.filter((url) => /\.map(?:$|[?#])/i.test(url)),
  ]).map((value) => {
    try {
      return new URL(value, finalUrl).toString();
    } catch {
      return value;
    }
  });

  if (sourceMapReferences.length) {
    signals.push({
      category: "source_map",
      severity: "warning",
      title: "Source map references visible",
      detail: "Production page markup exposes source map references. Review whether any public source maps reveal internal code comments, paths, or debugging detail.",
      evidence: sourceMapReferences,
    });
  }

  const configMarkers = summarizeEvidence([
    /__NEXT_DATA__/.test(html) ? "__NEXT_DATA__" : null,
    /__NUXT__/.test(html) ? "__NUXT__" : null,
    /window\.__INITIAL_STATE__/.test(html) ? "window.__INITIAL_STATE__" : null,
    /window\.__PRELOADED_STATE__/.test(html) ? "window.__PRELOADED_STATE__" : null,
    /window\.__APOLLO_STATE__/.test(html) ? "window.__APOLLO_STATE__" : null,
    /window\.__ENV\b/.test(html) ? "window.__ENV" : null,
    /drupalSettings/.test(html) ? "drupalSettings" : null,
    /window\.__remixContext/.test(html) ? "window.__remixContext" : null,
  ]);

  if (configMarkers.length) {
    signals.push({
      category: "client_config",
      severity: "info",
      title: "Client bootstrap data is visible",
      detail: "The page exposes client-side bootstrap or state objects. That is often normal, but it is worth reviewing for internal URLs, feature flags, and environment metadata that should stay private.",
      evidence: configMarkers,
    });
  }

  const publicTokenEvidence = summarizeEvidence([
    extractRedactedMatch(/pk_(live|test)_[A-Za-z0-9]{16,}/, html, redactToken),
    extractRedactedMatch(/AIza[0-9A-Za-z\-_]{20,}/, html, redactToken),
    extractRedactedMatch(/pk\.[A-Za-z0-9\-_]{20,}/, html, redactToken),
    extractRedactedMatch(/https:\/\/[A-Za-z0-9_-]+@[A-Za-z0-9.-]+\.ingest\.sentry\.io\/\d+/, html, redactToken),
    /apiKey["']?\s*:\s*["'][^"']{16,}["']/.test(html) && /projectId["']?\s*:\s*["'][^"']+["']/.test(html)
      ? "Firebase-style client config"
      : null,
  ]);

  if (publicTokenEvidence.length) {
    signals.push({
      category: "public_token",
      severity: "warning",
      title: "Public client-side tokens or DSNs were visible",
      detail: "The page markup includes token- or DSN-like values that may be intended for public use. Review scopes and restrictions so they cannot be misused or confused with secrets.",
      evidence: publicTokenEvidence,
    });
  }

  const versionEvidence = summarizeEvidence([
    metaGenerator && /\d/.test(metaGenerator) ? metaGenerator : null,
    extractRedactedMatch(/\/wp-(?:content|includes)\/[^"' ]+\?ver=\d[\w.-]*/i, html),
    extractRedactedMatch(/content\s*=\s*["'][^"']*(wordpress|drupal|joomla|ghost)[^"']*\d[^"']*["']/i, html),
  ]);

  if (versionEvidence.length) {
    signals.push({
      category: "version_leak",
      severity: "info",
      title: "Version metadata is publicly visible",
      detail: "The fetched page exposes framework or asset version markers. These can help maintenance, but they also make public fingerprinting easier.",
      evidence: versionEvidence,
    });
  }

  return signals;
}

function collectClientExposureSignals(html, finalUrl) {
  const signals = [];
  const htmlLower = html.toLowerCase();
  const isLikelyApiAsset = (value) =>
    /\/assets?\//i.test(value) ||
    /\.(?:css|js|mjs|png|jpe?g|gif|svg|webp|avif|woff2?|ttf|eot)(?:[?#]|$)/i.test(value);

  const rawEndpoints = summarizeEvidence([
    ...[...html.matchAll(/https?:\/\/[^"'`\s<>()]*(?:\/(?:api|graphql|trpc|socket\.io|rpc)[^"'`\s<>()]*)/gi)].map((match) => match[0]),
    ...[...html.matchAll(/["'`](\/(?:api|graphql|trpc|socket\.io|_next\/data)[^"'`<>\s]*)["'`]/gi)].map((match) => match[1]),
    ...[...html.matchAll(/["'`](\/[a-z0-9/_-]*(?:graphql|api|trpc)[^"'`<>\s]*)["'`]/gi)].map((match) => match[1]),
  ], CLIENT_EXPOSURE_EVIDENCE_LIMIT).map((value) => {
    try {
      return new URL(value, finalUrl).toString();
    } catch {
      return value;
    }
  }).filter((value) => !isLikelyApiAsset(value));

  if (rawEndpoints.length) {
    signals.push({
      category: "api_endpoint",
      severity: "info",
      title: "Client-visible API endpoints were referenced",
      detail: "The fetched page exposes endpoint-style paths or URLs in markup or bootstrap data. That is often normal, but it makes the public application surface easier to enumerate.",
      evidence: rawEndpoints,
    });
  }

  const serviceMarkers = summarizeEvidence([
    /supabase/i.test(html) ? "Supabase" : null,
    /algolia/i.test(html) ? "Algolia" : null,
    /sentry/i.test(html) ? "Sentry" : null,
    /firebase/i.test(html) ? "Firebase" : null,
    /segment/i.test(html) ? "Segment" : null,
    /launchdarkly/i.test(html) ? "LaunchDarkly" : null,
    /amplitude/i.test(html) ? "Amplitude" : null,
  ]);

  if (serviceMarkers.length) {
    signals.push({
      category: "service",
      severity: "info",
      title: "Client-integrated services were visible",
      detail: "Public page content reveals named third-party or backend-adjacent client integrations. Review what configuration or identifiers are intentionally exposed.",
      evidence: serviceMarkers,
    });
  }

  const configMarkers = summarizeEvidence([
    /apiBaseUrl/i.test(html) ? "apiBaseUrl" : null,
    /graphqlEndpoint/i.test(html) ? "graphqlEndpoint" : null,
    /sentryDsn/i.test(html) ? "sentryDsn" : null,
    /supabaseUrl/i.test(html) ? "supabaseUrl" : null,
    /projectId/i.test(html) && /apiKey/i.test(html) ? "projectId + apiKey" : null,
    /environment["']?\s*:\s*["'][^"']+/i.test(html) ? "environment" : null,
  ]);

  if (configMarkers.length) {
    signals.push({
      category: "config",
      severity: "info",
      title: "Client configuration markers were visible",
      detail: "The page includes configuration-style keys or bootstrap fields that may reveal how the client talks to backend services.",
      evidence: configMarkers,
    });
  }

  const environmentMarkers = summarizeEvidence([
    /\b(?:environment|env|release)[^"'`\n]{0,32}staging|staging[^"'`\n]{0,32}(?:environment|env|release)/i.test(html)
      ? "staging environment"
      : null,
    /\b(?:environment|env|release)[^"'`\n]{0,32}dev(?:elopment)?|dev(?:elopment)?[^"'`\n]{0,32}(?:environment|env|release)/i.test(html)
      ? "development environment"
      : null,
    /\b(?:environment|env|release)[^"'`\n]{0,32}internal|internal[^"'`\n]{0,32}(?:environment|env|release)/i.test(html)
      ? "internal environment"
      : null,
    /\b(?:environment|env|release)[^"'`\n]{0,32}sandbox|sandbox[^"'`\n]{0,32}(?:environment|env|release)/i.test(html)
      ? "sandbox environment"
      : null,
    /\b(?:environment|env|release)[^"'`\n]{0,32}preview|preview[^"'`\n]{0,32}(?:environment|env|release)/i.test(html)
      ? "preview environment"
      : null,
  ]);

  if (environmentMarkers.length) {
    signals.push({
      category: "environment",
      severity: "warning",
      title: "Environment naming was visible in client content",
      detail: "The fetched page references environment-like labels such as staging, development, preview, or internal. That can be harmless, but it is worth checking for unintended environment leakage.",
      evidence: environmentMarkers,
    });
  }

  return signals;
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
    bodyText.includes("403 forbidden") ||
    bodyText.includes("request forbidden by administrative rules") ||
    bodyText.includes("request blocked") ||
    title.includes("access denied") ||
    title.includes("403 forbidden")
  ) {
    return true;
  }

  return false;
}

async function fetchWithRedirects(initialUrl, redirectLimit = REDIRECT_LIMIT) {
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
    await assertPublicRedirectTarget(currentUrl);
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

function parseSecurityTxt(raw: string, url: URL): SecurityTxtInfo {
  const fields = {
    contact: [] as string[],
    policy: [] as string[],
    acknowledgments: [] as string[],
    encryption: [] as string[],
    hiring: [] as string[],
    preferredLanguages: [] as string[],
    canonical: [] as string[],
    expires: undefined as string | undefined,
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

async function fetchSecurityTxt(finalUrl: URL): Promise<SecurityTxtInfo> {
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

function unique<T>(values: Array<T | null | undefined | false>): T[] {
  return [...new Set(values.filter((value): value is T => Boolean(value)))];
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

function normalizeDiscoveredPath(value, finalUrl: URL): string | null {
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

function rankDiscoveredPaths(paths: Array<string | null | undefined | false>): string[] {
  return unique(paths)
    .sort((left, right) => scorePagePath(right) - scorePagePath(left))
    .slice(0, DISCOVERY_PATH_LIMIT);
}

function addDetectedTechnology(
  target: TechnologyResult[],
  seen: Set<string>,
  name: string,
  category: TechnologyResult["category"],
  evidence: string,
  version?: string | null,
  confidence: IssueConfidence = "medium",
  detection: TechnologyResult["detection"] = "inferred",
) {
  const key = `${name}:${category}`;
  if (seen.has(key)) {
    return;
  }
  seen.add(key);
  target.push({
    name,
    category,
    evidence,
    version: version || null,
    confidence,
    detection,
  });
}

function detectHtmlTechnologies(html, finalUrl, metaGenerator, externalScriptUrls, externalStylesheetUrls) {
  const technologies = [];
  const seen = new Set<string>();
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
  if (allUrls.some((url) => url.includes("adobedtm.com") || url.includes("adobedc.net"))) {
    addDetectedTechnology(technologies, seen, "Adobe Experience Cloud", "network", "Detected from Adobe tag or delivery assets");
  }
  if (allUrls.some((url) => url.includes("contentsquare") || url.includes("decibelinsight"))) {
    addDetectedTechnology(technologies, seen, "Contentsquare / Decibel", "network", "Detected from session analytics assets");
  }
  if (allUrls.some((url) => url.includes("imperva") || url.includes("incapsula"))) {
    addDetectedTechnology(technologies, seen, "Imperva", "security", "Detected from Imperva / Incapsula assets");
  }
  if (allUrls.some((url) => url.includes("onetrust"))) {
    addDetectedTechnology(technologies, seen, "OneTrust", "security", "Detected from OneTrust consent assets");
  }
  if (allUrls.some((url) => url.includes("braintree"))) {
    addDetectedTechnology(technologies, seen, "Braintree", "security", "Detected from payments-related assets");
  }
  if (allUrls.some((url) => url.includes("sentry.io"))) {
    addDetectedTechnology(technologies, seen, "Sentry", "security", "Detected from client monitoring assets");
  }
  if (allUrls.some((url) => url.includes("googletagmanager.com"))) {
    addDetectedTechnology(technologies, seen, "Tag Management", "network", "Detected from tag-manager assets");
  }
  if (allUrls.some((url) => url.includes("cloudfront.net"))) {
    addDetectedTechnology(technologies, seen, "Amazon CloudFront", "network", "Detected from asset hosting domain");
  }
  if (finalUrl.hostname.endsWith(".pages.dev")) {
    addDetectedTechnology(technologies, seen, "Cloudflare Pages", "hosting", "Derived from final hostname", null, "low", "inferred");
  }

  return technologies;
}

function analyzeAiSurface(html, finalUrl, externalScriptUrls, firstPartyPaths) {
  const htmlLower = html.toLowerCase();
  const vendors = [];
  const seen = new Set<string>();
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
      pattern: /\$crisp|crisp\.chat|client\.crisp|go\.crisp|crisp-im/i,
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
  const privacySignals = [];
  const governanceSignals = [];

  if (/do not share sensitive|may be inaccurate|ai-generated|generative ai|assistant may/i.test(htmlLower)) {
    disclosures.push("The page appears to include AI usage or safety disclosure language.");
  }
  if (/privacy policy/i.test(htmlLower) && /ai/i.test(htmlLower)) {
    disclosures.push("AI-related language appears alongside privacy-policy content.");
  }
  if (/do not share personal|do not enter personal|do not submit sensitive|avoid sharing confidential/i.test(htmlLower)) {
    privacySignals.push("The page appears to warn users not to enter sensitive or personal data.");
  }
  if (/data may be used to improve|used to train|retained for|stored to improve/i.test(htmlLower)) {
    privacySignals.push("The page appears to disclose AI-related retention or model-improvement language.");
  }
  if (/human review|reviewed by humans|monitored for quality/i.test(htmlLower)) {
    governanceSignals.push("The page appears to disclose human review or quality-monitoring language.");
  }
  if (/terms of use|acceptable use|responsible ai|ai principles/i.test(htmlLower) && /ai/i.test(htmlLower)) {
    governanceSignals.push("The page appears to reference AI governance or acceptable-use language.");
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
  if (highConfidenceAiSignals && !privacySignals.length) {
    issues.push("AI-related signals were detected, but no obvious data-handling or privacy guidance was found on the fetched page.");
  }
  if (privacySignals.length) {
    strengths.push("AI-related privacy guidance appears to be visible on the fetched page.");
  }
  if (governanceSignals.length) {
    strengths.push("AI governance or human-review language appears to be visible on the fetched page.");
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
    privacySignals,
    governanceSignals,
    issues,
    strengths,
  };
}

function classifyThirdPartyProvider(domain: string): Omit<ThirdPartyProvider, "domain"> {
  const lower = domain.toLowerCase();
  const providers: Array<{
    pattern: RegExp;
    name: string;
    category: ThirdPartyProvider["category"];
    risk: ThirdPartyProvider["risk"];
    evidence: string;
  }> = [
    { pattern: /(google-analytics|googletagmanager|doubleclick|omtrdc|adobedtm|adobedc|analytics)/, name: "Analytics / Tagging", category: "analytics", risk: "medium", evidence: "Detected from third-party analytics or tag-management assets" },
    { pattern: /(onetrust|cookiebot|usercentrics)/, name: "Consent Management", category: "consent", risk: "low", evidence: "Detected from consent-management assets" },
    { pattern: /(intercom|drift|zendesk|zopim|hubspot|freshchat|crisp|sprinklr)/, name: "Support / Chat", category: "support", risk: "medium", evidence: "Detected from public support or chat tooling" },
    { pattern: /(openai|anthropic|gemini|vertex|copilot|wizdom\.ai)/, name: "AI / Assistant Vendor", category: "ai", risk: "high", evidence: "Detected from AI-related scripts, assets, or public assistant tooling" },
    { pattern: /(contentsquare|decibelinsight|hotjar|fullstory|medallia)/, name: "Session Replay / Experience Analytics", category: "session_replay", risk: "high", evidence: "Detected from session-replay or detailed experience-analytics assets" },
    { pattern: /(braintree|paypal|cardinalcommerce|arcot|3dsecure|tsys|payment|payments)/, name: "Payments / Verification", category: "payments", risk: "medium", evidence: "Detected from payments or challenge-flow assets" },
    { pattern: /(facebook|twitter|linkedin|tiktok|pinterest|reddit|youtube|snapchat|instagram)/, name: "Social / Advertising", category: "social", risk: "medium", evidence: "Detected from social, embedded media, or advertising assets" },
    { pattern: /(ads|adservice|amazon-adsystem|smartadserver|pubmatic|gumgum|teads|casalemedia|openx|lijit|bidswitch)/, name: "Advertising", category: "ads", risk: "high", evidence: "Detected from advertising or programmatic asset domains" },
    { pattern: /(cloudfront|fastly|akamai|cloudflare|jsdelivr|cdnjs)/, name: "CDN / Delivery", category: "cdn", risk: "low", evidence: "Detected from CDN or static-delivery domains" },
    { pattern: /(imperva|incapsula|sucuri|sentry)/, name: "Security / Monitoring", category: "security", risk: "low", evidence: "Detected from security, edge-protection, or monitoring assets" },
  ];

  const match = providers.find((provider) => provider.pattern.test(lower));
  if (match) {
    return {
      name: match.name,
      category: match.category,
      risk: match.risk,
      evidence: match.evidence,
    };
  }
  return {
    name: domain,
    category: "other",
    risk: "medium",
    evidence: "Detected from third-party assets loaded by the page",
  };
}

function getSiteDomain(hostname) {
  const lower = hostname.toLowerCase();
  const parts = lower.split(".").filter(Boolean);
  if (parts.length <= 2) {
    return lower;
  }

  const compoundSuffixes = new Set(["co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "co.nz"]);
  const suffix = parts.slice(-2).join(".");
  if (compoundSuffixes.has(suffix) && parts.length >= 3) {
    return parts.slice(-3).join(".");
  }

  return parts.slice(-2).join(".");
}

function analyzeThirdPartyTrust(finalUrl, htmlSecurity, aiSurface: AiSurfaceInfo) {
  const siteDomain = getSiteDomain(finalUrl.hostname);
  const thirdPartyDomains = unique([
    ...(htmlSecurity.externalScriptDomains || []),
    ...(htmlSecurity.externalStylesheetDomains || []),
  ]).filter((domain) => domain && getSiteDomain(domain) !== siteDomain);

  const providers = thirdPartyDomains.map((domain) => {
    const classification = classifyThirdPartyProvider(domain);
    return {
      domain,
      ...classification,
    };
  });

  const highRiskProviders = providers.filter((provider) => provider.risk === "high").length;
  const issues = [];
  const strengths = [];

  if (highRiskProviders >= 3) {
    issues.push("The page relies on several high-trust or high-observability third parties, which expands data exposure and review scope.");
  } else if (highRiskProviders > 0) {
    issues.push("The page includes high-trust third-party providers that deserve explicit review and ownership.");
  }
  if ((htmlSecurity.missingSriScriptUrls || []).length > 0) {
    issues.push("Some third-party scripts are loaded without Subresource Integrity.");
  }
  if (providers.some((provider) => provider.category === "session_replay")) {
    issues.push("Session replay or experience analytics tooling appears to be present.");
  }
  if (providers.some((provider) => provider.category === "ai") && !aiSurface.disclosures.length) {
    issues.push("AI-related third-party tooling appears present without obvious on-page disclosure language.");
  }

  if (providers.some((provider) => provider.category === "consent")) {
    strengths.push("A consent-management provider appears to be present.");
  }
  if (providers.length > 0 && highRiskProviders === 0) {
    strengths.push("Third-party footprint appears present but mostly concentrated in lower-risk delivery, monitoring, or consent tooling.");
  }
  if (!providers.length) {
    strengths.push("No obvious third-party script or stylesheet domains were detected on the fetched page.");
  }

  const summary = !providers.length
    ? "Minimal visible third-party footprint on the fetched page."
    : highRiskProviders > 0
      ? "The page depends on several third-party providers that increase trust and data-flow complexity."
      : "The page uses third-party providers, but the visible footprint is weighted more toward delivery and operational tooling.";

  return {
    totalProviders: providers.length,
    highRiskProviders,
    providers,
    issues,
    strengths,
    summary,
  };
}

function buildExecutiveSummary(result): ExecutiveSummaryInfo {
  const missingHeaderCount = result.headers.filter((header) => header.status === "missing").length;
  const highRiskThirdParties = result.thirdPartyTrust.highRiskProviders;
  const posture = result.score >= 80 ? "strong" : result.score >= 60 ? "mixed" : "weak";

  let mainRisk = "Browser-layer hardening gaps are the main visible risk.";
  if (highRiskThirdParties >= 3) {
    mainRisk = "Third-party trust and data-flow sprawl are the main visible risk.";
  } else if (result.aiSurface.detected && result.aiSurface.issues.length > 0) {
    mainRisk = "Public AI or automation signals are visible without much supporting disclosure or privacy guidance.";
  } else if (result.domainSecurity.issues.length > 0 || result.publicSignals.issues.length > 0) {
    mainRisk = "Public trust and domain hygiene signals need attention alongside the web posture.";
  }

  const takeaways = [];
  takeaways.push(
    missingHeaderCount > 0
      ? `${missingHeaderCount} browser-facing protections are missing or weak on the scanned response.`
      : "Core browser-facing protections look consistently present on the scanned response.",
  );
  takeaways.push(
    result.thirdPartyTrust.totalProviders > 0
      ? `${result.thirdPartyTrust.totalProviders} third-party provider${result.thirdPartyTrust.totalProviders === 1 ? " was" : "s were"} detected, including ${highRiskThirdParties} higher-risk integration${highRiskThirdParties === 1 ? "" : "s"}.`
      : "No obvious third-party script or stylesheet providers were detected on the fetched page.",
  );
  takeaways.push(
    result.aiSurface.detected
      ? `${result.aiSurface.vendors.length || result.aiSurface.discoveredPaths.length} public AI or automation signal${(result.aiSurface.vendors.length || result.aiSurface.discoveredPaths.length) === 1 ? " was" : "s were"} detected.`
      : "No obvious public-facing AI or automation surface was detected.",
  );

  const overview =
    posture === "strong"
      ? "External posture looks broadly solid, with only a few areas that still deserve tuning."
      : posture === "mixed"
        ? "External posture looks operationally mature in places, but the report still shows several areas that need tightening."
        : "External posture shows multiple weaknesses that make the site look less well hardened than a mature public-facing platform should.";

  return {
    overview,
    mainRisk,
    posture,
    takeaways,
  };
}

function mergeTechnologies(...groups: Array<TechnologyResult[] | null | undefined>) {
  const merged: TechnologyResult[] = [];
  const byKey = new Map();
  const confidenceRank = { high: 3, medium: 2, low: 1 };

  for (const group of groups) {
    for (const technology of group || []) {
      const key = `${technology.name}:${technology.category}`;
      const existing = byKey.get(key);
      if (!existing) {
        byKey.set(key, technology);
        merged.push(technology);
        continue;
      }

      const existingScore =
        confidenceRank[existing.confidence] + (existing.detection === "observed" ? 10 : 0);
      const nextScore =
        confidenceRank[technology.confidence] + (technology.detection === "observed" ? 10 : 0);

      if (nextScore > existingScore) {
        const index = merged.indexOf(existing);
        if (index >= 0) {
          merged[index] = technology;
        }
        byKey.set(key, technology);
      }
    }
  }

  return merged;
}

async function fetchHtmlDocument(finalUrl) {
  const response = await requestText(finalUrl);
  const contentType = headerValue(response.headers, "content-type") || "";
  if (!contentType.toLowerCase().includes("text/html")) {
    return null;
  }

  const html = response.body;
  return {
    html,
    pageTitle: getHtmlTitle(html),
    signature: normalizeHtmlSignature(html),
  };
}

function analyzeHtmlSecurity(finalUrl: URL, document: { html: string; pageTitle: string | null } | null): HtmlSecurityInfo {
  try {
    if (!document) {
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
        passiveLeakSignals: [],
        clientExposureSignals: [],
        detectedTechnologies: [],
        aiSurface: {
          detected: false,
          assistantVisible: false,
          aiPageSignals: [],
          vendors: [],
          discoveredPaths: [],
          disclosures: [],
          privacySignals: [],
          governanceSignals: [],
          issues: ["Primary response was not HTML, so AI surface inspection was skipped."],
          strengths: [],
        },
        issues: ["Primary response was not HTML, so page content inspection was skipped."],
        strengths: [],
      };
    }

    const html = document.html;
    const issues = [];
    const strengths = [];
    const $ = cheerio.load(html);
    const pageTitle = document.pageTitle || $("title").first().text().trim() || null;
    const metaGenerator = $('meta[name="generator"]').attr("content") || null;

    const forms = $("form")
      .toArray()
      .map((form) => {
        const element = $(form);
        const action = element.attr("action") || null;
        const method = (element.attr("method") || "GET").toUpperCase();
        const resolvedAction = action ? new URL(action, finalUrl).toString() : finalUrl.toString();
        return {
          action,
          method,
          insecureSubmission: resolvedAction.startsWith("http://"),
          hasPasswordField: element.find('input[type="password"]').length > 0,
        };
      });

    const scriptElements = $("script").toArray();
    const externalScriptUrls = scriptElements
      .map((script) => $(script).attr("src"))
      .filter(Boolean)
      .map((src) => new URL(src as string, finalUrl).toString());
    const externalStylesheetUrls = $('link[rel~="stylesheet"]')
      .toArray()
      .map((link) => $(link).attr("href"))
      .filter(Boolean)
      .map((href) => new URL(href as string, finalUrl).toString());
    const firstPartyPaths = rankDiscoveredPaths([
      ...$("a[href]")
        .toArray()
        .map((anchor) => normalizeDiscoveredPath($(anchor).attr("href"), finalUrl)),
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
    const inlineScriptCount = scriptElements.filter((script) => !$(script).attr("src")).length;
    const inlineStyleCount = $("style").length;
    const missingSriScriptUrls = scriptElements
      .map((script) => {
        const element = $(script);
        const src = element.attr("src");
        if (!src) {
          return null;
        }
        const resolved = new URL(src, finalUrl);
        if (resolved.hostname === finalUrl.hostname || element.attr("integrity")) {
          return null;
        }
        return resolved.toString();
      })
      .filter(Boolean);
    const passiveLeakSignals = collectPassiveLeakSignals(
      html,
      finalUrl,
      metaGenerator || null,
      externalScriptUrls,
      externalStylesheetUrls,
    );
    const clientExposureSignals = collectClientExposureSignals(html, finalUrl);

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
    for (const signal of passiveLeakSignals) {
      if (signal.severity === "warning") {
        issues.push(signal.title);
      }
    }
    for (const signal of clientExposureSignals) {
      if (signal.severity === "warning") {
        issues.push(signal.title);
      }
    }
    if (firstPartyPaths.length) {
      strengths.push(`Discovered ${firstPartyPaths.length} same-origin navigation paths for low-noise follow-up scans.`);
    }
    if (passiveLeakSignals.length) {
      strengths.push(`Passive pre-check identified ${passiveLeakSignals.length} leak or fingerprinting signal${passiveLeakSignals.length === 1 ? "" : "s"} worth review.`);
    }
    if (clientExposureSignals.length) {
      strengths.push(`Client-side markup exposed ${clientExposureSignals.length} API or configuration signal${clientExposureSignals.length === 1 ? "" : "s"} for review.`);
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
      passiveLeakSignals,
      clientExposureSignals,
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
      passiveLeakSignals: [],
      clientExposureSignals: [],
      detectedTechnologies: [],
      aiSurface: {
        detected: false,
        assistantVisible: false,
        aiPageSignals: [],
        vendors: [],
        discoveredPaths: [],
        disclosures: [],
        privacySignals: [],
        governanceSignals: [],
        issues: [error instanceof Error ? error.message : "AI surface inspection failed."],
        strengths: [],
      },
      issues: [error instanceof Error ? error.message : "HTML inspection failed."],
      strengths: [],
    };
  }
}

export function analyzeHtmlDocument(input: string | URL, html: string): HtmlSecurityInfo {
  const finalUrl = typeof input === "string" ? new URL(input) : input;
  const pageTitle = extractHtmlTitle(html);
  return analyzeHtmlSecurity(finalUrl, { html, pageTitle });
}

function parseRobotsSitemaps(body: string): string[] {
  return unique(
    body
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter((line) => /^sitemap:/i.test(line))
      .map((line) => line.replace(/^sitemap:\s*/i, "").trim()),
  );
}

function parseSitemapPaths(xml: string, finalUrl: URL): string[] {
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

async function fetchPublicSignals(host: string): Promise<PublicSignalsInfo> {
  const apexHost = host.startsWith("www.") ? host.slice(4) : host;
  const sourceUrl = `https://hstspreload.org/api/v2/status?domain=${encodeURIComponent(apexHost)}`;
  const fallback: PublicSignalsInfo = {
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

    let status: PublicSignalsInfo["hstsPreload"]["status"] = "not_preloaded";
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
        if (response.statusCode === 405) {
          response = await requestOnce(probeUrl, "GET");
        } else if (response.statusCode === 401 || response.statusCode === 403) {
          response = await requestText(probeUrl);
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
        } else if (response.statusCode >= 500) {
          finding = "error";
          detail = "Discovery file path triggered a server-side error, so availability could not be determined cleanly.";
        } else {
          detail = "Discovery file not found.";
        }
      } else if (response.statusCode >= 200 && response.statusCode < 300) {
        finding = "exposed";
        detail = "Sensitive path returned a successful response.";
        issues.push(`${probe.label} may be exposed at ${probe.path}.`);
      } else if (response.statusCode === 401 || response.statusCode === 403) {
        const contentType = headerValue(response.headers, "content-type") || "";
        const blockedByGenericRules =
          typeof response.body === "string" &&
          contentType.includes("text/html") &&
          isAccessDeniedHtml(response.headers, response.body);

        if (blockedByGenericRules) {
          finding = "blocked";
          detail = "Probe was blocked by generic server or edge protection rules. This does not confirm the sensitive file exists.";
          strengths.push(`${probe.label} probe was blocked by generic protection.`);
        } else {
          finding = "interesting";
          detail = "Sensitive path may exist but is access-controlled.";
          strengths.push(`${probe.label} appears access-controlled.`);
        }
      } else if (response.statusCode >= 500) {
        finding = "error";
        detail = "Sensitive path triggered a server-side error, so the path may exist or be handled unexpectedly.";
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
      const detail = formatErrorMessage(error) || "Probe failed unexpectedly.";
      probes.push({
        label: probe.label,
        path: probe.path,
        statusCode: 0,
        finalUrl: probeUrl.toString(),
        finding: "error",
        detail,
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

async function analyzeCorsSecurity(finalUrl: URL, responseHeaders: ResponseHeaders): Promise<CorsSecurityInfo> {
  let optionsResponse: RequestHeadResult = { statusCode: 0, headers: {}, elapsedMs: 0 };
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

async function analyzeApiSurface(finalUrl, homepageContext = null) {
  const probes = [];
  const issues = [];
  const strengths = [];
  const homepageSignature = homepageContext?.signature || "";
  const homepageTitle = homepageContext?.pageTitle || null;

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
      } else if (response.statusCode === 405) {
        classification = "interesting";
        detail = "Endpoint appears to exist, but it does not allow the request method used by this probe.";
      } else if (response.statusCode === 429) {
        classification = "restricted";
        detail = "Endpoint appears rate-limited, so availability could not be assessed cleanly.";
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
        } else if ((contentType || "").includes("text/html")) {
          classification = "fallback";
          detail = classifyHtmlApiFallback(
            probe.path,
            finalUrl,
            resolvedUrl,
            response.body,
            homepageSignature,
            homepageTitle,
          )
            ? "Endpoint appears to return the site's standard HTML page rather than an API response."
            : "Endpoint returns an HTML page rather than a machine-readable API response.";
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

async function safeResolve<T>(operation: () => Promise<T>): Promise<T | null> {
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

async function analyzeDomainSecurity(host: string): Promise<DomainSecurityInfo> {
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

async function requestJson(targetUrl: URL, extraHeaders = {}) {
  const response = await requestText(targetUrl, {
    Accept: "application/json,text/plain;q=0.9,*/*;q=0.1",
    ...extraHeaders,
  });
  return {
    ...response,
    json: response.body ? JSON.parse(response.body) : null,
  };
}

async function analyzeUrlCore(input: string | URL, options: AnalyzeTargetOptions = {}) {
  const { includeCertificate = true } = options;
  let normalizedUrl = input instanceof URL ? input : normalizeUrl(input);
  let requestData: Awaited<ReturnType<typeof fetchWithRedirects>>;

  try {
    requestData = await fetchWithRedirects(normalizedUrl);
  } catch (error) {
    if (normalizedUrl.protocol === "https:" && shouldRetryOverHttp(error)) {
      const fallbackUrl = new URL(normalizedUrl);
      fallbackUrl.protocol = "http:";
      normalizedUrl = fallbackUrl;
      try {
        requestData = await fetchWithRedirects(normalizedUrl);
      } catch (fallbackError) {
        throw new Error(
          `HTTPS failed and the site did not respond cleanly over HTTP either: ${formatErrorMessage(fallbackError)}`,
        );
      }
    } else {
      throw error;
    }
  }
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
      owasp: [],
      mitre: [],
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
            owasp: [],
            mitre: [],
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
        owasp: [],
        mitre: [],
      })),
    );
  }

  const normalizedIssues = issues.map(classifyIssueTaxonomy);

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
    issues: normalizedIssues,
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
  const seen = new Set<string>();

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

export async function analyzeUrl(input: string): Promise<AnalysisResult> {
  const result = await analyzeUrlCore(input, { includeCertificate: true });
  const finalUrl = new URL(result.finalUrl);
  const ctDiscoveryPromise = fetchCtDiscovery(result.host, requestJson);
  let htmlDocument = null;
  try {
    htmlDocument = await fetchHtmlDocument(finalUrl);
  } catch {
    htmlDocument = null;
  }
  const htmlSecurity = analyzeHtmlSecurity(finalUrl, htmlDocument);
  const discovery = await collectDiscoveryPaths(finalUrl, htmlSecurity);
  const publicSignals = await fetchPublicSignals(result.host);
  const thirdPartyTrust = analyzeThirdPartyTrust(finalUrl, htmlSecurity, htmlSecurity.aiSurface);
  const identityProvider = await analyzeIdentityProvider(
    finalUrl,
    result.redirects,
    htmlSecurity,
    htmlDocument?.html || null,
    requestJson,
  );
  const ctDiscovery = await ctDiscoveryPromise;

  const enrichedResult = {
    ...result,
    technologies: mergeTechnologies(result.technologies, htmlSecurity.detectedTechnologies),
    crawl: await crawlRelatedPages(result, discovery),
    securityTxt: await fetchSecurityTxt(finalUrl),
    domainSecurity: await analyzeDomainSecurity(result.host),
    identityProvider,
    ctDiscovery,
    htmlSecurity,
    aiSurface: htmlSecurity.aiSurface,
    thirdPartyTrust,
    exposure: await analyzeExposure(finalUrl),
    corsSecurity: await analyzeCorsSecurity(finalUrl, result.rawHeaders),
    apiSurface: await analyzeApiSurface(finalUrl, htmlDocument),
    publicSignals,
  };

  return {
    ...enrichedResult,
    executiveSummary: buildExecutiveSummary(enrichedResult),
  };
}

export const analyzeTarget = analyzeUrl;
export { formatErrorMessage };
export type { AnalysisResult, AnalyzeTargetOptions, HtmlSecurityInfo } from "./types";
