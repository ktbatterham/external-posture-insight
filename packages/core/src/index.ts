import http from "node:http";
import https from "node:https";
import dns from "node:dns/promises";
import net from "node:net";
import tls from "node:tls";
import { URL } from "node:url";
import * as cheerio from "cheerio";
import { fetchCtDiscovery } from "./ctDiscovery.js";
import {
  analyzeAiSurface,
  analyzeThirdPartyTrust,
  buildExecutiveSummary,
  detectHtmlTechnologies,
  mergeTechnologies,
} from "./htmlInsights.js";
import { analyzeIdentityProvider } from "./identityProvider.js";
import {
  analyzeApiSurface,
  analyzeCorsSecurity,
  analyzeExposure,
  fetchPublicSignals,
} from "./surfaceEnrichment.js";
import {
  CLIENT_EXPOSURE_EVIDENCE_LIMIT,
  DISCOVERY_PATH_LIMIT,
  HTML_SIGNATURE_LIMIT,
  REDIRECT_LIMIT,
  REQUEST_TIMEOUT_MS,
  SUMMARY_EVIDENCE_LIMIT,
  TEXT_BODY_LIMIT,
  TLS_HANDSHAKE_TIMEOUT_MS,
} from "./scannerConfig.js";
import { collectLibraryFingerprints, fetchLibraryRiskSignals } from "./libraryRisk.js";
import { unique } from "./utils.js";
import { analyzeWafFingerprint } from "./wafFingerprint.js";
import type {
  AnalysisResult,
  AnalyzeTargetOptions,
  CertificateResult,
  CorsSecurityInfo,
  DomainSecurityInfo,
  HtmlSecurityInfo,
  PublicSignalsInfo,
  RemediationSnippet,
  SecurityTxtInfo,
} from "./types.js";

type ResponseHeaders = http.IncomingHttpHeaders;

const SCANNER_USER_AGENT = "ExternalPostureInsight/1.0";

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
    text.includes("outdated component") ||
    text.includes("known advis") ||
    text.includes("osv") ||
    text.includes("vulnerab") ||
    text.includes("library ")
  ) {
    owasp.push("A06 Vulnerable and Outdated Components");
  }

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

function buildLibraryRiskIssues(libraryRiskSignals) {
  return libraryRiskSignals.map((signal) => {
    const highestSeverity = signal.vulnerabilities.some((item) => item.severity === "critical" || item.severity === "high")
      ? "critical"
      : signal.vulnerabilities.some((item) => item.severity === "moderate")
        ? "warning"
        : "info";
    const references = signal.vulnerabilities
      .flatMap((item) => item.aliases)
      .filter(Boolean)
      .slice(0, 3);

    return {
      severity: highestSeverity,
      area: "headers",
      title: `${signal.packageName} ${signal.version} has known advisories`,
      detail: `OSV returned ${signal.vulnerabilities.length} advisory match${signal.vulnerabilities.length === 1 ? "" : "es"} for this publicly referenced library version.${references.length ? ` References: ${references.join(", ")}.` : ""}`,
      confidence: signal.confidence,
      source: "observed",
      owasp: [],
      mitre: [],
    };
  });
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

async function assertPublicRequestTarget(targetUrl: URL) {
  if (isLocalHostname(targetUrl.hostname) || isPrivateAddress(targetUrl.hostname)) {
    throw new Error(`Target ${targetUrl.hostname} is not public and was blocked.`);
  }

  if (net.isIP(targetUrl.hostname)) {
    return;
  }

  const lookups = await dns.lookup(targetUrl.hostname, { all: true });
  if (!lookups.length || lookups.some((entry) => isPrivateAddress(entry.address))) {
    throw new Error(`Target ${targetUrl.hostname} did not resolve exclusively to public IP addresses.`);
  }
}

async function requestWithHeaders(targetUrl: URL, method = "HEAD", extraHeaders = {}): Promise<RequestHeadResult> {
  await assertPublicRequestTarget(targetUrl);
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

async function requestText(targetUrl: URL, extraHeaders = {}): Promise<RequestTextResult> {
  await assertPublicRequestTarget(targetUrl);
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
        libraryFingerprints: [],
        libraryRiskSignals: [],
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
      libraryFingerprints: collectLibraryFingerprints(externalScriptUrls),
      libraryRiskSignals: [],
      detectedTechnologies: detectHtmlTechnologies(
        html,
        finalUrl,
        metaGenerator || null,
        externalScriptUrls,
        externalStylesheetUrls,
      ),
      aiSurface: analyzeAiSurface(html, externalScriptUrls, firstPartyPaths),
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
      libraryFingerprints: [],
      libraryRiskSignals: [],
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
    dsByHost,
  ] = await Promise.all([
    Promise.all(candidateHosts.map((candidate) => safeResolve(() => dns.resolveMx(candidate)))),
    Promise.all(candidateHosts.map((candidate) => safeResolve(() => dns.resolveNs(candidate)))),
    Promise.all(candidateHosts.map((candidate) => safeResolve(() => dns.resolveTxt(candidate)))),
    Promise.all(candidateHosts.map((candidate) => safeResolve(() => dns.resolveTxt(`_dmarc.${candidate}`)))),
    Promise.all(candidateHosts.map((candidate) => safeResolve(() => dns.resolveCaa(candidate)))),
    Promise.all(candidateHosts.map((candidate) => safeResolve(() => dns.resolveTxt(`_mta-sts.${candidate}`)))),
    Promise.all(candidateHosts.map((candidate) => safeResolve(() => dns.resolve(candidate, "DS")))),
  ]);

  const pickFirst = (values) => values.find((value) => value && value.length) || null;
  const mxRecordsRaw = pickFirst(mxByHost) || [];
  const nsRecordsRaw = pickFirst(nsByHost) || [];
  const txtRoot = pickFirst(txtRootByHost) || [];
  const txtDmarc = pickFirst(txtDmarcByHost) || [];
  const caaRaw = pickFirst(caaByHost) || [];
  const txtMtaSts = pickFirst(txtMtaStsByHost) || [];
  const dsRaw = pickFirst(dsByHost) || [];

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
  const dsRecords = (dsRaw || []).map((record) => `${record.keyTag} ${record.algorithm} ${record.digestType} ${record.digest}`);
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

  if (!dsRecords.length) {
    issues.push("No DNSSEC DS records detected at the domain apex.");
  } else {
    strengths.push("DNSSEC DS records are published.");
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
    dnssec: {
      enabled: dsRecords.length > 0,
      dsRecords,
      status: dsRecords.length > 0 ? "signed" : "not_signed",
    },
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
  const ctDiscoveryPromise = fetchCtDiscovery(result.host, requestJson, requestText);
  let htmlDocument = null;
  try {
    htmlDocument = await fetchHtmlDocument(finalUrl);
  } catch {
    htmlDocument = null;
  }
  const baseHtmlSecurity = analyzeHtmlSecurity(finalUrl, htmlDocument);
  const libraryRiskSignals = await fetchLibraryRiskSignals(baseHtmlSecurity.libraryFingerprints);
  const htmlSecurity = {
    ...baseHtmlSecurity,
    libraryRiskSignals,
    issues: [
      ...baseHtmlSecurity.issues,
      ...libraryRiskSignals.map(
        (signal) =>
          `${signal.packageName} ${signal.version} matched ${signal.vulnerabilities.length} OSV advisor${signal.vulnerabilities.length === 1 ? "y" : "ies"} from public script references.`,
      ),
    ],
    strengths:
      baseHtmlSecurity.libraryFingerprints.length > 0 && libraryRiskSignals.length === 0
        ? [...baseHtmlSecurity.strengths, "No OSV advisory matches were found for the explicitly versioned client libraries detected on the fetched page."]
        : baseHtmlSecurity.strengths,
  };
  const discovery = await collectDiscoveryPaths(finalUrl, htmlSecurity);
  const publicSignals = await fetchPublicSignals(result.host, { requestText });
  const thirdPartyTrust = analyzeThirdPartyTrust(finalUrl, htmlSecurity, htmlSecurity.aiSurface);
  const ctDiscovery = await ctDiscoveryPromise;
  const identityProvider = await analyzeIdentityProvider(
    finalUrl,
    result.redirects,
    htmlSecurity,
    htmlDocument?.html || null,
    requestJson,
    ctDiscovery,
  );
  const wafFingerprint = analyzeWafFingerprint(
    finalUrl,
    result.rawHeaders,
    htmlDocument?.html || null,
    result.redirects,
  );

  const enrichedResult = {
    ...result,
    issues: [...result.issues, ...buildLibraryRiskIssues(libraryRiskSignals).map(classifyIssueTaxonomy)],
    technologies: mergeTechnologies(result.technologies, htmlSecurity.detectedTechnologies),
    crawl: await crawlRelatedPages(result, discovery),
    securityTxt: await fetchSecurityTxt(finalUrl),
    domainSecurity: await analyzeDomainSecurity(result.host),
    identityProvider,
    ctDiscovery,
    htmlSecurity,
    aiSurface: htmlSecurity.aiSurface,
    thirdPartyTrust,
    wafFingerprint,
    exposure: await analyzeExposure(finalUrl, {
      exposureProbes: EXPOSURE_PROBES,
      requestOnce,
      requestText,
      fetchWithRedirects,
      headerValue,
      formatErrorMessage,
      isAccessDeniedHtml,
    }),
    corsSecurity: await analyzeCorsSecurity(finalUrl, result.rawHeaders, {
      requestWithHeaders,
      headerValue,
    }),
    apiSurface: await analyzeApiSurface(finalUrl, htmlDocument, {
      apiSurfaceProbes: API_SURFACE_PROBES,
      requestText,
      fetchWithRedirects,
      headerValue,
      isAccessDeniedHtml,
      classifyHtmlApiFallback,
    }),
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
