import { URL } from "node:url";
import * as cheerio from "cheerio";
import { scanTls } from "./certificate.js";
import { parseSetCookie } from "./cookie-analysis.js";
import { fetchCtDiscovery } from "./ctDiscovery.js";
import { analyzeDomainSecurity } from "./domain-security.js";
import {
  analyzeHeaders,
  buildLibraryRiskIssues,
  buildRawHeaders,
  buildRemediation,
  classifyIssueTaxonomy,
  SECURITY_HEADERS,
} from "./header-analysis.js";
import {
  analyzeAiSurface,
  analyzeThirdPartyTrust,
  buildExecutiveSummary,
  detectHtmlTechnologies,
  mergeTechnologies,
} from "./htmlInsights.js";
import {
  classifyHtmlApiFallback,
  collectClientExposureSignals,
  collectPassiveLeakSignals,
  extractHtmlTitle,
  getHtmlTitle,
  isAccessDeniedHtml,
  normalizeHtmlSignature,
} from "./html-extraction.js";
import { analyzeIdentityProvider } from "./identityProvider.js";
import {
  analyzeApiSurface,
  analyzeCorsSecurity,
  analyzeExposure,
  fetchPublicSignals,
} from "./surfaceEnrichment.js";
import { collectLibraryFingerprints, fetchLibraryRiskSignals } from "./libraryRisk.js";
import {
  fetchWithRedirects,
  requestJson,
  requestOnce,
  requestText,
  requestWithHeaders,
} from "./network.js";
import { normalizeDiscoveredPath, rankDiscoveredPaths } from "./path-discovery.js";
import { scoreAnalysis } from "./scoring.js";
import { fetchSecurityTxt } from "./security-txt.js";
import { detectTechnologies } from "./technology-detection.js";
import { headerValue, unique } from "./utils.js";
import { analyzeWafFingerprint } from "./wafFingerprint.js";
import type { AnalysisResult, AnalyzeTargetOptions, HtmlSecurityInfo } from "./types.js";

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
    securityTxt: await fetchSecurityTxt(finalUrl, requestText),
    domainSecurity: await analyzeDomainSecurity(result.host, requestText),
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
export { buildHistoryDiff, buildHistoryDiffFromSnapshots, snapshotFromAnalysis } from "./historyDiff.js";
export type { AnalysisResult, AnalyzeTargetOptions, HistoryDiff, HistorySnapshot, HtmlSecurityInfo } from "./types";
