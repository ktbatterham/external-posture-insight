import { URL } from "node:url";
import { scanTls } from "./certificate.js";
import { parseSetCookie } from "./cookie-analysis.js";
import { fetchCtDiscovery } from "./ctDiscovery.js";
import { analyzeDomainSecurity } from "./domain-security.js";
import {
  API_SURFACE_PROBES,
  CRAWL_CONCURRENCY_LIMIT,
  CRAWL_CANDIDATES,
  EXPOSURE_PROBES,
} from "./scannerConfig.js";
import {
  analyzeHeaders,
  buildLibraryRiskIssues,
  buildRawHeaders,
  buildRemediation,
  classifyIssueTaxonomy,
  SECURITY_HEADERS,
} from "./header-analysis.js";
import { analyzeThirdPartyTrust, buildExecutiveSummary, mergeTechnologies } from "./htmlInsights.js";
import { analyzeHtmlDocument as analyzeHtmlDocumentFromModule, analyzeHtmlSecurity, detectAssessmentLimitation, fetchHtmlDocument } from "./html-page-analysis.js";
import {
  classifyHtmlApiFallback,
  isAccessDeniedHtml,
} from "./html-extraction.js";
import { analyzeIdentityProvider } from "./identityProvider.js";
import { analyzeInfrastructure } from "./infrastructure.js";
import {
  analyzeApiSurface,
  analyzeCorsSecurity,
  analyzeExposure,
  fetchPublicSignals,
} from "./surfaceEnrichment.js";
import { fetchLibraryRiskSignals } from "./libraryRisk.js";
import {
  fetchWithRedirects,
  requestJson,
  requestOnce,
  requestText,
  requestWithHeaders,
} from "./network.js";
import { normalizeDiscoveredPath, rankDiscoveredPaths } from "./path-discovery.js";
import { scoreAnalysis, scorePostureAnalysis, summarizePostureGrade } from "./scoring.js";
import { fetchSecurityTxt } from "./security-txt.js";
import { detectTechnologies } from "./technology-detection.js";
import { headerValue, mapWithConcurrency, unique } from "./utils.js";
import { analyzeWafFingerprint } from "./wafFingerprint.js";
import type { AnalysisResult, AnalyzeTargetOptions, HtmlSecurityInfo } from "./types.js";

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
export function analyzeHtmlDocument(input: string | URL, html: string): HtmlSecurityInfo {
  return analyzeHtmlDocumentFromModule(input, html);
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
    assessmentLimitation: {
      limited: false,
      kind: null,
      title: null,
      detail: null,
    },
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
  const pages = await mapWithConcurrency(candidates, CRAWL_CONCURRENCY_LIMIT, async (candidate) => {
    try {
      const pageResult = await analyzeUrlCore(candidate.url, { includeCertificate: false });
      return summarizePageAnalysis(candidate.label, candidate.path, pageResult, rootHost);
    } catch {
      return {
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
      };
    }
  });

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
  const technologies = mergeTechnologies(result.technologies, htmlSecurity.detectedTechnologies);
  const infrastructure = await analyzeInfrastructure(finalUrl, result.rawHeaders, technologies);
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
  const assessmentLimitation = detectAssessmentLimitation(
    result.statusCode,
    result.rawHeaders,
    htmlDocument?.html || null,
  );
  const enrichedResult = {
    ...result,
    issues: [...result.issues, ...buildLibraryRiskIssues(libraryRiskSignals).map(classifyIssueTaxonomy)],
    technologies,
    crawl: await crawlRelatedPages(result, discovery),
    securityTxt: await fetchSecurityTxt(finalUrl, requestText),
    domainSecurity: await analyzeDomainSecurity(result.host, requestText),
    identityProvider,
    ctDiscovery,
    htmlSecurity,
    aiSurface: htmlSecurity.aiSurface,
    thirdPartyTrust,
    infrastructure,
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
    assessmentLimitation,
  };
  const postureScore = scorePostureAnalysis(enrichedResult);
  const scoredResult = {
    ...enrichedResult,
    score: postureScore.score,
    grade: postureScore.grade,
    summary: assessmentLimitation.limited
      ? "Assessment is limited because the target returned a blocked or restricted response."
      : summarizePostureGrade(postureScore.grade),
  };

  return {
    ...scoredResult,
    executiveSummary: buildExecutiveSummary(scoredResult),
  };
}

export const analyzeTarget = analyzeUrl;
export { formatErrorMessage };
export { analyzeInfrastructure } from "./infrastructure.js";
export { buildHistoryDiff, buildHistoryDiffFromSnapshots, snapshotFromAnalysis } from "./historyDiff.js";
export {
  assertPublicRequestTarget,
  isLocalHostname,
  isPrivateAddress,
} from "./network-validation.js";
export type { AnalysisResult, AnalyzeTargetOptions, HistoryDiff, HistorySnapshot, HtmlSecurityInfo } from "./types";
