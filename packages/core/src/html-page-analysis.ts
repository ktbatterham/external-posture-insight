import { URL } from "node:url";
import { createRequire } from "node:module";
import { analyzeAiSurface, detectHtmlTechnologies } from "./htmlInsights.js";
import {
  collectClientExposureSignals,
  collectPassiveLeakSignals,
  collectSameSiteHosts,
  extractHtmlTitle,
  getHtmlTitle,
  isAccessDeniedHtml,
  normalizeHtmlSignature,
} from "./html-extraction.js";
import { collectLibraryFingerprints } from "./libraryRisk.js";
import { normalizeDiscoveredPath, rankDiscoveredPaths } from "./path-discovery.js";
import { requestText } from "./network.js";
import type { HtmlSecurityInfo } from "./types.js";
import { headerValue, unique } from "./utils.js";

const require = createRequire(import.meta.url);
let cheerioModule: typeof import("cheerio") | null = null;

function loadCheerio() {
  cheerioModule ??= require("cheerio") as typeof import("cheerio");
  return cheerioModule;
}

export async function fetchHtmlDocument(finalUrl: URL) {
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

export function analyzeHtmlSecurity(finalUrl: URL, document: { html: string; pageTitle: string | null } | null): HtmlSecurityInfo {
  try {
    if (!document) {
      return {
        fetched: false,
        pageUrl: finalUrl.toString(),
        pageTitle: null,
        metaGenerator: null,
        forms: [],
        sameSiteHosts: [],
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
    const issues: string[] = [];
    const strengths: string[] = [];
    const cheerio = loadCheerio();
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
    const sameSiteHosts = collectSameSiteHosts(finalUrl, [
      ...$("a[href]").toArray().map((anchor) => $(anchor).attr("href")),
      ...scriptElements.map((script) => $(script).attr("src")),
      ...$('link[rel~="stylesheet"]').toArray().map((link) => $(link).attr("href")),
      ...forms.map((form) => form.action),
    ]);
    const firstPartyPaths = rankDiscoveredPaths([
      ...$("a[href]").toArray().map((anchor) => normalizeDiscoveredPath($(anchor).attr("href"), finalUrl)),
      ...forms.map((form) => normalizeDiscoveredPath(form.action, finalUrl)),
    ]);
    const trainingLabMarkers = unique([
      /(xss game|firing range|vulnweb|testfire|altoro mutual)/i.test(pageTitle || "")
        ? `Title: ${pageTitle}`
        : null,
      ...firstPartyPaths
        .filter((path) => /(xss|clickjacking|csrf|sql|sqli|mixedcontent|leakedcookie|dom)(?:\/|$|-|_)/i.test(path))
        .slice(0, 6),
    ]);
    const insecureResourceUrls = unique(
      [...externalScriptUrls, ...externalStylesheetUrls].filter((url) => url.startsWith("http://")),
    );
    const externalScriptDomains = unique(
      externalScriptUrls.map((url) => new URL(url).hostname).filter((hostname) => hostname !== finalUrl.hostname),
    );
    const externalStylesheetDomains = unique(
      externalStylesheetUrls.map((url) => new URL(url).hostname).filter((hostname) => hostname !== finalUrl.hostname),
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
      .filter(Boolean) as string[];
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
    if (sameSiteHosts.length) {
      strengths.push(
        `Page content referenced ${sameSiteHosts.length} same-site host${sameSiteHosts.length === 1 ? "" : "s"} for passive discovery.`,
      );
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
    if (trainingLabMarkers.length) {
      issues.push("Page content suggests an intentionally vulnerable training or challenge surface.");
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
      sameSiteHosts,
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
      sameSiteHosts: [],
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

export function detectAssessmentLimitation(
  statusCode: number,
  headers: Record<string, string>,
  html: string | null,
) {
  if (statusCode === 401) {
    return {
      limited: true,
      kind: "auth_required" as const,
      title: "Assessment limited by an authenticated response",
      detail: "The target required authentication before serving the normal page, so this result reflects a restricted response rather than the full application surface.",
    };
  }

  if (statusCode === 429) {
    return {
      limited: true,
      kind: "rate_limited" as const,
      title: "Assessment limited by rate limiting",
      detail: "The target rate-limited the scanner, so this result reflects a throttled response rather than a normal page render.",
    };
  }

  if (statusCode >= 500) {
    return {
      limited: true,
      kind: "service_unavailable" as const,
      title: "Assessment limited by service availability",
      detail: `The target returned HTTP ${statusCode}, so this result reflects an unavailable or error response rather than the normal site posture.`,
    };
  }

  if (statusCode === 403 && html && isAccessDeniedHtml(headers, html)) {
    return {
      limited: true,
      kind: "blocked_edge_response" as const,
      title: "Assessment limited by a blocked edge response",
      detail: "The target returned a generic blocked or protection-layer response, so missing headers on this page may not reflect the normal site posture.",
    };
  }

  return {
    limited: false,
    kind: null,
    title: null,
    detail: null,
  };
}
