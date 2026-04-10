import { CLIENT_EXPOSURE_EVIDENCE_LIMIT, HTML_SIGNATURE_LIMIT, SUMMARY_EVIDENCE_LIMIT } from "./scannerConfig.js";
import { headerValue, unique } from "./utils.js";

type ResponseHeaders = Record<string, string | string[] | undefined>;

export function normalizeHtmlSignature(body: string): string {
  return body
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .toLowerCase()
    .slice(0, HTML_SIGNATURE_LIMIT);
}

export function getHtmlTitle(body: string): string | null {
  const match = body.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  return match ? match[1].replace(/\s+/g, " ").trim() : null;
}

export function extractHtmlTitle(body: string): string | null {
  const title = getHtmlTitle(body);
  return title ? title.toLowerCase() : null;
}

export function summarizeEvidence<T>(values: Array<T | null | undefined | false>, limit = SUMMARY_EVIDENCE_LIMIT): T[] {
  return unique(values).slice(0, limit);
}

export function extractRedactedMatch(
  pattern: RegExp,
  html: string,
  transform: (value: string) => string = (value) => value,
): string | null {
  const match = html.match(pattern);
  return match ? transform(match[0]) : null;
}

export function redactToken(value: string, visible = 8): string {
  if (!value || value.length <= visible * 2) {
    return value;
  }
  return `${value.slice(0, visible)}...${value.slice(-visible)}`;
}

export function collectPassiveLeakSignals(
  html: string,
  finalUrl: URL,
  metaGenerator: string | null,
  externalScriptUrls: string[],
  externalStylesheetUrls: string[],
) {
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
    extractRedactedMatch(/AIza[0-9A-Za-z\\-_]{20,}/, html, redactToken),
    extractRedactedMatch(/pk\.[A-Za-z0-9\\-_]{20,}/, html, redactToken),
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
    metaGenerator && /\\d/.test(metaGenerator) ? metaGenerator : null,
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

export function collectClientExposureSignals(html: string, finalUrl: URL) {
  const signals = [];
  const isLikelyApiAsset = (value: string) =>
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
    /\b(?:environment|env|release)[^"'`\n]{0,32}staging|staging[^"'`\n]{0,32}(?:environment|env|release)/i.test(html) ? "staging environment" : null,
    /\b(?:environment|env|release)[^"'`\n]{0,32}dev(?:elopment)?|dev(?:elopment)?[^"'`\n]{0,32}(?:environment|env|release)/i.test(html) ? "development environment" : null,
    /\b(?:environment|env|release)[^"'`\n]{0,32}internal|internal[^"'`\n]{0,32}(?:environment|env|release)/i.test(html) ? "internal environment" : null,
    /\b(?:environment|env|release)[^"'`\n]{0,32}sandbox|sandbox[^"'`\n]{0,32}(?:environment|env|release)/i.test(html) ? "sandbox environment" : null,
    /\b(?:environment|env|release)[^"'`\n]{0,32}preview|preview[^"'`\n]{0,32}(?:environment|env|release)/i.test(html) ? "preview environment" : null,
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

export function classifyHtmlApiFallback(
  probePath: string,
  finalUrl: URL,
  resolvedUrl: URL,
  body: string,
  homepageSignature: string | null,
  homepageTitle: string | null,
): boolean {
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

export function isAccessDeniedHtml(headers: ResponseHeaders, body: string): boolean {
  const server = (headerValue(headers, "server") || "").toLowerCase();
  const bodyText = body.toLowerCase();
  const title = extractHtmlTitle(body) || "";

  return (
    server.includes("sucuri") ||
    bodyText.includes("website security - access denied") ||
    bodyText.includes("access denied") ||
    bodyText.includes("403 forbidden") ||
    bodyText.includes("request forbidden by administrative rules") ||
    bodyText.includes("request blocked") ||
    title.includes("access denied") ||
    title.includes("403 forbidden")
  );
}
