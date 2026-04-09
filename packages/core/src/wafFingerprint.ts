import { URL } from "node:url";
import type { RedirectHop, WafFingerprintInfo } from "./types.js";
import { unique } from "./utils.js";

type ResponseHeaders = Record<string, string | string[] | undefined>;

const headerValue = (headers: ResponseHeaders, name: string) => {
  const value = headers[name];
  if (Array.isArray(value)) {
    return value.join(", ");
  }
  return value ?? null;
};

const WAF_DETECTORS = [
  {
    name: "Cloudflare",
    confidence: "high" as const,
    detection: "observed" as const,
    test: (headers: ResponseHeaders, body: string) =>
      Boolean(headerValue(headers, "cf-ray") || headerValue(headers, "cf-cache-status") || /cloudflare/i.test(headerValue(headers, "server") || "") || /attention required|cloudflare/i.test(body)),
    evidence: (headers: ResponseHeaders) => headerValue(headers, "cf-ray") ? "Observed cf-ray / Cloudflare edge headers." : "Observed Cloudflare-branded edge response markers.",
  },
  {
    name: "Akamai",
    confidence: "high" as const,
    detection: "observed" as const,
    test: (headers: ResponseHeaders, body: string) =>
      Boolean(headerValue(headers, "x-akamai-transformed") || headerValue(headers, "akamai-cache-status") || /akamai/i.test(headerValue(headers, "server") || "") || /reference #\d+\.[a-z0-9.]+\.akamai/i.test(body)),
    evidence: () => "Observed Akamai edge headers or block-page signatures.",
  },
  {
    name: "Imperva",
    confidence: "high" as const,
    detection: "observed" as const,
    test: (headers: ResponseHeaders, body: string) =>
      Boolean(headerValue(headers, "x-iinfo") || /imperva|incapsula/i.test(headerValue(headers, "server") || "") || /incapsula incident id|imperva/i.test(body)),
    evidence: () => "Observed Imperva/Incapsula response markers.",
  },
  {
    name: "Sucuri",
    confidence: "high" as const,
    detection: "observed" as const,
    test: (headers: ResponseHeaders, body: string) =>
      Boolean(headerValue(headers, "x-sucuri-id") || headerValue(headers, "x-sucuri-cache") || /sucuri/i.test(headerValue(headers, "server") || "") || /sucuri website firewall/i.test(body)),
    evidence: () => "Observed Sucuri edge headers or branded error-page markers.",
  },
  {
    name: "Fastly",
    confidence: "medium" as const,
    detection: "observed" as const,
    test: (headers: ResponseHeaders) =>
      Boolean((headerValue(headers, "x-cache") || "").toLowerCase().includes("fastly") || (headerValue(headers, "x-served-by") || "").toLowerCase().includes("cache-")),
    evidence: () => "Observed Fastly cache headers.",
  },
  {
    name: "AWS CloudFront / WAF",
    confidence: "medium" as const,
    detection: "observed" as const,
    test: (headers: ResponseHeaders) =>
      Boolean(headerValue(headers, "x-amz-cf-id") || /cloudfront/i.test(headerValue(headers, "server") || "")),
    evidence: () => "Observed CloudFront edge headers.",
  },
  {
    name: "Azure Front Door",
    confidence: "high" as const,
    detection: "observed" as const,
    test: (headers: ResponseHeaders) => Boolean(headerValue(headers, "x-azure-ref")),
    evidence: () => "Observed x-azure-ref edge headers.",
  },
  {
    name: "F5 BIG-IP ASM",
    confidence: "medium" as const,
    detection: "observed" as const,
    test: (headers: ResponseHeaders, body: string) =>
      Boolean(headerValue(headers, "x-wa-info") || headerValue(headers, "x-cnection") || /the requested url was rejected/i.test(body)),
    evidence: () => "Observed F5-style response headers or rejection-body markers.",
  },
  {
    name: "Barracuda",
    confidence: "high" as const,
    detection: "observed" as const,
    test: (headers: ResponseHeaders) => Object.keys(headers).some((key) => key.toLowerCase().startsWith("x-barracuda-")),
    evidence: () => "Observed Barracuda-branded response headers.",
  },
  {
    name: "Nginx Plus / ModSecurity",
    confidence: "medium" as const,
    detection: "observed" as const,
    test: (headers: ResponseHeaders) =>
      Boolean((headerValue(headers, "server") || "").toLowerCase().includes("mod_security") || headerValue(headers, "x-response-code")),
    evidence: () => "Observed mod_security or gateway response markers.",
  },
  {
    name: "Palo Alto Prisma WAAS",
    confidence: "high" as const,
    detection: "observed" as const,
    test: (headers: ResponseHeaders) => Boolean(headerValue(headers, "x-pan-request-id")),
    evidence: () => "Observed x-pan-request-id header.",
  },
  {
    name: "Google Cloud Armor",
    confidence: "medium" as const,
    detection: "observed" as const,
    test: (headers: ResponseHeaders) =>
      Object.keys(headers).some((key) => key.toLowerCase().startsWith("x-goog-")) &&
      (headerValue(headers, "via") || "").toLowerCase().includes("google"),
    evidence: () => "Observed x-goog-* headers with Google edge routing markers.",
  },
  {
    name: "Vercel Edge Network",
    confidence: "high" as const,
    detection: "observed" as const,
    test: (headers: ResponseHeaders) => Boolean(headerValue(headers, "x-vercel-id")),
    evidence: () => "Observed x-vercel-id header.",
  },
];

export const analyzeWafFingerprint = (
  finalUrl: URL,
  headers: ResponseHeaders,
  html: string | null,
  redirects: RedirectHop[],
): WafFingerprintInfo => {
  const body = (html || "").toLowerCase();
  const providers = WAF_DETECTORS
    .filter((detector) => detector.test(headers, body))
    .map((detector) => ({
      name: detector.name,
      confidence: detector.confidence,
      detection: detector.detection,
      evidence: detector.evidence(headers),
    }));

  const via = headerValue(headers, "via");
  const server = headerValue(headers, "server");
  const xCdn = headerValue(headers, "x-cdn");
  const edgeSignals = unique([
    server && /(edge|proxy|gateway|cache|gtm|belfrage|varnish)/i.test(server) ? `Server: ${server}` : null,
    via ? `Via: ${via}` : null,
    xCdn ? `X-CDN: ${xCdn}` : null,
    redirects.some((hop) => {
      try {
        return hop.location ? new URL(hop.location, finalUrl).origin !== finalUrl.origin : false;
      } catch {
        return false;
      }
    })
      ? "Redirect chain includes a separate edge or identity origin."
      : null,
  ]);

  const strengths: string[] = [];
  const issues: string[] = [];

  if (providers.length) {
    strengths.push(`Edge protection or delivery signals point to ${providers.map((provider) => provider.name).join(", ")}.`);
  } else {
    strengths.push("No branded WAF or edge provider was conclusively identified from passive response evidence.");
  }

  if (edgeSignals.length) {
    strengths.push("Response headers exposed edge-network handling details that help classify the delivery path.");
  }

  if (providers.some((provider) => provider.name.includes("CloudFront"))) {
    issues.push("AWS edge delivery was observed, but passive evidence alone does not confirm whether AWS WAF policies are enforced.");
  }

  return {
    detected: Boolean(providers.length),
    providers,
    edgeSignals,
    issues,
    strengths,
    summary: providers.length
      ? `Passive response evidence suggests ${providers.map((provider) => provider.name).join(", ")} in front of the target.`
      : "No branded WAF or edge-protection provider was conclusively identified from passive response evidence.",
  };
};
