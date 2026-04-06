import type { CtDiscoveryInfo } from "./types.js";

const CT_SUBDOMAIN_LIMIT = 20;
const CT_WILDCARD_LIMIT = 5;
const CT_LOOKUP_TIMEOUT_MS = 1_500;
const CT_CACHE_TTL_MS = 15 * 60 * 1000;

interface CtCacheEntry {
  expiresAt: number;
  value: CtDiscoveryInfo;
}

interface JsonResponse<T = unknown> {
  statusCode: number;
  json: T | null;
}

type RequestJsonFn = (targetUrl: URL, extraHeaders?: Record<string, string>) => Promise<JsonResponse>;

const ctCache = new Map<string, CtCacheEntry>();

const unique = <T>(values: Array<T | null | undefined | false>): T[] =>
  [...new Set(values.filter((value): value is T => Boolean(value)))];

const withTimeout = async <T>(promise: Promise<T>, timeoutMs: number, message: string): Promise<T> => {
  let timeoutId: ReturnType<typeof setTimeout> | null = null;

  try {
    return await Promise.race([
      promise,
      new Promise<T>((_, reject) => {
        timeoutId = setTimeout(() => reject(new Error(message)), timeoutMs);
      }),
    ]);
  } finally {
    if (timeoutId) {
      clearTimeout(timeoutId);
    }
  }
};

const toDiscoveryDomain = (host: string) => {
  const normalized = host.replace(/\.$/, "").toLowerCase();
  const labels = normalized.split(".").filter(Boolean);
  if (labels.length <= 2) {
    return normalized;
  }

  const secondLevelLabels = new Set(["co", "com", "org", "net", "gov", "ac", "edu"]);
  const last = labels[labels.length - 1];
  const secondLast = labels[labels.length - 2];
  if (last.length === 2 && secondLevelLabels.has(secondLast)) {
    return labels.slice(-3).join(".");
  }

  return labels.slice(-2).join(".");
};

export const fetchCtDiscovery = async (host: string, requestJson: RequestJsonFn): Promise<CtDiscoveryInfo> => {
  const queriedDomain = toDiscoveryDomain(host);
  const cached = ctCache.get(queriedDomain);
  if (cached && cached.expiresAt > Date.now()) {
    return cached.value;
  }

  const sourceUrl = `https://crt.sh/?q=%25.${queriedDomain}&output=json`;

  try {
    const response = await withTimeout(
      requestJson(new URL(sourceUrl)),
      CT_LOOKUP_TIMEOUT_MS,
      "Certificate transparency lookup timed out.",
    );
    const rows = Array.isArray(response.json) ? response.json : [];
    const rawNames = rows.flatMap((entry) =>
      String((entry as { name_value?: string })?.name_value || "")
        .split(/\r?\n/)
        .map((value) => value.trim().toLowerCase())
        .filter(Boolean),
    );

    const wildcardEntries = unique(
      rawNames
        .filter((value) => value.startsWith("*."))
        .map((value) => value.slice(2))
        .filter((value) => value === queriedDomain || value.endsWith(`.${queriedDomain}`)),
    ).slice(0, CT_WILDCARD_LIMIT);
    const subdomains = unique(
      rawNames.filter((value) => !value.startsWith("*.") && value !== queriedDomain && value.endsWith(`.${queriedDomain}`)),
    ).slice(0, CT_SUBDOMAIN_LIMIT);

    const value: CtDiscoveryInfo = {
      queriedDomain,
      sourceUrl,
      subdomains,
      wildcardEntries,
      issues: subdomains.length
        ? []
        : ["Certificate transparency search did not return any distinct subdomains for this domain."],
      strengths: subdomains.length
        ? [`Certificate transparency surfaced ${subdomains.length} subdomain${subdomains.length === 1 ? "" : "s"} without touching the target.`]
        : [],
    };

    ctCache.set(queriedDomain, {
      expiresAt: Date.now() + CT_CACHE_TTL_MS,
      value,
    });

    return value;
  } catch (error) {
    return {
      queriedDomain,
      sourceUrl,
      subdomains: [],
      wildcardEntries: [],
      issues: [error instanceof Error ? `Certificate transparency lookup failed: ${error.message}` : "Certificate transparency lookup failed."],
      strengths: [],
    };
  }
};
