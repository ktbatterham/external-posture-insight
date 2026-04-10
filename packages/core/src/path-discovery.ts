import { DISCOVERY_PATH_LIMIT } from "./scannerConfig.js";
import { unique } from "./utils.js";

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

export function isLikelyPagePath(pathname: string): boolean {
  if (!pathname || pathname === "/") {
    return false;
  }

  return !/\.(?:css|js|mjs|json|xml|txt|ico|png|jpe?g|gif|svg|webp|avif|woff2?|ttf|eot|map|pdf|zip|gz|mp4|webm)$/i.test(pathname);
}

export function scorePagePath(pathname: string): number {
  return PAGE_PATH_PRIORITY_PATTERNS.reduce((score, pattern, index) => {
    if (pattern.test(pathname)) {
      return score + (PAGE_PATH_PRIORITY_PATTERNS.length - index) * 10;
    }
    return score;
  }, pathname.split("/").filter(Boolean).length <= 2 ? 5 : 0);
}

export function normalizeDiscoveredPath(value: string | undefined | null, finalUrl: URL): string | null {
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

export function rankDiscoveredPaths(paths: Array<string | null | undefined | false>): string[] {
  return unique(paths)
    .sort((left, right) => scorePagePath(right) - scorePagePath(left))
    .slice(0, DISCOVERY_PATH_LIMIT);
}
