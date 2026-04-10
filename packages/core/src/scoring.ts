import type { CertificateResult, CookieResult, RedirectHop, SecurityHeaderResult } from "./types.js";

const HEADER_PENALTY: Record<string, { missing: number; warning: number }> = {
  "strict-transport-security": { missing: 10, warning: 4 },
  "content-security-policy": { missing: 12, warning: 4 },
  "x-frame-options": { missing: 3, warning: 2 },
  "x-content-type-options": { missing: 4, warning: 2 },
  "referrer-policy": { missing: 3, warning: 2 },
  "permissions-policy": { missing: 1, warning: 1 },
  "cross-origin-opener-policy": { missing: 1, warning: 1 },
  "cross-origin-resource-policy": { missing: 1, warning: 1 },
};

export function scoreAnalysis({
  isHttps,
  headerResults,
  certificate,
  cookies,
  redirects,
}: {
  isHttps: boolean;
  headerResults: SecurityHeaderResult[];
  certificate: CertificateResult;
  cookies: CookieResult[];
  redirects: RedirectHop[];
}): { score: number; grade: string } {
  let score = 100;

  if (!isHttps) {
    score -= 35;
  }

  for (const header of headerResults) {
    const weights = HEADER_PENALTY[header.key] || { missing: 4, warning: 2 };
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

  const scoredCookies = new Map<string, { secure: boolean; httpOnly: boolean; sameSite: string | null }>();
  for (const cookie of cookies) {
    const expiresAt = cookie.expires ? Date.parse(cookie.expires) : NaN;
    if (!Number.isNaN(expiresAt) && expiresAt <= Date.now()) {
      continue;
    }

    const cookieKey = cookie.name.toLowerCase();
    const existing = scoredCookies.get(cookieKey);
    scoredCookies.set(cookieKey, existing
      ? { secure: existing.secure && cookie.secure, httpOnly: existing.httpOnly && cookie.httpOnly, sameSite: existing.sameSite && cookie.sameSite }
      : { secure: cookie.secure, httpOnly: cookie.httpOnly, sameSite: cookie.sameSite },
    );
  }

  let cookiePenalty = 0;
  for (const [name, cookie] of scoredCookies.entries()) {
    const isLikelyPreferenceCookie = /(locale|lang|language|country|theme|consent|prefs?|preference|visitor|device|did)/i.test(name);
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
