import type { AnalysisResult, CertificateResult, CookieResult, RedirectHop, SecurityHeaderResult } from "./types.js";

export type PostureAreaKey = "edge" | "content" | "domain" | "exposure" | "api" | "trust" | "ai";

export interface PostureAreaScore {
  key: PostureAreaKey;
  label: string;
  score: number;
  status: "strong" | "watch" | "weak";
}

type PostureScoringInput = Omit<AnalysisResult, "executiveSummary"> & {
  executiveSummary?: AnalysisResult["executiveSummary"];
};

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

const POSTURE_WEIGHTS: Record<PostureAreaKey, number> = {
  edge: 0.25,
  content: 0.2,
  domain: 0.2,
  exposure: 0.15,
  api: 0.1,
  trust: 0.05,
  ai: 0.05,
};

const clamp = (value: number) => Math.max(0, Math.min(100, value));

const statusForScore = (score: number): PostureAreaScore["status"] => {
  if (score >= 85) return "strong";
  if (score >= 65) return "watch";
  return "weak";
};

export function gradeForScore(score: number): string {
  if (score >= 97) return "A+";
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 70) return "C";
  if (score >= 60) return "D";
  return "F";
}

export function scoreAnalysis({
  isHttps,
  headerResults,
  certificate,
  cookies,
  redirects,
  limitedResponse = false,
}: {
  isHttps: boolean;
  headerResults: SecurityHeaderResult[];
  certificate: CertificateResult;
  cookies: CookieResult[];
  redirects: RedirectHop[];
  limitedResponse?: boolean;
}): { score: number; grade: string } {
  let score = 100;

  if (!isHttps) {
    score -= 35;
  }

  for (const header of headerResults) {
    const weights = HEADER_PENALTY[header.key] || { missing: 4, warning: 2 };
    if (header.status === "missing") {
      if (!limitedResponse) {
        score -= weights.missing;
      }
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
  if (!limitedResponse) {
    for (const [name, cookie] of scoredCookies.entries()) {
      const isLikelyPreferenceCookie = /(locale|lang|language|country|theme|consent|prefs?|preference|visitor|device|did)/i.test(name);
      let perCookiePenalty = 0;
      if (!cookie.secure) perCookiePenalty += 1;
      if (!cookie.httpOnly && !isLikelyPreferenceCookie) perCookiePenalty += 1;
      if (!cookie.sameSite) perCookiePenalty += 1;
      cookiePenalty += Math.min(perCookiePenalty, 4);
    }
  }
  score -= Math.min(cookiePenalty, 8);

  if (redirects.length > 1) {
    score -= Math.min(redirects.length - 1, 4) * 2;
  }

  if (limitedResponse) {
    score = Math.min(score, 84);
  }

  score = Math.max(0, Math.min(100, score));

  return { score, grade: gradeForScore(score) };
}

export function getPostureAreaScores(analysis: PostureScoringInput): PostureAreaScore[] {
  const cspHeaderFindings = analysis.headers.filter(
    (header) => header.key === "content-security-policy" && header.status !== "present",
  );
  const edgeHeaderFindings = analysis.headers.filter(
    (header) => header.key !== "content-security-policy" && header.status !== "present",
  );
  const missingHeaderCount = edgeHeaderFindings.filter((header) => header.status === "missing").length;
  const warningHeaderCount = edgeHeaderFindings.filter((header) => header.status === "warning").length;
  const cspHeaderIssueCount = cspHeaderFindings.length;
  const cookieIssueCount = analysis.cookies.reduce((count, cookie) => count + cookie.issues.length, 0);
  const redirectPenalty = analysis.redirects.length > 1 ? Math.max(analysis.redirects.length - 1, 0) * 2 : 0;
  const transportPenalty = new URL(analysis.finalUrl).protocol === "https:" ? 0 : 35;
  const certificatePenalty =
    analysis.certificate.available && !analysis.certificate.valid
      ? 25
      : analysis.certificate.protocol && /tlsv1(\.0|\.1)?$/i.test(analysis.certificate.protocol)
        ? 15
        : (analysis.certificate.daysRemaining ?? 365) <= 14
          ? 10
          : 0;

  const edgePenalty =
    transportPenalty +
    certificatePenalty +
    missingHeaderCount * 8 +
    warningHeaderCount * 4 +
    analysis.corsSecurity.issues.length * 8 +
    redirectPenalty;

  const contentPenalty =
    cspHeaderIssueCount * 10 +
    analysis.htmlSecurity.issues.length * 8 +
    cookieIssueCount * 4;

  const domainPenalty =
    analysis.domainSecurity.issues.length * 8 +
    analysis.securityTxt.issues.length * 5 +
    analysis.publicSignals.issues.length * 4;

  const exposurePenalty =
    analysis.exposure.issues.length * 20 +
    analysis.exposure.probes.filter((probe) => probe.finding === "interesting").length * 4;

  const apiPenalty =
    analysis.apiSurface.issues.length * 15 +
    analysis.apiSurface.probes.filter((probe) => probe.classification === "interesting").length * 4;

  const trustPenalty =
    analysis.thirdPartyTrust.highRiskProviders * 10 +
    analysis.thirdPartyTrust.issues.length * 6;

  const aiPenalty =
    analysis.aiSurface.issues.length * 12 +
    (analysis.aiSurface.detected && !analysis.aiSurface.disclosures.length ? 8 : 0);

  const areas: Array<Omit<PostureAreaScore, "status">> = [
    { key: "edge", label: "Edge Security", score: clamp(100 - edgePenalty) },
    { key: "content", label: "Content Security", score: clamp(100 - contentPenalty) },
    { key: "domain", label: "Domain & Trust", score: clamp(100 - domainPenalty) },
    { key: "exposure", label: "Exposure Control", score: clamp(100 - exposurePenalty) },
    { key: "api", label: "API Surface", score: clamp(100 - apiPenalty) },
    { key: "trust", label: "Third-Party Trust", score: clamp(100 - trustPenalty) },
    { key: "ai", label: "AI & Automation", score: clamp(100 - aiPenalty) },
  ];

  return areas.map((area) => ({
    ...area,
    status: statusForScore(area.score),
  }));
}

export function scorePostureAnalysis(analysis: PostureScoringInput): { score: number; grade: string } {
  const areaScores = getPostureAreaScores(analysis);
  const weightedScore = Math.round(
    areaScores.reduce((total, area) => total + area.score * POSTURE_WEIGHTS[area.key], 0),
  );
  const score = analysis.assessmentLimitation.limited ? Math.min(weightedScore, 84) : weightedScore;
  return { score, grade: gradeForScore(score) };
}

export function summarizePostureGrade(grade: string): string {
  if (grade === "A+" || grade === "A") {
    return "External posture looks strong across the main passive checks.";
  }
  if (grade === "B") {
    return "External posture is broadly sound, with a few posture areas still worth tightening.";
  }
  if (grade === "C") {
    return "External posture is mixed, with meaningful gaps across one or more posture areas.";
  }
  return "External posture needs work before this would count as well hardened.";
}
