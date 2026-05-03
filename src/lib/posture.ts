import { AnalysisResult } from "@/types/analysis";

export interface AreaScore {
  key: "edge" | "content" | "domain" | "exposure" | "api" | "trust" | "ai";
  label: string;
  score: number;
  status: "strong" | "watch" | "weak";
  notes: string[];
}

const clamp = (value: number) => Math.max(0, Math.min(100, value));

const severeAssessmentCaps: Record<
  NonNullable<AnalysisResult["assessmentLimitation"]["kind"]>,
  { default: number; domain: number }
> = {
  blocked_edge_response: { default: 59, domain: 78 },
  auth_required: { default: 59, domain: 78 },
  rate_limited: { default: 54, domain: 74 },
  service_unavailable: { default: 35, domain: 72 },
  other: { default: 59, domain: 74 },
};

const statusAvailabilityPenalty = (statusCode?: number) => {
  if (!statusCode) return 0;
  if (statusCode >= 500) return 35;
  if (statusCode === 429) return 20;
  return 0;
};

const AREA_HEADER_PENALTY: Record<string, { missing: number; warning: number }> = {
  "strict-transport-security": { missing: 12, warning: 5 },
  "x-frame-options": { missing: 4, warning: 2 },
  "x-content-type-options": { missing: 5, warning: 2 },
  "referrer-policy": { missing: 3, warning: 2 },
  "permissions-policy": { missing: 2, warning: 1 },
  "cross-origin-opener-policy": { missing: 2, warning: 1 },
  "cross-origin-resource-policy": { missing: 2, warning: 1 },
};

const headerPenalty = (header: AnalysisResult["headers"][number], fallback = { missing: 4, warning: 2 }) => {
  const weights = AREA_HEADER_PENALTY[header.key] || fallback;
  if (header.status === "missing") return weights.missing;
  if (header.status === "warning") return weights.warning;
  return 0;
};

const contentIssuePenalty = (issue: string) => {
  const normalized = issue.toLowerCase();
  if (normalized.includes("source map") || normalized.includes("public token") || normalized.includes("client config")) {
    return 8;
  }
  if (normalized.includes("missing sri")) {
    return 5;
  }
  if (normalized.includes("inline script")) {
    return 4;
  }
  if (normalized.includes("inline style")) {
    return 2;
  }
  return 4;
};

const domainIssuePenalty = (issue: string) => {
  const normalized = issue.toLowerCase();
  if (normalized.includes("dmarc") || normalized.includes("spf")) {
    return 8;
  }
  if (normalized.includes("mx")) {
    return 6;
  }
  if (normalized.includes("mta-sts")) {
    return 4;
  }
  if (normalized.includes("dnssec") || normalized.includes("caa")) {
    return 3;
  }
  return 5;
};

const publicSignalPenalty = (issue: string) => {
  const normalized = issue.toLowerCase();
  if (normalized.includes("hsts preload")) {
    return 1;
  }
  return 3;
};

const isHttpsFinalUrl = (finalUrl: string | undefined) => {
  if (!finalUrl) {
    return true;
  }

  try {
    return new URL(finalUrl).protocol === "https:";
  } catch {
    return true;
  }
};

const statusForScore = (score: number): AreaScore["status"] => {
  if (score >= 85) return "strong";
  if (score >= 65) return "watch";
  return "weak";
};

const cappedAreaScore = (analysis: AnalysisResult, areaKey: AreaScore["key"], score: number) => {
  if (!analysis.assessmentLimitation?.limited || !analysis.assessmentLimitation.kind) {
    return score;
  }

  const caps = severeAssessmentCaps[analysis.assessmentLimitation.kind];
  return Math.min(score, areaKey === "domain" ? caps.domain : caps.default);
};

export const getAreaScores = (analysis: AnalysisResult): AreaScore[] => {
  const cspHeaderFindings = analysis.headers.filter(
    (header) => header.key === "content-security-policy" && header.status !== "present",
  );
  const edgeHeaderFindings = analysis.headers.filter(
    (header) => header.key !== "content-security-policy" && header.status !== "present",
  );
  const edgeHeaderFindingCount = edgeHeaderFindings.length;
  const cspHeaderIssueCount = cspHeaderFindings.length;
  const cookieIssueCount = analysis.cookies.reduce((count, cookie) => count + cookie.issues.length, 0);
  const exposureInterestingCount = analysis.exposure.probes.filter((probe) => probe.finding !== "safe").length;
  const apiRespondedCount = analysis.apiSurface.probes.filter((probe) => probe.classification !== "absent").length;
  const apiFallbackCount = analysis.apiSurface.probes.filter((probe) => probe.classification === "fallback").length;
  const redirectPenalty = analysis.redirects.length > 1 ? Math.max(analysis.redirects.length - 1, 0) * 2 : 0;
  const availabilityPenalty = statusAvailabilityPenalty(analysis.statusCode);
  const transportPenalty = isHttpsFinalUrl(analysis.finalUrl) ? 0 : 35;
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
    edgeHeaderFindings.reduce((total, header) => total + headerPenalty(header), 0) +
    analysis.corsSecurity.issues.length * 8 +
    availabilityPenalty +
    redirectPenalty;

  const contentPenalty =
    cspHeaderIssueCount * 24 +
    Math.min(analysis.htmlSecurity.issues.reduce((total, issue) => total + contentIssuePenalty(issue), 0), 24) +
    Math.min(cookieIssueCount * 4, 16);

  const domainPenalty =
    Math.min(analysis.domainSecurity.issues.reduce((total, issue) => total + domainIssuePenalty(issue), 0), 40) +
    Math.min(analysis.securityTxt.issues.length * 3, 6) +
    Math.min(analysis.publicSignals.issues.reduce((total, issue) => total + publicSignalPenalty(issue), 0), 8);

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

  const edgeScore = cappedAreaScore(analysis, "edge", clamp(100 - edgePenalty));
  const contentScore = cappedAreaScore(analysis, "content", clamp(100 - contentPenalty));
  const domainScore = cappedAreaScore(analysis, "domain", clamp(100 - domainPenalty));
  const exposureScore = cappedAreaScore(analysis, "exposure", clamp(100 - exposurePenalty));
  const apiScore = cappedAreaScore(analysis, "api", clamp(100 - apiPenalty));
  const trustScore = cappedAreaScore(analysis, "trust", clamp(100 - trustPenalty));
  const aiScore = cappedAreaScore(analysis, "ai", clamp(100 - aiPenalty));

  const areas: AreaScore[] = [
    {
      key: "edge",
      label: "Edge Security",
      score: edgeScore,
      status: statusForScore(edgeScore),
      notes: [
        `${edgeHeaderFindingCount} header findings`,
        `${analysis.corsSecurity.issues.length} CORS findings`,
        ...(availabilityPenalty ? [`HTTP ${analysis.statusCode} limited assessment`] : []),
        ...(analysis.assessmentLimitation?.limited ? ["Limited confidence due to restricted page access"] : []),
      ],
    },
    {
      key: "content",
      label: "Content Security",
      score: contentScore,
      status: statusForScore(contentScore),
      notes: [
        `${cspHeaderIssueCount} CSP header findings`,
        `${analysis.htmlSecurity.issues.length} page-content findings`,
        `${cookieIssueCount} cookie findings`,
        ...(analysis.assessmentLimitation?.limited ? ["Page-dependent findings may be incomplete"] : []),
      ],
    },
    {
      key: "domain",
      label: "Domain & Trust",
      score: domainScore,
      status: statusForScore(domainScore),
      notes: [
        `${analysis.domainSecurity.issues.length} DNS/mail findings`,
        `${analysis.securityTxt.issues.length} security.txt findings`,
        `${analysis.publicSignals.issues.length} public trust findings`,
      ],
    },
    {
      key: "exposure",
      label: "Exposure Control",
      score: exposureScore,
      status: statusForScore(exposureScore),
      notes: [
        `${exposureInterestingCount} interesting exposure responses`,
        ...(analysis.assessmentLimitation?.limited ? ["Interpret alongside the limited overall assessment"] : []),
      ],
    },
    {
      key: "api",
      label: "API Surface",
      score: apiScore,
      status: statusForScore(apiScore),
      notes: [
        `${apiRespondedCount} endpoints responded`,
        `${apiFallbackCount} looked like frontend fallbacks`,
        ...(analysis.assessmentLimitation?.limited ? ["API visibility may not reflect the normal app surface"] : []),
      ],
    },
    {
      key: "trust",
      label: "Third-Party Trust",
      score: trustScore,
      status: statusForScore(trustScore),
      notes: [
        `${analysis.thirdPartyTrust.totalProviders} providers detected`,
        `${analysis.thirdPartyTrust.highRiskProviders} higher-risk providers`,
        ...(analysis.assessmentLimitation?.limited ? ["Third-party observations come from a limited page read"] : []),
      ],
    },
    {
      key: "ai",
      label: "AI & Automation",
      score: aiScore,
      status: statusForScore(aiScore),
      notes: [
        analysis.aiSurface.detected ? "AI or automation signals detected" : "No visible AI surface detected",
        `${analysis.aiSurface.issues.length} AI posture findings`,
        ...(analysis.assessmentLimitation?.limited ? ["AI surface visibility may be incomplete"] : []),
      ],
    },
  ];

  return areas;
};

export const getUnifiedIssueSummary = (analysis: AnalysisResult) => {
  const critical = analysis.issues.filter((issue) => issue.severity === "critical").length;
  const priorityWarnings = analysis.issues.filter((issue) => issue.severity === "warning").length;
  const supportingWatchItems =
    analysis.domainSecurity.issues.length +
    analysis.htmlSecurity.issues.length +
    analysis.corsSecurity.issues.length +
    analysis.apiSurface.issues.length +
    analysis.securityTxt.issues.length +
    analysis.publicSignals.issues.length +
    analysis.thirdPartyTrust.issues.length +
    analysis.aiSurface.issues.length;
  const coreInfo = analysis.issues.filter((issue) => issue.severity === "info").length;
  const interestingExposureSignals = analysis.exposure.probes.filter((probe) => probe.finding === "interesting").length;
  const observedSignals = coreInfo + interestingExposureSignals;

  return {
    critical,
    warning: priorityWarnings,
    info: observedSignals,
    coreWarnings: priorityWarnings,
    contextWarnings: supportingWatchItems,
    priorityWarnings,
    supportingWatchItems,
    coreInfo,
    contextInfo: interestingExposureSignals,
    interestingExposureSignals,
    observedSignals,
  };
};
