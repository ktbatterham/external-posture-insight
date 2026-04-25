import { AnalysisResult } from "@/types/analysis";

export interface AreaScore {
  key: "edge" | "content" | "domain" | "exposure" | "api" | "trust" | "ai";
  label: string;
  score: number;
  status: "strong" | "watch" | "weak";
  notes: string[];
}

const clamp = (value: number) => Math.max(0, Math.min(100, value));

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

export const getAreaScores = (analysis: AnalysisResult): AreaScore[] => {
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
  const exposureInterestingCount = analysis.exposure.probes.filter((probe) => probe.finding !== "safe").length;
  const apiRespondedCount = analysis.apiSurface.probes.filter((probe) => probe.classification !== "absent").length;
  const apiFallbackCount = analysis.apiSurface.probes.filter((probe) => probe.classification === "fallback").length;
  const redirectPenalty = analysis.redirects.length > 1 ? Math.max(analysis.redirects.length - 1, 0) * 2 : 0;
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

  const areas: AreaScore[] = [
    {
      key: "edge",
      label: "Edge Security",
      score: clamp(100 - edgePenalty),
      status: statusForScore(clamp(100 - edgePenalty)),
      notes: [
        `${missingHeaderCount + warningHeaderCount} header findings`,
        `${analysis.corsSecurity.issues.length} CORS findings`,
      ],
    },
    {
      key: "content",
      label: "Content Security",
      score: clamp(100 - contentPenalty),
      status: statusForScore(clamp(100 - contentPenalty)),
      notes: [
        `${cspHeaderIssueCount} CSP header findings`,
        `${analysis.htmlSecurity.issues.length} page-content findings`,
        `${cookieIssueCount} cookie findings`,
      ],
    },
    {
      key: "domain",
      label: "Domain & Trust",
      score: clamp(100 - domainPenalty),
      status: statusForScore(clamp(100 - domainPenalty)),
      notes: [
        `${analysis.domainSecurity.issues.length} DNS/mail findings`,
        `${analysis.securityTxt.issues.length} security.txt findings`,
        `${analysis.publicSignals.issues.length} public trust findings`,
      ],
    },
    {
      key: "exposure",
      label: "Exposure Control",
      score: clamp(100 - exposurePenalty),
      status: statusForScore(clamp(100 - exposurePenalty)),
      notes: [
        `${exposureInterestingCount} interesting exposure responses`,
      ],
    },
    {
      key: "api",
      label: "API Surface",
      score: clamp(100 - apiPenalty),
      status: statusForScore(clamp(100 - apiPenalty)),
      notes: [
        `${apiRespondedCount} endpoints responded`,
        `${apiFallbackCount} looked like frontend fallbacks`,
      ],
    },
    {
      key: "trust",
      label: "Third-Party Trust",
      score: clamp(100 - trustPenalty),
      status: statusForScore(clamp(100 - trustPenalty)),
      notes: [
        `${analysis.thirdPartyTrust.totalProviders} providers detected`,
        `${analysis.thirdPartyTrust.highRiskProviders} higher-risk providers`,
      ],
    },
    {
      key: "ai",
      label: "AI & Automation",
      score: clamp(100 - aiPenalty),
      status: statusForScore(clamp(100 - aiPenalty)),
      notes: [
        analysis.aiSurface.detected ? "AI or automation signals detected" : "No visible AI surface detected",
        `${analysis.aiSurface.issues.length} AI posture findings`,
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
