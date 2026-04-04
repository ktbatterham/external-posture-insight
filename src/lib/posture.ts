import { AnalysisResult } from "@/types/analysis";

export interface AreaScore {
  key: "edge" | "content" | "domain" | "exposure" | "api";
  label: string;
  score: number;
  status: "strong" | "watch" | "weak";
  notes: string[];
}

const clamp = (value: number) => Math.max(0, Math.min(100, value));

const statusForScore = (score: number): AreaScore["status"] => {
  if (score >= 85) return "strong";
  if (score >= 65) return "watch";
  return "weak";
};

export const getAreaScores = (analysis: AnalysisResult): AreaScore[] => {
  const edgePenalty =
    analysis.headers.filter((header) => header.status === "missing").length * 8 +
    analysis.headers.filter((header) => header.status === "warning").length * 4 +
    analysis.corsSecurity.issues.length * 8 +
    analysis.redirects.length > 1
      ? Math.max(analysis.redirects.length - 1, 0) * 2
      : 0;

  const contentPenalty =
    analysis.htmlSecurity.issues.length * 8 +
    analysis.cookies.reduce((count, cookie) => count + cookie.issues.length, 0) * 4;

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

  const areas: AreaScore[] = [
    {
      key: "edge",
      label: "Edge Security",
      score: clamp(100 - edgePenalty),
      status: statusForScore(clamp(100 - edgePenalty)),
      notes: [
        `${analysis.headers.filter((header) => header.status !== "present").length} header findings`,
        `${analysis.corsSecurity.issues.length} CORS findings`,
      ],
    },
    {
      key: "content",
      label: "Content Security",
      score: clamp(100 - contentPenalty),
      status: statusForScore(clamp(100 - contentPenalty)),
      notes: [
        `${analysis.htmlSecurity.issues.length} page-content findings`,
        `${analysis.cookies.reduce((count, cookie) => count + cookie.issues.length, 0)} cookie findings`,
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
        `${analysis.exposure.probes.filter((probe) => probe.finding !== "safe").length} interesting exposure responses`,
      ],
    },
    {
      key: "api",
      label: "API Surface",
      score: clamp(100 - apiPenalty),
      status: statusForScore(clamp(100 - apiPenalty)),
      notes: [
        `${analysis.apiSurface.probes.filter((probe) => probe.classification !== "absent").length} endpoints responded`,
        `${analysis.apiSurface.probes.filter((probe) => probe.classification === "fallback").length} looked like frontend fallbacks`,
      ],
    },
  ];

  return areas;
};

export const getUnifiedIssueSummary = (analysis: AnalysisResult) => {
  return {
    critical: analysis.issues.filter((issue) => issue.severity === "critical").length,
    warning:
      analysis.issues.filter((issue) => issue.severity === "warning").length +
      analysis.domainSecurity.issues.length +
      analysis.htmlSecurity.issues.length +
      analysis.corsSecurity.issues.length +
      analysis.apiSurface.issues.length +
      analysis.securityTxt.issues.length +
      analysis.publicSignals.issues.length,
    info:
      analysis.issues.filter((issue) => issue.severity === "info").length +
      analysis.exposure.probes.filter((probe) => probe.finding === "interesting").length,
  };
};
