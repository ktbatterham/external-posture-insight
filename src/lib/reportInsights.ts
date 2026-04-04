import { AnalysisResult, MitreRelevance, OwaspCategory } from "@/types/analysis";

export interface InsightBucket<T extends string> {
  label: T;
  count: number;
}

export interface DisclosurePosture {
  summary: string;
  strengths: string[];
  issues: string[];
  discoveredPages: string[];
}

const PATH_LABELS = [
  { pattern: /\/privacy/i, label: "Privacy" },
  { pattern: /\/terms|\/legal|\/acceptable-use/i, label: "Terms" },
  { pattern: /\/security|\/trust|\/responsible-ai/i, label: "Security" },
  { pattern: /\/contact|\/support/i, label: "Contact" },
  { pattern: /\/accessibility/i, label: "Accessibility" },
] as const;

const formatLabel = (value: string) =>
  value
    .split(/\s+/)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");

const countByLabel = <T extends string>(labels: T[]) => {
  const counts = new Map<T, number>();
  for (const label of labels) {
    counts.set(label, (counts.get(label) || 0) + 1);
  }
  return [...counts.entries()]
    .sort((left, right) => right[1] - left[1])
    .map(([label, count]) => ({ label, count }));
};

export const getOwaspSummary = (analysis: AnalysisResult): InsightBucket<OwaspCategory>[] =>
  countByLabel(analysis.issues.flatMap((issue) => issue.owasp)) as InsightBucket<OwaspCategory>[];

export const getMitreSummary = (analysis: AnalysisResult): InsightBucket<MitreRelevance>[] =>
  countByLabel(analysis.issues.flatMap((issue) => issue.mitre)) as InsightBucket<MitreRelevance>[];

export const getDominantThemes = (analysis: AnalysisResult) => {
  const owasp = getOwaspSummary(analysis).slice(0, 3);
  const mitre = getMitreSummary(analysis).slice(0, 3);
  const dominantOwasp = owasp[0]?.label || "A05 Security Misconfiguration";

  const summary =
    dominantOwasp === "A05 Security Misconfiguration"
      ? "Most visible issues are configuration and hardening gaps rather than application-specific exploit signals."
      : dominantOwasp === "A02 Cryptographic Failures"
        ? "Transport and cryptographic posture is the main visible weakness."
        : dominantOwasp === "A07 Identification and Authentication Failures"
          ? "Session and authentication-adjacent signals are more prominent than average."
          : "The visible issue mix spans several classes rather than one obvious dominant theme.";

  return {
    summary,
    owasp,
    mitre,
  };
};

export const getDisclosurePosture = (analysis: AnalysisResult): DisclosurePosture => {
  const firstPartyPaths = analysis.htmlSecurity.firstPartyPaths || [];
  const discoveredPages = PATH_LABELS.filter((item) =>
    firstPartyPaths.some((path) => item.pattern.test(path)),
  ).map((item) => item.label);

  const strengths: string[] = [];
  const issues: string[] = [];

  if (analysis.securityTxt.status === "present") {
    strengths.push("A valid security.txt disclosure route is published.");
  } else {
    issues.push("No valid security.txt disclosure route was detected.");
  }

  if (discoveredPages.includes("Privacy")) {
    strengths.push("A privacy-related page was discovered passively.");
  } else {
    issues.push("No obvious privacy-policy page was discovered from the fetched page.");
  }

  if (discoveredPages.includes("Terms")) {
    strengths.push("A terms or legal page was discovered passively.");
  }

  if (discoveredPages.includes("Contact")) {
    strengths.push("A contact or support path was discovered passively.");
  }

  if (analysis.aiSurface.detected) {
    if (analysis.aiSurface.privacySignals.length || analysis.aiSurface.governanceSignals.length || analysis.aiSurface.disclosures.length) {
      strengths.push("AI-related disclosure or governance language is visible.");
    } else {
      issues.push("AI or automation signals are visible without much supporting disclosure language.");
    }
  }

  const summary =
    strengths.length >= 3 && issues.length <= 1
      ? "Disclosure and trust posture looks relatively transparent from passive signals."
      : strengths.length >= 1
        ? "Some trust and disclosure signals are present, but the public-facing guidance still feels partial."
        : "Public trust and disclosure posture looks thin from passive signals.";

  return {
    summary,
    strengths,
    issues,
    discoveredPages,
  };
};
