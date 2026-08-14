import type { AnalysisResult, ScanIssue } from "./types.js";

type FailOnSeverity = Exclude<ScanIssue["severity"], "good">;

export type GithubActionsSummaryOptions = {
  analyses: AnalysisResult[];
  scanMode: "standard" | "quiet" | "deep-passive";
  policyMessages?: string[];
};

const scannerUrl = (targetUrl: string) => {
  const url = new URL("https://app.securl.online/");
  url.searchParams.set("url", targetUrl);
  url.searchParams.set("utm_source", "github_actions");
  url.searchParams.set("utm_medium", "ci");
  url.searchParams.set("utm_campaign", "release_evidence");
  return url.toString();
};

const issueCounts = (analysis: AnalysisResult) =>
  analysis.issues.reduce<Record<FailOnSeverity, number>>(
    (counts, issue) => {
      counts[issue.severity] += 1;
      return counts;
    },
    { info: 0, warning: 0, critical: 0 },
  );

const escapeTableCell = (value: string) => value.replaceAll("|", "\\|").replaceAll("\n", " ");

export function buildGithubActionsSummary({
  analyses,
  scanMode,
  policyMessages = [],
}: GithubActionsSummaryOptions): string {
  const incomplete = analyses.filter((analysis) => analysis.assessmentLimitation?.limited);
  const rows = analyses.map((analysis) => {
    const counts = issueCounts(analysis);
    return `| ${escapeTableCell(analysis.host)} | ${analysis.score}/100 | ${escapeTableCell(analysis.grade)} | ${counts.critical} | ${counts.warning} | ${analysis.statusCode} |`;
  });
  const links = analyses.map((analysis) =>
    `- [Review ${analysis.host} in the interactive scanner and start monitoring](${scannerUrl(analysis.finalUrl)})`);

  return [
    "## SecURL release evidence",
    "",
    `Passive external posture scan completed for ${analyses.length} public target${analyses.length === 1 ? "" : "s"} in \`${scanMode}\` mode.`,
    "",
    "| Target | Score | Grade | Critical | Warning | HTTP |",
    "| --- | ---: | :---: | ---: | ---: | ---: |",
    ...rows,
    "",
    incomplete.length ? "### Assessment result: incomplete" : "### Assessment result: complete",
    "",
    ...(incomplete.length
      ? incomplete.map((analysis) => `- ${analysis.host}: ${analysis.assessmentLimitation?.title ?? "The target could not be assessed completely."}`)
      : ["The target returned enough public evidence for the posture result to be evaluated."]),
    "",
    incomplete.length
      ? "### Policy result: not evaluated"
      : policyMessages.length ? "### Policy result: failed" : "### Policy result: passed",
    "",
    ...(incomplete.length
      ? ["A release policy cannot pass when the public target could not be assessed completely."]
      : policyMessages.length ? policyMessages.map((message) => `- ${message}`) : ["No configured release policy failed."]),
    "",
    "### Continue from the evidence",
    "",
    ...links,
    "",
    "The link opens a target-prefilled hosted scan. Starting a scan or watch remains an explicit user action.",
    "",
    "The attached JSON evidence contains a digest-verifiable Posture Manifest for the release record.",
    "",
  ].join("\n");
}
