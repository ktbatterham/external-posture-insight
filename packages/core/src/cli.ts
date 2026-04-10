import { writeFile } from "node:fs/promises";
import { readFile } from "node:fs/promises";
import process from "node:process";
import { analyzeUrl, buildHistoryDiffFromSnapshots, formatErrorMessage, snapshotFromAnalysis } from "./index.js";
import type { AnalysisResult, HistoryDiff } from "./types.js";

type OutputFormat = "json" | "markdown" | "summary";

const usage = `External Posture Insight CLI

Usage:
  external-posture-insight scan <target> [--format json|markdown|summary] [--baseline <report.json>] [--output <file>]
  external-posture-insight --help

Examples:
  npx @ktbatterham/external-posture-core scan example.com
  npx @ktbatterham/external-posture-core scan https://example.com --format markdown
  npx @ktbatterham/external-posture-core scan example.com --format json --output report.json
  npx @ktbatterham/external-posture-core scan example.com --baseline previous-report.json
`;

const parseArgs = (argv: string[]) => {
  const args = [...argv];
  const command = args.shift();

  if (!command || command === "--help" || command === "-h" || command === "help") {
    return { command: "help" as const };
  }

  if (command !== "scan") {
    throw new Error(`Unknown command: ${command}`);
  }

  const target = args.shift();
  if (!target) {
    throw new Error("Missing target. Usage: external-posture-insight scan <target>");
  }

  let format: OutputFormat = "summary";
  let outputPath: string | null = null;
  let baselinePath: string | null = null;

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === "--format") {
      const value = args[index + 1];
      if (!value || !["json", "markdown", "summary"].includes(value)) {
        throw new Error("Invalid --format value. Use json, markdown, or summary.");
      }
      format = value as OutputFormat;
      index += 1;
      continue;
    }

    if (arg === "--output") {
      const value = args[index + 1];
      if (!value) {
        throw new Error("Missing --output value.");
      }
      outputPath = value;
      index += 1;
      continue;
    }

    if (arg === "--baseline") {
      const value = args[index + 1];
      if (!value) {
        throw new Error("Missing --baseline value.");
      }
      baselinePath = value;
      index += 1;
      continue;
    }

    if (arg === "--help" || arg === "-h") {
      return { command: "help" as const };
    }

    throw new Error(`Unknown argument: ${arg}`);
  }

  return {
    command: "scan" as const,
    target,
    format,
    outputPath,
    baselinePath,
  };
};

const parseBaselineAnalysis = async (baselinePath: string) => {
  const raw = await readFile(baselinePath, "utf8");
  let parsed: AnalysisResult | { analysis?: AnalysisResult };

  try {
    parsed = JSON.parse(raw) as AnalysisResult | { analysis?: AnalysisResult };
  } catch {
    throw new Error("Baseline file is not valid JSON.");
  }

  if (parsed && typeof parsed === "object" && "analysis" in parsed && parsed.analysis) {
    return parsed.analysis;
  }

  if (parsed && typeof parsed === "object" && "finalUrl" in parsed && "score" in parsed) {
    return parsed as AnalysisResult;
  }

  throw new Error("Baseline file must contain a prior analysis JSON report.");
};

const formatDiffSummary = (diff: HistoryDiff | null) => {
  if (!diff) {
    return "Changes since baseline: No comparable baseline was provided.";
  }

  return [
    "Changes since baseline:",
    ...(
      diff.summary.length
        ? diff.summary
        : ["No material posture changes summarized."]
    ).map((item) => `- ${item}`),
  ].join("\n");
};

const formatSummary = (analysis: AnalysisResult, diff: HistoryDiff | null = null) =>
  [
    `Target: ${analysis.inputUrl}`,
    `Final URL: ${analysis.finalUrl}`,
    `Score: ${analysis.score}/100 (${analysis.grade})`,
    `Status: ${analysis.statusCode}`,
    `Summary: ${analysis.summary}`,
    `Top issues: ${analysis.issues.length ? analysis.issues.slice(0, 5).map((issue) => issue.title).join("; ") : "None recorded"}`,
    `Identity: ${analysis.identityProvider.provider ?? "None observed"}${analysis.identityProvider.protocol ? ` (${analysis.identityProvider.protocol.toUpperCase()})` : ""}`,
    `WAF/Edge: ${analysis.wafFingerprint.providers.length ? analysis.wafFingerprint.providers.map((provider) => provider.name).join(", ") : "None conclusively identified"}`,
    `CT coverage: ${analysis.ctDiscovery.coverageSummary}`,
    ...(diff ? ["", formatDiffSummary(diff)] : []),
  ].join("\n");

const formatMarkdown = (analysis: AnalysisResult, diff: HistoryDiff | null = null) =>
  [
    `# External Posture Insight: ${analysis.host}`,
    "",
    `- Final URL: ${analysis.finalUrl}`,
    `- Scanned: ${new Date(analysis.scannedAt).toISOString()}`,
    `- Score: ${analysis.score}/100`,
    `- Grade: ${analysis.grade}`,
    `- HTTP status: ${analysis.statusCode}`,
    "",
    "## Executive Summary",
    "",
    `- Overview: ${analysis.executiveSummary.overview}`,
    `- Main risk: ${analysis.executiveSummary.mainRisk}`,
    ...analysis.executiveSummary.takeaways.map((takeaway) => `- ${takeaway}`),
    "",
    "## Key Findings",
    "",
    ...(analysis.issues.length
      ? analysis.issues.slice(0, 10).map((issue) => `- [${issue.severity}] ${issue.title}: ${issue.detail}`)
      : ["- No core findings recorded."]),
    "",
    "## Identity Provider",
    "",
    `- Provider: ${analysis.identityProvider.provider ?? "Not identified"}`,
    `- Protocol: ${analysis.identityProvider.protocol ?? "Not inferred"}`,
    `- OIDC config: ${analysis.identityProvider.openIdConfigurationUrl ?? "Not observed"}`,
    "",
    "## WAF & Edge Fingerprint",
    "",
    `- Summary: ${analysis.wafFingerprint.summary}`,
    ...(analysis.wafFingerprint.providers.length
      ? analysis.wafFingerprint.providers.map((provider) => `- ${provider.name} (${provider.confidence} confidence): ${provider.evidence}`)
      : ["- No branded WAF or edge provider was conclusively identified."]),
    "",
    "## Certificate Transparency",
    "",
    `- Coverage summary: ${analysis.ctDiscovery.coverageSummary}`,
    ...(analysis.ctDiscovery.prioritizedHosts.length
      ? analysis.ctDiscovery.prioritizedHosts.slice(0, 8).map((host) => `- ${host.host} [${host.priority} ${host.category}]`)
      : ["- No prioritized CT hosts recorded."]),
    ...(diff
      ? [
          "",
          "## Changes Since Baseline",
          "",
          ...(diff.summary.length ? diff.summary.map((item) => `- ${item}`) : ["- No material posture changes summarized."]),
        ]
      : []),
  ].join("\n");

const renderOutput = (analysis: AnalysisResult, format: OutputFormat, diff: HistoryDiff | null = null) => {
  if (format === "json") {
    return `${JSON.stringify(diff ? { analysis, diff } : analysis, null, 2)}\n`;
  }
  if (format === "markdown") {
    return `${formatMarkdown(analysis, diff)}\n`;
  }
  return `${formatSummary(analysis, diff)}\n`;
};

const main = async () => {
  try {
    const parsed = parseArgs(process.argv.slice(2));
    if (parsed.command === "help") {
      process.stdout.write(usage);
      return;
    }

    const analysis = await analyzeUrl(parsed.target);
    const baselineAnalysis = parsed.baselinePath ? await parseBaselineAnalysis(parsed.baselinePath) : null;
    const diff = baselineAnalysis
      ? buildHistoryDiffFromSnapshots(snapshotFromAnalysis(analysis), snapshotFromAnalysis(baselineAnalysis))
      : null;
    const output = renderOutput(analysis, parsed.format, diff);

    if (parsed.outputPath) {
      await writeFile(parsed.outputPath, output, "utf8");
    } else {
      process.stdout.write(output);
    }
  } catch (error) {
    process.stderr.write(`${formatErrorMessage(error)}\n`);
    process.stderr.write("Use --help for CLI usage.\n");
    process.exitCode = 1;
  }
};

void main();
