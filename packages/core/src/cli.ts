import { writeFile } from "node:fs/promises";
import { readFile } from "node:fs/promises";
import process from "node:process";
import { analyzeUrl, buildHistoryDiffFromSnapshots, formatErrorMessage, snapshotFromAnalysis } from "./index.js";
import type { AnalysisResult, HistoryDiff, ScanIssue } from "./types.js";

type OutputFormat = "json" | "markdown" | "summary" | "sarif";
type ParsedArgs =
  | { command: "help" }
  | {
      command: "scan";
      targets: string[];
      format: OutputFormat;
      outputPath: string | null;
      baselinePath: string | null;
    }
  | {
      command: "compare";
      currentPath: string;
      baselinePath: string;
      format: OutputFormat;
      outputPath: string | null;
    };

const usage = `External Posture Insight CLI

Usage:
  external-posture-insight scan <target...> [--format json|markdown|summary|sarif] [--baseline <report.json>] [--output <file>]
  external-posture-insight compare <current-report.json> <baseline-report.json> [--format json|markdown|summary|sarif] [--output <file>]
  external-posture-insight --help

Examples:
  npx @ktbatterham/external-posture-core scan example.com
  npx @ktbatterham/external-posture-core scan example.com github.com bbc.co.uk
  npx @ktbatterham/external-posture-core scan https://example.com --format markdown
  npx @ktbatterham/external-posture-core scan example.com --format sarif --output findings.sarif
  npx @ktbatterham/external-posture-core scan example.com --format json --output report.json
  npx @ktbatterham/external-posture-core scan example.com --baseline previous-report.json
  npx @ktbatterham/external-posture-core compare current-report.json baseline-report.json
  npx @ktbatterham/external-posture-core compare current-report.json baseline-report.json --format sarif
`;

const parseArgs = (argv: string[]): ParsedArgs => {
  const args = [...argv];
  const command = args.shift();

  if (!command || command === "--help" || command === "-h" || command === "help") {
    return { command: "help" as const };
  }

  if (!["scan", "compare"].includes(command)) {
    throw new Error(`Unknown command: ${command}`);
  }

  let format: OutputFormat = "summary";
  let outputPath: string | null = null;
  let baselinePath: string | null = null;
  let currentPath: string | null = null;
  const positionals: string[] = [];

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];

    if (arg === "--format") {
      const value = args[index + 1];
      if (!value || !["json", "markdown", "summary", "sarif"].includes(value)) {
        throw new Error("Invalid --format value. Use json, markdown, summary, or sarif.");
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

    if (arg.startsWith("--")) {
      throw new Error(`Unknown argument: ${arg}`);
    }

    positionals.push(arg);
  }

  if (command === "scan") {
    if (!positionals.length) {
      throw new Error("Missing target. Usage: external-posture-insight scan <target...>");
    }
    if (positionals.length > 1 && baselinePath) {
      throw new Error("Baseline comparison is only supported for a single target scan. Use the compare command for saved reports.");
    }

    return {
      command: "scan",
      targets: positionals,
      format,
      outputPath,
      baselinePath,
    };
  }

  [currentPath, baselinePath] = positionals;
  if (!currentPath || !baselinePath) {
    throw new Error("Missing report paths. Usage: external-posture-insight compare <current-report.json> <baseline-report.json>");
  }

  return {
    command: "compare",
    currentPath,
    baselinePath,
    format,
    outputPath,
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

const formatComparisonSummary = (current: AnalysisResult, baseline: AnalysisResult, diff: HistoryDiff) =>
  [
    `Current: ${current.finalUrl}`,
    `Baseline: ${baseline.finalUrl}`,
    `Score change: ${baseline.score}/100 (${baseline.grade}) -> ${current.score}/100 (${current.grade})`,
    `Status change: ${baseline.statusCode} -> ${current.statusCode}`,
    "",
    formatDiffSummary(diff),
  ].join("\n");

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

const formatBatchSummary = (analyses: AnalysisResult[]) =>
  [
    "Batch results:",
    ...analyses.map(
      (analysis) =>
        `- ${analysis.host}: ${analysis.score}/100 (${analysis.grade}) | status ${analysis.statusCode} | ${analysis.finalUrl}`,
    ),
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

const formatBatchMarkdown = (analyses: AnalysisResult[]) =>
  [
    "# External Posture Insight Batch Scan",
    "",
    "| Target | Score | Grade | Status | Final URL |",
    "| --- | ---: | :---: | ---: | --- |",
    ...analyses.map(
      (analysis) =>
        `| ${analysis.host} | ${analysis.score}/100 | ${analysis.grade} | ${analysis.statusCode} | ${analysis.finalUrl} |`,
    ),
  ].join("\n");

const toSarifLevel = (severity: ScanIssue["severity"]) => {
  if (severity === "critical") {
    return "error";
  }
  if (severity === "warning") {
    return "warning";
  }
  return "note";
};

const toRuleId = (title: string) =>
  title
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "") || "external-posture-finding";

const buildSarifLog = (
  analyses: AnalysisResult[],
  options: {
    baselineByHost?: Map<string, AnalysisResult>;
    newIssueOnly?: boolean;
  } = {},
) => {
  const rules = new Map<
    string,
    {
      id: string;
      name: string;
      shortDescription: { text: string };
      fullDescription: { text: string };
      help: { text: string };
      properties: { tags: string[] };
    }
  >();
  const results: Array<Record<string, unknown>> = [];

  for (const analysis of analyses) {
    const baseline = options.baselineByHost?.get(analysis.host) ?? null;
    const newIssueTitles = options.newIssueOnly && baseline
      ? new Set(
          buildHistoryDiffFromSnapshots(
            snapshotFromAnalysis(analysis),
            snapshotFromAnalysis(baseline),
          ).newIssues,
        )
      : null;

    for (const issue of analysis.issues) {
      if (newIssueTitles && !newIssueTitles.has(issue.title)) {
        continue;
      }

      const ruleId = toRuleId(issue.title);
      if (!rules.has(ruleId)) {
        rules.set(ruleId, {
          id: ruleId,
          name: issue.title,
          shortDescription: { text: issue.title },
          fullDescription: { text: issue.detail },
          help: { text: issue.detail },
          properties: {
            tags: [...issue.owasp, ...issue.mitre, issue.area, issue.source, issue.confidence],
          },
        });
      }

      const message = baseline && newIssueTitles
        ? `${issue.detail} New compared with baseline ${baseline.finalUrl}.`
        : issue.detail;

      results.push({
        ruleId,
        level: toSarifLevel(issue.severity),
        message: { text: message },
        locations: [
          {
            physicalLocation: {
              artifactLocation: { uri: analysis.finalUrl },
            },
          },
        ],
        properties: {
          host: analysis.host,
          scannedAt: analysis.scannedAt,
          score: analysis.score,
          grade: analysis.grade,
          statusCode: analysis.statusCode,
          severity: issue.severity,
          area: issue.area,
          confidence: issue.confidence,
          source: issue.source,
          owasp: issue.owasp,
          mitre: issue.mitre,
        },
      });
    }
  }

  return {
    version: "2.1.0",
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    runs: [
      {
        tool: {
          driver: {
            name: "External Posture Insight",
            informationUri: "https://www.npmjs.com/package/@ktbatterham/external-posture-core",
            rules: [...rules.values()],
          },
        },
        results,
      },
    ],
  };
};

const renderSingleOutput = (analysis: AnalysisResult, format: OutputFormat, diff: HistoryDiff | null = null) => {
  if (format === "json") {
    return `${JSON.stringify(diff ? { analysis, diff } : analysis, null, 2)}\n`;
  }
  if (format === "sarif") {
    return `${JSON.stringify(buildSarifLog([analysis]), null, 2)}\n`;
  }
  if (format === "markdown") {
    return `${formatMarkdown(analysis, diff)}\n`;
  }
  return `${formatSummary(analysis, diff)}\n`;
};

const renderBatchOutput = (analyses: AnalysisResult[], format: OutputFormat) => {
  if (format === "json") {
    return `${JSON.stringify({ analyses }, null, 2)}\n`;
  }
  if (format === "sarif") {
    return `${JSON.stringify(buildSarifLog(analyses), null, 2)}\n`;
  }
  if (format === "markdown") {
    return `${formatBatchMarkdown(analyses)}\n`;
  }
  return `${formatBatchSummary(analyses)}\n`;
};

const renderComparisonOutput = (
  current: AnalysisResult,
  baseline: AnalysisResult,
  diff: HistoryDiff,
  format: OutputFormat,
) => {
  if (format === "json") {
    return `${JSON.stringify({ current, baseline, diff }, null, 2)}\n`;
  }
  if (format === "sarif") {
    return `${JSON.stringify(
      buildSarifLog([current], {
        baselineByHost: new Map([[current.host, baseline]]),
        newIssueOnly: true,
      }),
      null,
      2,
    )}\n`;
  }
  if (format === "markdown") {
    return `${[
      `# External Posture Insight Comparison: ${current.host}`,
      "",
      `- Current: ${current.finalUrl}`,
      `- Baseline: ${baseline.finalUrl}`,
      `- Score change: ${baseline.score}/100 (${baseline.grade}) -> ${current.score}/100 (${current.grade})`,
      `- Status change: ${baseline.statusCode} -> ${current.statusCode}`,
      "",
      "## Changes Since Baseline",
      "",
      ...(diff.summary.length ? diff.summary.map((item) => `- ${item}`) : ["- No material posture changes summarized."]),
    ].join("\n")}\n`;
  }
  return `${formatComparisonSummary(current, baseline, diff)}\n`;
};

const main = async () => {
  try {
    const parsed = parseArgs(process.argv.slice(2));
    if (parsed.command === "help") {
      process.stdout.write(usage);
      return;
    }

    let output: string;

    if (parsed.command === "scan") {
      const analyses: AnalysisResult[] = [];
      for (const target of parsed.targets) {
        analyses.push(await analyzeUrl(target));
      }

      if (analyses.length === 1) {
        const [analysis] = analyses;
        const baselineAnalysis = parsed.baselinePath ? await parseBaselineAnalysis(parsed.baselinePath) : null;
        const diff = baselineAnalysis
          ? buildHistoryDiffFromSnapshots(snapshotFromAnalysis(analysis), snapshotFromAnalysis(baselineAnalysis))
          : null;
        output = renderSingleOutput(analysis, parsed.format, diff);
      } else {
        output = renderBatchOutput(analyses, parsed.format);
      }

      if (parsed.outputPath) {
        await writeFile(parsed.outputPath, output, "utf8");
      } else {
        process.stdout.write(output);
      }
      return;
    }

    const currentAnalysis = await parseBaselineAnalysis(parsed.currentPath);
    const baselineAnalysis = await parseBaselineAnalysis(parsed.baselinePath);
    const diff = buildHistoryDiffFromSnapshots(
      snapshotFromAnalysis(currentAnalysis),
      snapshotFromAnalysis(baselineAnalysis),
    );
    output = renderComparisonOutput(currentAnalysis, baselineAnalysis, diff, parsed.format);

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
