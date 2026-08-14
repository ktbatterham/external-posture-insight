const HOSTED_SCANNER_URL = "https://app.securl.online/";
const CLI_MONITORING_CAMPAIGN = "cli_monitoring_watch";

export type CliGrowthBridgeContext = {
  targetUrl: string;
  targetCount: number;
  format: string;
  outputPath: string | null;
  baselinePath: string | null;
  hasPolicy: boolean;
  stdoutIsTty: boolean;
  stderrIsTty: boolean;
  stdinIsTty: boolean;
};

export const buildCliGrowthPrompt = (context: CliGrowthBridgeContext): string | null => {
  if (
    context.targetCount !== 1
    || context.format !== "summary"
    || context.outputPath
    || context.baselinePath
    || context.hasPolicy
    || !context.stdoutIsTty
    || !context.stderrIsTty
    || !context.stdinIsTty
  ) {
    return null;
  }

  const destination = new URL(HOSTED_SCANNER_URL).hostname;
  return [
    "Watch this site for security drift in the free web app?",
    `This sends the target URL to ${destination}. [y/N] `,
  ].join("\n");
};

export const buildCliMonitoringHandoffUrl = (targetUrl: string): string => {
  const url = new URL(HOSTED_SCANNER_URL);
  url.searchParams.set("url", targetUrl);
  url.searchParams.set("utm_source", "securl_cli");
  url.searchParams.set("utm_medium", "cli");
  url.searchParams.set("utm_campaign", CLI_MONITORING_CAMPAIGN);
  return url.toString();
};

export const acceptsMonitoringHandoff = (answer: string): boolean => /^(?:y|yes)$/i.test(answer.trim());
