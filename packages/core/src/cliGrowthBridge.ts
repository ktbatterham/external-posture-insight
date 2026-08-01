const HOSTED_SCANNER_URL = "https://app.securl.online/";

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
    "Create a free shareable web report with fixes and monitoring?",
    `This sends the target URL to ${destination}. [y/N] `,
  ].join("\n");
};

export const acceptsHostedReport = (answer: string): boolean => /^(?:y|yes)$/i.test(answer.trim());
