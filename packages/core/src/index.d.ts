export type { AnalysisResult, HtmlSecurityInfo, AnalyzeTargetOptions } from "./types";
export * from "./types";

export declare function analyzeTarget(input: string): Promise<import("./types").AnalysisResult>;
export declare function analyzeUrl(input: string): Promise<import("./types").AnalysisResult>;
export declare function analyzeHtmlDocument(
  input: string | URL,
  html: string,
): import("./types").HtmlSecurityInfo;
export declare function formatErrorMessage(error: unknown): string;
