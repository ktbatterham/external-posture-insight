export type Severity = "good" | "info" | "warning" | "critical";
export type IssueConfidence = "high" | "medium" | "low";
export type IssueSource = "observed" | "heuristic" | "inferred";

export interface SecurityHeaderResult {
  key: string;
  label: string;
  description: string;
  recommendation: string;
  value: string | null;
  status: "present" | "missing" | "warning";
  severity: Severity;
  summary: string;
}

export interface CookieResult {
  name: string;
  valuePreview: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite: string | null;
  domain: string | null;
  path: string | null;
  expires: string | null;
  maxAge: string | null;
  issues: string[];
  risk: "low" | "medium" | "high";
}

export interface TechnologyResult {
  name: string;
  category: "server" | "frontend" | "security" | "hosting" | "network";
  evidence: string;
  version: string | null;
}

export interface CertificateResult {
  available: boolean;
  valid: boolean;
  authorized: boolean;
  issuer: string | null;
  subject: string | null;
  validFrom: string | null;
  validTo: string | null;
  daysRemaining: number | null;
  protocol: string | null;
  cipher: string | null;
  fingerprint: string | null;
  subjectAltName: string[];
  issues: string[];
}

export interface RedirectHop {
  url: string;
  statusCode: number;
  location: string | null;
  secure: boolean;
}

export interface ScanIssue {
  severity: Exclude<Severity, "good">;
  area: "transport" | "headers" | "certificate" | "cookies";
  title: string;
  detail: string;
  confidence: IssueConfidence;
  source: IssueSource;
}

export interface RemediationSnippet {
  platform: "nginx" | "apache" | "cloudflare" | "vercel" | "netlify";
  title: string;
  description: string;
  filename: string;
  snippet: string;
}

export interface CrawlPageResult {
  label: string;
  path: string;
  finalUrl: string;
  sameOrigin: boolean;
  statusCode: number;
  responseTimeMs: number;
  score: number;
  grade: string;
  missingHeaders: string[];
  warningHeaders: string[];
  issueCount: number;
}

export interface CrawlSummary {
  pages: CrawlPageResult[];
  weakestPage: string | null;
  strongestPage: string | null;
  inconsistentHeaders: string[];
  discoverySources: string[];
}

export interface HistorySnapshot {
  finalUrl: string;
  host: string;
  scannedAt: string;
  score: number;
  grade: string;
  statusCode: number;
  responseTimeMs: number;
  headers: Pick<SecurityHeaderResult, "label" | "status" | "value">[];
  issues: Pick<ScanIssue, "severity" | "title" | "detail" | "confidence" | "source">[];
}

export interface HistoryDiff {
  previousScore: number | null;
  scoreDelta: number | null;
  previousGrade: string | null;
  newIssues: string[];
  resolvedIssues: string[];
  headerChanges: Array<{
    label: string;
    from: string;
    to: string;
  }>;
}

export interface SecurityTxtInfo {
  status: "present" | "missing" | "invalid";
  url: string | null;
  contact: string[];
  expires: string | null;
  policy: string[];
  acknowledgments: string[];
  encryption: string[];
  hiring: string[];
  preferredLanguages: string[];
  canonical: string[];
  raw: string | null;
  issues: string[];
}

export interface DomainSecurityInfo {
  host: string;
  mxRecords: string[];
  nsRecords: string[];
  caaRecords: string[];
  spf: string | null;
  dmarc: string | null;
  mtaSts: {
    dns: string | null;
    policyUrl: string | null;
    policy: string | null;
  };
  issues: string[];
  strengths: string[];
}

export interface HtmlFormInfo {
  action: string | null;
  method: string;
  insecureSubmission: boolean;
  hasPasswordField: boolean;
}

export interface HtmlSecurityInfo {
  fetched: boolean;
  pageUrl: string | null;
  pageTitle: string | null;
  metaGenerator: string | null;
  forms: HtmlFormInfo[];
  externalScriptDomains: string[];
  externalStylesheetDomains: string[];
  insecureResourceUrls: string[];
  inlineScriptCount: number;
  inlineStyleCount: number;
  missingSriScriptUrls: string[];
  firstPartyPaths: string[];
  detectedTechnologies: TechnologyResult[];
  issues: string[];
  strengths: string[];
}

export interface AiSurfaceInfo {
  detected: boolean;
  assistantVisible: boolean;
  aiPageSignals: string[];
  vendors: Array<{
    name: string;
    evidence: string;
    category: "ai_vendor" | "support_automation" | "assistant_ui";
    confidence: IssueConfidence;
  }>;
  discoveredPaths: string[];
  disclosures: string[];
  issues: string[];
  strengths: string[];
}

export interface ExposureProbe {
  label: string;
  path: string;
  statusCode: number;
  finalUrl: string;
  finding: "safe" | "interesting" | "exposed" | "error";
  detail: string;
}

export interface ExposureSummary {
  probes: ExposureProbe[];
  issues: string[];
  strengths: string[];
}

export interface CorsSecurityInfo {
  allowedOrigin: string | null;
  allowCredentials: string | null;
  allowMethods: string[];
  allowHeaders: string[];
  allowPrivateNetwork: string | null;
  vary: string | null;
  optionsStatus: number;
  issues: string[];
  strengths: string[];
}

export interface ApiSurfaceProbe {
  label: string;
  path: string;
  statusCode: number;
  finalUrl: string;
  classification: "absent" | "public" | "restricted" | "interesting" | "fallback" | "error";
  contentType: string | null;
  detail: string;
}

export interface ApiSurfaceInfo {
  probes: ApiSurfaceProbe[];
  issues: string[];
  strengths: string[];
}

export interface PublicSignalsInfo {
  hstsPreload: {
    status: "preloaded" | "pending" | "eligible" | "not_preloaded" | "unknown";
    summary: string;
    sourceUrl: string;
  };
  issues: string[];
  strengths: string[];
}

export interface AnalysisResult {
  inputUrl: string;
  normalizedUrl: string;
  finalUrl: string;
  host: string;
  scannedAt: string;
  responseTimeMs: number;
  statusCode: number;
  score: number;
  grade: string;
  summary: string;
  headers: SecurityHeaderResult[];
  rawHeaders: Record<string, string>;
  cookies: CookieResult[];
  technologies: TechnologyResult[];
  certificate: CertificateResult;
  redirects: RedirectHop[];
  issues: ScanIssue[];
  strengths: string[];
  remediation: RemediationSnippet[];
  crawl: CrawlSummary;
  securityTxt: SecurityTxtInfo;
  domainSecurity: DomainSecurityInfo;
  htmlSecurity: HtmlSecurityInfo;
  aiSurface: AiSurfaceInfo;
  exposure: ExposureSummary;
  corsSecurity: CorsSecurityInfo;
  apiSurface: ApiSurfaceInfo;
  publicSignals: PublicSignalsInfo;
}
