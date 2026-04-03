export type Severity = "good" | "info" | "warning" | "critical";

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
}
