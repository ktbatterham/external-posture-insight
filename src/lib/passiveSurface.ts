import { HtmlSecurityInfo } from "@/types/analysis";

const AUTH_PATH_PATTERNS: Array<{ label: string; pattern: RegExp }> = [
  { label: "login", pattern: /\/log(?:in|on)\b/i },
  { label: "signup", pattern: /\/sign(?:up|in)\b|\/register\b/i },
  { label: "account", pattern: /\/account\b|\/profile\b|\/user\b/i },
  { label: "password", pattern: /password|reset-password|forgot-password/i },
  { label: "admin", pattern: /\/admin\b|\/dashboard\b/i },
  { label: "auth", pattern: /\/auth\b|\/sso\b|\/oauth\b/i },
];

const resolveOrigin = (value: string | null, pageUrl: string | null) => {
  if (!value || !pageUrl) {
    return null;
  }

  try {
    return new URL(value, pageUrl).origin;
  } catch {
    return null;
  }
};

const toAbsoluteUrl = (value: string | null, pageUrl: string | null) => {
  if (!value || !pageUrl) {
    return value;
  }

  try {
    return new URL(value, pageUrl).toString();
  } catch {
    return value;
  }
};

const classifyAuthPath = (path: string) =>
  AUTH_PATH_PATTERNS.find((entry) => entry.pattern.test(path))?.label ?? "auth";

export interface AuthSurfaceSummary {
  authPaths: Array<{
    path: string;
    category: string;
  }>;
  passwordFormCount: number;
  sameOriginPasswordForms: number;
  externalPasswordForms: string[];
  insecurePasswordForms: number;
  summary: string;
}

export interface DataCollectionSummary {
  totalForms: number;
  sameOriginForms: number;
  externalForms: string[];
  insecureForms: number;
  postForms: number;
  summary: string;
}

export const getAuthSurfaceSummary = (htmlSecurity: HtmlSecurityInfo): AuthSurfaceSummary => {
  const authPaths = [
    ...htmlSecurity.firstPartyPaths
      .filter((path) => AUTH_PATH_PATTERNS.some((entry) => entry.pattern.test(path)))
      .map((path) => ({
        path,
        category: classifyAuthPath(path),
      })),
    ...htmlSecurity.forms
      .filter((form) => form.hasPasswordField && form.action)
      .map((form) => ({
        path: toAbsoluteUrl(form.action, htmlSecurity.pageUrl) ?? form.action ?? "(same page)",
        category: "password_form",
      })),
  ].filter((entry, index, all) => all.findIndex((candidate) => candidate.path === entry.path) === index);

  const passwordForms = htmlSecurity.forms.filter((form) => form.hasPasswordField);
  const pageOrigin = resolveOrigin(htmlSecurity.pageUrl, htmlSecurity.pageUrl);
  const externalPasswordForms = passwordForms
    .filter((form) => {
      const actionOrigin = resolveOrigin(form.action, htmlSecurity.pageUrl);
      return actionOrigin && pageOrigin && actionOrigin !== pageOrigin;
    })
    .map((form) => toAbsoluteUrl(form.action, htmlSecurity.pageUrl) ?? "(external action)");

  const sameOriginPasswordForms = passwordForms.length - externalPasswordForms.length;
  const insecurePasswordForms = passwordForms.filter((form) => form.insecureSubmission).length;

  let summary = "No obvious authentication or account-management surface was discovered passively.";
  if (passwordForms.length || authPaths.length) {
    summary = `Passive discovery found ${authPaths.length || passwordForms.length} authentication-adjacent route${authPaths.length === 1 ? "" : "s"} or form signal${authPaths.length + passwordForms.length === 1 ? "" : "s"}.`;
  }
  if (externalPasswordForms.length) {
    summary += " At least one password form submits to a different origin and deserves confirmation.";
  } else if (insecurePasswordForms) {
    summary += " At least one password form submits insecurely and should be reviewed quickly.";
  }

  return {
    authPaths,
    passwordFormCount: passwordForms.length,
    sameOriginPasswordForms,
    externalPasswordForms,
    insecurePasswordForms,
    summary,
  };
};

export const getDataCollectionSummary = (htmlSecurity: HtmlSecurityInfo): DataCollectionSummary => {
  const pageOrigin = resolveOrigin(htmlSecurity.pageUrl, htmlSecurity.pageUrl);
  const externalForms = htmlSecurity.forms
    .filter((form) => {
      const actionOrigin = resolveOrigin(form.action, htmlSecurity.pageUrl);
      return actionOrigin && pageOrigin && actionOrigin !== pageOrigin;
    })
    .map((form) => toAbsoluteUrl(form.action, htmlSecurity.pageUrl) ?? "(external action)")
    .filter((value, index, all) => all.indexOf(value) === index);

  const insecureForms = htmlSecurity.forms.filter((form) => form.insecureSubmission).length;
  const postForms = htmlSecurity.forms.filter((form) => form.method === "POST").length;
  const sameOriginForms = Math.max(htmlSecurity.forms.length - externalForms.length, 0);

  let summary = htmlSecurity.forms.length
    ? `The fetched page exposes ${htmlSecurity.forms.length} public form${htmlSecurity.forms.length === 1 ? "" : "s"} that may collect user input.`
    : "No public form collection surface was detected on the fetched page.";

  if (externalForms.length) {
    summary += " Some form submissions leave the current origin and should be intentional.";
  } else if (insecureForms) {
    summary += " At least one form appears to submit insecurely.";
  }

  return {
    totalForms: htmlSecurity.forms.length,
    sameOriginForms,
    externalForms,
    insecureForms,
    postForms,
    summary,
  };
};
