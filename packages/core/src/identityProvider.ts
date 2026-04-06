import { URL } from "node:url";
import type { HtmlSecurityInfo, IdentityProviderInfo, RedirectHop } from "./types.js";

interface JsonResponse<T = unknown> {
  statusCode: number;
  json: T | null;
}

type RequestJsonFn = (targetUrl: URL, extraHeaders?: Record<string, string>) => Promise<JsonResponse>;

const DISCOVERY_PATH_LIMIT = 10;
const SUMMARY_EVIDENCE_LIMIT = 3;

const unique = <T>(values: Array<T | null | undefined | false>): T[] =>
  [...new Set(values.filter((value): value is T => Boolean(value)))];

const IDENTITY_PROVIDER_PATTERNS = [
  { provider: "Microsoft Entra ID", pattern: /(^|\.)login\.microsoftonline\.com$/i },
  { provider: "Okta", pattern: /(^|\.)okta(?:-emea)?\.com$/i },
  { provider: "Auth0", pattern: /(^|\.)auth0\.com$/i },
  { provider: "Ping Identity", pattern: /(^|\.)ping(?:one|identity)\.com$/i },
  { provider: "OneLogin", pattern: /(^|\.)onelogin\.com$/i },
  { provider: "Amazon Cognito", pattern: /amazoncognito\.com$/i },
  { provider: "Google Identity", pattern: /(^|\.)accounts\.google\.com$/i },
  { provider: "Keycloak", pattern: /keycloak/i },
];

const detectIdentityProviderName = (candidates: string[]) => {
  for (const candidate of candidates) {
    for (const entry of IDENTITY_PROVIDER_PATTERNS) {
      if (entry.pattern.test(candidate)) {
        return entry.provider;
      }
    }
  }
  return null;
};

const collectRedirectUriSignals = (html: string, finalUrl: URL) => {
  const signals: string[] = [];
  const matches = [...html.matchAll(/(?:redirect_uri|post_logout_redirect_uri)=([^"'`\s<>()&]+)/gi)];

  for (const match of matches) {
    try {
      const decoded = decodeURIComponent(match[1]);
      const redirectUrl = new URL(decoded, finalUrl);
      if (
        redirectUrl.protocol === "http:" ||
        redirectUrl.hostname === "localhost" ||
        redirectUrl.hostname.endsWith(".localhost") ||
        redirectUrl.origin !== finalUrl.origin
      ) {
        signals.push(redirectUrl.toString());
      }
    } catch {
      continue;
    }
  }

  return unique(signals).slice(0, SUMMARY_EVIDENCE_LIMIT);
};

const deriveOpenIdCandidates = (finalUrl: URL, redirects: RedirectHop[], htmlSecurity: HtmlSecurityInfo) => {
  const candidates = [new URL("/.well-known/openid-configuration", finalUrl.origin).toString()];
  if (/login\.microsoftonline\.com$/i.test(finalUrl.hostname)) {
    candidates.push(new URL("/common/v2.0/.well-known/openid-configuration", finalUrl.origin).toString());
  }

  const loginPaths = [
    ...redirects
      .map((hop) => hop.location)
      .filter((location): location is string => Boolean(location)),
    ...htmlSecurity.firstPartyPaths.filter((path) => /login|signin|oauth|authorize|sso|auth/i.test(path)),
  ];

  for (const value of loginPaths) {
    try {
      const resolved = new URL(value, finalUrl);
      const pathname = resolved.pathname;
      if (/\/oauth2\/[^/]+\/v1\/authorize/i.test(pathname)) {
        const issuerPath = pathname.replace(/\/v1\/authorize.*$/i, "");
        candidates.push(new URL(`${issuerPath}/.well-known/openid-configuration`, resolved.origin).toString());
      } else if (/\/authorize/i.test(pathname)) {
        const issuerPath = pathname.replace(/\/authorize.*$/i, "");
        candidates.push(new URL(`${issuerPath}/.well-known/openid-configuration`, resolved.origin).toString());
      }
    } catch {
      continue;
    }
  }

  return unique(candidates);
};

export const analyzeIdentityProvider = async (
  finalUrl: URL,
  redirects: RedirectHop[],
  htmlSecurity: HtmlSecurityInfo,
  html: string | null,
  requestJson: RequestJsonFn,
): Promise<IdentityProviderInfo> => {
  const redirectOrigins = unique(
    redirects
      .map((hop) => hop.location)
      .filter(Boolean)
      .map((location) => {
        try {
          return new URL(location as string, finalUrl).origin;
        } catch {
          return null;
        }
      }),
  );
  const redirectHosts = redirectOrigins.map((origin) => new URL(origin).hostname);
  const loginPaths = unique(
    htmlSecurity.firstPartyPaths.filter((path) => /login|signin|oauth|authorize|sso|auth/i.test(path)),
  ).slice(0, DISCOVERY_PATH_LIMIT);
  const provider = detectIdentityProviderName([
    finalUrl.hostname,
    ...redirectHosts,
    ...htmlSecurity.externalScriptDomains,
    ...htmlSecurity.externalStylesheetDomains,
    ...htmlSecurity.aiSurface.discoveredPaths,
  ]);
  const redirectUriSignals = html ? collectRedirectUriSignals(html, finalUrl) : [];

  let openIdConfigurationUrl: string | null = null;
  let issuer: string | null = null;
  let authorizationEndpoint: string | null = null;
  let tokenEndpoint: string | null = null;
  let endSessionEndpoint: string | null = null;
  const strengths: string[] = [];
  const issues: string[] = [];

  for (const candidate of deriveOpenIdCandidates(finalUrl, redirects, htmlSecurity)) {
    try {
      const response = await requestJson(new URL(candidate));
      if (response.statusCode >= 200 && response.statusCode < 300 && response.json) {
        const metadata = response.json as Record<string, string | undefined>;
        openIdConfigurationUrl = candidate;
        issuer = metadata.issuer || null;
        authorizationEndpoint = metadata.authorization_endpoint || null;
        tokenEndpoint = metadata.token_endpoint || null;
        endSessionEndpoint = metadata.end_session_endpoint || metadata.revocation_endpoint || null;
        break;
      }
    } catch {
      continue;
    }
  }

  if (provider) {
    strengths.push(`Identity provider signals point to ${provider}.`);
  }
  if (openIdConfigurationUrl) {
    strengths.push("An OpenID Connect configuration endpoint is publicly exposed.");
  }
  if (redirectOrigins.some((origin) => origin !== finalUrl.origin)) {
    strengths.push("Authentication redirects point to a dedicated identity origin.");
  }
  if (redirectUriSignals.length) {
    issues.push("Public markup exposed OAuth redirect_uri-style parameters worth review.");
  }
  if (!provider && !openIdConfigurationUrl && !loginPaths.length && !redirectOrigins.length) {
    strengths.push("No obvious public IdP or OAuth surface was detected from passive signals.");
  }

  return {
    detected: Boolean(provider || openIdConfigurationUrl || redirectOrigins.length || loginPaths.length),
    provider,
    redirectOrigins,
    loginPaths,
    openIdConfigurationUrl,
    issuer,
    authorizationEndpoint,
    tokenEndpoint,
    endSessionEndpoint,
    redirectUriSignals,
    issues,
    strengths,
  };
};
