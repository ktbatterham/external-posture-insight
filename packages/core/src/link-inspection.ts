import net from "node:net";
import { domainToUnicode } from "node:url";
import { fetchWithRedirects } from "./network.js";
import { headerValue } from "./utils.js";

export type LinkSignalLevel = "info" | "attention" | "high";

export interface LinkSignal {
  id: string;
  level: LinkSignalLevel;
  title: string;
  detail: string;
}

export interface LinkInspectionResult {
  schema: "securl.link-inspection.v1";
  submittedUrl: string;
  normalizedUrl: string;
  destinationUrl: string | null;
  verdict: {
    level: "no_obvious_concern" | "review" | "high_attention" | "blocked";
    title: string;
    summary: string;
  };
  input: {
    hostname: string;
    unicodeHostname: string;
    scheme: string;
    port: string | null;
  };
  redirects: Array<{
    position: number;
    url: string;
    hostname: string;
    statusCode: number;
    location: string | null;
    originChanged: boolean;
    downgradedToHttp: boolean;
  }>;
  response: {
    statusCode: number;
    contentType: string | null;
    contentLength: string | null;
    contentDisposition: string | null;
    elapsedMs: number | null;
  } | null;
  signals: LinkSignal[];
  limitations: string[];
}

const SHORTENER_HOSTS = new Set([
  "bit.ly", "bitly.is", "buff.ly", "cutt.ly", "goo.gl", "is.gd", "lnkd.in", "ow.ly",
  "rebrand.ly", "t.co", "tiny.cc", "tinyurl.com", "trib.al", "youtu.be",
]);

const REDIRECT_PARAMETER_NAMES = new Set([
  "continue", "dest", "destination", "next", "redirect", "redirect_uri",
  "redirect_url", "return", "return_to", "target", "url",
]);

function signal(id: string, level: LinkSignalLevel, title: string, detail: string): LinkSignal {
  return { id, level, title, detail };
}

function inspectLexicalUrl(target: URL): LinkSignal[] {
  const signals: LinkSignal[] = [];
  const unicodeHostname = domainToUnicode(target.hostname);
  if (target.username || target.password) {
    signals.push(signal("embedded_credentials", "high", "The URL hides a destination behind an @ sign", "Text before the @ sign is user information, not the site being opened."));
  }
  if (target.protocol === "http:") {
    signals.push(signal("unencrypted_http", "attention", "The link starts without HTTPS", "Traffic to the first destination is not protected by TLS."));
  }
  if (target.hostname.includes("xn--")) {
    signals.push(signal("internationalized_hostname", "attention", "The hostname uses encoded international characters", `The browser-readable hostname is ${unicodeHostname || target.hostname}. Check that spelling carefully.`));
  }
  if (net.isIP(target.hostname.replace(/^\[(.*)\]$/, "$1"))) {
    signals.push(signal("ip_literal", "attention", "The link uses an IP address instead of a domain", "That can be legitimate, but it removes the familiar domain name users normally verify."));
  }
  if (target.port && !((target.protocol === "https:" && target.port === "443") || (target.protocol === "http:" && target.port === "80"))) {
    signals.push(signal("unusual_port", "attention", "The link uses a non-standard port", `The destination explicitly requests port ${target.port}.`));
  }
  if (SHORTENER_HOSTS.has(target.hostname.toLowerCase())) {
    signals.push(signal("known_shortener", "attention", "The destination is hidden by a link shortener", "The redirect chain below reveals where it actually leads."));
  }
  const labels = target.hostname.split(".").filter(Boolean);
  if (labels.length >= 6) {
    signals.push(signal("deep_subdomain", "attention", "The hostname has many subdomain levels", "Read the hostname from right to left and verify the registered domain."));
  }
  for (const [name, value] of target.searchParams) {
    if (!REDIRECT_PARAMETER_NAMES.has(name.toLowerCase())) continue;
    try {
      const nested = new URL(value, target);
      if (nested.origin !== target.origin) {
        signals.push(signal("nested_destination", "attention", "The URL contains another destination", `Parameter ${name} points to ${nested.hostname}.`));
        break;
      }
    } catch {
      // A non-URL value is not evidence of a redirect target.
    }
  }
  return signals;
}

function buildVerdict(signals: LinkSignal[], blocked = false): LinkInspectionResult["verdict"] {
  if (blocked) {
    return { level: "blocked", title: "Link not opened", summary: "SecURL stopped before making a request because the URL was unsupported or unsafe to fetch." };
  }
  if (signals.some((item) => item.level === "high")) {
    return { level: "high_attention", title: "Treat this link with caution", summary: "The URL or redirect path contains a high-attention characteristic. Verify it through another channel before opening it." };
  }
  if (signals.some((item) => item.level === "attention")) {
    return { level: "review", title: "Review before opening", summary: "The link resolved, but one or more characteristics deserve a closer look." };
  }
  return { level: "no_obvious_concern", title: "No obvious link-level concern found", summary: "The destination resolved and the URL and redirect checks below found no obvious concern. This is not a malware verdict." };
}

export async function inspectLink(rawTarget: string): Promise<LinkInspectionResult> {
  const submittedUrl = rawTarget.trim();
  const normalizedInput = /^https?:\/\//i.test(submittedUrl) ? submittedUrl : `https://${submittedUrl}`;
  let initialUrl: URL;
  try {
    initialUrl = new URL(normalizedInput);
  } catch {
    throw new Error("Enter a valid public http or https URL.");
  }
  if (!["http:", "https:"].includes(initialUrl.protocol)) {
    throw new Error("Only public http and https URLs are supported.");
  }

  const signals = inspectLexicalUrl(initialUrl);
  const base = {
    schema: "securl.link-inspection.v1" as const,
    submittedUrl,
    normalizedUrl: initialUrl.toString(),
    input: {
      hostname: initialUrl.hostname,
      unicodeHostname: domainToUnicode(initialUrl.hostname) || initialUrl.hostname,
      scheme: initialUrl.protocol.replace(":", ""),
      port: initialUrl.port || null,
    },
    limitations: [
      "This passive check does not execute page scripts, submit forms, download attachments, or sign in.",
      "No malware, domain-age, blocklist, or reputation provider is queried, so this is not a guarantee that a link is safe.",
    ],
  };

  if (initialUrl.username || initialUrl.password) {
    return { ...base, destinationUrl: null, verdict: buildVerdict(signals, true), redirects: [], response: null, signals };
  }

  // Resolve links as a browser navigation would. Some redirect services return a
  // different response to HEAD, while GET still discards the body in requestOnce.
  const result = await fetchWithRedirects(initialUrl, undefined, { method: "GET" });
  const redirects = result.redirects.map((hop, position, chain) => {
    const url = new URL(hop.url);
    const next = position < chain.length - 1 ? new URL(chain[position + 1].url) : null;
    const downgradedToHttp = Boolean(next && url.protocol === "https:" && next.protocol === "http:");
    if (next && next.origin !== url.origin) {
      signals.push(signal(`origin_change_${position}`, "info", "The redirect changes origin", `${url.hostname} sends the request to ${next.hostname}.`));
    }
    if (downgradedToHttp) {
      signals.push(signal(`https_downgrade_${position}`, "high", "A redirect drops HTTPS", `${url.hostname} redirects to an unencrypted HTTP destination.`));
    }
    return {
      position: position + 1,
      url: hop.url,
      hostname: url.hostname,
      statusCode: hop.statusCode,
      location: hop.location,
      originChanged: Boolean(next && next.origin !== url.origin),
      downgradedToHttp,
    };
  });
  const contentDisposition = headerValue(result.response.headers, "content-disposition");
  const unresolvedLocation = headerValue(result.response.headers, "location");
  if ([301, 302, 303, 307, 308].includes(result.response.statusCode) && unresolvedLocation) {
    signals.push(signal("redirect_limit", "high", "The redirect chain did not reach a final response", "SecURL stopped at its redirect safety limit. Do not assume the last URL shown is the true final destination."));
  }
  if (contentDisposition && /attachment/i.test(contentDisposition)) {
    signals.push(signal("attachment", "attention", "The destination returns a download", `The server describes the response as ${contentDisposition}.`));
  }
  const contentType = headerValue(result.response.headers, "content-type");
  if (contentType && !/^(text\/html|application\/xhtml\+xml)(?:;|$)/i.test(contentType)) {
    signals.push(signal("non_html_response", "info", "The destination is not a normal web page", `The server reports ${contentType}.`));
  }
  if (redirects.length >= 6) {
    signals.push(signal("many_redirects", "attention", "The link takes a long redirect path", `${redirects.length - 1} redirects were followed before the final response.`));
  }

  return {
    ...base,
    destinationUrl: result.finalUrl.toString(),
    verdict: buildVerdict(signals),
    redirects,
    response: {
      statusCode: result.response.statusCode,
      contentType,
      contentLength: headerValue(result.response.headers, "content-length"),
      contentDisposition,
      elapsedMs: result.response.elapsedMs ?? null,
    },
    signals,
  };
}
