import type {
  AiSurfaceInfo,
  AnalysisResult,
  ExecutiveSummaryInfo,
  IssueConfidence,
  TechnologyResult,
  ThirdPartyProvider,
  ThirdPartyTrustInfo,
} from "./types.js";

const unique = <T>(values: Array<T | null | undefined | false>): T[] =>
  [...new Set(values.filter((value): value is T => Boolean(value)))];

const addDetectedTechnology = (
  target: TechnologyResult[],
  seen: Set<string>,
  name: string,
  category: TechnologyResult["category"],
  evidence: string,
  version?: string | null,
  confidence: IssueConfidence = "medium",
  detection: TechnologyResult["detection"] = "inferred",
) => {
  const key = `${name}:${category}`;
  if (seen.has(key)) {
    return;
  }
  seen.add(key);
  target.push({
    name,
    category,
    evidence,
    version: version || null,
    confidence,
    detection,
  });
};

export const detectHtmlTechnologies = (
  html: string,
  finalUrl: URL,
  metaGenerator: string | null,
  externalScriptUrls: string[],
  externalStylesheetUrls: string[],
): TechnologyResult[] => {
  const technologies: TechnologyResult[] = [];
  const seen = new Set<string>();
  const htmlLower = html.toLowerCase();
  const allUrls = [...externalScriptUrls, ...externalStylesheetUrls].map((url) => url.toLowerCase());
  const generator = metaGenerator?.toLowerCase() || "";

  if (generator.includes("wordpress") || htmlLower.includes("/wp-content/") || htmlLower.includes("/wp-includes/")) {
    addDetectedTechnology(technologies, seen, "WordPress", "frontend", "Detected from meta generator or wp-content assets");
  }
  if (generator.includes("drupal") || htmlLower.includes("drupalsettings") || htmlLower.includes("/sites/default/files/")) {
    addDetectedTechnology(technologies, seen, "Drupal", "frontend", "Detected from Drupal page markers");
  }
  if (generator.includes("joomla")) {
    addDetectedTechnology(technologies, seen, "Joomla", "frontend", "Detected from meta generator");
  }
  if (generator.includes("ghost")) {
    addDetectedTechnology(technologies, seen, "Ghost", "frontend", "Detected from meta generator");
  }
  if (generator.includes("webflow") || allUrls.some((url) => url.includes("webflow"))) {
    addDetectedTechnology(technologies, seen, "Webflow", "hosting", "Detected from Webflow assets or generator");
  }
  if (generator.includes("wix") || allUrls.some((url) => url.includes("wixstatic.com"))) {
    addDetectedTechnology(technologies, seen, "Wix", "hosting", "Detected from Wix assets or generator");
  }
  if (allUrls.some((url) => url.includes("static1.squarespace.com")) || generator.includes("squarespace")) {
    addDetectedTechnology(technologies, seen, "Squarespace", "hosting", "Detected from Squarespace assets or generator");
  }
  if (htmlLower.includes("/_next/") || htmlLower.includes("__next_data__")) {
    addDetectedTechnology(technologies, seen, "Next.js", "frontend", "Detected from Next.js page assets");
  }
  if (htmlLower.includes("/_nuxt/") || htmlLower.includes("__nuxt")) {
    addDetectedTechnology(technologies, seen, "Nuxt", "frontend", "Detected from Nuxt page assets");
  }
  if (allUrls.some((url) => url.includes("cdn.shopify.com")) || htmlLower.includes("shopify.theme")) {
    addDetectedTechnology(technologies, seen, "Shopify", "hosting", "Detected from Shopify assets");
  }
  if (allUrls.some((url) => url.includes("code.jquery.com")) || htmlLower.includes("jquery")) {
    addDetectedTechnology(technologies, seen, "jQuery", "frontend", "Detected from jQuery asset references");
  }
  if (allUrls.some((url) => url.includes("googletagmanager.com"))) {
    addDetectedTechnology(technologies, seen, "Google Tag Manager", "network", "Detected from third-party script domains");
  }
  if (allUrls.some((url) => url.includes("google-analytics.com") || url.includes("gtag/js"))) {
    addDetectedTechnology(technologies, seen, "Google Analytics", "network", "Detected from analytics asset references");
  }
  if (allUrls.some((url) => url.includes("app.usercentrics.eu"))) {
    addDetectedTechnology(technologies, seen, "Usercentrics", "security", "Detected from consent-management script");
  }
  if (allUrls.some((url) => url.includes("consent.cookiebot.com"))) {
    addDetectedTechnology(technologies, seen, "Cookiebot", "security", "Detected from consent-management script");
  }
  if (allUrls.some((url) => url.includes("js.hs-scripts.com"))) {
    addDetectedTechnology(technologies, seen, "HubSpot", "network", "Detected from HubSpot script references");
  }
  if (allUrls.some((url) => url.includes("adobedtm.com") || url.includes("adobedc.net"))) {
    addDetectedTechnology(technologies, seen, "Adobe Experience Cloud", "network", "Detected from Adobe tag or delivery assets");
  }
  if (allUrls.some((url) => url.includes("contentsquare") || url.includes("decibelinsight"))) {
    addDetectedTechnology(technologies, seen, "Contentsquare / Decibel", "network", "Detected from session analytics assets");
  }
  if (allUrls.some((url) => url.includes("imperva") || url.includes("incapsula"))) {
    addDetectedTechnology(technologies, seen, "Imperva", "security", "Detected from Imperva / Incapsula assets");
  }
  if (allUrls.some((url) => url.includes("onetrust"))) {
    addDetectedTechnology(technologies, seen, "OneTrust", "security", "Detected from OneTrust consent assets");
  }
  if (allUrls.some((url) => url.includes("braintree"))) {
    addDetectedTechnology(technologies, seen, "Braintree", "security", "Detected from payments-related assets");
  }
  if (allUrls.some((url) => url.includes("sentry.io"))) {
    addDetectedTechnology(technologies, seen, "Sentry", "security", "Detected from client monitoring assets");
  }
  if (allUrls.some((url) => url.includes("cloudfront.net"))) {
    addDetectedTechnology(technologies, seen, "Amazon CloudFront", "network", "Detected from asset hosting domain");
  }
  if (finalUrl.hostname.endsWith(".pages.dev")) {
    addDetectedTechnology(technologies, seen, "Cloudflare Pages", "hosting", "Derived from final hostname", null, "low", "inferred");
  }

  return technologies;
};

export const analyzeAiSurface = (
  html: string,
  externalScriptUrls: string[],
  firstPartyPaths: string[],
): AiSurfaceInfo => {
  const htmlLower = html.toLowerCase();
  const vendors: AiSurfaceInfo["vendors"] = [];
  const seen = new Set<string>();
  const addVendor = (
    name: string,
    evidence: string,
    category: AiSurfaceInfo["vendors"][number]["category"],
    confidence: IssueConfidence,
  ) => {
    const key = `${name}:${category}`;
    if (seen.has(key)) {
      return;
    }
    seen.add(key);
    vendors.push({ name, evidence, category, confidence });
  };

  const vendorMatchers: Array<{
    name: string;
    pattern: RegExp;
    evidence: string;
    category: AiSurfaceInfo["vendors"][number]["category"];
    confidence: IssueConfidence;
  }> = [
    { name: "Intercom Fin", pattern: /intercom.*fin|fin ai|intercom/i, evidence: "Detected from Intercom-related assets or markup", category: "support_automation", confidence: "medium" },
    { name: "Drift", pattern: /drift\.com|driftt/i, evidence: "Detected from Drift assets or widget markup", category: "support_automation", confidence: "high" },
    { name: "Zendesk AI", pattern: /zendesk|zopim/i, evidence: "Detected from Zendesk widget assets or markup", category: "support_automation", confidence: "medium" },
    { name: "HubSpot Chat", pattern: /hubspot|hs-scripts/i, evidence: "Detected from HubSpot assets or chat markup", category: "support_automation", confidence: "medium" },
    { name: "Salesforce Einstein", pattern: /einstein|salesforce ai/i, evidence: "Detected from Salesforce or Einstein signals", category: "ai_vendor", confidence: "medium" },
    { name: "Crisp", pattern: /\$crisp|crisp\.chat|client\.crisp|go\.crisp|crisp-im/i, evidence: "Detected from Crisp widget assets or markup", category: "support_automation", confidence: "high" },
    { name: "Freshchat", pattern: /freshchat|freshworks/i, evidence: "Detected from Freshchat assets or markup", category: "support_automation", confidence: "high" },
    { name: "OpenAI", pattern: /openai/i, evidence: "Detected from OpenAI-related assets or markup", category: "ai_vendor", confidence: "high" },
    { name: "Anthropic", pattern: /anthropic|claude/i, evidence: "Detected from Anthropic-related assets or markup", category: "ai_vendor", confidence: "high" },
    { name: "Google Gemini", pattern: /gemini|generativelanguage|vertex ai/i, evidence: "Detected from Google AI-related assets or markup", category: "ai_vendor", confidence: "medium" },
    { name: "Microsoft Copilot", pattern: /\bmicrosoft copilot\b|copilot for|copilot studio|copilot.microsoft/i, evidence: "Detected from Copilot-specific assets or markup", category: "assistant_ui", confidence: "medium" },
  ];

  const combinedSignals = `${htmlLower} ${externalScriptUrls.join(" ").toLowerCase()}`;
  for (const matcher of vendorMatchers) {
    if (matcher.pattern.test(combinedSignals)) {
      addVendor(matcher.name, matcher.evidence, matcher.category, matcher.confidence);
    }
  }

  const assistantVisible =
    /chat with (ai|our ai)|ask ai|ai assistant|virtual assistant|talk to our assistant|assistant for/i.test(htmlLower) ||
    /aria-label=["'][^"']*(chat with ai|ai assistant|ask ai|virtual assistant)[^"']*["']/i.test(html);

  const aiPageSignals = firstPartyPaths.filter((path) => /\/(ai|assistant|copilot|chat|ask-ai|automation)(\/|$)/i.test(path));
  const disclosures: string[] = [];
  const privacySignals: string[] = [];
  const governanceSignals: string[] = [];

  if (/do not share sensitive|may be inaccurate|ai-generated|generative ai|assistant may/i.test(htmlLower)) {
    disclosures.push("The page appears to include AI usage or safety disclosure language.");
  }
  if (/privacy policy/i.test(htmlLower) && /ai/i.test(htmlLower)) {
    disclosures.push("AI-related language appears alongside privacy-policy content.");
  }
  if (/do not share personal|do not enter personal|do not submit sensitive|avoid sharing confidential/i.test(htmlLower)) {
    privacySignals.push("The page appears to warn users not to enter sensitive or personal data.");
  }
  if (/data may be used to improve|used to train|retained for|stored to improve/i.test(htmlLower)) {
    privacySignals.push("The page appears to disclose AI-related retention or model-improvement language.");
  }
  if (/human review|reviewed by humans|monitored for quality/i.test(htmlLower)) {
    governanceSignals.push("The page appears to disclose human review or quality-monitoring language.");
  }
  if (/terms of use|acceptable use|responsible ai|ai principles/i.test(htmlLower) && /ai/i.test(htmlLower)) {
    governanceSignals.push("The page appears to reference AI governance or acceptable-use language.");
  }

  const issues: string[] = [];
  const strengths: string[] = [];
  const automationOnly = vendors.length > 0 && vendors.every((vendor) => vendor.category === "support_automation");
  const highConfidenceAiSignals =
    assistantVisible ||
    vendors.some((vendor) => vendor.category === "ai_vendor" && vendor.confidence === "high") ||
    aiPageSignals.length > 0;

  if (assistantVisible || vendors.length || aiPageSignals.length) {
    strengths.push(
      automationOnly && !assistantVisible && !aiPageSignals.length
        ? "Public-facing support automation signals were detected passively."
        : "Public-facing AI or automation signals were detected passively.",
    );
  }
  if (highConfidenceAiSignals && !disclosures.length) {
    issues.push("AI-related signals were detected, but no obvious AI disclosure language was found on the fetched page.");
  } else if (automationOnly && !disclosures.length) {
    issues.push("Support automation signals were detected, but no obvious disclosure language was found on the fetched page.");
  }
  if (highConfidenceAiSignals && !privacySignals.length) {
    issues.push("AI-related signals were detected, but no obvious data-handling or privacy guidance was found on the fetched page.");
  }
  if (privacySignals.length) {
    strengths.push("AI-related privacy guidance appears to be visible on the fetched page.");
  }
  if (governanceSignals.length) {
    strengths.push("AI governance or human-review language appears to be visible on the fetched page.");
  }
  if (!assistantVisible && !vendors.length && !aiPageSignals.length) {
    strengths.push("No obvious public-facing AI assistant or automation surface was detected on the fetched page.");
  }

  return {
    detected: Boolean(assistantVisible || vendors.length || aiPageSignals.length),
    assistantVisible,
    aiPageSignals,
    vendors,
    discoveredPaths: aiPageSignals,
    disclosures,
    privacySignals,
    governanceSignals,
    issues,
    strengths,
  };
};

const classifyThirdPartyProvider = (domain: string): Omit<ThirdPartyProvider, "domain"> => {
  const lower = domain.toLowerCase();
  const providers: Array<{
    pattern: RegExp;
    name: string;
    category: ThirdPartyProvider["category"];
    risk: ThirdPartyProvider["risk"];
    evidence: string;
  }> = [
    { pattern: /(google-analytics|googletagmanager|doubleclick|omtrdc|adobedtm|adobedc|analytics)/, name: "Analytics / Tagging", category: "analytics", risk: "medium", evidence: "Detected from third-party analytics or tag-management assets" },
    { pattern: /(onetrust|cookiebot|usercentrics)/, name: "Consent Management", category: "consent", risk: "low", evidence: "Detected from consent-management assets" },
    { pattern: /(intercom|drift|zendesk|zopim|hubspot|freshchat|crisp|sprinklr)/, name: "Support / Chat", category: "support", risk: "medium", evidence: "Detected from public support or chat tooling" },
    { pattern: /(openai|anthropic|gemini|vertex|copilot|wizdom\.ai)/, name: "AI / Assistant Vendor", category: "ai", risk: "high", evidence: "Detected from AI-related scripts, assets, or public assistant tooling" },
    { pattern: /(contentsquare|decibelinsight|hotjar|fullstory|medallia)/, name: "Session Replay / Experience Analytics", category: "session_replay", risk: "high", evidence: "Detected from session-replay or detailed experience-analytics assets" },
    { pattern: /(braintree|paypal|cardinalcommerce|arcot|3dsecure|tsys|payment|payments)/, name: "Payments / Verification", category: "payments", risk: "medium", evidence: "Detected from payments or challenge-flow assets" },
    { pattern: /(facebook|twitter|linkedin|tiktok|pinterest|reddit|youtube|snapchat|instagram)/, name: "Social / Advertising", category: "social", risk: "medium", evidence: "Detected from social, embedded media, or advertising assets" },
    { pattern: /(ads|adservice|amazon-adsystem|smartadserver|pubmatic|gumgum|teads|casalemedia|openx|lijit|bidswitch)/, name: "Advertising", category: "ads", risk: "high", evidence: "Detected from advertising or programmatic asset domains" },
    { pattern: /(cloudfront|fastly|akamai|cloudflare|jsdelivr|cdnjs)/, name: "CDN / Delivery", category: "cdn", risk: "low", evidence: "Detected from CDN or static-delivery domains" },
    { pattern: /(imperva|incapsula|sucuri|sentry)/, name: "Security / Monitoring", category: "security", risk: "low", evidence: "Detected from security, edge-protection, or monitoring assets" },
  ];

  const match = providers.find((provider) => provider.pattern.test(lower));
  if (match) {
    return {
      name: match.name,
      category: match.category,
      risk: match.risk,
      evidence: match.evidence,
    };
  }

  return {
    name: domain,
    category: "other",
    risk: "medium",
    evidence: "Detected from third-party assets loaded by the page",
  };
};

const getSiteDomain = (hostname: string): string => {
  const lower = hostname.toLowerCase();
  const parts = lower.split(".").filter(Boolean);
  if (parts.length <= 2) {
    return lower;
  }

  const compoundSuffixes = new Set(["co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "co.nz"]);
  const suffix = parts.slice(-2).join(".");
  if (compoundSuffixes.has(suffix) && parts.length >= 3) {
    return parts.slice(-3).join(".");
  }

  return parts.slice(-2).join(".");
};

export const analyzeThirdPartyTrust = (
  finalUrl: URL,
  htmlSecurity: Pick<AnalysisResult["htmlSecurity"], "externalScriptDomains" | "externalStylesheetDomains" | "missingSriScriptUrls">,
  aiSurface: AiSurfaceInfo,
): ThirdPartyTrustInfo => {
  const siteDomain = getSiteDomain(finalUrl.hostname);
  const thirdPartyDomains = unique([
    ...(htmlSecurity.externalScriptDomains || []),
    ...(htmlSecurity.externalStylesheetDomains || []),
  ]).filter((domain) => domain && getSiteDomain(domain) !== siteDomain);

  const providers = thirdPartyDomains.map((domain) => ({
    domain,
    ...classifyThirdPartyProvider(domain),
  }));

  const highRiskProviders = providers.filter((provider) => provider.risk === "high").length;
  const issues: string[] = [];
  const strengths: string[] = [];

  if (highRiskProviders >= 3) {
    issues.push("The page relies on several high-trust or high-observability third parties, which expands data exposure and review scope.");
  } else if (highRiskProviders > 0) {
    issues.push("The page includes high-trust third-party providers that deserve explicit review and ownership.");
  }
  if ((htmlSecurity.missingSriScriptUrls || []).length > 0) {
    issues.push("Some third-party scripts are loaded without Subresource Integrity.");
  }
  if (providers.some((provider) => provider.category === "session_replay")) {
    issues.push("Session replay or experience analytics tooling appears to be present.");
  }
  if (providers.some((provider) => provider.category === "ai") && !aiSurface.disclosures.length) {
    issues.push("AI-related third-party tooling appears present without obvious on-page disclosure language.");
  }

  if (providers.some((provider) => provider.category === "consent")) {
    strengths.push("A consent-management provider appears to be present.");
  }
  if (providers.length > 0 && highRiskProviders === 0) {
    strengths.push("Third-party footprint appears present but mostly concentrated in lower-risk delivery, monitoring, or consent tooling.");
  }
  if (!providers.length) {
    strengths.push("No obvious third-party script or stylesheet domains were detected on the fetched page.");
  }

  const summary = !providers.length
    ? "Minimal visible third-party footprint on the fetched page."
    : highRiskProviders > 0
      ? "The page depends on several third-party providers that increase trust and data-flow complexity."
      : "The page uses third-party providers, but the visible footprint is weighted more toward delivery and operational tooling.";

  return {
    totalProviders: providers.length,
    highRiskProviders,
    providers,
    issues,
    strengths,
    summary,
  };
};

export const buildExecutiveSummary = (
  result: Pick<AnalysisResult, "score" | "headers" | "thirdPartyTrust" | "aiSurface" | "domainSecurity" | "publicSignals">,
): ExecutiveSummaryInfo => {
  const missingHeaderCount = result.headers.filter((header) => header.status === "missing").length;
  const highRiskThirdParties = result.thirdPartyTrust.highRiskProviders;
  const posture: ExecutiveSummaryInfo["posture"] =
    result.score >= 80 ? "strong" : result.score >= 60 ? "mixed" : "weak";

  let mainRisk = "Browser-layer hardening gaps are the main visible risk.";
  if (highRiskThirdParties >= 3) {
    mainRisk = "Third-party trust and data-flow sprawl are the main visible risk.";
  } else if (result.aiSurface.detected && result.aiSurface.issues.length > 0) {
    mainRisk = "Public AI or automation signals are visible without much supporting disclosure or privacy guidance.";
  } else if (result.domainSecurity.issues.length > 0 || result.publicSignals.issues.length > 0) {
    mainRisk = "Public trust and domain hygiene signals need attention alongside the web posture.";
  }

  const takeaways = [
    missingHeaderCount > 0
      ? `${missingHeaderCount} browser-facing protections are missing or weak on the scanned response.`
      : "Core browser-facing protections look consistently present on the scanned response.",
    result.thirdPartyTrust.totalProviders > 0
      ? `${result.thirdPartyTrust.totalProviders} third-party provider${result.thirdPartyTrust.totalProviders === 1 ? " was" : "s were"} detected, including ${highRiskThirdParties} higher-risk integration${highRiskThirdParties === 1 ? "" : "s"}.`
      : "No obvious third-party script or stylesheet providers were detected on the fetched page.",
    result.aiSurface.detected
      ? `${result.aiSurface.vendors.length || result.aiSurface.discoveredPaths.length} public AI or automation signal${(result.aiSurface.vendors.length || result.aiSurface.discoveredPaths.length) === 1 ? " was" : "s were"} detected.`
      : "No obvious public-facing AI or automation surface was detected.",
  ];

  const overview =
    posture === "strong"
      ? "External posture looks broadly solid, with only a few areas that still deserve tuning."
      : posture === "mixed"
        ? "External posture looks operationally mature in places, but the report still shows several areas that need tightening."
        : "External posture shows multiple weaknesses that make the site look less well hardened than a mature public-facing platform should.";

  return {
    overview,
    mainRisk,
    posture,
    takeaways,
  };
};

export const mergeTechnologies = (...groups: Array<TechnologyResult[] | null | undefined>): TechnologyResult[] => {
  const merged: TechnologyResult[] = [];
  const byKey = new Map<string, TechnologyResult>();
  const confidenceRank: Record<IssueConfidence, number> = { high: 3, medium: 2, low: 1 };

  for (const group of groups) {
    for (const technology of group || []) {
      const key = `${technology.name}:${technology.category}`;
      const existing = byKey.get(key);
      if (!existing) {
        byKey.set(key, technology);
        merged.push(technology);
        continue;
      }

      const existingScore =
        confidenceRank[existing.confidence] + (existing.detection === "observed" ? 10 : 0);
      const nextScore =
        confidenceRank[technology.confidence] + (technology.detection === "observed" ? 10 : 0);

      if (nextScore > existingScore) {
        const index = merged.indexOf(existing);
        if (index >= 0) {
          merged[index] = technology;
        }
        byKey.set(key, technology);
      }
    }
  }

  return merged;
};
