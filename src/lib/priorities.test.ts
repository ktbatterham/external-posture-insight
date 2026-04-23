import { describe, expect, it } from "vitest";
import { getPriorityActions } from "@/lib/priorities";
import { AnalysisResult } from "@/types/analysis";

const createAnalysis = (overrides: Partial<AnalysisResult> = {}): AnalysisResult =>
  ({
    headers: [],
    corsSecurity: { issues: [] },
    redirects: [],
    htmlSecurity: { issues: [], missingSriScriptUrls: [], passiveLeakSignals: [] },
    cookies: [],
    exposure: { issues: [], probes: [] },
    apiSurface: { issues: [], probes: [] },
    domainSecurity: { issues: [], dmarc: "v=DMARC1; p=reject;" },
    securityTxt: { issues: [], status: "present" },
    publicSignals: { issues: [], hstsPreload: { status: "not_listed" } },
    thirdPartyTrust: { totalProviders: 0, highRiskProviders: 0, issues: [] },
    aiSurface: { detected: false, disclosures: [], issues: [] },
    crawl: { inconsistentHeaders: [] },
    certificate: { daysRemaining: 120 },
    issues: [],
    ...overrides,
  }) as AnalysisResult;

describe("getPriorityActions", () => {
  it("adds a fallback action for the weakest area when no explicit rule matched it", () => {
    const analysis = createAnalysis({
      exposure: {
        issues: ["Directory listing style response on /.well-known/"],
        probes: [{ finding: "interesting" }],
      },
    });

    const actions = getPriorityActions(analysis);
    const fallback = actions.find((action) => action.areaKey === "exposure");
    expect(fallback).toBeDefined();
    expect(fallback?.title).toBe("Review exposure control posture");
    expect(fallback?.priorityReason).toContain("Exposure Control");
  });

  it("orders actions by weakest area score before severity", () => {
    const analysis = createAnalysis({
      headers: [{ key: "strict-transport-security", status: "missing" }],
      domainSecurity: {
        issues: [
          "SPF policy is too permissive",
          "DMARC policy not enforcing",
          "MTA-STS not found",
          "No DNSSEC evidence",
        ],
        dmarc: "v=DMARC1; p=none;",
      },
      securityTxt: { issues: ["Missing contact"], status: "missing" },
      publicSignals: { issues: ["No trust page found"], hstsPreload: { status: "not_listed" } },
    });

    const actions = getPriorityActions(analysis);
    expect(actions[0]?.areaKey).toBe("domain");
    expect(actions[0]?.title).toContain("domain");
  });

  it("caps output to five actions", () => {
    const analysis = createAnalysis({
      headers: [
        { key: "strict-transport-security", status: "missing" },
        { key: "content-security-policy", status: "missing" },
      ],
      crawl: { inconsistentHeaders: ["Strict-Transport-Security", "X-Frame-Options"] },
      htmlSecurity: {
        issues: ["inline script without nonce"],
        missingSriScriptUrls: ["https://cdn.example.com/app.js"],
        passiveLeakSignals: [{ severity: "warning", value: "source map reference" }],
      },
      thirdPartyTrust: { totalProviders: 4, highRiskProviders: 2, issues: ["adtech provider present"] },
      aiSurface: { detected: true, disclosures: [], issues: ["no privacy guidance"] },
      apiSurface: { issues: ["/api/auth responds publicly"], probes: [{ classification: "interesting" }] },
    });

    const actions = getPriorityActions(analysis);
    expect(actions).toHaveLength(5);
  });
});
