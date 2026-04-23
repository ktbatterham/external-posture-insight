import { describe, expect, it } from "vitest";
import { getAreaScores } from "@/lib/posture";

const createAnalysis = (overrides: Record<string, unknown> = {}) =>
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
    ...overrides,
  }) as any;

describe("getAreaScores", () => {
  it("penalizes content security when CSP is missing", () => {
    const analysis = createAnalysis({
      headers: [{ key: "content-security-policy", status: "missing" }],
    });

    const content = getAreaScores(analysis).find((area) => area.key === "content");
    expect(content?.score).toBe(90);
    expect(content?.status).toBe("strong");
  });

  it("clamps heavily penalized edge score at zero and marks it weak", () => {
    const analysis = createAnalysis({
      headers: Array.from({ length: 20 }, (_, index) => ({
        key: `x-test-header-${index}`,
        status: "missing",
      })),
      corsSecurity: { issues: ["open wildcard", "credentials+wildcard", "unsafe methods"] },
      redirects: [{ statusCode: 301 }, { statusCode: 302 }, { statusCode: 302 }],
    });

    const edge = getAreaScores(analysis).find((area) => area.key === "edge");
    expect(edge?.score).toBe(0);
    expect(edge?.status).toBe("weak");
  });

  it("applies status thresholds consistently", () => {
    const strong = getAreaScores(createAnalysis()).find((area) => area.key === "domain");
    const watch = getAreaScores(
      createAnalysis({
        domainSecurity: { issues: ["mx warning", "spf warning", "dmarc warning"], dmarc: "v=DMARC1; p=none;" },
      }),
    ).find((area) => area.key === "domain");
    const weak = getAreaScores(
      createAnalysis({
        domainSecurity: { issues: Array.from({ length: 8 }, (_, i) => `issue-${i}`), dmarc: "v=DMARC1; p=none;" },
      }),
    ).find((area) => area.key === "domain");

    expect(strong?.status).toBe("strong");
    expect(watch?.status).toBe("watch");
    expect(weak?.status).toBe("weak");
  });
});
