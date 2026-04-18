import assert from "node:assert/strict";
import test from "node:test";
import {
  analyzeHeaders,
  buildLibraryRiskIssues,
  buildRemediation,
  classifyIssueTaxonomy,
} from "../dist/header-analysis.js";

test("analyzeHeaders flags weak HSTS and risky CSP allowances", () => {
  const { headers, issues, strengths } = analyzeHeaders(
    {
      "strict-transport-security": "max-age=300",
      "content-security-policy": "default-src 'self'; script-src 'self' 'unsafe-inline'",
      "x-frame-options": "SAMEORIGIN",
      "x-content-type-options": "nosniff",
      "referrer-policy": "strict-origin-when-cross-origin",
    },
    true,
  );

  assert.equal(headers.find((header) => header.key === "strict-transport-security")?.status, "warning");
  assert.equal(headers.find((header) => header.key === "content-security-policy")?.status, "warning");
  assert.equal(issues.some((issue) => issue.title === "HSTS could be stronger"), true);
  assert.equal(issues.some((issue) => issue.title === "CSP contains risky allowances"), true);
  assert.equal(strengths.includes("Strong HSTS policy detected."), false);
});

test("classifyIssueTaxonomy maps library advisories to OWASP A06", () => {
  const [issue] = buildLibraryRiskIssues([
    {
      packageName: "jquery",
      version: "3.4.0",
      confidence: "high",
      sourceUrl: "https://cdn.example.com/jquery-3.4.0.min.js",
      evidence: "Detected from a versioned jQuery script URL",
      vulnerabilities: [
        {
          id: "OSV-1",
          summary: "Example advisory",
          severity: "high",
          aliases: ["CVE-2020-0001"],
          referenceUrl: "https://osv.dev/example",
        },
      ],
    },
  ]);

  const normalized = classifyIssueTaxonomy(issue);
  assert.equal(normalized.owasp.includes("A06 Vulnerable and Outdated Components"), true);
  assert.equal(normalized.mitre.includes("Reconnaissance"), true);
});

test("buildRemediation emits snippets for missing headers", () => {
  const remediation = buildRemediation([
    {
      key: "x-content-type-options",
      label: "X-Content-Type-Options",
      description: "",
      recommendation: "",
      value: null,
      status: "missing",
      severity: "warning",
      summary: "Missing.",
    },
  ]);

  assert.equal(remediation.length > 0, true);
  assert.match(remediation[0].snippet, /X-Content-Type-Options/);
});

test("classifyIssueTaxonomy keeps cookie hardening tags focused", () => {
  const normalized = classifyIssueTaxonomy({
    severity: "warning",
    area: "cookies",
    title: "Cookie JSESSIONID needs attention",
    detail: "Missing HttpOnly flag",
    confidence: "high",
    source: "observed",
    owasp: [],
    mitre: [],
  });

  assert.equal(normalized.owasp.includes("A07 Identification and Authentication Failures"), true);
  assert.equal(normalized.owasp.includes("A05 Security Misconfiguration"), true);
  assert.equal(normalized.mitre.includes("Credential Access"), true);
  assert.equal(normalized.mitre.includes("Reconnaissance"), false);
  assert.equal(normalized.mitre.includes("Defense Evasion"), false);
});
