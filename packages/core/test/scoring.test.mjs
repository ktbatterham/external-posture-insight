import assert from "node:assert/strict";
import test from "node:test";
import { scoreAnalysis } from "../dist/scoring.js";

test("scoreAnalysis heavily penalizes plain HTTP and invalid transport posture", () => {
  const result = scoreAnalysis({
    isHttps: false,
    headerResults: [
      { key: "strict-transport-security", status: "missing" },
      { key: "content-security-policy", status: "missing" },
      { key: "x-frame-options", status: "missing" },
    ],
    certificate: {
      available: false,
      valid: false,
      authorized: false,
      issuer: null,
      subject: null,
      validFrom: null,
      validTo: null,
      daysRemaining: null,
      protocol: null,
      cipher: null,
      fingerprint: null,
      subjectAltName: [],
      issues: [],
    },
    cookies: [],
    redirects: [],
  });

  assert.equal(result.score < 50, true);
  assert.equal(result.grade, "F");
});

test("scoreAnalysis preserves a strong score for a hardened HTTPS site", () => {
  const result = scoreAnalysis({
    isHttps: true,
    headerResults: [
      { key: "strict-transport-security", status: "present" },
      { key: "content-security-policy", status: "present" },
      { key: "x-frame-options", status: "present" },
      { key: "x-content-type-options", status: "present" },
      { key: "referrer-policy", status: "present" },
    ],
    certificate: {
      available: true,
      valid: true,
      authorized: true,
      issuer: "Example CA",
      subject: "example.com",
      validFrom: null,
      validTo: null,
      daysRemaining: 120,
      protocol: "TLSv1.3",
      cipher: null,
      fingerprint: null,
      subjectAltName: [],
      issues: [],
    },
    cookies: [
      { name: "session", secure: true, httpOnly: true, sameSite: "Lax", expires: null },
    ],
    redirects: [{ url: "https://example.com", statusCode: 200, location: null, secure: true }],
  });

  assert.equal(result.score >= 90, true);
  assert.equal(["A+", "A"].includes(result.grade), true);
});
