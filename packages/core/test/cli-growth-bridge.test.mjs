import assert from "node:assert/strict";
import test from "node:test";
import { acceptsHostedReport, buildCliGrowthPrompt } from "../dist/cliGrowthBridge.js";

const interactiveScan = {
  targetUrl: "https://example.com/path?q=one two",
  targetCount: 1,
  format: "summary",
  outputPath: null,
  baselinePath: null,
  hasPolicy: false,
  stdoutIsTty: true,
  stderrIsTty: true,
  stdinIsTty: true,
};

test("CLI growth bridge offers one explicit consent-safe hosted continuation", () => {
  const prompt = buildCliGrowthPrompt(interactiveScan);
  assert.ok(prompt);
  assert.match(prompt, /free shareable web report/i);
  assert.match(prompt, /sends the target URL/i);
  assert.match(prompt, /app\.securl\.online/);
  assert.match(prompt, /\[y\/N\]/);
});

test("CLI growth bridge stays out of machine-oriented and policy runs", () => {
  const suppressedContexts = [
    { targetCount: 2 },
    { format: "json" },
    { format: "ci-json" },
    { format: "sarif" },
    { outputPath: "report.txt" },
    { baselinePath: "baseline.json" },
    { hasPolicy: true },
    { stdoutIsTty: false },
    { stderrIsTty: false },
    { stdinIsTty: false },
  ];
  for (const override of suppressedContexts) {
    assert.equal(buildCliGrowthPrompt({ ...interactiveScan, ...override }), null);
  }
});

test("CLI hosted continuation accepts only an explicit affirmative response", () => {
  assert.equal(acceptsHostedReport("y"), true);
  assert.equal(acceptsHostedReport(" YES "), true);
  assert.equal(acceptsHostedReport(""), false);
  assert.equal(acceptsHostedReport("n"), false);
  assert.equal(acceptsHostedReport("later"), false);
});
