import assert from "node:assert/strict";
import test from "node:test";
import {
  acceptsMonitoringHandoff,
  buildCliGrowthPrompt,
  buildCliMonitoringHandoffUrl,
} from "../dist/cliGrowthBridge.js";

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

test("CLI growth bridge offers one explicit consent-safe monitoring continuation", () => {
  const prompt = buildCliGrowthPrompt(interactiveScan);
  assert.ok(prompt);
  assert.match(prompt, /watch this site for security drift/i);
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

test("CLI monitoring continuation builds an attributed target-prefilled handoff", () => {
  const handoff = new URL(buildCliMonitoringHandoffUrl(interactiveScan.targetUrl));
  assert.equal(handoff.origin, "https://app.securl.online");
  assert.equal(handoff.pathname, "/");
  assert.equal(handoff.searchParams.get("url"), interactiveScan.targetUrl);
  assert.equal(handoff.searchParams.get("utm_source"), "securl_cli");
  assert.equal(handoff.searchParams.get("utm_medium"), "cli");
  assert.equal(handoff.searchParams.get("utm_campaign"), "cli_monitoring_watch");
});

test("CLI monitoring continuation accepts only an explicit affirmative response", () => {
  assert.equal(acceptsMonitoringHandoff("y"), true);
  assert.equal(acceptsMonitoringHandoff(" YES "), true);
  assert.equal(acceptsMonitoringHandoff(""), false);
  assert.equal(acceptsMonitoringHandoff("n"), false);
  assert.equal(acceptsMonitoringHandoff("later"), false);
});
