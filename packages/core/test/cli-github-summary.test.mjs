import assert from "node:assert/strict";
import test from "node:test";

import { buildGithubActionsSummary } from "../dist/cliGithubSummary.js";

const analysis = {
  host: "example.com",
  finalUrl: "https://example.com/",
  score: 82,
  grade: "B",
  statusCode: 200,
  issues: [
    { severity: "critical" },
    { severity: "warning" },
    { severity: "warning" },
    { severity: "info" },
  ],
};

test("GitHub Actions summary makes release evidence and the next action visible", () => {
  const summary = buildGithubActionsSummary({
    analyses: [analysis],
    scanMode: "quiet",
  });

  assert.match(summary, /SecURL release evidence/);
  assert.match(summary, /\| example\.com \| 82\/100 \| B \| 1 \| 2 \| 200 \|/);
  assert.match(summary, /Policy result: passed/);

  const match = summary.match(/\((https:\/\/app\.securl\.online\/\?[^)]+)\)/);
  assert.ok(match);
  const continuation = new URL(match[1]);
  assert.equal(continuation.searchParams.get("url"), "https://example.com/");
  assert.equal(continuation.searchParams.get("utm_source"), "github_actions");
  assert.equal(continuation.searchParams.get("utm_medium"), "ci");
  assert.equal(continuation.searchParams.get("utm_campaign"), "release_evidence");
  assert.match(summary, /explicit user action/);
});

test("GitHub Actions summary shows configured policy failures", () => {
  const summary = buildGithubActionsSummary({
    analyses: [analysis],
    scanMode: "standard",
    policyMessages: ["Policy failed: score fell below 90 for example.com (82)."],
  });

  assert.match(summary, /Policy result: failed/);
  assert.match(summary, /score fell below 90/);
});
