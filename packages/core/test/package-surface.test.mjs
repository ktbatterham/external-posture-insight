import assert from "node:assert/strict";
import { access } from "node:fs/promises";
import { execFile as execFileCallback } from "node:child_process";
import test from "node:test";
import { promisify } from "node:util";

const execFile = promisify(execFileCallback);

test("package surface exports expected public functions", async () => {
  const pkg = await import("../dist/index.js");

  assert.equal(typeof pkg.analyzeTarget, "function");
  assert.equal(typeof pkg.analyzeUrl, "function");
  assert.equal(typeof pkg.analyzeHtmlDocument, "function");
  assert.equal(typeof pkg.snapshotFromAnalysis, "function");
  assert.equal(typeof pkg.buildHistoryDiffFromSnapshots, "function");
  assert.equal(typeof pkg.formatErrorMessage, "function");
});

test("package surface includes a working CLI help entrypoint", async () => {
  await access(new URL("../dist/cli.js", import.meta.url));
  const { stdout } = await execFile(process.execPath, [new URL("../dist/cli.js", import.meta.url).pathname, "--help"]);

  assert.match(stdout, /External Posture Insight CLI/);
  assert.match(stdout, /scan <target\.\.\.>/);
  assert.match(stdout, /--baseline/);
  assert.match(stdout, /json\|markdown\|summary\|sarif/);
  assert.match(stdout, /--fail-on info\|warning\|critical/);
  assert.match(stdout, /--fail-on-regression/);
  assert.match(stdout, /compare <current-report\.json> <baseline-report\.json>/);
});
