import assert from "node:assert/strict";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { execFile as execFileCallback } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { promisify } from "node:util";

const execFile = promisify(execFileCallback);
const cliPath = new URL("../dist/cli.js", import.meta.url).pathname;

test("CLI compare command renders a diff summary from saved reports", async () => {
  const tempDir = await mkdtemp(join(tmpdir(), "epi-cli-"));
  const baselinePath = join(tempDir, "baseline.json");
  const currentPath = join(tempDir, "current.json");

  const baseline = {
    inputUrl: "https://example.com",
    finalUrl: "https://example.com",
    host: "example.com",
    scannedAt: "2026-04-16T08:00:00.000Z",
    score: 80,
    grade: "B",
    statusCode: 200,
    responseTimeMs: 120,
    certificate: { daysRemaining: 30 },
    thirdPartyTrust: { providers: [] },
    aiSurface: { vendors: [] },
    identityProvider: { provider: null },
    wafFingerprint: { providers: [] },
    ctDiscovery: { prioritizedHosts: [] },
    headers: [],
    issues: [],
  };

  const current = {
    ...baseline,
    scannedAt: "2026-04-16T09:00:00.000Z",
    score: 72,
    grade: "C",
    statusCode: 403,
    responseTimeMs: 90,
    issues: [{ severity: "warning", title: "Blocked edge response", detail: "Blocked", confidence: "high", source: "observed" }],
  };

  await writeFile(baselinePath, JSON.stringify(baseline), "utf8");
  await writeFile(currentPath, JSON.stringify(current), "utf8");

  const { stdout } = await execFile(process.execPath, [cliPath, "compare", currentPath, baselinePath]);

  assert.match(stdout, /Current: https:\/\/example.com/);
  assert.match(stdout, /Baseline: https:\/\/example.com/);
  assert.match(stdout, /Score change: 80\/100 \(B\) -> 72\/100 \(C\)/);
});

test("CLI compare command writes structured JSON output", async () => {
  const tempDir = await mkdtemp(join(tmpdir(), "epi-cli-"));
  const baselinePath = join(tempDir, "baseline.json");
  const currentPath = join(tempDir, "current.json");
  const outputPath = join(tempDir, "compare.json");

  const baseline = {
    inputUrl: "https://example.com",
    finalUrl: "https://example.com",
    host: "example.com",
    scannedAt: "2026-04-16T08:00:00.000Z",
    score: 90,
    grade: "A",
    statusCode: 200,
    responseTimeMs: 120,
    certificate: { daysRemaining: 30 },
    thirdPartyTrust: { providers: [] },
    aiSurface: { vendors: [] },
    identityProvider: { provider: null },
    wafFingerprint: { providers: [] },
    ctDiscovery: { prioritizedHosts: [] },
    headers: [],
    issues: [],
  };

  const current = { ...baseline, score: 88, grade: "B", scannedAt: "2026-04-16T09:00:00.000Z" };

  await writeFile(baselinePath, JSON.stringify(baseline), "utf8");
  await writeFile(currentPath, JSON.stringify(current), "utf8");

  await execFile(process.execPath, [cliPath, "compare", currentPath, baselinePath, "--format", "json", "--output", outputPath]);
  const output = JSON.parse(await readFile(outputPath, "utf8"));

  assert.equal(output.current.finalUrl, "https://example.com");
  assert.equal(output.baseline.grade, "A");
  assert.equal(output.diff.previousScore, 90);
});

test("CLI rejects malformed baseline JSON with a clean error", async () => {
  const tempDir = await mkdtemp(join(tmpdir(), "epi-cli-"));
  const baselinePath = join(tempDir, "baseline.json");

  await writeFile(baselinePath, "{not valid json", "utf8");

  await assert.rejects(
    execFile(process.execPath, [cliPath, "compare", baselinePath, baselinePath]),
    (error) => {
      assert.match(error.stderr, /Baseline file is not valid JSON\./);
      assert.match(error.stderr, /Use --help for CLI usage\./);
      return true;
    },
  );
});

test("CLI rejects multi-target scans with a baseline file", async () => {
  await assert.rejects(
    execFile(process.execPath, [cliPath, "scan", "example.com", "github.com", "--baseline", "previous-report.json"]),
    (error) => {
      assert.match(
        error.stderr,
        /Baseline comparison is only supported for a single target scan\./,
      );
      assert.match(error.stderr, /Use --help for CLI usage\./);
      return true;
    },
  );
});
