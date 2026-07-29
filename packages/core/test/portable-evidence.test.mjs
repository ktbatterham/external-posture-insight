import assert from "node:assert/strict";
import test from "node:test";

import {
  buildPortableEvidence,
  postureManifestSha256,
  verifyPortableEvidence,
} from "../dist/portableEvidence.js";

const manifest = (overrides = {}) => ({
  version: "1.0",
  manifestId: "pm_0123456789abcdef01234567",
  generatedAt: "2026-07-29T06:00:00.000Z",
  engine: { name: "securl", version: "1.28.0" },
  target: {
    inputUrl: "example.com",
    normalizedUrl: "https://example.com/",
    finalUrl: "https://example.com/",
    host: "example.com",
  },
  scan: {
    mode: "standard",
    scannedAt: "2026-07-29T06:00:00.000Z",
    responseTimeMs: 100,
    statusCode: 200,
    timing: null,
    assessmentLimitation: { limited: false, kind: null, detail: null },
  },
  posture: {
    score: 80,
    grade: "B",
    summary: "Sound.",
    issueCounts: {},
    strengthCount: 1,
    scoreDrivers: [],
  },
  checks: {
    observationLedger: {
      version: "1.0",
      target: "https://example.com/",
      generatedAt: "2026-07-29T06:00:00.000Z",
      observations: [],
    },
    skipped: [],
  },
  evidence: {
    evidenceSummary: null,
    evidenceQuality: null,
    signalClarity: null,
  },
  policy: {
    source: "default",
    evaluation: {
      version: "1.0",
      policy: { id: "baseline", name: "Baseline", version: "1.0" },
      target: "https://example.com/",
      evaluatedAt: "2026-07-29T06:00:00.000Z",
      passed: true,
      violations: [],
      summary: {
        rulesEvaluated: 1,
        violations: 0,
        bySeverity: { info: 0, warning: 0, critical: 0 },
        highestSeverity: null,
      },
    },
  },
  ...overrides,
});

test("portable evidence preserves the manifest and verifies its canonical digest", () => {
  const source = manifest();
  const bundle = buildPortableEvidence(source, {
    source: "hosted",
    scanId: "scan-123",
  });

  assert.equal(bundle.version, "1.0");
  assert.match(bundle.evidenceId, /^pe_[a-f0-9]{24}$/);
  assert.equal(bundle.provenance.source, "hosted");
  assert.equal(bundle.provenance.scanId, "scan-123");
  assert.equal(bundle.integrity.manifestSha256, postureManifestSha256(source));
  assert.equal(bundle.compatibility.manifestSchema, "https://securl.online/schemas/posture-manifest-v1.json");
  assert.equal(bundle.manifest, source);
  assert.equal(bundle.comparison, null);
  assert.equal(verifyPortableEvidence(bundle), true);

  bundle.manifest.posture.score = 79;
  assert.equal(verifyPortableEvidence(bundle), false);
});

test("portable evidence compares manifest observation ledgers without embedding a second manifest", () => {
  const baseline = manifest({
    manifestId: "pm_aaaaaaaaaaaaaaaaaaaaaaaa",
    generatedAt: "2026-07-28T06:00:00.000Z",
    scan: {
      ...manifest().scan,
      scannedAt: "2026-07-28T06:00:00.000Z",
    },
    posture: { ...manifest().posture, score: 75, grade: "C" },
  });
  const bundle = buildPortableEvidence(manifest(), {
    source: "cli",
    baseline,
  });

  assert.equal(bundle.comparison.scoreDelta, 5);
  assert.equal(bundle.comparison.baseline.manifestId, baseline.manifestId);
  assert.equal(bundle.comparison.current.manifestId, manifest().manifestId);
  assert.equal(bundle.comparison.observationDrift.summary.direction, "unchanged");
  assert.equal(Object.hasOwn(bundle.comparison, "baselineManifest"), false);
});

test("portable evidence rejects baselines for a different host", () => {
  const baseline = manifest({
    target: { ...manifest().target, host: "other.example" },
  });
  assert.throws(
    () => buildPortableEvidence(manifest(), { source: "cli", baseline }),
    /does not match current host/,
  );
});
