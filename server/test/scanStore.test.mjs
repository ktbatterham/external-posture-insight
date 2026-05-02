import assert from "node:assert/strict";
import test from "node:test";
import { createScanStore } from "../scanStore.mjs";

test("scan store tracks queued, running, and completed scans", () => {
  const store = createScanStore();
  const scan = store.createScan({
    url: "https://example.com",
    mode: "standard",
    requesterScope: "ip:test",
    clientIp: "127.0.0.1",
  });

  assert.equal(scan.status, "queued");

  store.markRunning(scan.id);
  store.markCompleted(scan.id, {
    securityScore: 74,
    grade: "C",
    title: "Example title",
    assessmentLimitation: { limited: false },
    executiveSummary: { mainRisk: "Browser hardening gaps" },
    findings: [{ id: "one" }, { id: "two" }],
  });

  const saved = store.getScan(scan.id);
  assert.equal(saved.status, "completed");
  assert.equal(saved.summary.score, 74);
  assert.equal(saved.summary.grade, "C");
  assert.equal(saved.summary.findingsCount, 2);
  assert.equal(saved.summary.mainRisk, "Browser hardening gaps");
});

test("scan store summarizes failed scans and newest-first ordering", () => {
  const store = createScanStore();
  const first = store.createScan({
    url: "https://first.example",
    mode: "standard",
    requesterScope: "ip:test",
    clientIp: "127.0.0.1",
  });
  const second = store.createScan({
    url: "https://second.example",
    mode: "quiet",
    requesterScope: "ip:test",
    clientIp: "127.0.0.1",
  });

  store.markFailed(first.id, "scan_runtime_failure", "Socket hang up");
  store.markFailed(second.id, "invalid_target_private", "Private targets are not allowed.");

  const list = store.listScans();
  assert.equal(list[0].id, second.id);
  assert.equal(list[0].status, "failed");
  assert.equal(list[0].failureClass, "invalid_target_private");
  assert.equal(list[1].id, first.id);
});

