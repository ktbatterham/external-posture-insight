import crypto from "node:crypto";

function buildScanSummary(scan) {
  const result = scan.result;
  const limitation = result?.assessmentLimitation;
  const findingsCount = Array.isArray(result?.findings) ? result.findings.length : 0;

  return {
    id: scan.id,
    status: scan.status,
    url: scan.url,
    mode: scan.mode,
    requestedAt: scan.requestedAt,
    startedAt: scan.startedAt,
    completedAt: scan.completedAt,
    failureClass: scan.failureClass,
    error: scan.error,
    score: result?.securityScore ?? null,
    grade: result?.grade ?? null,
    limited: limitation?.limited ?? false,
    limitedKind: limitation?.kind ?? null,
    title: result?.title ?? null,
    mainRisk: result?.executiveSummary?.mainRisk ?? null,
    findingsCount,
  };
}

export function createScanStore({ maxEntries = 200 } = {}) {
  const scans = new Map();
  const order = [];

  const touchOrder = (id) => {
    const index = order.indexOf(id);
    if (index >= 0) {
      order.splice(index, 1);
    }
    order.unshift(id);

    while (order.length > maxEntries) {
      const staleId = order.pop();
      if (staleId) {
        scans.delete(staleId);
      }
    }
  };

  return {
    createScan({ url, mode, requesterScope, clientIp }) {
      const scan = {
        id: crypto.randomUUID(),
        status: "queued",
        url,
        mode,
        requesterScope,
        clientIp,
        requestedAt: new Date().toISOString(),
        startedAt: null,
        completedAt: null,
        failureClass: null,
        error: null,
        result: null,
      };
      scans.set(scan.id, scan);
      touchOrder(scan.id);
      return scan;
    },
    markRunning(id) {
      const scan = scans.get(id);
      if (!scan) {
        return null;
      }
      scan.status = "running";
      scan.startedAt = new Date().toISOString();
      touchOrder(id);
      return scan;
    },
    markCompleted(id, result) {
      const scan = scans.get(id);
      if (!scan) {
        return null;
      }
      scan.status = "completed";
      scan.completedAt = new Date().toISOString();
      scan.result = result;
      touchOrder(id);
      return scan;
    },
    markFailed(id, failureClass, message) {
      const scan = scans.get(id);
      if (!scan) {
        return null;
      }
      scan.status = "failed";
      scan.completedAt = new Date().toISOString();
      scan.failureClass = failureClass;
      scan.error = message;
      touchOrder(id);
      return scan;
    },
    getScan(id) {
      const scan = scans.get(id);
      if (!scan) {
        return null;
      }
      return {
        ...scan,
        summary: buildScanSummary(scan),
      };
    },
    listScans({ limit = 20 } = {}) {
      return order.slice(0, Math.max(1, limit)).map((id) => buildScanSummary(scans.get(id))).filter(Boolean);
    },
  };
}

