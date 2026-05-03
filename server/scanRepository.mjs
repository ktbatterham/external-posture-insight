import crypto from "node:crypto";

export function buildScanSummary(scan) {
  const result = scan.result;
  const limitation = result?.assessmentLimitation;
  const findingsCount = Array.isArray(result?.issues) ? result.issues.length : 0;

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
    score: result?.score ?? null,
    grade: result?.grade ?? null,
    limited: limitation?.limited ?? false,
    limitedKind: limitation?.kind ?? null,
    title: result?.title ?? null,
    mainRisk: result?.executiveSummary?.mainRisk ?? null,
    findingsCount,
  };
}

export function buildPersistedScanRecord(scan) {
  return {
    id: scan.id,
    ownerId: scan.ownerId ?? null,
    status: scan.status,
    url: scan.url,
    mode: scan.mode,
    requestedAt: scan.requestedAt,
    startedAt: scan.startedAt,
    completedAt: scan.completedAt,
    requesterScope: scan.requesterScope,
    clientIp: scan.clientIp,
    failureClass: scan.failureClass,
    error: scan.error,
    summary: buildScanSummary(scan),
    result: scan.result,
  };
}

function enrichScan(scan) {
  if (!scan) {
    return null;
  }
  return {
    ...scan,
    summary: buildScanSummary(scan),
  };
}

export function createInMemoryScanRepository({ maxEntries = 200 } = {}) {
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
    kind: "memory",
    createScan({ url, mode, requesterScope, clientIp, ownerId = null }) {
      const scan = {
        id: crypto.randomUUID(),
        ownerId,
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
      return enrichScan(scan);
    },
    markRunning(id) {
      const scan = scans.get(id);
      if (!scan) {
        return null;
      }
      scan.status = "running";
      scan.startedAt = new Date().toISOString();
      touchOrder(id);
      return enrichScan(scan);
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
      return enrichScan(scan);
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
      return enrichScan(scan);
    },
    getScan(id, { requesterScope = null, ownerId = null } = {}) {
      const scan = scans.get(id);
      if (ownerId && scan?.ownerId !== ownerId) {
        return null;
      }
      if (requesterScope && scan?.requesterScope !== requesterScope) {
        return null;
      }
      return enrichScan(scan);
    },
    listScans({ limit = 20, requesterScope = null, ownerId = null } = {}) {
      const scopedOrder = ownerId
        ? order.filter((id) => scans.get(id)?.ownerId === ownerId)
        : requesterScope
          ? order.filter((id) => scans.get(id)?.requesterScope === requesterScope)
        : order;

      return scopedOrder
        .slice(0, Math.max(1, limit))
        .map((id) => enrichScan(scans.get(id))?.summary)
        .filter(Boolean);
    },
    listPersistedRecords({ limit = 20 } = {}) {
      return order
        .slice(0, Math.max(1, limit))
        .map((id) => scans.get(id))
        .filter(Boolean)
        .map((scan) => buildPersistedScanRecord(scan));
    },
  };
}
