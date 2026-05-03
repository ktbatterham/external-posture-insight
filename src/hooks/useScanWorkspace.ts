import { startTransition, useEffect, useRef, useState } from "react";
import { toast } from "sonner";
import type { AnalysisResult, HistoryDiff } from "@/types/analysis";
import { getAreaScores } from "@/lib/posture";
import { buildHtmlReport, buildMarkdownReport } from "@/lib/reportExport";
import { readBrowserStorage, writeBrowserStorage } from "@/lib/browserStorage";
import {
  buildHistoryState,
  buildRecentScans,
  downloadFile,
  HISTORY_KEY,
  MONITORED_TARGET_LIMIT,
  MONITORED_TARGETS_KEY,
  type MonitoredTarget,
  RECENT_SCANS_KEY,
  type RecentScan,
  SCAN_OWNER_KEY,
  saveHistorySnapshot,
  STORAGE_SCHEMA_VERSION,
  type StoredHistorySnapshot,
  syncMonitoredTargetFromAnalysis,
  toMonitoredTargetView,
} from "@/lib/scanWorkspace";
import type { ReportWorkspaceSectionKey } from "@/lib/reportWorkspace";

export const useScanWorkspace = () => {
  const [isLoading, setIsLoading] = useState(false);
  const [analysisData, setAnalysisData] = useState<AnalysisResult | null>(null);
  const [recentScans, setRecentScans] = useState<RecentScan[]>([]);
  const [history, setHistory] = useState<StoredHistorySnapshot[]>([]);
  const [historyDiff, setHistoryDiff] = useState<HistoryDiff | null>(null);
  const [monitoredTargets, setMonitoredTargets] = useState<MonitoredTarget[]>([]);
  const [activeRecentScanUrl, setActiveRecentScanUrl] = useState<string | null>(null);
  const [activeReportSection, setActiveReportSection] = useState<ReportWorkspaceSectionKey>("overview");
  const autoScanRanRef = useRef(false);
  const analyzeUrlRef = useRef<(url: string, setAsCurrent?: boolean) => Promise<AnalysisResult>>();
  const historyByHostRef = useRef<Record<string, StoredHistorySnapshot[]>>({});
  const areaScores = analysisData ? getAreaScores(analysisData) : [];

  useEffect(() => {
    let cancelled = false;

    void (async () => {
      const [storedRecentScans, storedMonitoredTargets, storedHistory] = await Promise.all([
        readBrowserStorage<RecentScan[]>(RECENT_SCANS_KEY, [], STORAGE_SCHEMA_VERSION),
        readBrowserStorage<MonitoredTarget[]>(MONITORED_TARGETS_KEY, [], STORAGE_SCHEMA_VERSION),
        readBrowserStorage<Record<string, StoredHistorySnapshot[]>>(HISTORY_KEY, {}, STORAGE_SCHEMA_VERSION),
      ]);

      if (cancelled) {
        return;
      }

      historyByHostRef.current = storedHistory;
      startTransition(() => {
        setRecentScans(storedRecentScans);
        setMonitoredTargets(storedMonitoredTargets);
      });
    })();

    return () => {
      cancelled = true;
    };
  }, []);

  const persistAnalysis = (payload: AnalysisResult, setAsCurrent = true) => {
    startTransition(() => {
      if (setAsCurrent) {
        setAnalysisData(payload);
      }
      setRecentScans((current) => {
        const next = buildRecentScans(current, {
          url: payload.finalUrl,
          grade: payload.grade,
          scannedAt: payload.scannedAt,
        });
        void writeBrowserStorage(RECENT_SCANS_KEY, next, STORAGE_SCHEMA_VERSION);
        return next;
      });
      const { next, nextForHost } = saveHistorySnapshot(historyByHostRef.current, payload, getAreaScores(payload));
      historyByHostRef.current = next;
      void writeBrowserStorage(HISTORY_KEY, next, STORAGE_SCHEMA_VERSION);
      if (setAsCurrent) {
        const historyState = buildHistoryState(nextForHost);
        setHistory(historyState.history);
        setHistoryDiff(historyState.diff);
      }
      setMonitoredTargets((current) => {
        const next = syncMonitoredTargetFromAnalysis(current, payload);
        if (next !== current) {
          void writeBrowserStorage(MONITORED_TARGETS_KEY, next, STORAGE_SCHEMA_VERSION);
        }
        return next;
      });
    });
  };

  const readJsonResponse = async (response: Response) => {
    const payload = await response.json();
    if (!response.ok) {
      throw new Error(payload.error || "Scan failed.");
    }
    return payload;
  };

  const getScanOwnerToken = async () => {
    const existing = await readBrowserStorage<string | null>(SCAN_OWNER_KEY, null, STORAGE_SCHEMA_VERSION);
    if (existing) {
      return existing;
    }

    const generated = globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random().toString(36).slice(2)}`;
    await writeBrowserStorage(SCAN_OWNER_KEY, generated, STORAGE_SCHEMA_VERSION);
    return generated;
  };

  const analyzeUrl = async (url: string, setAsCurrent = true) => {
    const scanOwnerToken = await getScanOwnerToken();
    const scanHeaders = {
      "Content-Type": "application/json",
      "X-Scan-Owner": scanOwnerToken,
    };
    const createResponse = await fetch("/api/scans", {
      method: "POST",
      headers: scanHeaders,
      body: JSON.stringify({ url }),
    });
    const createdPayload = await readJsonResponse(createResponse);
    const scanId = createdPayload.scan?.id;

    if (!scanId) {
      throw new Error("Scan did not return a tracking id.");
    }

    for (let attempt = 0; attempt < 120; attempt += 1) {
      const scanResponse = await fetch(`/api/scans/${encodeURIComponent(scanId)}`, {
        headers: {
          "X-Scan-Owner": scanOwnerToken,
        },
      });
      const scanPayload = await readJsonResponse(scanResponse);
      const scan = scanPayload.scan;

      if (scan?.status === "completed" && scan.result) {
        const payload = scan.result as AnalysisResult;
        persistAnalysis(payload, setAsCurrent);
        return payload;
      }

      if (scan?.status === "failed") {
        throw new Error(scan.error || "Scan failed.");
      }

      await new Promise((resolve) => window.setTimeout(resolve, 1000));
    }

    throw new Error("Scan is still running. Please try again shortly.");
  };

  analyzeUrlRef.current = analyzeUrl;

  const handleAnalyze = async (url: string, source: "form" | "recent" = "form") => {
    setIsLoading(true);
    if (source === "recent") {
      setActiveRecentScanUrl(url);
    }

    try {
      const result = await analyzeUrl(url, true);
      if (source === "recent") {
        toast.success(`Reloaded ${result.host}.`);
      }
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Unable to scan that site.");
    } finally {
      setActiveRecentScanUrl(null);
      setIsLoading(false);
    }
  };

  useEffect(() => {
    if (typeof window === "undefined" || autoScanRanRef.current) {
      return;
    }

    const params = new URLSearchParams(window.location.search);
    const target = params.get("target");
    if (!target) {
      return;
    }

    autoScanRanRef.current = true;
    void (async () => {
      setIsLoading(true);
      try {
        await analyzeUrlRef.current?.(target, true);
      } catch (error) {
        toast.error(error instanceof Error ? error.message : "Unable to scan that site.");
      } finally {
        setIsLoading(false);
      }
    })();
  }, []);

  const saveCurrentAsMonitored = (cadence: MonitoredTarget["cadence"]) => {
    if (!analysisData) {
      return;
    }

    const alreadyTracked = monitoredTargets.some((target) => target.url === analysisData.finalUrl);
    if (!alreadyTracked && monitoredTargets.length >= MONITORED_TARGET_LIMIT) {
      toast.error(`You can save up to ${MONITORED_TARGET_LIMIT} monitoring targets in this browser. Remove one first to add another.`);
      return;
    }

    setMonitoredTargets((current) => {
      const next = [
        {
          url: analysisData.finalUrl,
          label: analysisData.host,
          cadence,
          addedAt: new Date().toISOString(),
          lastScannedAt: analysisData.scannedAt,
        },
        ...current.filter((target) => target.url !== analysisData.finalUrl),
      ].slice(0, MONITORED_TARGET_LIMIT);
      void writeBrowserStorage(MONITORED_TARGETS_KEY, next, STORAGE_SCHEMA_VERSION);
      return next;
    });

    toast.success(`Saved ${analysisData.host} as a ${cadence} monitoring target.`);
  };

  const removeMonitoredTarget = (url: string) => {
    setMonitoredTargets((current) => {
      const next = current.filter((target) => target.url !== url);
      void writeBrowserStorage(MONITORED_TARGETS_KEY, next, STORAGE_SCHEMA_VERSION);
      return next;
    });
  };

  const runTargetScan = async (url: string, setAsCurrent = true) => {
    setIsLoading(true);
    try {
      const result = await analyzeUrl(url, setAsCurrent);
      toast.success(`Scanned ${result.host}.`);
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Unable to scan that monitored target.");
    } finally {
      setIsLoading(false);
    }
  };

  const runDueScans = async () => {
    const dueTargets = monitoredTargets.map(toMonitoredTargetView).filter((target) => target.due);
    if (!dueTargets.length) {
      toast.message("No monitoring targets are due right now.");
      return;
    }

    setIsLoading(true);
    let successCount = 0;
    let failureCount = 0;

    for (const target of dueTargets) {
      try {
        await analyzeUrl(target.url, false);
        successCount += 1;
      } catch {
        failureCount += 1;
      }
    }

    if (successCount && failureCount) {
      toast.warning(`Completed ${successCount} due monitoring scan${successCount === 1 ? "" : "s"} with ${failureCount} failure${failureCount === 1 ? "" : "s"}.`);
    } else if (successCount) {
      toast.success(`Completed ${successCount} due monitoring scan${successCount === 1 ? "" : "s"}.`);
    } else {
      toast.error("All due monitoring scans failed.");
    }

    setIsLoading(false);
  };

  const exportReport = () => {
    if (!analysisData) {
      return;
    }

    downloadFile(
      `security-report-${analysisData.host}.json`,
      JSON.stringify(analysisData, null, 2),
      "application/json;charset=utf-8",
    );
  };

  const exportMarkdown = () => {
    if (!analysisData) return;
    downloadFile(
      `security-report-${analysisData.host}.md`,
      buildMarkdownReport(analysisData, historyDiff),
      "text/markdown;charset=utf-8",
    );
  };

  const exportHtml = () => {
    if (!analysisData) return;
    downloadFile(
      `security-report-${analysisData.host}.html`,
      buildHtmlReport(analysisData, historyDiff),
      "text/html;charset=utf-8",
    );
  };

  const exportPdf = () => {
    if (!analysisData) return;
    const iframe = document.createElement("iframe");
    iframe.style.position = "fixed";
    iframe.style.right = "0";
    iframe.style.bottom = "0";
    iframe.style.width = "0";
    iframe.style.height = "0";
    iframe.style.border = "0";
    iframe.setAttribute("aria-hidden", "true");

    const cleanup = () => {
      window.setTimeout(() => {
        iframe.remove();
      }, 1000);
    };

    iframe.onload = () => {
      const frameWindow = iframe.contentWindow;
      if (!frameWindow) {
        toast.error("Could not prepare the PDF export.");
        cleanup();
        return;
      }

      frameWindow.focus();
      window.setTimeout(() => {
        frameWindow.print();
        cleanup();
      }, 250);
    };

    document.body.appendChild(iframe);
    const frameDocument = iframe.contentDocument;
    if (!frameDocument) {
      toast.error("Could not prepare the PDF export.");
      cleanup();
      return;
    }

    frameDocument.open();
    frameDocument.write(buildHtmlReport(analysisData, historyDiff));
    frameDocument.close();
  };

  return {
    isLoading,
    analysisData,
    recentScans,
    history,
    historyDiff,
    monitoredTargets,
    activeRecentScanUrl,
    activeReportSection,
    areaScores,
    monitoredViews: monitoredTargets.map(toMonitoredTargetView),
    setActiveReportSection,
    handleAnalyze,
    saveCurrentAsMonitored,
    removeMonitoredTarget,
    runTargetScan,
    runDueScans,
    exportReport,
    exportMarkdown,
    exportHtml,
    exportPdf,
  };
};
