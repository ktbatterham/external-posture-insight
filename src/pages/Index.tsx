import { startTransition, useEffect, useRef, useState } from "react";
import { Clock3 } from "lucide-react";
import { toast } from "sonner";
import { MonitoredTargetView, MonitoredTargetsPanel } from "@/components/MonitoredTargetsPanel";
import { UrlForm } from "@/components/UrlForm";
import { Card, CardContent } from "@/components/ui/card";
import { AnalysisResult, HistoryDiff, HistorySnapshot } from "@/types/analysis";
import { getAreaScores } from "@/lib/posture";
import { buildHtmlReport, buildMarkdownReport } from "@/lib/reportExport";
import { readBrowserStorage, writeBrowserStorage } from "@/lib/browserStorage";
import { buildHistoryDiff, snapshotFromAnalysis } from "../../packages/core/src/historyDiff";
import { ClientSection } from "@/components/report/ClientSection";
import { EvidenceSection } from "@/components/report/EvidenceSection";
import { ExposureSection } from "@/components/report/ExposureSection";
import { FindingsSection } from "@/components/report/FindingsSection";
import { OverviewSection } from "@/components/report/OverviewSection";
import { TrustSection } from "@/components/report/TrustSection";

const RECENT_SCANS_KEY = "secure-header-insight:recent-scans";
const HISTORY_KEY = "secure-header-insight:history";
const MONITORED_TARGETS_KEY = "secure-header-insight:monitored-targets";
const STORAGE_SCHEMA_VERSION = 1;
const MONITORED_TARGET_LIMIT = 12;

interface RecentScan {
  url: string;
  grade: string;
  scannedAt: string;
}

interface MonitoredTarget {
  url: string;
  label: string;
  cadence: "daily" | "weekly";
  addedAt: string;
  lastScannedAt: string | null;
}

const buildRecentScans = (current: RecentScan[], scan: RecentScan) =>
  [scan, ...current.filter((item) => item.url !== scan.url)].slice(0, 6);

const syncMonitoredTargetFromAnalysis = (targets: MonitoredTarget[], payload: AnalysisResult) => {
  let changed = false;
  const next = targets.map((target) => {
    const matchesTarget =
      target.url === payload.finalUrl || target.url === payload.normalizedUrl || target.label === payload.host;
    if (!matchesTarget) {
      return target;
    }

    const updatedTarget = {
      ...target,
      url: payload.finalUrl,
      label: payload.host,
      lastScannedAt: payload.scannedAt,
    };

    if (
      updatedTarget.url !== target.url ||
      updatedTarget.label !== target.label ||
      updatedTarget.lastScannedAt !== target.lastScannedAt
    ) {
      changed = true;
    }

    return updatedTarget;
  });

  return changed ? next : targets;
};

const cadenceMs: Record<MonitoredTarget["cadence"], number> = {
  daily: 24 * 60 * 60 * 1000,
  weekly: 7 * 24 * 60 * 60 * 1000,
};

const toMonitoredTargetView = (target: MonitoredTarget): MonitoredTargetView => {
  const baseTime = target.lastScannedAt ? new Date(target.lastScannedAt).getTime() : new Date(target.addedAt).getTime();
  const nextDueAt = new Date(baseTime + cadenceMs[target.cadence]).toISOString();
  return {
    ...target,
    nextDueAt,
    due: Date.now() >= new Date(nextDueAt).getTime(),
  };
};

const saveHistorySnapshot = (
  current: Record<string, HistorySnapshot[]>,
  analysis: AnalysisResult,
) => {
  const key = analysis.host;
  const snapshot = snapshotFromAnalysis(analysis);
  const nextForHost = [snapshot, ...(current[key] || [])].slice(0, 10);
  const next = { ...current, [key]: nextForHost };
  return { next, nextForHost };
};

const downloadFile = (filename: string, content: BlobPart, type: string) => {
  const blob = new Blob([content], { type });
  const objectUrl = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = objectUrl;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(objectUrl);
};

const Index = () => {
  const [isLoading, setIsLoading] = useState(false);
  const [analysisData, setAnalysisData] = useState<AnalysisResult | null>(null);
  const [recentScans, setRecentScans] = useState<RecentScan[]>([]);
  const [history, setHistory] = useState<HistorySnapshot[]>([]);
  const [historyDiff, setHistoryDiff] = useState<HistoryDiff | null>(null);
  const [monitoredTargets, setMonitoredTargets] = useState<MonitoredTarget[]>([]);
  const autoScanRanRef = useRef(false);
  const analyzeUrlRef = useRef<(url: string, setAsCurrent?: boolean) => Promise<AnalysisResult>>();
  const historyByHostRef = useRef<Record<string, HistorySnapshot[]>>({});
  const areaScores = analysisData ? getAreaScores(analysisData) : [];

  useEffect(() => {
    let cancelled = false;

    void (async () => {
      const [storedRecentScans, storedMonitoredTargets, storedHistory] = await Promise.all([
        readBrowserStorage<RecentScan[]>(RECENT_SCANS_KEY, [], STORAGE_SCHEMA_VERSION),
        readBrowserStorage<MonitoredTarget[]>(MONITORED_TARGETS_KEY, [], STORAGE_SCHEMA_VERSION),
        readBrowserStorage<Record<string, HistorySnapshot[]>>(HISTORY_KEY, {}, STORAGE_SCHEMA_VERSION),
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
      setRecentScans((current) =>
        {
          const next = buildRecentScans(current, {
            url: payload.finalUrl,
            grade: payload.grade,
            scannedAt: payload.scannedAt,
          });
          void writeBrowserStorage(RECENT_SCANS_KEY, next, STORAGE_SCHEMA_VERSION);
          return next;
        },
      );
      const { next, nextForHost } = saveHistorySnapshot(historyByHostRef.current, payload);
      historyByHostRef.current = next;
      void writeBrowserStorage(HISTORY_KEY, next, STORAGE_SCHEMA_VERSION);
      if (setAsCurrent) {
        setHistory(nextForHost);
        setHistoryDiff(buildHistoryDiff(nextForHost));
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

  const analyzeUrl = async (url: string, setAsCurrent = true) => {
    const response = await fetch(`/api/analyze?url=${encodeURIComponent(url)}`);
    const payload = await response.json();

    if (!response.ok) {
      throw new Error(payload.error || "Scan failed.");
    }

    persistAnalysis(payload, setAsCurrent);
    return payload as AnalysisResult;
  };

  analyzeUrlRef.current = analyzeUrl;

  const handleAnalyze = async (url: string) => {
    setIsLoading(true);

    try {
      await analyzeUrl(url, true);
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Unable to scan that site.");
    } finally {
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

  const monitoredViews = monitoredTargets.map(toMonitoredTargetView);

  return (
    <div className="min-h-screen bg-[radial-gradient(circle_at_top_left,_rgba(58,111,255,0.14),_transparent_30%),linear-gradient(180deg,_#f7fafc_0%,_#eef3f8_45%,_#f8fbfd_100%)]">
      <div className="mx-auto max-w-7xl px-4 py-10 sm:px-6 lg:px-8">
        <section className="rounded-[2rem] border border-white/70 bg-white/70 px-6 py-8 shadow-2xl shadow-slate-200/50 backdrop-blur sm:px-8">
          <div className="space-y-6">
            <div className="grid gap-6 lg:grid-cols-[1.2fr_0.8fr] lg:items-stretch">
              <div className="space-y-6">
                <div className="inline-flex rounded-full border border-sky-200 bg-sky-50 px-3 py-1 text-xs font-semibold uppercase tracking-[0.18em] text-sky-900">
                  External posture analysis
                </div>
                <div className="space-y-4">
                  <h1 className="max-w-3xl text-4xl font-bold tracking-[-0.035em] text-slate-950 sm:text-5xl">
                    Understand a site's public security posture before the noisy tools even start.
                  </h1>
                </div>
                <UrlForm onSubmit={handleAnalyze} isLoading={isLoading} initialValue="example.com" />
              </div>

              <Card className="h-full overflow-hidden border-slate-200 bg-[#102143] text-slate-50 shadow-xl">
                <CardContent className="flex h-full flex-col space-y-4 p-6">
                  <p className="text-xs uppercase tracking-[0.18em] text-slate-300">What this scan checks</p>
                  <div className="grid gap-3 text-sm text-slate-100">
                    <div className="rounded-2xl border border-white/10 bg-white/5 p-4">
                      Headers, redirects, TLS, cookies, and browser isolation controls with confidence-labeled findings.
                    </div>
                    <div className="rounded-2xl border border-white/10 bg-white/5 p-4">
                      DNS and email posture, security.txt, public HSTS preload signals, and passive page-risk analysis.
                    </div>
                    <div className="rounded-2xl border border-white/10 bg-white/5 p-4">
                      Detected stack and AI surface signals, low-noise exposure checks, exports, and monitoring targets.
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>

            {recentScans.length > 0 ? (
              <div className="space-y-3 rounded-[1.5rem] border border-white/70 bg-white/60 p-4">
                <div className="flex items-center gap-2 text-sm font-semibold text-slate-700">
                  <Clock3 className="h-4 w-4" />
                  Recent scans
                </div>
                <div className="grid gap-3 md:grid-cols-3">
                  {recentScans.slice(0, 3).map((scan) => (
                    <button
                      key={scan.url}
                      type="button"
                      onClick={() => handleAnalyze(scan.url)}
                      className="rounded-2xl border border-slate-200 bg-white px-4 py-3 text-left shadow-sm transition hover:-translate-y-0.5 hover:shadow-md"
                    >
                      <div className="flex items-center justify-between gap-3">
                        <span className="truncate text-sm font-medium text-slate-900">{scan.url}</span>
                        <span className="text-lg font-black text-slate-700">{scan.grade}</span>
                      </div>
                      <p className="mt-2 text-xs text-slate-500">{new Date(scan.scannedAt).toLocaleString()}</p>
                    </button>
                  ))}
                </div>
              </div>
            ) : null}

            <MonitoredTargetsPanel
              targets={monitoredViews}
              currentUrl={analysisData?.finalUrl ?? recentScans[0]?.url ?? null}
              monitoredCount={monitoredTargets.length}
              dueCount={monitoredViews.filter((target) => target.due).length}
              embedded
              onAddDaily={() => saveCurrentAsMonitored("daily")}
              onAddWeekly={() => saveCurrentAsMonitored("weekly")}
              onRunDue={runDueScans}
              onRunTarget={(url) => void runTargetScan(url, true)}
              onRemove={removeMonitoredTarget}
              busy={isLoading}
            />
          </div>
        </section>

        {analysisData && (
          <section className="mt-8 space-y-8">
            <OverviewSection
              analysisData={analysisData}
              historyDiff={historyDiff}
              areaScores={areaScores}
              exportPdf={exportPdf}
              exportMarkdown={exportMarkdown}
              exportHtml={exportHtml}
              exportReport={exportReport}
            />
            <FindingsSection analysisData={analysisData} />
            <TrustSection analysisData={analysisData} />
            <ClientSection analysisData={analysisData} />
            <ExposureSection analysisData={analysisData} />
            <EvidenceSection analysisData={analysisData} history={history} historyDiff={historyDiff} />
          </section>
        )}
      </div>
    </div>
  );
};

export default Index;
