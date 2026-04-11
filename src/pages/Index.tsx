import { startTransition, useEffect, useRef, useState } from "react";
import { Activity, Clock3, Download, Link2, Server } from "lucide-react";
import { toast } from "sonner";
import { MonitoredTargetView, MonitoredTargetsPanel } from "@/components/MonitoredTargetsPanel";
import { CertificateAnalysis } from "@/components/CertificateAnalysis";
import { ClientExposurePanel } from "@/components/ClientExposurePanel";
import { CookieAnalysis } from "@/components/CookieAnalysis";
import { CorsSecurityPanel } from "@/components/CorsSecurityPanel";
import { CrawlPanel } from "@/components/CrawlPanel";
import { CtDiscoveryPanel } from "@/components/CtDiscoveryPanel";
import { DataCollectionPanel } from "@/components/DataCollectionPanel";
import { DomainSecurityPanel } from "@/components/DomainSecurityPanel";
import { DisclosureTrustPanel } from "@/components/DisclosureTrustPanel";
import { ExposurePanel } from "@/components/ExposurePanel";
import { FindingsPanel } from "@/components/FindingsPanel";
import { HeadersTable } from "@/components/HeadersTable";
import { HistoryPanel } from "@/components/HistoryPanel";
import { HtmlSecurityPanel } from "@/components/HtmlSecurityPanel";
import { IdentityProviderPanel } from "@/components/IdentityProviderPanel";
import { MonitoringPanel } from "@/components/MonitoringPanel";
import { PostureSummaryPanel } from "@/components/PostureSummaryPanel";
import { PriorityActionsPanel } from "@/components/PriorityActionsPanel";
import { PublicSignalsPanel } from "@/components/PublicSignalsPanel";
import { RawHeadersPanel } from "@/components/RawHeadersPanel";
import { RemediationPanel } from "@/components/RemediationPanel";
import { RedirectChain } from "@/components/RedirectChain";
import { SecurityTxtPanel } from "@/components/SecurityTxtPanel";
import { TechnologyStack } from "@/components/TechnologyStack";
import { TaxonomySummaryPanel } from "@/components/TaxonomySummaryPanel";
import { ThirdPartyTrustPanel } from "@/components/ThirdPartyTrustPanel";
import { UrlForm } from "@/components/UrlForm";
import { WafFingerprintPanel } from "@/components/WafFingerprintPanel";
import { AuthSurfacePanel } from "@/components/AuthSurfacePanel";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { AnalysisResult, HistoryDiff, HistorySnapshot } from "@/types/analysis";
import { ApiSurfacePanel } from "@/components/ApiSurfacePanel";
import { AiSurfacePanel } from "@/components/AiSurfacePanel";
import { getHttpStatusDetails } from "@/lib/httpStatus";
import { getAreaScores } from "@/lib/posture";
import { buildHtmlReport, buildMarkdownReport } from "@/lib/reportExport";
import { readBrowserStorage, writeBrowserStorage } from "@/lib/browserStorage";
import { buildHistoryDiff, snapshotFromAnalysis } from "../../packages/core/src/historyDiff";

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

const METRIC_CARD_CLASS =
  "rounded-[1.75rem] border border-white/60 bg-white/80 p-5 shadow-lg shadow-slate-200/50 backdrop-blur";

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

const sectionTitleClass = "text-xs font-semibold uppercase tracking-[0.18em] text-slate-500";

const ReportSectionHeader = ({
  eyebrow,
  title,
  description,
}: {
  eyebrow: string;
  title: string;
  description: string;
}) => (
  <div className="max-w-3xl space-y-3">
    <p className={sectionTitleClass}>{eyebrow}</p>
    <div className="space-y-2">
      <h2 className="text-3xl font-black tracking-tight text-slate-950">{title}</h2>
      <p className="text-sm leading-7 text-slate-600">{description}</p>
    </div>
  </div>
);

const trafficLightStyles = {
  strong: {
    ring: "border-emerald-200 bg-emerald-50",
    pill: "bg-emerald-600",
    text: "text-emerald-900",
  },
  watch: {
    ring: "border-amber-200 bg-amber-50",
    pill: "bg-amber-500",
    text: "text-amber-900",
  },
  weak: {
    ring: "border-rose-200 bg-rose-50",
    pill: "bg-rose-600",
    text: "text-rose-900",
  },
} as const;

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
            <div id="overview" className="space-y-6">
              {analysisData.assessmentLimitation.limited ? (
                <div className="rounded-[1.75rem] border border-amber-200 bg-amber-50 px-5 py-4 text-amber-950">
                  <p className="text-xs font-semibold uppercase tracking-[0.18em] text-amber-700">
                    {analysisData.assessmentLimitation.title}
                  </p>
                  <p className="mt-2 text-sm leading-7 text-amber-900">
                    {analysisData.assessmentLimitation.detail}
                  </p>
                </div>
              ) : null}

              <div className="space-y-4">
                <div className="rounded-[2rem] border border-amber-200 bg-gradient-to-br from-amber-50 to-white px-6 py-6 shadow-sm ring-1 ring-amber-200">
                  <div className="grid gap-4 xl:grid-cols-[1.15fr_0.7fr_1.55fr] xl:items-start">
                    <div>
                      <p className={sectionTitleClass}>Target</p>
                      <p className="mt-3 text-3xl font-black tracking-tight text-slate-950">{analysisData.host}</p>
                      <p className="mt-2 break-all text-sm text-slate-500">{analysisData.finalUrl}</p>
                    </div>
                    <div className="rounded-[1.5rem] bg-white/80 px-5 py-5 shadow-sm">
                      <p className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">Scan timestamp</p>
                      <p className="mt-3 text-sm font-semibold text-slate-950">
                        {new Date(analysisData.scannedAt).toLocaleString()}
                      </p>
                    </div>

                    <div className="rounded-[1.5rem] bg-white/80 px-5 py-5 shadow-sm">
                      <p className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">Analyst read</p>
                      <p className="mt-3 text-base leading-8 text-slate-700">
                        {analysisData.executiveSummary.overview}
                      </p>
                    </div>
                  </div>

                  <div className="mt-5 grid gap-3 xl:grid-cols-[0.7fr_0.7fr_0.7fr_1.55fr]">
                    <div className="rounded-[1.5rem] bg-white/80 px-5 py-5 shadow-sm">
                      <p className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">Overall posture</p>
                      <p className="mt-3 text-2xl font-black capitalize text-slate-950">
                        {analysisData.executiveSummary.posture}
                      </p>
                    </div>
                    <div className="rounded-[1.5rem] bg-white/80 px-5 py-5 shadow-sm">
                      <p className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">HTTP status</p>
                      <p className="mt-3 text-3xl font-black text-slate-950">{analysisData.statusCode}</p>
                      <p className="mt-2 text-sm text-slate-500">{getHttpStatusDetails(analysisData.statusCode).label}</p>
                    </div>
                    <div className="rounded-[1.5rem] bg-white/80 px-5 py-5 shadow-sm">
                      <p className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">Response time</p>
                      <p className="mt-3 text-3xl font-black text-slate-950">{analysisData.responseTimeMs}ms</p>
                    </div>
                    <div className="rounded-[1.5rem] bg-white/80 px-5 py-5 shadow-sm">
                      <p className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">Main visible risk</p>
                      <p className="mt-3 text-base font-semibold leading-7 text-slate-950">
                        {analysisData.executiveSummary.mainRisk}
                      </p>
                    </div>
                  </div>

                  <div className="mt-5 border-t border-white/80 pt-5">
                    <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
                      <div className="rounded-[1.5rem] border border-amber-200 bg-amber-50/80 px-4 py-4 shadow-sm">
                        <div className="flex items-center justify-between gap-3">
                          <p className="text-sm font-semibold text-slate-900">Healthcheck</p>
                          <span className="inline-flex h-3 w-3 rounded-full bg-amber-500" aria-hidden="true" />
                        </div>
                        <div className="mt-4 flex items-end gap-2">
                          <span className="text-3xl font-black text-amber-700">{analysisData.grade}</span>
                        </div>
                        <p className="mt-2 text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">
                          overall grade
                        </p>
                      </div>
                      {areaScores.map((area) => {
                        const style = trafficLightStyles[area.status];
                        return (
                          <div
                            key={area.key}
                            className={`rounded-[1.5rem] border border-white/80 bg-white/80 px-4 py-4 shadow-sm ${style.ring}`}
                          >
                            <div className="flex items-center justify-between gap-3">
                              <p className="text-sm font-semibold text-slate-900">{area.label}</p>
                              <span className={`inline-flex h-3 w-3 rounded-full ${style.pill}`} aria-hidden="true" />
                            </div>
                            <div className="mt-4 flex items-end gap-2">
                              <span className={`text-3xl font-black ${style.text}`}>{area.score}%</span>
                              <span className="pb-1 text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">
                                {area.status}
                              </span>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>

                  <div className="mt-5 border-t border-white/80 pt-5">
                    <div className="rounded-[1.5rem] bg-white/80 px-5 py-5 shadow-sm">
                      <p className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">What stands out</p>
                      <div className="mt-4 grid gap-3 xl:grid-cols-3">
                        {analysisData.executiveSummary.takeaways.map((takeaway, index) => (
                          <div key={takeaway} className="flex gap-3 rounded-2xl bg-white px-4 py-4 text-sm text-slate-700 shadow-sm ring-1 ring-slate-100">
                            <div className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-slate-100 text-xs font-semibold text-slate-600">
                              {index + 1}
                            </div>
                            <p className="leading-6">{takeaway}</p>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>

                  <div className="mt-5 border-t border-white/80 pt-5">
                    <div className="flex flex-wrap gap-3">
                      <Button variant="outline" className="rounded-2xl" onClick={exportPdf}>
                        Export PDF
                      </Button>
                      <Button variant="outline" className="rounded-2xl" onClick={exportMarkdown}>
                        Export Markdown
                      </Button>
                      <Button variant="outline" className="rounded-2xl" onClick={exportHtml}>
                        Export HTML
                      </Button>
                      <Button variant="outline" className="rounded-2xl" onClick={exportReport}>
                        <Download className="mr-2 h-4 w-4" />
                        Export JSON
                      </Button>
                    </div>
                  </div>
                </div>
              </div>

              <div className="space-y-4">
                <div>
                  <p className={sectionTitleClass}>Posture summary</p>
                  <p className="mt-2 max-w-3xl text-sm leading-7 text-slate-600">
                    Start with the directional breakdown across the major posture areas before moving into specific findings and taxonomy detail.
                  </p>
                </div>
                <PostureSummaryPanel analysis={analysisData} />
              </div>

              <div className="space-y-4">
                <PriorityActionsPanel analysis={analysisData} />
                <MonitoringPanel analysis={analysisData} diff={historyDiff} />
              </div>
            </div>

            <div id="findings" className="space-y-6">
              <ReportSectionHeader
                eyebrow="Risks"
                title="What matters most"
                description="This layer brings the scanner’s main story together: the strongest findings, category posture, taxonomy themes, and practical remediation."
              />

              <FindingsPanel issues={analysisData.issues} strengths={analysisData.strengths} />

              <div className="space-y-4">
                <div>
                  <p className={sectionTitleClass}>Risk themes</p>
                  <p className="mt-2 max-w-3xl text-sm leading-7 text-slate-600">
                    OWASP and MITRE patterns work better as their own interpretation layer rather than competing for width with the posture breakdown.
                  </p>
                </div>
                <TaxonomySummaryPanel analysis={analysisData} />
              </div>

              <RemediationPanel remediation={analysisData.remediation} />
            </div>

            <div id="trust" className="space-y-6">
              <ReportSectionHeader
                eyebrow="Trust"
                title="Domain, identity, and public trust posture"
                description="These sections explain whether the organisation’s public-facing trust signals, identity surface, and edge posture reinforce or weaken the overall assessment."
              />

              <div className="space-y-4">
                <div>
                  <p className={sectionTitleClass}>Domain & email foundation</p>
                  <p className="mt-2 max-w-3xl text-sm leading-7 text-slate-600">
                    DNS, mail-authentication, and related trust controls tend to be denser than the rest of this layer, so they sit here as their own reference block.
                  </p>
                </div>
                <DomainSecurityPanel domainSecurity={analysisData.domainSecurity} />
              </div>

              <div className="space-y-8">
                <PublicSignalsPanel publicSignals={analysisData.publicSignals} />
                <DisclosureTrustPanel analysis={analysisData} />
              </div>

              <div className="space-y-8">
                <IdentityProviderPanel identityProvider={analysisData.identityProvider} />
                <WafFingerprintPanel wafFingerprint={analysisData.wafFingerprint} />
                <CtDiscoveryPanel ctDiscovery={analysisData.ctDiscovery} />
              </div>
            </div>

            <div id="client" className="space-y-6">
              <ReportSectionHeader
                eyebrow="Client Surface"
                title="What the application reveals about itself"
                description="This layer groups passive page inspection, client-side exposure, ecosystem tooling, and data-collection behavior so the application surface reads as one story instead of several competing panels."
              />

              <HtmlSecurityPanel htmlSecurity={analysisData.htmlSecurity} />

              <div className="space-y-8">
                <ClientExposurePanel htmlSecurity={analysisData.htmlSecurity} />
                <AiSurfacePanel aiSurface={analysisData.aiSurface} />
                <ThirdPartyTrustPanel thirdPartyTrust={analysisData.thirdPartyTrust} />
              </div>

              <div className="space-y-8">
                <AuthSurfacePanel htmlSecurity={analysisData.htmlSecurity} />
                <DataCollectionPanel htmlSecurity={analysisData.htmlSecurity} />
              </div>
            </div>

            <div id="exposure" className="space-y-6">
              <ReportSectionHeader
                eyebrow="Exposure"
                title="Public endpoints and browser-facing attack surface"
                description="These checks focus on low-noise endpoint exposure, cross-origin behavior, and machine-readable surfaces that could widen the public attack surface."
              />

              <ExposurePanel exposure={analysisData.exposure} />

              <div className="space-y-8">
                <CorsSecurityPanel corsSecurity={analysisData.corsSecurity} />
                <ApiSurfacePanel apiSurface={analysisData.apiSurface} />
              </div>
            </div>

            <div id="evidence" className="space-y-6">
              <ReportSectionHeader
                eyebrow="Evidence"
                title="Supporting detail and raw evidence"
                description="This final layer keeps the operational detail available without forcing it to compete with the primary assessment above."
              />

              <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
                <div className={METRIC_CARD_CLASS}>
                  <div className="flex items-center gap-2 text-sm font-medium text-slate-500">
                    <Activity className="h-4 w-4" />
                    Response time
                  </div>
                  <div className="mt-3 text-3xl font-black text-slate-950">{analysisData.responseTimeMs}ms</div>
                </div>
                <div className={METRIC_CARD_CLASS}>
                  <div className="flex items-center gap-2 text-sm font-medium text-slate-500">
                    <Link2 className="h-4 w-4" />
                    Final URL
                  </div>
                  <div className="mt-3 truncate text-lg font-bold text-slate-950">{analysisData.finalUrl}</div>
                </div>
                <div className={METRIC_CARD_CLASS}>
                  <div className="flex items-center gap-2 text-sm font-medium text-slate-500">
                    <Server className="h-4 w-4" />
                    HTTP status
                  </div>
                  <div className="mt-3 text-3xl font-black text-slate-950">{analysisData.statusCode}</div>
                  <p className="mt-2 text-sm font-medium text-slate-500">
                    {getHttpStatusDetails(analysisData.statusCode).label}
                  </p>
                  <p className="mt-2 text-sm leading-6 text-slate-500">
                    {getHttpStatusDetails(analysisData.statusCode).meaning}
                  </p>
                </div>
                <div className={METRIC_CARD_CLASS}>
                  <div className="flex items-center gap-2 text-sm font-medium text-slate-500">
                    <Clock3 className="h-4 w-4" />
                    Scanned
                  </div>
                  <div className="mt-3 text-lg font-bold text-slate-950">
                    {new Date(analysisData.scannedAt).toLocaleString()}
                  </div>
                </div>
              </div>

              <div className="grid gap-8 xl:grid-cols-[1.15fr_0.85fr]">
                <div className="space-y-8">
                  <div className="rounded-[2rem] border border-slate-200 bg-white p-6 shadow-sm">
                    <h2 className="mb-4 text-2xl font-bold text-slate-950">Security Headers</h2>
                    <HeadersTable headers={analysisData.headers} />
                  </div>
                  <RawHeadersPanel headers={analysisData.rawHeaders} />
                  <CrawlPanel crawl={analysisData.crawl} />
                  <HistoryPanel history={history} diff={historyDiff} />
                </div>

                <div className="space-y-8">
                  <SecurityTxtPanel securityTxt={analysisData.securityTxt} />
                  <CertificateAnalysis certInfo={analysisData.certificate} />
                  <RedirectChain redirects={analysisData.redirects} />
                  <TechnologyStack technologies={analysisData.technologies} />
                  <CookieAnalysis cookies={analysisData.cookies} />
                </div>
              </div>
            </div>
          </section>
        )}
      </div>
    </div>
  );
};

export default Index;
