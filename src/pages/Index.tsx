import { startTransition, useEffect, useEffectEvent, useRef, useState } from "react";
import { Activity, Clock3, Download, Link2, Presentation, Server } from "lucide-react";
import { toast } from "sonner";
import { MonitoredTargetView, MonitoredTargetsPanel } from "@/components/MonitoredTargetsPanel";
import { CertificateAnalysis } from "@/components/CertificateAnalysis";
import { ClientExposurePanel } from "@/components/ClientExposurePanel";
import { CookieAnalysis } from "@/components/CookieAnalysis";
import { CorsSecurityPanel } from "@/components/CorsSecurityPanel";
import { CrawlPanel } from "@/components/CrawlPanel";
import { DataCollectionPanel } from "@/components/DataCollectionPanel";
import { DomainSecurityPanel } from "@/components/DomainSecurityPanel";
import { DisclosureTrustPanel } from "@/components/DisclosureTrustPanel";
import { ExposurePanel } from "@/components/ExposurePanel";
import { ExecutiveSummaryPanel } from "@/components/ExecutiveSummaryPanel";
import { FindingsPanel } from "@/components/FindingsPanel";
import { HeadersTable } from "@/components/HeadersTable";
import { HistoryPanel } from "@/components/HistoryPanel";
import { HomeDashboardPanel } from "@/components/HomeDashboardPanel";
import { HtmlSecurityPanel } from "@/components/HtmlSecurityPanel";
import { MonitoringPanel } from "@/components/MonitoringPanel";
import { PostureSummaryPanel } from "@/components/PostureSummaryPanel";
import { PriorityActionsPanel } from "@/components/PriorityActionsPanel";
import { PublicSignalsPanel } from "@/components/PublicSignalsPanel";
import { RawHeadersPanel } from "@/components/RawHeadersPanel";
import { RemediationPanel } from "@/components/RemediationPanel";
import { ReportModeBanner } from "@/components/ReportModeBanner";
import { RedirectChain } from "@/components/RedirectChain";
import { SecurityGrade } from "@/components/SecurityGrade";
import { SecurityTxtPanel } from "@/components/SecurityTxtPanel";
import { TechnologyStack } from "@/components/TechnologyStack";
import { TaxonomySummaryPanel } from "@/components/TaxonomySummaryPanel";
import { ThirdPartyTrustPanel } from "@/components/ThirdPartyTrustPanel";
import { UrlForm } from "@/components/UrlForm";
import { AuthSurfacePanel } from "@/components/AuthSurfacePanel";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { AnalysisResult, HistoryDiff, HistorySnapshot } from "@/types/analysis";
import { ApiSurfacePanel } from "@/components/ApiSurfacePanel";
import { AiSurfacePanel } from "@/components/AiSurfacePanel";
import { getHttpStatusDetails } from "@/lib/httpStatus";
import { buildHtmlReport, buildMarkdownReport } from "@/lib/reportExport";

const RECENT_SCANS_KEY = "secure-header-insight:recent-scans";
const HISTORY_KEY = "secure-header-insight:history";
const MONITORED_TARGETS_KEY = "secure-header-insight:monitored-targets";

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

const REPORT_SECTIONS = [
  { id: "overview", label: "Overview" },
  { id: "findings", label: "Findings" },
  { id: "trust", label: "Trust" },
  { id: "discovery", label: "Discovery" },
  { id: "exposure", label: "Exposure" },
  { id: "headers", label: "Headers" },
  { id: "cookies", label: "Cookies" },
] as const;

const loadRecentScans = (): RecentScan[] => {
  if (typeof window === "undefined") {
    return [];
  }

  try {
    const raw = window.localStorage.getItem(RECENT_SCANS_KEY);
    return raw ? (JSON.parse(raw) as RecentScan[]) : [];
  } catch {
    return [];
  }
};

const buildRecentScans = (current: RecentScan[], scan: RecentScan) =>
  [scan, ...current.filter((item) => item.url !== scan.url)].slice(0, 6);

const saveRecentScan = (current: RecentScan[], scan: RecentScan) => {
  const next = buildRecentScans(current, scan);
  window.localStorage.setItem(RECENT_SCANS_KEY, JSON.stringify(next));
  return next;
};

const loadMonitoredTargets = (): MonitoredTarget[] => {
  if (typeof window === "undefined") {
    return [];
  }

  try {
    const raw = window.localStorage.getItem(MONITORED_TARGETS_KEY);
    return raw ? (JSON.parse(raw) as MonitoredTarget[]) : [];
  } catch {
    return [];
  }
};

const saveMonitoredTargets = (targets: MonitoredTarget[]) => {
  window.localStorage.setItem(MONITORED_TARGETS_KEY, JSON.stringify(targets));
  return targets;
};

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

const loadHistory = (): Record<string, HistorySnapshot[]> => {
  if (typeof window === "undefined") {
    return {};
  }

  try {
    const raw = window.localStorage.getItem(HISTORY_KEY);
    return raw ? (JSON.parse(raw) as Record<string, HistorySnapshot[]>) : {};
  } catch {
    return {};
  }
};

const snapshotFromAnalysis = (analysis: AnalysisResult): HistorySnapshot => ({
  finalUrl: analysis.finalUrl,
  host: analysis.host,
  scannedAt: analysis.scannedAt,
  score: analysis.score,
  grade: analysis.grade,
  statusCode: analysis.statusCode,
  responseTimeMs: analysis.responseTimeMs,
  headers: analysis.headers.map((header) => ({
    label: header.label,
    status: header.status,
    value: header.value,
  })),
  issues: analysis.issues.map((issue) => ({
    severity: issue.severity,
    title: issue.title,
    detail: issue.detail,
    confidence: issue.confidence,
    source: issue.source,
  })),
});

const saveHistorySnapshot = (analysis: AnalysisResult) => {
  const current = loadHistory();
  const key = analysis.host;
  const snapshot = snapshotFromAnalysis(analysis);
  const nextForHost = [snapshot, ...(current[key] || [])].slice(0, 10);
  const next = { ...current, [key]: nextForHost };
  window.localStorage.setItem(HISTORY_KEY, JSON.stringify(next));
  return nextForHost;
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

const buildHistoryDiff = (history: HistorySnapshot[]): HistoryDiff | null => {
  if (history.length < 2) {
    return null;
  }

  const [current, previous] = history;
  const currentIssues = new Set(current.issues.map((issue) => issue.title));
  const previousIssues = new Set(previous.issues.map((issue) => issue.title));
  const previousHeaders = new Map(previous.headers.map((header) => [header.label, header.status]));

  return {
    previousScore: previous.score,
    scoreDelta: current.score - previous.score,
    previousGrade: previous.grade,
    newIssues: [...currentIssues].filter((issue) => !previousIssues.has(issue)),
    resolvedIssues: [...previousIssues].filter((issue) => !currentIssues.has(issue)),
    headerChanges: current.headers
      .map((header) => ({
        label: header.label,
        from: previousHeaders.get(header.label) ?? "unknown",
        to: header.status,
      }))
      .filter((change) => change.from !== change.to),
  };
};

const sectionTitleClass = "text-xs font-semibold uppercase tracking-[0.18em] text-slate-500";

const Index = () => {
  const [isLoading, setIsLoading] = useState(false);
  const [analysisData, setAnalysisData] = useState<AnalysisResult | null>(null);
  const [recentScans, setRecentScans] = useState<RecentScan[]>(loadRecentScans);
  const [history, setHistory] = useState<HistorySnapshot[]>([]);
  const [historyDiff, setHistoryDiff] = useState<HistoryDiff | null>(null);
  const [monitoredTargets, setMonitoredTargets] = useState<MonitoredTarget[]>(loadMonitoredTargets);
  const [reportMode, setReportMode] = useState(() => {
    if (typeof window === "undefined") {
      return false;
    }
    return new URLSearchParams(window.location.search).get("view") === "report";
  });
  const autoScanRanRef = useRef(false);

  const persistAnalysis = (payload: AnalysisResult, setAsCurrent = true) => {
    startTransition(() => {
      if (setAsCurrent) {
        setAnalysisData(payload);
      }
      setRecentScans((current) =>
        saveRecentScan(current, {
          url: payload.finalUrl,
          grade: payload.grade,
          scannedAt: payload.scannedAt,
        }),
      );
      const nextHistory = saveHistorySnapshot(payload);
      if (setAsCurrent) {
        setHistory(nextHistory);
        setHistoryDiff(buildHistoryDiff(nextHistory));
      }
      setMonitoredTargets((current) => {
        const next = syncMonitoredTargetFromAnalysis(current, payload);
        if (next !== current) {
          saveMonitoredTargets(next);
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

  const runAutoScan = useEffectEvent(async (target: string) => {
    setIsLoading(true);
    try {
      await analyzeUrl(target, true);
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Unable to scan that site.");
    } finally {
      setIsLoading(false);
    }
  });

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
    void runAutoScan(target);
  }, [runAutoScan]);

  const saveCurrentAsMonitored = (cadence: MonitoredTarget["cadence"]) => {
    if (!analysisData) {
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
      ].slice(0, 12);
      saveMonitoredTargets(next);
      return next;
    });

    toast.success(`Saved ${analysisData.host} as a ${cadence} monitoring target.`);
  };

  const removeMonitoredTarget = (url: string) => {
    setMonitoredTargets((current) => {
      const next = current.filter((target) => target.url !== url);
      saveMonitoredTargets(next);
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
      buildMarkdownReport(analysisData),
      "text/markdown;charset=utf-8",
    );
  };

  const exportHtml = () => {
    if (!analysisData) return;
    downloadFile(
      `security-report-${analysisData.host}.html`,
      buildHtmlReport(analysisData),
      "text/html;charset=utf-8",
    );
  };

  const monitoredViews = monitoredTargets.map(toMonitoredTargetView);
  const reportShareUrl =
    typeof window !== "undefined" && analysisData
      ? `${window.location.origin}${window.location.pathname}?view=report&target=${encodeURIComponent(analysisData.finalUrl)}`
      : null;

  const copyReportLink = async () => {
    if (!reportShareUrl) {
      return;
    }

    try {
      await navigator.clipboard.writeText(reportShareUrl);
      toast.success("Report link copied.");
    } catch {
      toast.error("Could not copy the report link.");
    }
  };

  const enterReportMode = () => {
    setReportMode(true);
    if (typeof window !== "undefined" && analysisData) {
      const url = new URL(window.location.href);
      url.searchParams.set("view", "report");
      url.searchParams.set("target", analysisData.finalUrl);
      window.history.replaceState({}, "", url.toString());
    }
  };

  const exitReportMode = () => {
    setReportMode(false);
    if (typeof window !== "undefined") {
      const url = new URL(window.location.href);
      url.searchParams.delete("view");
      url.searchParams.delete("target");
      window.history.replaceState({}, "", url.toString());
    }
  };

  return (
    <div className="min-h-screen bg-[radial-gradient(circle_at_top_left,_rgba(58,111,255,0.14),_transparent_30%),linear-gradient(180deg,_#f7fafc_0%,_#eef3f8_45%,_#f8fbfd_100%)]">
      <div className="mx-auto max-w-7xl px-4 py-10 sm:px-6 lg:px-8">
        {!reportMode && (
        <section className="rounded-[2rem] border border-white/70 bg-white/70 px-6 py-8 shadow-2xl shadow-slate-200/50 backdrop-blur sm:px-8">
          <div className="grid gap-10 lg:grid-cols-[1.2fr_0.8fr]">
            <div className="space-y-6">
              <div className="inline-flex rounded-full border border-sky-200 bg-sky-50 px-3 py-1 text-xs font-semibold uppercase tracking-[0.18em] text-sky-900">
                External posture analysis
              </div>
              <div className="space-y-4">
                <h1 className="max-w-3xl font-serif text-4xl font-bold tracking-tight text-slate-950 sm:text-5xl">
                  Understand a site's public security posture before the noisy tools even start.
                </h1>
                <p className="max-w-2xl text-base leading-7 text-slate-600">
                  External Posture Insight combines live header and TLS analysis with passive discovery, DNS and email
                  posture, public trust signals, AI surface detection, and low-noise monitoring workflows.
                </p>
              </div>
              <UrlForm onSubmit={handleAnalyze} isLoading={isLoading} initialValue="example.com" />
            </div>

            <Card className="overflow-hidden border-slate-200 bg-slate-950 text-slate-50 shadow-xl">
              <CardContent className="space-y-4 p-6">
                <p className="text-xs uppercase tracking-[0.18em] text-slate-400">What this scan checks</p>
                <div className="grid gap-3 text-sm text-slate-200">
                  <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-4">
                    Headers, redirects, TLS, cookies, and browser isolation controls with confidence-labeled findings.
                  </div>
                  <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-4">
                    DNS and email posture, security.txt, public HSTS preload signals, and passive page-risk analysis.
                  </div>
                  <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-4">
                    Detected stack and AI surface signals, low-noise exposure checks, exports, and monitoring targets.
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </section>
        )}

        {!reportMode && recentScans.length > 0 && (
          <section className="mt-8">
            <div className="mb-3 flex items-center gap-2 text-sm font-semibold text-slate-600">
              <Clock3 className="h-4 w-4" />
              Recent scans
            </div>
            <div className="grid gap-3 md:grid-cols-3 xl:grid-cols-6">
              {recentScans.map((scan) => (
                <button
                  key={scan.url}
                  type="button"
                  onClick={() => handleAnalyze(scan.url)}
                  className="rounded-2xl border border-white/70 bg-white/80 px-4 py-3 text-left shadow-sm transition hover:-translate-y-0.5 hover:shadow-md"
                >
                  <div className="flex items-center justify-between gap-3">
                    <span className="truncate text-sm font-medium text-slate-900">{scan.url}</span>
                    <span className="text-lg font-black text-slate-700">{scan.grade}</span>
                  </div>
                  <p className="mt-2 text-xs text-slate-500">{new Date(scan.scannedAt).toLocaleString()}</p>
                </button>
              ))}
            </div>
          </section>
        )}

        {!reportMode && (
          <section className="mt-8">
            <HomeDashboardPanel
              monitoredCount={monitoredTargets.length}
              dueCount={monitoredViews.filter((target) => target.due).length}
              recentCount={recentScans.length}
              lastScanAt={recentScans[0]?.scannedAt ?? null}
            />
          </section>
        )}

        <section className="mt-8">
          <MonitoredTargetsPanel
            targets={monitoredViews}
            currentUrl={analysisData?.finalUrl ?? null}
            onAddDaily={() => saveCurrentAsMonitored("daily")}
            onAddWeekly={() => saveCurrentAsMonitored("weekly")}
            onRunDue={runDueScans}
            onRunTarget={(url) => void runTargetScan(url, true)}
            onRemove={removeMonitoredTarget}
            busy={isLoading}
          />
        </section>

        {analysisData && (
          <section className="mt-8 space-y-8">
            {reportMode ? (
              <ReportModeBanner shareUrl={reportShareUrl} onCopy={copyReportLink} onExit={exitReportMode} />
            ) : (
              <div className="flex justify-end">
                <Button variant="outline" className="rounded-2xl" onClick={enterReportMode}>
                  <Presentation className="mr-2 h-4 w-4" />
                  Report mode
                </Button>
              </div>
            )}

            <div id="overview" className="space-y-5">
              <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
                <SecurityGrade
                  grade={analysisData.grade}
                  score={analysisData.score}
                  summary={analysisData.summary}
                />
                <div className="flex flex-wrap gap-3">
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

              <div className="grid gap-4 xl:grid-cols-[1.2fr_0.8fr]">
                <Card className="border-slate-200 shadow-sm">
                  <CardContent className="grid gap-4 p-5 md:grid-cols-2 xl:grid-cols-4">
                    <div>
                      <p className={sectionTitleClass}>Scanned target</p>
                      <p className="mt-2 text-lg font-semibold text-slate-950">{analysisData.host}</p>
                      <p className="mt-1 text-sm text-slate-500">{analysisData.finalUrl}</p>
                    </div>
                    <div>
                      <p className={sectionTitleClass}>Overall posture</p>
                      <p className="mt-2 text-lg font-semibold capitalize text-slate-950">
                        {analysisData.executiveSummary.posture}
                      </p>
                      <p className="mt-1 text-sm text-slate-500">{analysisData.executiveSummary.mainRisk}</p>
                    </div>
                    <div>
                      <p className={sectionTitleClass}>Scan timestamp</p>
                      <p className="mt-2 text-lg font-semibold text-slate-950">
                        {new Date(analysisData.scannedAt).toLocaleString()}
                      </p>
                      <p className="mt-1 text-sm text-slate-500">Latest completed scan for this target in this browser.</p>
                    </div>
                    <div>
                      <p className={sectionTitleClass}>What to do first</p>
                      <p className="mt-2 text-lg font-semibold text-slate-950">
                        {analysisData.headers.filter((header) => header.status !== "present").length > 0
                          ? "Fix missing protections"
                          : "Review deeper posture"}
                      </p>
                      <p className="mt-1 text-sm text-slate-500">
                        Start with the executive readout and priority actions before drilling into raw details.
                      </p>
                    </div>
                  </CardContent>
                </Card>

                <Card className="border-slate-200 shadow-sm">
                  <CardContent className="p-5">
                    <p className={sectionTitleClass}>Jump to</p>
                    <div className="mt-4 flex flex-wrap gap-2">
                      {REPORT_SECTIONS.map((section) => (
                        <a
                          key={section.id}
                          href={`#${section.id}`}
                          className="rounded-full border border-slate-200 bg-slate-50 px-3 py-2 text-sm font-medium text-slate-700 transition hover:border-sky-300 hover:bg-sky-50 hover:text-sky-900"
                        >
                          {section.label}
                        </a>
                      ))}
                    </div>
                    <p className="mt-4 text-sm leading-6 text-slate-500">
                      The report is organized from decision support first to raw evidence later, so you can skim the story before diving into the mechanics.
                    </p>
                  </CardContent>
                </Card>
              </div>
            </div>

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

            <div className="grid gap-8 xl:grid-cols-[1.1fr_0.9fr]">
              <ExecutiveSummaryPanel summary={analysisData.executiveSummary} />
              <PostureSummaryPanel analysis={analysisData} />
            </div>

            <TaxonomySummaryPanel analysis={analysisData} />

            <div id="findings" className="grid gap-8 xl:grid-cols-2">
              <PriorityActionsPanel analysis={analysisData} />
              <MonitoringPanel analysis={analysisData} diff={historyDiff} />
            </div>

            <RemediationPanel remediation={analysisData.remediation} />

            <div id="discovery" className="space-y-8">
              <CrawlPanel crawl={analysisData.crawl} />

              <HistoryPanel history={history} diff={historyDiff} />
            </div>

            <div id="trust" className="grid gap-8 xl:grid-cols-3">
              <DomainSecurityPanel domainSecurity={analysisData.domainSecurity} />
              <PublicSignalsPanel publicSignals={analysisData.publicSignals} />
              <DisclosureTrustPanel analysis={analysisData} />
            </div>

            <HtmlSecurityPanel htmlSecurity={analysisData.htmlSecurity} />
            <ClientExposurePanel htmlSecurity={analysisData.htmlSecurity} />
            <div className="grid gap-8 xl:grid-cols-2">
              <AuthSurfacePanel htmlSecurity={analysisData.htmlSecurity} />
              <DataCollectionPanel htmlSecurity={analysisData.htmlSecurity} />
            </div>

            <div className="grid gap-8 xl:grid-cols-2">
              <AiSurfacePanel aiSurface={analysisData.aiSurface} />
              <ThirdPartyTrustPanel thirdPartyTrust={analysisData.thirdPartyTrust} />
            </div>

            <div id="exposure" className="space-y-8">
              <ExposurePanel exposure={analysisData.exposure} />

              <CorsSecurityPanel corsSecurity={analysisData.corsSecurity} />

              <ApiSurfacePanel apiSurface={analysisData.apiSurface} />
            </div>

            <div className="grid gap-8 xl:grid-cols-[1.2fr_0.8fr]">
              <div id="headers" className="space-y-8">
                <div className="rounded-[2rem] border border-slate-200 bg-white p-6 shadow-sm">
                  <h2 className="mb-4 text-2xl font-bold text-slate-950">Security Headers</h2>
                  <HeadersTable headers={analysisData.headers} />
                </div>
                <RawHeadersPanel headers={analysisData.rawHeaders} />
              </div>

              <div className="space-y-8">
                <FindingsPanel issues={analysisData.issues} strengths={analysisData.strengths} />
                <SecurityTxtPanel securityTxt={analysisData.securityTxt} />
                <CertificateAnalysis certInfo={analysisData.certificate} />
                <RedirectChain redirects={analysisData.redirects} />
              </div>
            </div>

            <div id="cookies" className="grid gap-8 xl:grid-cols-2">
              <TechnologyStack technologies={analysisData.technologies} />
              <CookieAnalysis cookies={analysisData.cookies} />
            </div>
          </section>
        )}
      </div>
    </div>
  );
};

export default Index;
