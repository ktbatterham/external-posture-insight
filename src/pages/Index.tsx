import { startTransition, useEffect, useRef, useState } from "react";
import { Clock3, Layers3, ShieldCheck, Sparkles } from "lucide-react";
import { toast } from "sonner";
import { MonitoredTargetView, MonitoredTargetsPanel } from "@/components/MonitoredTargetsPanel";
import { UrlForm } from "@/components/UrlForm";
import { Card, CardContent } from "@/components/ui/card";
import { AnalysisResult, HistoryDiff, HistorySnapshot } from "@/types/analysis";
import { getAreaScores } from "@/lib/posture";
import { buildHtmlReport, buildMarkdownReport } from "@/lib/reportExport";
import { readBrowserStorage, writeBrowserStorage } from "@/lib/browserStorage";
import { buildHistoryDiff, snapshotFromAnalysis } from "../../packages/core/src/historyDiff";
import { EvidenceSection } from "@/components/report/EvidenceSection";
import { OverviewSection } from "@/components/report/OverviewSection";
import { FindingsPanel } from "@/components/FindingsPanel";
import { TaxonomySummaryPanel } from "@/components/TaxonomySummaryPanel";
import { PriorityActionsPanel } from "@/components/PriorityActionsPanel";
import { RemediationPanel } from "@/components/RemediationPanel";
import { DomainSecurityPanel } from "@/components/DomainSecurityPanel";
import { PublicSignalsPanel } from "@/components/PublicSignalsPanel";
import { DisclosureTrustPanel } from "@/components/DisclosureTrustPanel";
import { IdentityProviderPanel } from "@/components/IdentityProviderPanel";
import { InfrastructurePanel } from "@/components/InfrastructurePanel";
import { WafFingerprintPanel } from "@/components/WafFingerprintPanel";
import { CtDiscoveryPanel } from "@/components/CtDiscoveryPanel";
import { HtmlSecurityPanel } from "@/components/HtmlSecurityPanel";
import { ClientExposurePanel } from "@/components/ClientExposurePanel";
import { AiSurfacePanel } from "@/components/AiSurfacePanel";
import { ThirdPartyTrustPanel } from "@/components/ThirdPartyTrustPanel";
import { AuthSurfacePanel } from "@/components/AuthSurfacePanel";
import { DataCollectionPanel } from "@/components/DataCollectionPanel";
import { ExposurePanel } from "@/components/ExposurePanel";
import { CorsSecurityPanel } from "@/components/CorsSecurityPanel";
import { ApiSurfacePanel } from "@/components/ApiSurfacePanel";

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

interface StoredHistoryAreaScore {
  key: string;
  label: string;
  score: number;
  status: "strong" | "watch" | "weak";
}

type StoredHistorySnapshot = HistorySnapshot & {
  areaScores?: StoredHistoryAreaScore[];
};

type ReportWorkspaceSectionKey =
  | "overview"
  | "findings-top"
  | "findings-themes"
  | "findings-actions"
  | "findings-remediation"
  | "trust-domain"
  | "trust-signals"
  | "trust-edge"
  | "client-page"
  | "client-surface"
  | "client-auth"
  | "exposure-checks"
  | "exposure-api"
  | "evidence";

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
  current: Record<string, StoredHistorySnapshot[]>,
  analysis: AnalysisResult,
  areaScores: StoredHistoryAreaScore[],
) => {
  const key = analysis.host;
  const snapshot: StoredHistorySnapshot = {
    ...snapshotFromAnalysis(analysis),
    areaScores,
  };
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
      const { next, nextForHost } = saveHistorySnapshot(historyByHostRef.current, payload, getAreaScores(payload));
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

  const monitoredViews = monitoredTargets.map(toMonitoredTargetView);

  const reportSections = analysisData
    ? [
        {
          key: "overview" as const,
          eyebrow: "Healthcheck",
          title: "At a glance",
          summary: "Score, priorities, exports, and monitoring.",
          content: (
            <OverviewSection
              analysisData={analysisData}
              historyDiff={historyDiff}
              history={history}
              areaScores={areaScores}
              exportPdf={exportPdf}
              exportMarkdown={exportMarkdown}
              exportHtml={exportHtml}
              exportReport={exportReport}
              compact
            />
          ),
        },
        {
          key: "findings-top" as const,
          eyebrow: "Risks",
          title: "Top findings",
          summary: "Strengths and highest-priority issues.",
          content: <FindingsPanel issues={analysisData.issues} strengths={analysisData.strengths} />,
        },
        {
          key: "findings-themes" as const,
          eyebrow: "Risks",
          title: "Risk themes",
          summary: "OWASP and MITRE reads.",
          content: <TaxonomySummaryPanel analysis={analysisData} />,
        },
        {
          key: "findings-actions" as const,
          eyebrow: "Risks",
          title: "Priority actions",
          summary: "What to fix first.",
          content: <PriorityActionsPanel analysis={analysisData} />,
        },
        {
          key: "findings-remediation" as const,
          eyebrow: "Risks",
          title: "Fix snippets",
          summary: "Implementation examples by platform.",
          content: <RemediationPanel remediation={analysisData.remediation} />,
        },
        {
          key: "trust-domain" as const,
          eyebrow: "Trust",
          title: "Domain & email",
          summary: "Mail and DNS foundation.",
          content: <DomainSecurityPanel domainSecurity={analysisData.domainSecurity} />,
        },
        {
          key: "trust-signals" as const,
          eyebrow: "Trust",
          title: "Trust signals",
          summary: "Disclosure and public signals.",
          content: (
            <div className="space-y-8">
              <PublicSignalsPanel publicSignals={analysisData.publicSignals} />
              <DisclosureTrustPanel analysis={analysisData} />
            </div>
          ),
        },
        {
          key: "trust-edge" as const,
          eyebrow: "Trust",
          title: "Identity & edge",
          summary: "Identity, infra, WAF, and CT.",
          content: (
            <div className="space-y-8">
              <IdentityProviderPanel identityProvider={analysisData.identityProvider} />
              <InfrastructurePanel infrastructure={analysisData.infrastructure} />
              <WafFingerprintPanel wafFingerprint={analysisData.wafFingerprint} />
              <CtDiscoveryPanel ctDiscovery={analysisData.ctDiscovery} />
            </div>
          ),
        },
        {
          key: "client-page" as const,
          eyebrow: "Client",
          title: "Page security",
          summary: "HTML and browser-facing posture.",
          content: (
            <div className="space-y-8">
              <HtmlSecurityPanel htmlSecurity={analysisData.htmlSecurity} />
              <ClientExposurePanel htmlSecurity={analysisData.htmlSecurity} />
            </div>
          ),
        },
        {
          key: "client-surface" as const,
          eyebrow: "Client",
          title: "Third-party & AI",
          summary: "Suppliers and AI surface.",
          content: (
            <div className="space-y-8">
              <AiSurfacePanel aiSurface={analysisData.aiSurface} />
              <ThirdPartyTrustPanel thirdPartyTrust={analysisData.thirdPartyTrust} />
            </div>
          ),
        },
        {
          key: "client-auth" as const,
          eyebrow: "Client",
          title: "Auth & collection",
          summary: "Auth paths and collection clues.",
          content: (
            <div className="space-y-8">
              <AuthSurfacePanel htmlSecurity={analysisData.htmlSecurity} />
              <DataCollectionPanel htmlSecurity={analysisData.htmlSecurity} />
            </div>
          ),
        },
        {
          key: "exposure-checks" as const,
          eyebrow: "Exposure",
          title: "Exposure checks",
          summary: "Low-noise path probes.",
          content: <ExposurePanel exposure={analysisData.exposure} />,
        },
        {
          key: "exposure-api" as const,
          eyebrow: "Exposure",
          title: "API & CORS",
          summary: "API hints and cross-origin posture.",
          content: (
            <div className="space-y-8">
              <CorsSecurityPanel corsSecurity={analysisData.corsSecurity} />
              <ApiSurfacePanel apiSurface={analysisData.apiSurface} />
            </div>
          ),
        },
        {
          key: "evidence" as const,
          eyebrow: "Evidence",
          title: "Raw evidence and history",
          summary: "Headers, redirects, certs, cookies, and history.",
          content: <EvidenceSection analysisData={analysisData} history={history} historyDiff={historyDiff} compact />,
        },
      ]
    : [];

  const activeSection = reportSections.find((section) => section.key === activeReportSection) ?? reportSections[0];

  return (
    <div className="min-h-screen overflow-hidden bg-[#070b14] text-slate-100">
      <div className="pointer-events-none fixed inset-0 -z-10 bg-[radial-gradient(circle_at_18%_0%,rgba(181,106,44,0.16),transparent_34%),radial-gradient(circle_at_82%_12%,rgba(122,166,182,0.12),transparent_30%),linear-gradient(180deg,#070b14_0%,#0b1220_48%,#101827_100%)]" />
      <div className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
        <section className="rounded-[2.25rem] border border-white/10 bg-white/[0.05] p-5 shadow-2xl shadow-black/30 ring-1 ring-white/[0.04] backdrop-blur-xl sm:p-7 lg:p-8">
          <div className="grid gap-8 lg:grid-cols-[1.2fr_0.8fr] lg:items-start">
            <div className="space-y-6">
              <div className="space-y-5">
                <div className="inline-flex items-center gap-2 rounded-full border border-[#b56a2c]/25 bg-[#b56a2c]/12 px-3 py-1 text-xs font-semibold uppercase tracking-[0.2em] text-[#f0d5bc]">
                  <Sparkles className="h-3.5 w-3.5" />
                  SecURL
                </div>
                <div className="space-y-4">
                  <h1 className="max-w-3xl text-4xl font-semibold tracking-[-0.055em] text-white sm:text-5xl lg:text-6xl">
                    Public attack surface, quietly mapped.
                  </h1>
                  <p className="max-w-2xl text-base leading-7 text-slate-400 sm:text-lg">
                    Passive-first URL and domain posture analysis with a fast healthcheck up front and supporting evidence when you need to go deeper.
                  </p>
                </div>
              </div>
              <UrlForm onSubmit={handleAnalyze} isLoading={isLoading} initialValue="example.com" />
            </div>

            <div className="h-full rounded-[1.8rem] border border-white/10 bg-slate-950/35 p-5 shadow-[inset_0_1px_0_rgba(255,255,255,0.04)] sm:p-6">
              <div className="mb-4 flex items-center justify-between gap-3">
                <p className="text-xs font-semibold uppercase tracking-[0.2em] text-slate-400">What this scan checks</p>
                <ShieldCheck className="h-5 w-5 text-[#d89a63]" />
              </div>
              <div className="space-y-3">
                {[
                  "Headers, redirects, TLS, cookies, and browser isolation controls with confidence-labeled findings.",
                  "DNS and email posture, security.txt, HSTS preload signals, and passive page-risk analysis.",
                  "Detected stack, AI surface, exposure checks, exports, and browser-local monitoring targets.",
                ].map((item, index) => (
                  <div
                    key={item}
                    className={`rounded-[1.2rem] px-4 py-4 text-sm leading-7 text-slate-200 ${
                      index < 2 ? "border-b border-white/10" : ""
                    }`}
                  >
                    {item}
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div className="mt-5 rounded-[1.7rem] border border-white/10 bg-white/[0.04] p-4 sm:p-5">
            <div className="grid gap-5 xl:grid-cols-[minmax(0,0.82fr)_minmax(0,1.18fr)] xl:items-start">
              <div className={`space-y-3 ${recentScans.length > 0 ? "" : "hidden"}`}>
                <div className="flex items-center gap-2 text-sm font-semibold text-slate-200">
                  <Clock3 className="h-4 w-4 text-[#d89a63]" />
                  Recent scans
                </div>
                <div className="grid gap-3 md:grid-cols-3 xl:grid-cols-1">
                  {recentScans.slice(0, 3).map((scan) => (
                    <button
                      key={scan.url}
                      type="button"
                      onClick={() => void handleAnalyze(scan.url, "recent")}
                      disabled={isLoading}
                      className={`rounded-[1.2rem] border px-4 py-3 text-left shadow-sm transition ${
                        activeRecentScanUrl === scan.url
                          ? "border-[#b56a2c]/45 bg-[#b56a2c]/12"
                          : "border-white/10 bg-slate-950/45 hover:-translate-y-0.5 hover:border-[#b56a2c]/25 hover:bg-white/[0.08]"
                      } ${isLoading ? "cursor-wait" : ""}`}
                      aria-busy={activeRecentScanUrl === scan.url}
                    >
                      <div className="flex items-center justify-between gap-3">
                        <span className="truncate text-sm font-medium text-slate-100">{scan.url}</span>
                        <span className="text-sm font-semibold uppercase tracking-[0.14em] text-[#f0d5bc]">
                          {activeRecentScanUrl === scan.url ? "Scanning" : scan.grade}
                        </span>
                      </div>
                      <p className="mt-2 text-xs text-slate-500">{new Date(scan.scannedAt).toLocaleString()}</p>
                    </button>
                  ))}
                </div>
              </div>

              <div className={recentScans.length > 0 ? "border-t border-white/10 pt-5 xl:border-l xl:border-t-0 xl:pt-0 xl:pl-5" : ""}>
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
            </div>
          </div>
        </section>

        {analysisData && (
          <section className="mt-6 space-y-4">
            <div className="flex items-center gap-2 px-1 text-sm font-semibold uppercase tracking-[0.18em] text-slate-500">
              <Layers3 className="h-4 w-4" />
              Report workspace
            </div>
            <div className="grid gap-4 lg:grid-cols-[18rem_minmax(0,1fr)] xl:grid-cols-[19.5rem_minmax(0,1fr)]">
              <aside className="lg:sticky lg:top-6 lg:self-start">
                <div className="overflow-hidden rounded-[1.75rem] border border-white/10 bg-white/[0.04] shadow-2xl shadow-black/15 ring-1 ring-white/[0.03] backdrop-blur">
                  <div className="border-b border-white/10 px-5 py-4">
                    <p className="text-xs font-semibold uppercase tracking-[0.2em] text-[#d89a63]/80">Sections</p>
                    <p className="mt-2 text-sm leading-6 text-slate-400">
                      Choose a report area to open it in the main workspace.
                    </p>
                  </div>
                  <div className="p-3">
                    <div className="space-y-2">
                      {reportSections.map((section) => {
                        const active = section.key === activeSection?.key;
                        return (
                          <button
                            key={section.key}
                            type="button"
                            onClick={() => setActiveReportSection(section.key)}
                            className={`w-full rounded-[1.1rem] border px-4 py-4 text-left transition ${
                              active
                                ? "border-[#b56a2c]/35 bg-[#b56a2c]/12 shadow-[0_12px_28px_-22px_rgba(181,106,44,0.45)]"
                                : "border-transparent bg-transparent hover:border-white/10 hover:bg-white/[0.04]"
                            }`}
                          >
                    <p className={`text-base font-semibold ${active ? "text-white" : "text-slate-200"}`}>
                      {section.title}
                    </p>
                    {active ? (
                      <p className="mt-2 text-sm leading-6 text-slate-400">
                        {section.summary}
                      </p>
                    ) : null}
                  </button>
                );
              })}
                    </div>
                  </div>
                </div>
              </aside>

              {activeSection ? (
                <div className="overflow-hidden rounded-[1.75rem] border border-white/10 bg-white/[0.04] shadow-2xl shadow-black/15 ring-1 ring-white/[0.03] backdrop-blur">
                  <div className="border-b border-white/10 px-5 py-5 sm:px-6">
                    <h2 className="text-2xl font-semibold tracking-[-0.035em] text-white">
                      {activeSection.title}
                    </h2>
                  </div>
                  <div className="bg-white/[0.02] px-4 py-6 text-slate-100 sm:px-6 lg:px-8">
                    {activeSection.content}
                  </div>
                </div>
              ) : null}
            </div>
          </section>
        )}
      </div>
    </div>
  );
};

export default Index;
