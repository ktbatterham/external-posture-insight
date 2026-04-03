import { startTransition, useEffect, useState } from "react";
import { Activity, Clock3, Download, Link2, Server } from "lucide-react";
import { toast } from "sonner";
import { CertificateAnalysis } from "@/components/CertificateAnalysis";
import { CookieAnalysis } from "@/components/CookieAnalysis";
import { CrawlPanel } from "@/components/CrawlPanel";
import { DomainSecurityPanel } from "@/components/DomainSecurityPanel";
import { FindingsPanel } from "@/components/FindingsPanel";
import { HeadersTable } from "@/components/HeadersTable";
import { HistoryPanel } from "@/components/HistoryPanel";
import { RawHeadersPanel } from "@/components/RawHeadersPanel";
import { RemediationPanel } from "@/components/RemediationPanel";
import { RedirectChain } from "@/components/RedirectChain";
import { SecurityGrade } from "@/components/SecurityGrade";
import { SecurityTxtPanel } from "@/components/SecurityTxtPanel";
import { TechnologyStack } from "@/components/TechnologyStack";
import { UrlForm } from "@/components/UrlForm";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { AnalysisResult, HistoryDiff, HistorySnapshot } from "@/types/analysis";

const RECENT_SCANS_KEY = "secure-header-insight:recent-scans";
const HISTORY_KEY = "secure-header-insight:history";

interface RecentScan {
  url: string;
  grade: string;
  scannedAt: string;
}

const METRIC_CARD_CLASS =
  "rounded-[1.75rem] border border-white/60 bg-white/80 p-5 shadow-lg shadow-slate-200/50 backdrop-blur";

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

const saveRecentScan = (scan: RecentScan) => {
  const next = [scan, ...loadRecentScans().filter((item) => item.url !== scan.url)].slice(0, 6);
  window.localStorage.setItem(RECENT_SCANS_KEY, JSON.stringify(next));
  return next;
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

const Index = () => {
  const [isLoading, setIsLoading] = useState(false);
  const [analysisData, setAnalysisData] = useState<AnalysisResult | null>(null);
  const [recentScans, setRecentScans] = useState<RecentScan[]>([]);
  const [history, setHistory] = useState<HistorySnapshot[]>([]);
  const [historyDiff, setHistoryDiff] = useState<HistoryDiff | null>(null);

  useEffect(() => {
    setRecentScans(loadRecentScans());
  }, []);

  const handleAnalyze = async (url: string) => {
    setIsLoading(true);

    try {
      const response = await fetch(`/api/analyze?url=${encodeURIComponent(url)}`);
      const payload = await response.json();

      if (!response.ok) {
        throw new Error(payload.error || "Scan failed.");
      }

      startTransition(() => {
        setAnalysisData(payload);
        setRecentScans(
          saveRecentScan({
            url: payload.finalUrl,
            grade: payload.grade,
            scannedAt: payload.scannedAt,
          }),
        );
        const nextHistory = saveHistorySnapshot(payload);
        setHistory(nextHistory);
        setHistoryDiff(buildHistoryDiff(nextHistory));
      });
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Unable to scan that site.");
    } finally {
      setIsLoading(false);
    }
  };

  const exportReport = () => {
    if (!analysisData) {
      return;
    }

    const blob = new Blob([JSON.stringify(analysisData, null, 2)], {
      type: "application/json;charset=utf-8",
    });
    const objectUrl = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = objectUrl;
    link.download = `security-report-${analysisData.host}.json`;
    link.click();
    URL.revokeObjectURL(objectUrl);
  };

  return (
    <div className="min-h-screen bg-[radial-gradient(circle_at_top_left,_rgba(58,111,255,0.14),_transparent_30%),linear-gradient(180deg,_#f7fafc_0%,_#eef3f8_45%,_#f8fbfd_100%)]">
      <div className="mx-auto max-w-7xl px-4 py-10 sm:px-6 lg:px-8">
        <section className="rounded-[2rem] border border-white/70 bg-white/70 px-6 py-8 shadow-2xl shadow-slate-200/50 backdrop-blur sm:px-8">
          <div className="grid gap-10 lg:grid-cols-[1.2fr_0.8fr]">
            <div className="space-y-6">
              <div className="inline-flex rounded-full border border-sky-200 bg-sky-50 px-3 py-1 text-xs font-semibold uppercase tracking-[0.18em] text-sky-900">
                Live HTTP security analysis
              </div>
              <div className="space-y-4">
                <h1 className="max-w-3xl font-serif text-4xl font-bold tracking-tight text-slate-950 sm:text-5xl">
                  See what a site actually returns, not what a demo thinks it should.
                </h1>
                <p className="max-w-2xl text-base leading-7 text-slate-600">
                  Secure Header Insight now scans live response headers, follows redirects, inspects TLS details,
                  parses cookies, and turns the result into a report you can act on.
                </p>
              </div>
              <UrlForm onSubmit={handleAnalyze} isLoading={isLoading} initialValue="https://example.com" />
            </div>

            <Card className="overflow-hidden border-slate-200 bg-slate-950 text-slate-50 shadow-xl">
              <CardContent className="space-y-4 p-6">
                <p className="text-xs uppercase tracking-[0.18em] text-slate-400">What this scan checks</p>
                <div className="grid gap-3 text-sm text-slate-200">
                  <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-4">
                    Security headers including CSP, HSTS, framing, MIME sniffing, referrer, and isolation policies.
                  </div>
                  <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-4">
                    TLS trust, protocol version, expiry window, cipher details, and final redirect destination.
                  </div>
                  <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-4">
                    `Set-Cookie` flags, inferred stack signals, raw headers, and a downloadable JSON report.
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </section>

        {recentScans.length > 0 && (
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

        {analysisData && (
          <section className="mt-8 space-y-8">
            <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
              <SecurityGrade
                grade={analysisData.grade}
                score={analysisData.score}
                summary={analysisData.summary}
              />
              <div className="flex gap-3">
                <Button variant="outline" className="rounded-2xl" onClick={exportReport}>
                  <Download className="mr-2 h-4 w-4" />
                  Export JSON
                </Button>
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

            <RemediationPanel remediation={analysisData.remediation} />

            <CrawlPanel crawl={analysisData.crawl} />

            <HistoryPanel history={history} diff={historyDiff} />

            <DomainSecurityPanel domainSecurity={analysisData.domainSecurity} />

            <div className="grid gap-8 xl:grid-cols-[1.2fr_0.8fr]">
              <div className="space-y-8">
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

            <div className="grid gap-8 xl:grid-cols-2">
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
