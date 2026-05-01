import { History, TrendingDown, TrendingUp } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { EmptyState } from "@/components/ui/panel-primitives";
import { HistoryDiff, HistorySnapshot } from "@/types/analysis";

interface HistoryPanelProps {
  history: HistorySnapshot[];
  diff: HistoryDiff | null;
}

export const HistoryPanel = ({ history, diff }: HistoryPanelProps) => {
  if (!history.length) {
    return (
      <Card className="border-white/10 bg-white/[0.04] shadow-[0_24px_60px_-36px_rgba(0,0,0,0.65)]">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <History className="h-5 w-5" />
            Scan History
          </CardTitle>
        </CardHeader>
        <CardContent>
          <EmptyState>
            No prior saved scans are available for this target yet, so change-over-time comparison is not available.
          </EmptyState>
        </CardContent>
      </Card>
    );
  }

  const trendPoints = [...history].slice(0, 8).reverse();
  const trendScores = trendPoints.map((snapshot) => snapshot.score);
  const minScore = Math.min(...trendScores);
  const maxScore = Math.max(...trendScores);
  const range = Math.max(maxScore - minScore, 1);
  const sparkline = trendPoints
    .map((snapshot, index) => {
      const x = trendPoints.length === 1 ? 0 : (index / (trendPoints.length - 1)) * 100;
      const y = 100 - ((snapshot.score - minScore) / range) * 100;
      return `${x},${y}`;
    })
    .join(" ");
  const latestTrendPoint = trendPoints.at(-1);
  const firstTrendPoint = trendPoints[0];
  const trendDelta = trendPoints.length > 1 && latestTrendPoint && firstTrendPoint ? latestTrendPoint.score - firstTrendPoint.score : 0;
  const trendLabel = trendDelta >= 5 ? "Improving" : trendDelta <= -5 ? "Degrading" : "Stable";
  const trendStroke = trendDelta > 0 ? "#7aa6b6" : trendDelta < 0 ? "#b56a2c" : "#94a3b8";

  return (
    <Card className="border-white/10 bg-white/[0.04] shadow-[0_24px_60px_-36px_rgba(0,0,0,0.65)]">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <History className="h-5 w-5" />
          Scan History
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-5">
        {diff && diff.previousScore !== null ? (
          <div className="grid gap-4 md:grid-cols-3">
            <div className="rounded-[1.35rem] border border-white/10 bg-white/[0.04] p-4">
              <p className="text-xs uppercase tracking-[0.18em] text-slate-400">Score change</p>
              <div className="mt-2 flex items-center gap-2">
                {diff.scoreDelta !== null && diff.scoreDelta >= 0 ? (
                  <TrendingUp className="h-4 w-4 text-[#bcd4de]" />
                ) : (
                  <TrendingDown className="h-4 w-4 text-[#d89a63]" />
                )}
                <span className="text-lg font-semibold text-slate-50">
                  {diff.scoreDelta !== null && diff.scoreDelta > 0 ? "+" : ""}
                  {diff.scoreDelta ?? 0}
                </span>
                <span className="text-sm text-slate-400">
                  from {diff.previousGrade} / {diff.previousScore}
                </span>
              </div>
            </div>
            <div className="rounded-[1.35rem] border border-white/10 bg-white/[0.04] p-4">
              <p className="text-xs uppercase tracking-[0.18em] text-slate-400">Issue delta</p>
              <div className="mt-2 flex flex-wrap gap-2">
                <Badge variant="secondary" className="bg-[#b56a2c]/14 text-[#f0d5bc]">
                  {diff.newIssues.length} new
                </Badge>
                <Badge variant="secondary" className="bg-[#4f6676]/14 text-[#d6e5ec]">
                  {diff.resolvedIssues.length} resolved
                </Badge>
                <Badge variant="secondary" className="bg-[#9b774f]/14 text-[#f0d5bc]">
                  {diff.headerChanges.length} header changes
                </Badge>
              </div>
            </div>
            <div className="rounded-[1.35rem] border border-white/10 bg-white/[0.04] p-4">
              <p className="text-xs uppercase tracking-[0.18em] text-slate-400">Score trend</p>
              <div className="mt-3 flex items-center justify-between gap-3">
                <div>
                  <p className="text-lg font-semibold text-slate-50">{trendLabel}</p>
                  <p className="text-sm text-slate-400">
                    {trendDelta > 0 ? "+" : ""}
                    {trendDelta} over {trendPoints.length} saved scan{trendPoints.length === 1 ? "" : "s"}
                  </p>
                </div>
                <svg viewBox="0 0 100 40" className="h-10 w-28 overflow-visible">
                  <polyline
                    fill="none"
                    stroke={trendStroke}
                    strokeWidth="4"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    points={sparkline
                      .split(" ")
                      .map((point) => {
                        const [x, y] = point.split(",");
                        return `${x},${Number(y) * 0.4}`;
                      })
                      .join(" ")}
                  />
                </svg>
              </div>
            </div>
          </div>
        ) : trendPoints.length > 1 ? (
          <div className="grid gap-4 md:grid-cols-1">
            <div className="rounded-[1.35rem] border border-white/10 bg-white/[0.04] p-4">
              <p className="text-xs uppercase tracking-[0.18em] text-slate-400">Score trend</p>
              <div className="mt-3 flex items-center justify-between gap-3">
                <div>
                  <p className="text-lg font-semibold text-slate-50">{trendLabel}</p>
                  <p className="text-sm text-slate-400">
                    {trendDelta > 0 ? "+" : ""}
                    {trendDelta} over {trendPoints.length} saved scan{trendPoints.length === 1 ? "" : "s"}
                  </p>
                </div>
                <svg viewBox="0 0 100 40" className="h-10 w-28 overflow-visible">
                  <polyline
                    fill="none"
                    stroke={trendStroke}
                    strokeWidth="4"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    points={sparkline
                      .split(" ")
                      .map((point) => {
                        const [x, y] = point.split(",");
                        return `${x},${Number(y) * 0.4}`;
                      })
                      .join(" ")}
                  />
                </svg>
              </div>
            </div>
          </div>
        ) : null}

        {diff && (
          <div className="grid gap-4 md:grid-cols-3">
            <div className="rounded-[1.35rem] border border-[#b56a2c]/35 bg-[#b56a2c]/12 p-4">
              <p className="text-sm font-semibold text-[#f0d5bc]">New issues</p>
              <div className="mt-3 space-y-2 text-sm text-[#f4dfcd]">
                {diff.newIssues.length ? diff.newIssues.map((issue) => <p key={issue}>{issue}</p>) : <p>None</p>}
              </div>
            </div>
            <div className="rounded-[1.35rem] border border-[#4f6676]/35 bg-[#4f6676]/12 p-4">
              <p className="text-sm font-semibold text-[#d6e5ec]">Resolved issues</p>
              <div className="mt-3 space-y-2 text-sm text-[#edf3f6]">
                {diff.resolvedIssues.length ? diff.resolvedIssues.map((issue) => <p key={issue}>{issue}</p>) : <p>None</p>}
              </div>
            </div>
            <div className="rounded-[1.35rem] border border-[#9b774f]/35 bg-[#9b774f]/10 p-4">
              <p className="text-sm font-semibold text-[#f0d5bc]">Header changes</p>
              <div className="mt-3 space-y-2 text-sm text-[#f4dfcd]">
                {diff.headerChanges.length ? diff.headerChanges.map((change) => (
                  <p key={`${change.label}-${change.from}-${change.to}`}>
                    {change.label}: {change.from} {"->"} {change.to}
                  </p>
                )) : <p>None</p>}
              </div>
            </div>
          </div>
        )}

        {diff && (
          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
            <div className="rounded-[1.35rem] border border-[#4f6676]/35 bg-[#4f6676]/12 p-4">
              <p className="text-sm font-semibold text-[#d6e5ec]">Third-party changes</p>
              <div className="mt-3 space-y-2 text-sm text-[#edf3f6]">
                {diff.newThirdPartyProviders.length
                  ? diff.newThirdPartyProviders.map((provider) => <p key={`new-third-party-${provider}`}>New: {provider}</p>)
                  : <p>No new providers</p>}
                {diff.removedThirdPartyProviders.length
                  ? diff.removedThirdPartyProviders.map((provider) => <p key={`old-third-party-${provider}`}>Removed: {provider}</p>)
                  : null}
              </div>
            </div>
            <div className="rounded-[1.35rem] border border-[#4f6676]/35 bg-[#4f6676]/12 p-4">
              <p className="text-sm font-semibold text-[#d6e5ec]">Identity / WAF</p>
              <div className="mt-3 space-y-2 text-sm text-[#edf3f6]">
                {diff.identityProviderChange ? (
                  <p>
                    IdP: {diff.identityProviderChange.from ?? "none"} {"->"} {diff.identityProviderChange.to ?? "none"}
                  </p>
                ) : (
                  <p>No IdP change</p>
                )}
                {diff.wafProviderChanges.newProviders.length
                  ? diff.wafProviderChanges.newProviders.map((provider) => <p key={`new-waf-${provider}`}>New WAF: {provider}</p>)
                  : null}
                {diff.wafProviderChanges.removedProviders.length
                  ? diff.wafProviderChanges.removedProviders.map((provider) => <p key={`old-waf-${provider}`}>Removed WAF: {provider}</p>)
                  : null}
                {!diff.wafProviderChanges.newProviders.length && !diff.wafProviderChanges.removedProviders.length ? <p>No WAF change</p> : null}
              </div>
            </div>
            <div className="rounded-[1.35rem] border border-[#4f6676]/35 bg-[#4f6676]/12 p-4">
              <p className="text-sm font-semibold text-[#d6e5ec]">CT / AI changes</p>
              <div className="mt-3 space-y-2 text-sm text-[#edf3f6]">
                {diff.ctPriorityHostChanges.newHosts.length
                  ? diff.ctPriorityHostChanges.newHosts.map((host) => <p key={`new-ct-${host}`}>New CT host: {host}</p>)
                  : <p>No new CT priority hosts</p>}
                {diff.newAiVendors.length
                  ? diff.newAiVendors.map((vendor) => <p key={`new-ai-${vendor}`}>New AI vendor: {vendor}</p>)
                  : null}
                {diff.removedAiVendors.length
                  ? diff.removedAiVendors.map((vendor) => <p key={`old-ai-${vendor}`}>Removed AI vendor: {vendor}</p>)
                  : null}
              </div>
            </div>
            <div className="rounded-[1.35rem] border border-white/10 bg-white/[0.04] p-4">
              <p className="text-sm font-semibold text-slate-100">Transport delta</p>
              <div className="mt-3 space-y-2 text-sm text-slate-200">
                <p>
                  HTTP: {diff.statusCodeDelta?.from ?? "unknown"} {"->"} {diff.statusCodeDelta?.to ?? "unknown"}
                </p>
                <p>
                  Cert days: {diff.certificateDaysRemainingDelta?.from ?? "unknown"} {"->"} {diff.certificateDaysRemainingDelta?.to ?? "unknown"}
                </p>
              </div>
            </div>
          </div>
        )}

        {diff?.summary.length ? (
          <div className="rounded-[1.35rem] border border-white/10 bg-white/[0.04] p-4">
            <p className="text-sm font-semibold text-slate-100">What changed</p>
            <div className="mt-3 space-y-2 text-sm text-slate-300">
              {diff.summary.map((item) => (
                <p key={item}>{item}</p>
              ))}
            </div>
          </div>
        ) : null}

        <div className="grid gap-3">
          {history.map((snapshot) => (
            <div key={`${snapshot.scannedAt}-${snapshot.finalUrl}`} className="rounded-[1.35rem] border border-white/10 bg-white/[0.04] p-4">
              <div className="flex flex-col gap-2 md:flex-row md:items-center md:justify-between">
                <div className="min-w-0">
                  <p className="truncate text-sm font-semibold text-slate-50" title={snapshot.finalUrl}>{snapshot.finalUrl}</p>
                  <p className="text-xs text-slate-400">{new Date(snapshot.scannedAt).toLocaleString()}</p>
                </div>
                <div className="flex items-center gap-2">
                  <Badge variant="secondary" className="bg-white/[0.1] text-slate-100">{snapshot.grade}</Badge>
                  <span className="text-sm font-semibold text-slate-200">{snapshot.score}/100</span>
                </div>
              </div>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
};
