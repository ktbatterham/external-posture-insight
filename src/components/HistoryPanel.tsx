import { History, TrendingDown, TrendingUp } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { HistoryDiff, HistorySnapshot } from "@/types/analysis";

interface HistoryPanelProps {
  history: HistorySnapshot[];
  diff: HistoryDiff | null;
}

export const HistoryPanel = ({ history, diff }: HistoryPanelProps) => {
  if (!history.length) {
    return null;
  }

  return (
    <Card className="border-slate-200 shadow-sm">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <History className="h-5 w-5" />
          Scan History
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-5">
        {diff && diff.previousScore !== null && (
          <div className="grid gap-4 md:grid-cols-2">
            <div className="rounded-2xl bg-slate-50 p-4">
              <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Score change</p>
              <div className="mt-2 flex items-center gap-2">
                {diff.scoreDelta !== null && diff.scoreDelta >= 0 ? (
                  <TrendingUp className="h-4 w-4 text-emerald-600" />
                ) : (
                  <TrendingDown className="h-4 w-4 text-rose-600" />
                )}
                <span className="text-lg font-semibold text-slate-950">
                  {diff.scoreDelta !== null && diff.scoreDelta > 0 ? "+" : ""}
                  {diff.scoreDelta ?? 0}
                </span>
                <span className="text-sm text-slate-500">
                  from {diff.previousGrade} / {diff.previousScore}
                </span>
              </div>
            </div>
            <div className="rounded-2xl bg-slate-50 p-4">
              <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Issue delta</p>
              <div className="mt-2 flex flex-wrap gap-2">
                <Badge variant="secondary" className="bg-rose-100 text-rose-900">
                  {diff.newIssues.length} new
                </Badge>
                <Badge variant="secondary" className="bg-emerald-100 text-emerald-900">
                  {diff.resolvedIssues.length} resolved
                </Badge>
                <Badge variant="secondary" className="bg-amber-100 text-amber-900">
                  {diff.headerChanges.length} header changes
                </Badge>
              </div>
            </div>
          </div>
        )}

        {diff && (
          <div className="grid gap-4 md:grid-cols-3">
            <div className="rounded-2xl border border-rose-200 bg-rose-50 p-4">
              <p className="text-sm font-semibold text-rose-900">New issues</p>
              <div className="mt-3 space-y-2 text-sm text-rose-900">
                {diff.newIssues.length ? diff.newIssues.map((issue) => <p key={issue}>{issue}</p>) : <p>None</p>}
              </div>
            </div>
            <div className="rounded-2xl border border-emerald-200 bg-emerald-50 p-4">
              <p className="text-sm font-semibold text-emerald-900">Resolved issues</p>
              <div className="mt-3 space-y-2 text-sm text-emerald-900">
                {diff.resolvedIssues.length ? diff.resolvedIssues.map((issue) => <p key={issue}>{issue}</p>) : <p>None</p>}
              </div>
            </div>
            <div className="rounded-2xl border border-amber-200 bg-amber-50 p-4">
              <p className="text-sm font-semibold text-amber-900">Header changes</p>
              <div className="mt-3 space-y-2 text-sm text-amber-900">
                {diff.headerChanges.length ? diff.headerChanges.map((change) => (
                  <p key={`${change.label}-${change.from}-${change.to}`}>
                    {change.label}: {change.from} {"->"} {change.to}
                  </p>
                )) : <p>None</p>}
              </div>
            </div>
          </div>
        )}

        <div className="grid gap-3">
          {history.map((snapshot) => (
            <div key={`${snapshot.scannedAt}-${snapshot.finalUrl}`} className="rounded-2xl border border-slate-200 bg-white p-4">
              <div className="flex flex-col gap-2 md:flex-row md:items-center md:justify-between">
                <div>
                  <p className="text-sm font-semibold text-slate-950">{snapshot.finalUrl}</p>
                  <p className="text-xs text-slate-500">{new Date(snapshot.scannedAt).toLocaleString()}</p>
                </div>
                <div className="flex items-center gap-2">
                  <Badge variant="secondary">{snapshot.grade}</Badge>
                  <span className="text-sm font-semibold text-slate-700">{snapshot.score}/100</span>
                </div>
              </div>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
};
