import { BarChart3 } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { AnalysisResult } from "@/types/analysis";

interface PostureSummaryPanelProps {
  analysis: AnalysisResult;
}

export const PostureSummaryPanel = ({ analysis }: PostureSummaryPanelProps) => {
  const severityCounts = analysis.issues.reduce(
    (acc, issue) => {
      acc[issue.severity] += 1;
      return acc;
    },
    { critical: 0, warning: 0, info: 0 },
  );

  const areaCounts = analysis.issues.reduce<Record<string, number>>((acc, issue) => {
    acc[issue.area] = (acc[issue.area] || 0) + 1;
    return acc;
  }, {});

  const topAreas = Object.entries(areaCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 4);

  return (
    <Card className="border-slate-200 shadow-sm">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <BarChart3 className="h-5 w-5" />
          Posture Summary
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-5">
        <div className="grid gap-4 md:grid-cols-3">
          <div className="rounded-2xl bg-rose-50 p-4">
            <p className="text-xs uppercase tracking-[0.18em] text-rose-700">Critical</p>
            <p className="mt-2 text-3xl font-black text-rose-900">{severityCounts.critical}</p>
          </div>
          <div className="rounded-2xl bg-amber-50 p-4">
            <p className="text-xs uppercase tracking-[0.18em] text-amber-700">Warnings</p>
            <p className="mt-2 text-3xl font-black text-amber-900">{severityCounts.warning}</p>
          </div>
          <div className="rounded-2xl bg-sky-50 p-4">
            <p className="text-xs uppercase tracking-[0.18em] text-sky-700">Info</p>
            <p className="mt-2 text-3xl font-black text-sky-900">{severityCounts.info}</p>
          </div>
        </div>

        <div className="rounded-2xl bg-slate-50 p-4">
          <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Most affected areas</p>
          <div className="mt-3 grid gap-2">
            {topAreas.length ? topAreas.map(([area, count]) => (
              <div key={area} className="flex items-center justify-between rounded-xl bg-white px-3 py-2 text-sm text-slate-700">
                <span className="capitalize">{area}</span>
                <span className="font-semibold">{count}</span>
              </div>
            )) : <p className="text-sm text-slate-500">No issues recorded.</p>}
          </div>
        </div>

        <div className="grid gap-4 md:grid-cols-3">
          <div className="rounded-2xl bg-slate-50 p-4">
            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Header issues</p>
            <p className="mt-2 text-2xl font-semibold text-slate-950">
              {analysis.headers.filter((header) => header.status !== "present").length}
            </p>
          </div>
          <div className="rounded-2xl bg-slate-50 p-4">
            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Cookie issues</p>
            <p className="mt-2 text-2xl font-semibold text-slate-950">
              {analysis.cookies.reduce((count, cookie) => count + cookie.issues.length, 0)}
            </p>
          </div>
          <div className="rounded-2xl bg-slate-50 p-4">
            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Same-origin crawl pages</p>
            <p className="mt-2 text-2xl font-semibold text-slate-950">
              {analysis.crawl.pages.filter((page) => page.sameOrigin).length}
            </p>
          </div>
        </div>
      </CardContent>
    </Card>
  );
};
