import { BarChart3 } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { AnalysisResult } from "@/types/analysis";
import { getAreaScores, getUnifiedIssueSummary } from "@/lib/posture";

interface PostureSummaryPanelProps {
  analysis: AnalysisResult;
}

export const PostureSummaryPanel = ({ analysis }: PostureSummaryPanelProps) => {
  const severityCounts = getUnifiedIssueSummary(analysis);
  const areaScores = getAreaScores(analysis);

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
          <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Category scores</p>
          <p className="mt-2 text-sm leading-6 text-slate-600">
            These category scores are directional breakdowns of the posture by area. They help explain where risk is concentrated, but they are not intended to add up to or exactly match the single overall score.
          </p>
          <div className="mt-3 grid gap-2">
            {areaScores.map((area) => (
              <div key={area.key} className="rounded-xl bg-white px-3 py-3 text-sm text-slate-700">
                <div className="flex items-center justify-between">
                  <span className="font-medium">{area.label}</span>
                  <span className="font-semibold">{area.score}/100</span>
                </div>
                <div className="mt-2 h-2 rounded-full bg-slate-100">
                  <div
                    className={`h-2 rounded-full ${
                      area.status === "strong"
                        ? "bg-emerald-500"
                        : area.status === "watch"
                          ? "bg-amber-500"
                          : "bg-rose-500"
                    }`}
                    style={{ width: `${area.score}%` }}
                  />
                </div>
                <p className="mt-2 text-xs text-slate-500">{area.notes.join(" · ")}</p>
              </div>
            ))}
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
