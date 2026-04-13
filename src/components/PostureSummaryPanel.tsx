import { BarChart3 } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { StatBox } from "@/components/ui/panel-primitives";
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
          <StatBox variant="critical" label="Critical" value={<p className="text-3xl font-black">{severityCounts.critical}</p>} />
          <StatBox variant="warning" label="Warnings" value={<p className="text-3xl font-black">{severityCounts.warning}</p>} />
          <StatBox variant="info" label="Info" value={<p className="text-3xl font-black">{severityCounts.info}</p>} />
        </div>

        <div className="rounded-2xl bg-slate-50 p-4">
          <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Category scores</p>
          <div className="mt-3 grid gap-2">
            {areaScores.map((area) => (
              <div key={area.key} className="rounded-xl bg-white px-3 py-3 text-sm text-slate-700">
                <div className="flex items-center justify-between gap-3">
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
          <StatBox
            label="Header issues"
            value={<p className="text-2xl font-semibold">{analysis.headers.filter((header) => header.status !== "present").length}</p>}
          />
          <StatBox
            label="Cookie issues"
            value={<p className="text-2xl font-semibold">{analysis.cookies.reduce((count, cookie) => count + cookie.issues.length, 0)}</p>}
          />
          <StatBox
            label="Same-origin crawl pages"
            value={<p className="text-2xl font-semibold">{analysis.crawl.pages.filter((page) => page.sameOrigin).length}</p>}
          />
        </div>
      </CardContent>
    </Card>
  );
};
