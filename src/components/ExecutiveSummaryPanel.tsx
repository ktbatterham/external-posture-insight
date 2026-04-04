import { BriefcaseBusiness, Sparkles } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ExecutiveSummaryInfo } from "@/types/analysis";

interface ExecutiveSummaryPanelProps {
  summary: ExecutiveSummaryInfo;
}

const postureStyles = {
  strong: "border-emerald-200 bg-emerald-50 text-emerald-950",
  mixed: "border-amber-200 bg-amber-50 text-amber-950",
  weak: "border-rose-200 bg-rose-50 text-rose-950",
} as const;

export const ExecutiveSummaryPanel = ({ summary }: ExecutiveSummaryPanelProps) => {
  return (
    <Card className="border-slate-200 shadow-sm">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <BriefcaseBusiness className="h-5 w-5" />
          Executive Readout
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-5">
        <div className={`rounded-[1.5rem] border px-5 py-5 ${postureStyles[summary.posture]}`}>
          <div className="flex items-center gap-2 text-xs uppercase tracking-[0.18em] opacity-75">
            <Sparkles className="h-4 w-4" />
            Overall read
          </div>
          <p className="mt-3 text-xl font-semibold leading-8">{summary.overview}</p>
        </div>

        <div className="rounded-[1.5rem] bg-slate-50 p-5">
          <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Main visible risk</p>
          <p className="mt-3 text-base font-medium leading-7 text-slate-900">{summary.mainRisk}</p>
        </div>

        <div className="rounded-[1.5rem] bg-slate-50 p-5">
          <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Top takeaways</p>
          <div className="mt-4 space-y-3">
            {summary.takeaways.map((takeaway, index) => (
              <div key={takeaway} className="flex gap-3 rounded-2xl bg-white px-4 py-4 text-sm text-slate-700">
                <div className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-slate-100 text-xs font-semibold text-slate-600">
                  {index + 1}
                </div>
                <p className="leading-6">{takeaway}</p>
              </div>
            ))}
          </div>
        </div>
      </CardContent>
    </Card>
  );
};
