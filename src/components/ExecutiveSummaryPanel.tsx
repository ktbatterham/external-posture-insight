import { BriefcaseBusiness } from "lucide-react";
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
      <CardContent className="space-y-4">
        <div className={`rounded-2xl border px-4 py-4 ${postureStyles[summary.posture]}`}>
          <p className="text-xs uppercase tracking-[0.18em] opacity-75">Overall read</p>
          <p className="mt-2 text-lg font-semibold">{summary.overview}</p>
        </div>

        <div className="rounded-2xl bg-slate-50 p-4">
          <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Main visible risk</p>
          <p className="mt-2 text-sm font-medium text-slate-900">{summary.mainRisk}</p>
        </div>

        <div className="rounded-2xl bg-slate-50 p-4">
          <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Top takeaways</p>
          <div className="mt-3 space-y-2">
            {summary.takeaways.map((takeaway) => (
              <p key={takeaway} className="rounded-xl bg-white px-3 py-3 text-sm text-slate-700">
                {takeaway}
              </p>
            ))}
          </div>
        </div>
      </CardContent>
    </Card>
  );
};
