import { AlertTriangle, Info, ShieldCheck, ShieldX } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ScanIssue } from "@/types/analysis";

interface FindingsPanelProps {
  issues: ScanIssue[];
  strengths: string[];
}

const issueStyles = {
  critical: {
    icon: <ShieldX className="h-4 w-4" />,
    className: "border-rose-200 bg-rose-50 text-rose-900",
  },
  warning: {
    icon: <AlertTriangle className="h-4 w-4" />,
    className: "border-amber-200 bg-amber-50 text-amber-900",
  },
  info: {
    icon: <Info className="h-4 w-4" />,
    className: "border-sky-200 bg-sky-50 text-sky-900",
  },
} as const;

export const FindingsPanel = ({ issues, strengths }: FindingsPanelProps) => {
  return (
    <Card className="border-slate-200 shadow-sm">
      <CardHeader>
        <CardTitle>Top Findings</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {strengths.slice(0, 3).map((strength) => (
          <div
            key={strength}
            className="flex gap-3 rounded-2xl border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-900"
          >
            <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0" />
            <span>{strength}</span>
          </div>
        ))}

        {issues.length ? (
          issues.slice(0, 6).map((issue) => (
            <div
              key={`${issue.area}-${issue.title}-${issue.detail}`}
              className={`flex gap-3 rounded-2xl border px-4 py-3 text-sm ${issueStyles[issue.severity].className}`}
            >
              <div className="mt-0.5 shrink-0">{issueStyles[issue.severity].icon}</div>
              <div>
                <div className="font-medium">{issue.title}</div>
                <p className="mt-1 opacity-90">{issue.detail}</p>
              </div>
            </div>
          ))
        ) : (
          <div className="rounded-2xl border border-dashed border-slate-300 bg-slate-50 px-4 py-6 text-sm text-slate-500">
            No obvious issues were detected in the scanned response.
          </div>
        )}
      </CardContent>
    </Card>
  );
};
