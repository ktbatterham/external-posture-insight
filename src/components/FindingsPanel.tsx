import { AlertTriangle, Info, ShieldCheck, ShieldX } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { EmptyState } from "@/components/ui/panel-primitives";
import { ScanIssue } from "@/types/analysis";

interface FindingsPanelProps {
  issues: ScanIssue[];
  strengths: string[];
}

const severityWeight = { critical: 0, warning: 1, info: 2 } as const;
const confidenceWeight = { high: 0, medium: 1, low: 2 } as const;

const issueAccent = {
  critical: {
    icon: <ShieldX className="h-4 w-4" />,
    chip: "bg-[#8e5c3b]/18 text-[#f0d5bc] border-[#b56a2c]/30",
    iconWrap: "bg-[#8e5c3b]/18 text-[#f0d5bc]",
  },
  warning: {
    icon: <AlertTriangle className="h-4 w-4" />,
    chip: "bg-[#74452b]/18 text-[#e2c0a2] border-[#8e5c3b]/30",
    iconWrap: "bg-[#74452b]/18 text-[#e2c0a2]",
  },
  info: {
    icon: <Info className="h-4 w-4" />,
    chip: "bg-white/[0.08] text-slate-200 border-white/10",
    iconWrap: "bg-white/[0.08] text-slate-200",
  },
} as const;

const confidenceStyles = {
  high: "bg-white/[0.12] text-slate-100 border-white/10",
  medium: "bg-[#b56a2c]/14 text-[#f0d5bc] border-[#b56a2c]/25",
  low: "bg-white/[0.06] text-slate-300 border-white/10",
} as const;

export const FindingsPanel = ({ issues, strengths }: FindingsPanelProps) => {
  const rankedIssues = [...issues].sort((left, right) => {
    return (
      severityWeight[left.severity] - severityWeight[right.severity] ||
      confidenceWeight[left.confidence] - confidenceWeight[right.confidence]
    );
  });

  return (
    <Card className="border-white/10 bg-white/[0.04] shadow-[0_24px_60px_-36px_rgba(0,0,0,0.65)]">
      <CardHeader className="pb-3">
        <CardTitle>Top Findings</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {strengths.length ? (
          <div className="rounded-[1.35rem] border border-white/10 bg-white/[0.03] p-4 shadow-[0_18px_40px_-28px_rgba(0,0,0,0.7)]">
            <div className="flex items-center gap-2">
              <ShieldCheck className="h-4 w-4 text-[#d89a63]" />
              <p className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-400">Observed strengths</p>
            </div>
            <div className="mt-3 grid gap-2">
              {strengths.slice(0, 3).map((strength) => (
                <div
                  key={strength}
                  className="rounded-2xl border border-white/10 bg-slate-950/45 px-3 py-3 text-sm leading-6 text-slate-200"
                >
                  {strength}
                </div>
              ))}
            </div>
          </div>
        ) : null}

        {rankedIssues.length ? (
          <div className="overflow-hidden rounded-[1.35rem] border border-white/10 bg-white/[0.03] shadow-[0_18px_40px_-28px_rgba(0,0,0,0.7)]">
            <div className="hidden grid-cols-[minmax(0,1.45fr)_8.5rem_7.5rem] gap-4 border-b border-white/10 px-4 py-3 md:grid">
              <p className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">Finding</p>
              <p className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">Confidence</p>
              <p className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">Surface</p>
            </div>
            <div>
              {rankedIssues.slice(0, 6).map((issue, index) => {
                const accent = issueAccent[issue.severity];
                return (
                  <div
                    key={`${issue.area}-${issue.title}-${issue.detail}`}
                    className={`px-4 py-4 ${index < Math.min(rankedIssues.length, 6) - 1 ? "border-b border-white/10" : ""}`}
                  >
                    <div className="grid gap-3 md:grid-cols-[minmax(0,1.45fr)_8.5rem_7.5rem] md:items-start">
                      <div>
                        <div className="flex items-start gap-3">
                          <span className={`inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-full ${accent.iconWrap}`}>
                            {accent.icon}
                          </span>
                          <div className="min-w-0">
                            <p className="text-base font-semibold leading-6 text-white">{issue.title}</p>
                            <p className="mt-1 text-sm leading-6 text-slate-300">{issue.detail}</p>
                          </div>
                        </div>
                        <div className="mt-3 flex flex-wrap gap-2 pl-11">
                          <Badge variant="outline" className={accent.chip}>
                            {issue.severity}
                          </Badge>
                          {issue.owasp.slice(0, 2).map((label) => (
                            <Badge key={label} variant="outline" className="border-white/10 bg-white/[0.03] text-slate-300">
                              {label}
                            </Badge>
                          ))}
                          {issue.mitre.slice(0, 2).map((label) => (
                            <Badge key={label} variant="outline" className="border-white/10 bg-white/[0.03] text-slate-300">
                              MITRE: {label}
                            </Badge>
                          ))}
                        </div>
                      </div>
                      <div className="md:pt-1">
                        <Badge variant="outline" className={confidenceStyles[issue.confidence]}>
                          {issue.confidence} confidence
                        </Badge>
                      </div>
                      <div className="md:pt-1">
                        <Badge variant="outline" className="border-white/10 bg-white/[0.03] text-slate-300">
                          {issue.source}
                        </Badge>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        ) : (
          <EmptyState>No obvious issues were detected in the scanned response.</EmptyState>
        )}
      </CardContent>
    </Card>
  );
};
