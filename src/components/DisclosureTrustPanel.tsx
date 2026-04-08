import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { AnalysisResult } from "@/types/analysis";
import { getDisclosurePosture } from "@/lib/reportInsights";
import { FileCheck2, ShieldAlert, ShieldCheck } from "lucide-react";

interface DisclosureTrustPanelProps {
  analysis: AnalysisResult;
}

export const DisclosureTrustPanel = ({ analysis }: DisclosureTrustPanelProps) => {
  const disclosure = getDisclosurePosture(analysis);

  return (
    <Card className="h-full border-slate-200 shadow-sm">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <FileCheck2 className="h-5 w-5" />
          Disclosure & Trust
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-5">
        <div className="min-w-0 rounded-[1.5rem] bg-slate-50 p-5">
          <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Public-facing read</p>
          <p className="mt-3 overflow-hidden break-words text-sm leading-7 text-slate-800">{disclosure.summary}</p>
        </div>

        <div className="min-w-0 rounded-2xl bg-slate-50 p-4">
          <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Discovered policy pages</p>
          <div className="mt-3 flex flex-wrap gap-2">
            {disclosure.discoveredPages.length ? (
              disclosure.discoveredPages.map((page) => (
                <Badge key={page} variant="outline" className="max-w-full overflow-hidden break-all text-left">
                  {page}
                </Badge>
              ))
            ) : (
              <span className="text-sm leading-6 text-slate-500">No obvious policy, trust, or contact pages were discovered passively.</span>
            )}
          </div>
        </div>

        <div className="space-y-2">
          {disclosure.strengths.map((strength) => (
            <div key={strength} className="flex gap-3 rounded-2xl border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-900">
              <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0" />
              <span>{strength}</span>
            </div>
          ))}
          {disclosure.issues.map((issue) => (
            <div key={issue} className="flex gap-3 rounded-2xl border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-900">
              <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0" />
              <span>{issue}</span>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
};
