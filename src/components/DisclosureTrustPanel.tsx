import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { StatBox, StatusAlert } from "@/components/ui/panel-primitives";
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
        <div className="min-w-0 rounded-2xl bg-slate-50 p-5">
          <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Public-facing read</p>
          <p className="mt-3 overflow-hidden break-words text-sm leading-7 text-slate-800">{disclosure.summary}</p>
        </div>

        <StatBox
          label="Discovered policy pages"
          value={
            <div className="flex flex-wrap gap-2">
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
          }
        />

        <div className="space-y-2">
          {disclosure.strengths.map((strength) => (
            <StatusAlert key={strength} variant="success" icon={<ShieldCheck />}>{strength}</StatusAlert>
          ))}
          {disclosure.issues.map((issue) => (
            <StatusAlert key={issue} variant="warning" icon={<ShieldAlert />}>{issue}</StatusAlert>
          ))}
        </div>
      </CardContent>
    </Card>
  );
};
