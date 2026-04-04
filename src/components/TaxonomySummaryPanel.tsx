import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { AnalysisResult } from "@/types/analysis";
import { getDominantThemes } from "@/lib/reportInsights";
import { Layers3 } from "lucide-react";

interface TaxonomySummaryPanelProps {
  analysis: AnalysisResult;
}

export const TaxonomySummaryPanel = ({ analysis }: TaxonomySummaryPanelProps) => {
  const themes = getDominantThemes(analysis);

  return (
    <Card className="border-slate-200 shadow-sm">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Layers3 className="h-5 w-5" />
          Risk Themes
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-5">
        <div className="rounded-[1.5rem] bg-slate-50 p-5">
          <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Dominant read</p>
          <p className="mt-3 text-sm leading-7 text-slate-800">{themes.summary}</p>
        </div>

        <div className="grid gap-4 md:grid-cols-2">
          <div className="rounded-2xl bg-slate-50 p-4">
            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">OWASP themes</p>
            <div className="mt-3 flex flex-wrap gap-2">
              {themes.owasp.length ? (
                themes.owasp.map((item) => (
                  <Badge key={item.label} variant="outline">
                    {item.label} · {item.count}
                  </Badge>
                ))
              ) : (
                <span className="text-sm text-slate-500">No OWASP-tagged findings yet.</span>
              )}
            </div>
          </div>
          <div className="rounded-2xl bg-slate-50 p-4">
            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">MITRE relevance</p>
            <div className="mt-3 flex flex-wrap gap-2">
              {themes.mitre.length ? (
                themes.mitre.map((item) => (
                  <Badge key={item.label} variant="outline">
                    {item.label} · {item.count}
                  </Badge>
                ))
              ) : (
                <span className="text-sm text-slate-500">No MITRE-relevant mappings yet.</span>
              )}
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
};
