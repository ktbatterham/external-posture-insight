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
        <div className="rounded-2xl bg-slate-50 p-5">
          <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Dominant read</p>
          <p className="mt-3 text-sm leading-7 text-slate-800">{themes.summary}</p>
        </div>

        <div className="grid gap-4 md:grid-cols-2">
          <div className="rounded-2xl bg-slate-50 p-4">
            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">OWASP themes</p>
            <div className="mt-3 space-y-3">
              {themes.owasp.length ? (
                themes.owasp.map((item) => (
                  <div key={item.label} className="rounded-xl border border-slate-200 bg-white p-3">
                    <div className="flex items-center justify-between gap-3">
                      <p className="text-sm font-semibold text-slate-950">{item.label}</p>
                      <span className="rounded-full bg-slate-100 px-2.5 py-1 text-xs font-semibold text-slate-700">
                        {item.count}
                      </span>
                    </div>
                    <p className="mt-2 text-sm leading-6 text-slate-700">{item.summary}</p>
                    <p className="mt-2 text-xs font-medium uppercase tracking-[0.18em] text-slate-500">Why it matters</p>
                    <p className="mt-1 text-sm leading-6 text-slate-600">{item.whyItMatters}</p>
                    <div className="mt-3">
                      <p className="text-xs font-medium uppercase tracking-[0.18em] text-slate-500">Driving findings</p>
                      {item.examples.length ? (
                        <ul className="mt-2 space-y-1 text-sm text-slate-700">
                          {item.examples.map((example) => (
                            <li key={example}>{example}</li>
                          ))}
                        </ul>
                      ) : (
                        <p className="mt-2 text-sm text-slate-500">No example findings recorded.</p>
                      )}
                    </div>
                  </div>
                ))
              ) : (
                <span className="text-sm text-slate-500">No OWASP-tagged findings yet.</span>
              )}
            </div>
          </div>
          <div className="rounded-2xl bg-slate-50 p-4">
            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">MITRE relevance</p>
            <div className="mt-3 space-y-3">
              {themes.mitre.length ? (
                themes.mitre.map((item) => (
                  <div key={item.label} className="rounded-xl border border-slate-200 bg-white p-3">
                    <div className="flex items-center justify-between gap-3">
                      <p className="text-sm font-semibold text-slate-950">{item.label}</p>
                      <span className="rounded-full bg-slate-100 px-2.5 py-1 text-xs font-semibold text-slate-700">
                        {item.count}
                      </span>
                    </div>
                    <p className="mt-2 text-sm leading-6 text-slate-700">{item.summary}</p>
                    <p className="mt-2 text-xs font-medium uppercase tracking-[0.18em] text-slate-500">Why it matters</p>
                    <p className="mt-1 text-sm leading-6 text-slate-600">{item.whyItMatters}</p>
                    <div className="mt-3">
                      <p className="text-xs font-medium uppercase tracking-[0.18em] text-slate-500">Driving findings</p>
                      {item.examples.length ? (
                        <ul className="mt-2 space-y-1 text-sm text-slate-700">
                          {item.examples.map((example) => (
                            <li key={example}>{example}</li>
                          ))}
                        </ul>
                      ) : (
                        <p className="mt-2 text-sm text-slate-500">No example findings recorded.</p>
                      )}
                    </div>
                  </div>
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
