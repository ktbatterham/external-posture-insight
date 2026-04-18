import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { AnalysisResult } from "@/types/analysis";
import { getDominantThemes } from "@/lib/reportInsights";
import { Layers3 } from "lucide-react";

interface TaxonomySummaryPanelProps {
  analysis: AnalysisResult;
}

interface ThemeItem {
  label: string;
  summary: string;
  whyItMatters: string;
  examples: string[];
}

interface ThemeColumnProps {
  title: string;
  emptyState: string;
  items: ThemeItem[];
}

const ThemeColumn = ({ title, emptyState, items }: ThemeColumnProps) => (
  <div className="rounded-2xl border border-slate-200/70 bg-white/90 p-4 shadow-[0_8px_18px_-14px_rgba(15,23,42,0.3),0_1px_0_rgba(255,255,255,0.65)_inset]">
    <p className="text-xs uppercase tracking-[0.18em] text-slate-500">{title}</p>
    <div className="mt-3 space-y-3">
      {items.length ? (
        items.map((item) => {
          const topExamples = item.examples.slice(0, 3);
          const remainingExampleCount = Math.max(item.examples.length - topExamples.length, 0);

          return (
            <div key={item.label} className="rounded-xl border border-slate-200/70 bg-white/90 p-4">
              <p className="text-sm font-semibold text-slate-950">{item.label}</p>
              <p className="mt-2 text-sm leading-6 text-slate-700">{item.summary}</p>
              <p className="mt-3 text-xs font-medium uppercase tracking-[0.18em] text-slate-500">Why it matters</p>
              <p className="mt-1 text-sm leading-6 text-slate-600">{item.whyItMatters}</p>
              <div className="mt-3">
                <p className="text-xs font-medium uppercase tracking-[0.18em] text-slate-500">Driving findings</p>
                {topExamples.length ? (
                  <ul className="mt-2 space-y-1 text-sm text-slate-700">
                    {topExamples.map((example) => (
                      <li key={example} className="flex items-start gap-2">
                        <span className="mt-2 inline-block h-1.5 w-1.5 shrink-0 rounded-full bg-slate-400" aria-hidden="true" />
                        <span>{example}</span>
                      </li>
                    ))}
                    {remainingExampleCount > 0 ? (
                      <li className="text-xs font-medium uppercase tracking-[0.16em] text-slate-500">
                        +{remainingExampleCount} more finding{remainingExampleCount === 1 ? "" : "s"}
                      </li>
                    ) : null}
                  </ul>
                ) : (
                  <p className="mt-2 text-sm text-slate-500">No example findings recorded.</p>
                )}
              </div>
            </div>
          );
        })
      ) : (
        <span className="text-sm text-slate-500">{emptyState}</span>
      )}
    </div>
  </div>
);

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
        <div className="rounded-2xl border border-slate-200/70 bg-white/90 p-5 shadow-[0_8px_18px_-14px_rgba(15,23,42,0.3),0_1px_0_rgba(255,255,255,0.65)_inset]">
          <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Dominant read</p>
          <p className="mt-3 text-sm leading-7 text-slate-800">{themes.summary}</p>
        </div>

        <div className="grid gap-4 md:grid-cols-2">
          <ThemeColumn title="OWASP themes" emptyState="No OWASP-tagged findings yet." items={themes.owasp} />
          <ThemeColumn title="MITRE relevance" emptyState="No MITRE-relevant mappings yet." items={themes.mitre} />
        </div>
      </CardContent>
    </Card>
  );
};
