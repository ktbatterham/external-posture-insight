import { GitCompareArrows, Route } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { StatBox } from "@/components/ui/panel-primitives";
import { getHttpStatusDetails } from "@/lib/httpStatus";
import { CrawlSummary } from "@/types/analysis";

interface CrawlPanelProps {
  crawl: CrawlSummary;
}

const gradeStyles: Record<string, string> = {
  "A+": "bg-emerald-100 text-emerald-900",
  A: "bg-emerald-100 text-emerald-900",
  B: "bg-lime-100 text-lime-900",
  C: "bg-amber-100 text-amber-900",
  D: "bg-orange-100 text-orange-900",
  F: "bg-rose-100 text-rose-900",
  Redirected: "bg-slate-200 text-slate-800",
};

export const CrawlPanel = ({ crawl }: CrawlPanelProps) => {
  if (!crawl.pages.length) {
    return null;
  }

  return (
    <Card className="border-slate-200 shadow-sm">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Route className="h-5 w-5" />
          Multi-Page Crawl
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-5">
        <div className="grid gap-4 md:grid-cols-2">
          <StatBox label="Strongest page" value={<p className="text-lg font-semibold">{crawl.strongestPage ?? "Unknown"}</p>} />
          <StatBox label="Weakest page" value={<p className="text-lg font-semibold">{crawl.weakestPage ?? "Unknown"}</p>} />
        </div>

        {crawl.discoverySources.length > 0 && (
          <StatBox
            label="Discovery sources"
            value={
              <div className="flex flex-wrap gap-2">
                {crawl.discoverySources.map((source) => (
                  <Badge key={source} variant="outline">{source}</Badge>
                ))}
              </div>
            }
          />
        )}

        {crawl.inconsistentHeaders.length > 0 && (
          <div className="rounded-2xl border border-amber-200 bg-amber-50 p-4">
            <div className="flex items-center gap-2 text-sm font-semibold text-amber-900">
              <GitCompareArrows className="h-4 w-4" />
              Inconsistent across routes
            </div>
            <div className="mt-3 flex flex-wrap gap-2">
              {crawl.inconsistentHeaders.map((header) => (
                <Badge key={header} variant="secondary" className="bg-amber-100 text-amber-900">
                  {header}
                </Badge>
              ))}
            </div>
          </div>
        )}

        <div className="grid gap-3">
          {crawl.pages.map((page) => {
            const status = page.statusCode ? getHttpStatusDetails(page.statusCode) : null;
            return (
              <div key={`${page.path}-${page.label}`} className="rounded-2xl border border-slate-200 bg-white p-4">
                <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
                  <div className="min-w-0">
                    <div className="flex min-w-0 items-center gap-2">
                      <h3 className="shrink-0 font-semibold text-slate-950">{page.label}</h3>
                      <code className="min-w-0 truncate rounded bg-slate-100 px-2 py-0.5 text-xs text-slate-600" title={page.path}>{page.path}</code>
                    </div>
                    <p className="mt-2 truncate text-sm text-slate-500" title={page.finalUrl}>{page.finalUrl}</p>
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge variant="secondary" className={gradeStyles[page.grade] ?? gradeStyles.F}>
                      {page.grade}
                    </Badge>
                    {page.sameOrigin ? (
                      <span className="text-sm font-semibold text-slate-600">{page.score}/100</span>
                    ) : (
                      <span className="text-sm font-semibold text-slate-600">off-origin redirect</span>
                    )}
                  </div>
                </div>
                <div className="mt-4 grid gap-3 text-sm md:grid-cols-3">
                  <div className="rounded-xl bg-slate-50 p-3 text-slate-600">
                    <div>Status {page.statusCode ? `${page.statusCode} ${status?.label}` : "unreachable"} · {page.responseTimeMs}ms</div>
                    {status ? (
                      <div className="mt-1 text-xs leading-5 text-slate-500">{status.meaning}</div>
                    ) : null}
                  </div>
                  <div className="rounded-xl bg-slate-50 p-3 text-slate-600">
                    Missing: {!page.sameOrigin ? "not compared" : page.missingHeaders.length ? page.missingHeaders.join(", ") : "none"}
                  </div>
                  <div className="rounded-xl bg-slate-50 p-3 text-slate-600">
                    Warnings: {!page.sameOrigin ? "not compared" : page.warningHeaders.length ? page.warningHeaders.join(", ") : "none"}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </CardContent>
    </Card>
  );
};
