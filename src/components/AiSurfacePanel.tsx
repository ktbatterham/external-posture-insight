import { Bot, ShieldAlert, ShieldCheck } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { getAiSurfaceClassificationSummary } from "@/lib/aiSurface";
import { AiSurfaceInfo } from "@/types/analysis";

interface AiSurfacePanelProps {
  aiSurface: AiSurfaceInfo;
}

export const AiSurfacePanel = ({ aiSurface }: AiSurfacePanelProps) => {
  const categoryLabel = {
    ai_vendor: "AI vendor",
    support_automation: "Support automation",
    assistant_ui: "Assistant UI",
  } as const;

  const confidenceStyles = {
    high: "bg-slate-200 text-slate-800",
    medium: "bg-amber-100 text-amber-900",
    low: "bg-sky-100 text-sky-900",
  } as const;

  const classificationSummary = getAiSurfaceClassificationSummary(aiSurface);

  return (
    <Card className="border-slate-200 shadow-sm">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Bot className="h-5 w-5" />
          AI Surface
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-5">
        <div className="rounded-2xl border border-sky-200 bg-sky-50 px-4 py-4">
          <p className="text-xs uppercase tracking-[0.18em] text-sky-700">Classification</p>
          <p className="mt-2 text-lg font-semibold text-sky-950">{classificationSummary}</p>
        </div>

        <div className="grid gap-4 md:grid-cols-4">
          <div className="rounded-2xl bg-slate-50 p-4">
            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">AI detected</p>
            <p className="mt-2 text-2xl font-semibold text-slate-950">{aiSurface.detected ? "Yes" : "No"}</p>
          </div>
          <div className="rounded-2xl bg-slate-50 p-4">
            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Assistant visible</p>
            <p className="mt-2 text-2xl font-semibold text-slate-950">{aiSurface.assistantVisible ? "Yes" : "No"}</p>
          </div>
          <div className="rounded-2xl bg-slate-50 p-4">
            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Vendors</p>
            <p className="mt-2 text-2xl font-semibold text-slate-950">{aiSurface.vendors.length}</p>
          </div>
          <div className="rounded-2xl bg-slate-50 p-4">
            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">AI paths</p>
            <p className="mt-2 text-2xl font-semibold text-slate-950">{aiSurface.discoveredPaths.length}</p>
          </div>
        </div>

        {aiSurface.vendors.length > 0 && (
          <div className="rounded-2xl bg-slate-50 p-4">
            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Detected vendors</p>
            <div className="mt-3 grid gap-3">
              {aiSurface.vendors.map((vendor) => (
                <div key={`${vendor.name}-${vendor.category}`} className="rounded-xl bg-white px-4 py-3">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-medium text-slate-900">{vendor.name}</span>
                    <Badge variant="outline">{categoryLabel[vendor.category]}</Badge>
                    <Badge variant="secondary" className={confidenceStyles[vendor.confidence]}>
                      {vendor.confidence} confidence
                    </Badge>
                  </div>
                  <p className="mt-2 text-xs text-slate-500">{vendor.evidence}</p>
                </div>
              ))}
            </div>
          </div>
        )}

        {aiSurface.discoveredPaths.length > 0 && (
          <div className="rounded-2xl bg-slate-50 p-4">
            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">AI-related paths</p>
            <div className="mt-3 flex flex-wrap gap-2">
              {aiSurface.discoveredPaths.map((path) => (
                <Badge key={path} variant="outline">{path}</Badge>
              ))}
            </div>
          </div>
        )}

        {(aiSurface.privacySignals.length > 0 || aiSurface.governanceSignals.length > 0) && (
          <div className="grid gap-4 md:grid-cols-2">
            <div className="rounded-2xl bg-slate-50 p-4">
              <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Privacy signals</p>
              <div className="mt-3 space-y-2">
                {aiSurface.privacySignals.length > 0 ? (
                  aiSurface.privacySignals.map((signal) => (
                    <p key={signal} className="rounded-xl bg-white px-3 py-3 text-sm text-slate-700">
                      {signal}
                    </p>
                  ))
                ) : (
                  <p className="text-sm text-slate-500">No AI-related privacy guidance was identified on the fetched page.</p>
                )}
              </div>
            </div>
            <div className="rounded-2xl bg-slate-50 p-4">
              <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Governance signals</p>
              <div className="mt-3 space-y-2">
                {aiSurface.governanceSignals.length > 0 ? (
                  aiSurface.governanceSignals.map((signal) => (
                    <p key={signal} className="rounded-xl bg-white px-3 py-3 text-sm text-slate-700">
                      {signal}
                    </p>
                  ))
                ) : (
                  <p className="text-sm text-slate-500">No visible AI governance or human-review language was identified.</p>
                )}
              </div>
            </div>
          </div>
        )}

        <div className="space-y-2">
          {aiSurface.strengths.map((strength) => (
            <div key={strength} className="flex gap-3 rounded-2xl border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-900">
              <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0" />
              <span>{strength}</span>
            </div>
          ))}
          {aiSurface.disclosures.map((disclosure) => (
            <div key={disclosure} className="flex gap-3 rounded-2xl border border-sky-200 bg-sky-50 px-4 py-3 text-sm text-sky-900">
              <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0" />
              <span>{disclosure}</span>
            </div>
          ))}
          {aiSurface.issues.map((issue) => (
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
