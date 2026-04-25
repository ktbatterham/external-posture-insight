import { Bot, ShieldAlert, ShieldCheck } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { StatBox, StatusAlert, TruncatedChip } from "@/components/ui/panel-primitives";
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
        <StatBox
          variant="info"
          label="Classification"
          value={<p className="text-lg font-semibold">{classificationSummary}</p>}
        />

        <div className="grid gap-4 md:grid-cols-4">
          <StatBox label="AI detected" value={<p className="text-2xl font-semibold">{aiSurface.detected ? "Yes" : "No"}</p>} />
          <StatBox label="Assistant visible" value={<p className="text-2xl font-semibold">{aiSurface.assistantVisible ? "Yes" : "No"}</p>} />
          <StatBox label="Vendors" value={<p className="text-2xl font-semibold">{aiSurface.vendors.length}</p>} />
          <StatBox label="AI paths" value={<p className="text-2xl font-semibold">{aiSurface.discoveredPaths.length}</p>} />
        </div>

        {aiSurface.vendors.length > 0 && (
          <StatBox
            label="Detected vendors"
            value={
              <div className="grid gap-3">
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
            }
          />
        )}

        {aiSurface.discoveredPaths.length > 0 && (
          <StatBox
            label="AI-related paths"
            value={
              <div className="flex flex-wrap gap-2">
                {aiSurface.discoveredPaths.map((path) => <TruncatedChip key={path} value={path} />)}
              </div>
            }
          />
        )}

        {(aiSurface.privacySignals.length > 0 || aiSurface.governanceSignals.length > 0) && (
          <div className="grid gap-4 md:grid-cols-2">
            <StatBox
              label="Privacy signals"
              value={
                <div className="space-y-2">
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
              }
            />
            <StatBox
              label="Governance signals"
              value={
                <div className="space-y-2">
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
              }
            />
          </div>
        )}

        <div className="space-y-2">
          {aiSurface.strengths.map((strength) => (
            <StatusAlert key={strength} variant="success" icon={<ShieldCheck />}>{strength}</StatusAlert>
          ))}
          {aiSurface.disclosures.map((disclosure) => (
            <StatusAlert key={disclosure} variant="info" icon={<ShieldCheck />}>{disclosure}</StatusAlert>
          ))}
          {aiSurface.issues.map((issue) => (
            <StatusAlert key={issue} variant="warning" icon={<ShieldAlert />}>{issue}</StatusAlert>
          ))}
        </div>
      </CardContent>
    </Card>
  );
};
