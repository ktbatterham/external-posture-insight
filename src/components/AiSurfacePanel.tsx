import { Bot, ShieldAlert, ShieldCheck } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { AiSurfaceInfo } from "@/types/analysis";

interface AiSurfacePanelProps {
  aiSurface: AiSurfaceInfo;
}

export const AiSurfacePanel = ({ aiSurface }: AiSurfacePanelProps) => {
  return (
    <Card className="border-slate-200 shadow-sm">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Bot className="h-5 w-5" />
          AI Surface
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-5">
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
            <div className="mt-3 flex flex-wrap gap-2">
              {aiSurface.vendors.map((vendor) => (
                <Badge key={vendor.name} variant="outline">{vendor.name}</Badge>
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
