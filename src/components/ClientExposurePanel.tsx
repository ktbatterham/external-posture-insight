import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { HtmlSecurityInfo } from "@/types/analysis";
import { Cpu, ShieldAlert } from "lucide-react";

interface ClientExposurePanelProps {
  htmlSecurity: HtmlSecurityInfo;
}

export const ClientExposurePanel = ({ htmlSecurity }: ClientExposurePanelProps) => {
  if (!htmlSecurity.clientExposureSignals.length) {
    return null;
  }

  return (
    <Card className="border-slate-200 shadow-sm">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Cpu className="h-5 w-5" />
          Client Config & API Exposure
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {htmlSecurity.clientExposureSignals.map((signal) => (
          <div key={`${signal.category}-${signal.title}`} className="rounded-2xl border border-slate-200 bg-white p-4">
            <div className="flex flex-wrap items-center gap-2">
              <p className="font-semibold text-slate-950">{signal.title}</p>
              <Badge variant={signal.severity === "warning" ? "destructive" : "secondary"}>
                {signal.severity}
              </Badge>
              <Badge variant="outline">{signal.category.replace(/_/g, " ")}</Badge>
            </div>
            <p className="mt-3 text-sm text-slate-600">{signal.detail}</p>
            <div className="mt-3 flex flex-wrap gap-2">
              {signal.evidence.map((item) => (
                <Badge key={item} variant="outline">
                  {item}
                </Badge>
              ))}
            </div>
          </div>
        ))}

        {htmlSecurity.clientExposureSignals.some((signal) => signal.severity === "warning") ? (
          <div className="flex gap-3 rounded-2xl border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-900">
            <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0" />
            <span>Environment-like naming or unexpectedly explicit client configuration deserves a quick review before deeper testing.</span>
          </div>
        ) : null}
      </CardContent>
    </Card>
  );
};
