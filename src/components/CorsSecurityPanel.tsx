import { ArrowLeftRight, ShieldAlert, ShieldCheck } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { CorsSecurityInfo } from "@/types/analysis";

interface CorsSecurityPanelProps {
  corsSecurity: CorsSecurityInfo;
}

export const CorsSecurityPanel = ({ corsSecurity }: CorsSecurityPanelProps) => {
  return (
    <Card className="border-slate-200 shadow-sm">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <ArrowLeftRight className="h-5 w-5" />
          CORS & Methods
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-5">
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          <div className="rounded-2xl bg-slate-50 p-4">
            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Allowed origin</p>
            <p className="mt-2 break-all text-sm text-slate-700">{corsSecurity.allowedOrigin ?? "None"}</p>
          </div>
          <div className="rounded-2xl bg-slate-50 p-4">
            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Credentials</p>
            <p className="mt-2 text-sm text-slate-700">{corsSecurity.allowCredentials ?? "Not set"}</p>
          </div>
          <div className="rounded-2xl bg-slate-50 p-4">
            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">OPTIONS status</p>
            <p className="mt-2 text-sm text-slate-700">{corsSecurity.optionsStatus || "No response"}</p>
          </div>
          <div className="rounded-2xl bg-slate-50 p-4">
            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Vary</p>
            <p className="mt-2 break-all text-sm text-slate-700">{corsSecurity.vary ?? "Not set"}</p>
          </div>
        </div>

        <div className="grid gap-4 md:grid-cols-2">
          <div className="rounded-2xl bg-slate-50 p-4">
            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Allowed methods</p>
            <div className="mt-3 flex flex-wrap gap-2">
              {corsSecurity.allowMethods.length ? corsSecurity.allowMethods.map((method) => (
                <Badge key={method} variant="outline">{method}</Badge>
              )) : <span className="text-sm text-slate-500">None advertised</span>}
            </div>
          </div>
          <div className="rounded-2xl bg-slate-50 p-4">
            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Allowed headers</p>
            <div className="mt-3 flex flex-wrap gap-2">
              {corsSecurity.allowHeaders.length ? corsSecurity.allowHeaders.map((header) => (
                <Badge key={header} variant="outline">{header}</Badge>
              )) : <span className="text-sm text-slate-500">None advertised</span>}
            </div>
          </div>
        </div>

        <div className="space-y-2">
          {corsSecurity.strengths.map((strength) => (
            <div key={strength} className="flex gap-3 rounded-2xl border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-900">
              <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0" />
              <span>{strength}</span>
            </div>
          ))}
          {corsSecurity.issues.map((issue) => (
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
