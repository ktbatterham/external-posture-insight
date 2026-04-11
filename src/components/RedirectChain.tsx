import { ArrowRight, Route } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { getHttpStatusDetails } from "@/lib/httpStatus";
import { RedirectHop } from "@/types/analysis";

interface RedirectChainProps {
  redirects: RedirectHop[];
}

export const RedirectChain = ({ redirects }: RedirectChainProps) => {
  return (
    <Card className="border-slate-200 shadow-sm">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Route className="h-5 w-5" />
          Redirect Chain
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        {redirects.map((hop, index) => {
          const status = getHttpStatusDetails(hop.statusCode);
          return (
            <div key={`${hop.url}-${index}`} className="rounded-2xl border border-slate-200 bg-white px-4 py-3">
              <div className="flex flex-col gap-2 md:flex-row md:items-center md:justify-between">
                <div className="min-w-0">
                  <p className="truncate text-sm font-medium text-slate-900">{hop.url}</p>
                  <p className="text-xs text-slate-500">{hop.secure ? "HTTPS" : "HTTP"}</p>
                </div>
                <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">
                  <span>Status {hop.statusCode} {status.label}</span>
                  {hop.location && <ArrowRight className="h-3.5 w-3.5" />}
                </div>
              </div>
              <p className="mt-2 text-xs leading-5 text-slate-500">{status.meaning}</p>
              {hop.location && <p className="mt-3 break-all text-xs text-slate-500">Location: {hop.location}</p>}
            </div>
          );
        })}
      </CardContent>
    </Card>
  );
};
