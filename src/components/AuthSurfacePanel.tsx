import { KeyRound, ShieldAlert } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { getAuthSurfaceSummary } from "@/lib/passiveSurface";
import { HtmlSecurityInfo } from "@/types/analysis";

interface AuthSurfacePanelProps {
  htmlSecurity: HtmlSecurityInfo;
}

export const AuthSurfacePanel = ({ htmlSecurity }: AuthSurfacePanelProps) => {
  const summary = getAuthSurfaceSummary(htmlSecurity);

  if (!summary.authPaths.length && !summary.passwordFormCount) {
    return null;
  }

  return (
    <Card className="border-slate-200 shadow-sm">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <KeyRound className="h-5 w-5" />
          Auth Surface
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-5">
        <p className="text-sm leading-6 text-slate-600">{summary.summary}</p>

        <div className="grid gap-4 md:grid-cols-4">
          <div className="rounded-2xl bg-slate-50 p-4">
            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Auth paths</p>
            <p className="mt-2 text-2xl font-semibold text-slate-950">{summary.authPaths.length}</p>
          </div>
          <div className="rounded-2xl bg-slate-50 p-4">
            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Password forms</p>
            <p className="mt-2 text-2xl font-semibold text-slate-950">{summary.passwordFormCount}</p>
          </div>
          <div className="rounded-2xl bg-slate-50 p-4">
            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">External password posts</p>
            <p className="mt-2 text-2xl font-semibold text-slate-950">{summary.externalPasswordForms.length}</p>
          </div>
          <div className="rounded-2xl bg-slate-50 p-4">
            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Insecure password posts</p>
            <p className="mt-2 text-2xl font-semibold text-slate-950">{summary.insecurePasswordForms}</p>
          </div>
        </div>

        {summary.authPaths.length ? (
          <div className="rounded-2xl bg-slate-50 p-4">
            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Observed auth-adjacent paths</p>
            <div className="mt-3 flex flex-wrap gap-2">
              {summary.authPaths.map((item) => (
                <Badge key={item.path} variant="outline">
                  {item.path} · {item.category}
                </Badge>
              ))}
            </div>
          </div>
        ) : null}

        {summary.externalPasswordForms.length ? (
          <div className="flex gap-3 rounded-2xl border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-900">
            <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0" />
            <span>
              Password handling appears to involve an external origin. That can be legitimate for SSO, but it is worth
              confirming against the expected identity flow.
            </span>
          </div>
        ) : null}
      </CardContent>
    </Card>
  );
};
