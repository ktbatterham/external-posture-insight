import { CodeXml, ShieldAlert, ShieldCheck } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { HtmlSecurityInfo } from "@/types/analysis";

interface HtmlSecurityPanelProps {
  htmlSecurity: HtmlSecurityInfo;
}

export const HtmlSecurityPanel = ({ htmlSecurity }: HtmlSecurityPanelProps) => {
  return (
    <Card className="border-slate-200 shadow-sm">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <CodeXml className="h-5 w-5" />
          Passive Page Inspection
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-5">
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          <div className="rounded-2xl bg-slate-50 p-4">
            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Forms</p>
            <p className="mt-2 text-2xl font-semibold text-slate-950">{htmlSecurity.forms.length}</p>
          </div>
          <div className="rounded-2xl bg-slate-50 p-4">
            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">External script domains</p>
            <p className="mt-2 text-2xl font-semibold text-slate-950">{htmlSecurity.externalScriptDomains.length}</p>
          </div>
          <div className="rounded-2xl bg-slate-50 p-4">
            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Inline scripts</p>
            <p className="mt-2 text-2xl font-semibold text-slate-950">{htmlSecurity.inlineScriptCount}</p>
          </div>
          <div className="rounded-2xl bg-slate-50 p-4">
            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Missing SRI</p>
            <p className="mt-2 text-2xl font-semibold text-slate-950">{htmlSecurity.missingSriScriptUrls.length}</p>
          </div>
        </div>

        {htmlSecurity.forms.length > 0 && (
          <div className="rounded-2xl bg-slate-50 p-4">
            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Forms</p>
            <div className="mt-3 space-y-2">
              {htmlSecurity.forms.map((form, index) => (
                <div key={`${form.action ?? "self"}-${index}`} className="rounded-xl bg-white p-3 text-sm text-slate-700">
                  <p>Method: {form.method}</p>
                  <p>Action: {form.action ?? "(same page)"}</p>
                  <div className="mt-2 flex flex-wrap gap-2">
                    {form.hasPasswordField && <Badge variant="secondary">Password field</Badge>}
                    {form.insecureSubmission && <Badge variant="destructive">Insecure submit</Badge>}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {(htmlSecurity.externalScriptDomains.length > 0 || htmlSecurity.externalStylesheetDomains.length > 0) && (
          <div className="grid gap-4 md:grid-cols-2">
            <div className="rounded-2xl bg-slate-50 p-4">
              <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Third-party scripts</p>
              <div className="mt-3 flex flex-wrap gap-2">
                {htmlSecurity.externalScriptDomains.map((domain) => (
                  <Badge key={domain} variant="outline">{domain}</Badge>
                ))}
              </div>
            </div>
            <div className="rounded-2xl bg-slate-50 p-4">
              <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Third-party stylesheets</p>
              <div className="mt-3 flex flex-wrap gap-2">
                {htmlSecurity.externalStylesheetDomains.map((domain) => (
                  <Badge key={domain} variant="outline">{domain}</Badge>
                ))}
              </div>
            </div>
          </div>
        )}

        <div className="space-y-2">
          {htmlSecurity.strengths.map((strength) => (
            <div key={strength} className="flex gap-3 rounded-2xl border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-900">
              <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0" />
              <span>{strength}</span>
            </div>
          ))}
          {htmlSecurity.issues.map((issue) => (
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
