import { FormInput, ShieldAlert } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { getDataCollectionSummary } from "@/lib/passiveSurface";
import { HtmlSecurityInfo } from "@/types/analysis";

interface DataCollectionPanelProps {
  htmlSecurity: HtmlSecurityInfo;
}

export const DataCollectionPanel = ({ htmlSecurity }: DataCollectionPanelProps) => {
  const summary = getDataCollectionSummary(htmlSecurity);

  if (!summary.totalForms) {
    return null;
  }

  return (
    <Card className="border-slate-200 shadow-sm">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <FormInput className="h-5 w-5" />
          Data Collection Surface
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-5">
        <p className="text-sm leading-6 text-slate-600">{summary.summary}</p>

        <div className="grid gap-4 md:grid-cols-4">
          <div className="rounded-2xl bg-slate-50 p-4">
            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Public forms</p>
            <p className="mt-2 text-2xl font-semibold text-slate-950">{summary.totalForms}</p>
          </div>
          <div className="rounded-2xl bg-slate-50 p-4">
            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">POST forms</p>
            <p className="mt-2 text-2xl font-semibold text-slate-950">{summary.postForms}</p>
          </div>
          <div className="rounded-2xl bg-slate-50 p-4">
            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">External submit targets</p>
            <p className="mt-2 text-2xl font-semibold text-slate-950">{summary.externalForms.length}</p>
          </div>
          <div className="rounded-2xl bg-slate-50 p-4">
            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Insecure submits</p>
            <p className="mt-2 text-2xl font-semibold text-slate-950">{summary.insecureForms}</p>
          </div>
        </div>

        {summary.externalForms.length ? (
          <div className="rounded-2xl bg-slate-50 p-4">
            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">External submission targets</p>
            <div className="mt-3 flex flex-wrap gap-2">
              {summary.externalForms.map((action) => (
                <Badge key={action} variant="outline">
                  {action}
                </Badge>
              ))}
            </div>
          </div>
        ) : null}

        {(summary.externalForms.length || summary.insecureForms) ? (
          <div className="flex gap-3 rounded-2xl border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-900">
            <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0" />
            <span>
              Public forms that post off-origin or without HTTPS deserve a quick trust review, especially on contact,
              support, or account-related flows.
            </span>
          </div>
        ) : null}
      </CardContent>
    </Card>
  );
};
