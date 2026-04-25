import { FormInput, ShieldAlert } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { StatBox, StatusAlert, TruncatedChip } from "@/components/ui/panel-primitives";
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
          <StatBox label="Public forms" value={<p className="text-2xl font-semibold">{summary.totalForms}</p>} />
          <StatBox label="POST forms" value={<p className="text-2xl font-semibold">{summary.postForms}</p>} />
          <StatBox label="External submit targets" value={<p className="text-2xl font-semibold">{summary.externalForms.length}</p>} />
          <StatBox label="Insecure submits" value={<p className="text-2xl font-semibold">{summary.insecureForms}</p>} />
        </div>

        {summary.externalForms.length ? (
          <StatBox
            label="External submission targets"
            value={
              <div className="flex flex-wrap gap-2">
                {summary.externalForms.map((action) => (
                  <TruncatedChip key={action} value={action} />
                ))}
              </div>
            }
          />
        ) : null}

        {(summary.externalForms.length || summary.insecureForms) ? (
          <StatusAlert variant="warning" icon={<ShieldAlert />}>
            Public forms that post off-origin or without HTTPS deserve a quick trust review, especially on contact,
            support, or account-related flows.
          </StatusAlert>
        ) : null}
      </CardContent>
    </Card>
  );
};
