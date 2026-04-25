import { FolderSearch, ShieldAlert, ShieldCheck } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { StatusAlert } from "@/components/ui/panel-primitives";
import { getHttpStatusDetails } from "@/lib/httpStatus";
import { ExposureSummary } from "@/types/analysis";

interface ExposurePanelProps {
  exposure: ExposureSummary;
}

const findingStyles = {
  safe: "bg-emerald-100 text-emerald-900",
  interesting: "bg-amber-100 text-amber-900",
  blocked: "bg-slate-200 text-slate-900",
  exposed: "bg-rose-100 text-rose-900",
  error: "bg-orange-100 text-orange-900",
} as const;

export const ExposurePanel = ({ exposure }: ExposurePanelProps) => {
  return (
    <Card className="border-slate-200 shadow-sm">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <FolderSearch className="h-5 w-5" />
          Low-Noise Exposure Checks
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid gap-3">
          {exposure.probes.map((probe) => {
            const status = probe.statusCode ? getHttpStatusDetails(probe.statusCode) : null;
            return (
              <div key={probe.path} className="rounded-2xl border border-slate-200 bg-white p-4">
                <div className="flex flex-col gap-2 md:flex-row md:items-center md:justify-between">
                  <div className="min-w-0">
                    <p className="font-semibold text-slate-950">{probe.label}</p>
                    <p className="truncate text-sm text-slate-500" title={probe.path}>{probe.path}</p>
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge variant="secondary" className={findingStyles[probe.finding]}>
                      {probe.finding}
                    </Badge>
                    <span className="text-sm font-semibold text-slate-700">
                      {probe.statusCode ? `${probe.statusCode} ${status?.label}` : "n/a"}
                    </span>
                  </div>
                </div>
                <p className="mt-3 text-sm text-slate-600">{probe.detail}</p>
                {status ? (
                  <p className="mt-1 text-xs leading-5 text-slate-500">
                    {status.meaning}
                  </p>
                ) : null}
              </div>
            );
          })}
        </div>

        <div className="space-y-2">
          {exposure.strengths.map((strength) => (
            <StatusAlert key={strength} variant="success" icon={<ShieldCheck />}>{strength}</StatusAlert>
          ))}
          {exposure.issues.map((issue) => (
            <StatusAlert key={issue} variant="critical" icon={<ShieldAlert />}>{issue}</StatusAlert>
          ))}
        </div>
      </CardContent>
    </Card>
  );
};
