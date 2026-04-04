import { FolderSearch, ShieldAlert, ShieldCheck } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { getHttpStatusDetails } from "@/lib/httpStatus";
import { ExposureSummary } from "@/types/analysis";

interface ExposurePanelProps {
  exposure: ExposureSummary;
}

const findingStyles = {
  safe: "bg-emerald-100 text-emerald-900",
  interesting: "bg-amber-100 text-amber-900",
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
                  <div>
                    <p className="font-semibold text-slate-950">{probe.label}</p>
                    <p className="text-sm text-slate-500">{probe.path}</p>
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
            <div key={strength} className="flex gap-3 rounded-2xl border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-900">
              <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0" />
              <span>{strength}</span>
            </div>
          ))}
          {exposure.issues.map((issue) => (
            <div key={issue} className="flex gap-3 rounded-2xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-900">
              <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0" />
              <span>{issue}</span>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
};
