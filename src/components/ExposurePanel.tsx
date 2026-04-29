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
  safe: "bg-white/[0.08] text-slate-100",
  interesting: "bg-[#8e5c3b]/14 text-[#f0d5bc]",
  blocked: "bg-white/[0.08] text-slate-100",
  exposed: "bg-[#b56a2c]/16 text-[#f0d5bc]",
  error: "bg-[#b56a2c]/18 text-[#f0d5bc]",
} as const;

export const ExposurePanel = ({ exposure }: ExposurePanelProps) => {
  return (
    <Card className="border-white/10 bg-white/[0.04] shadow-[0_24px_60px_-36px_rgba(0,0,0,0.65)]">
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
              <div key={probe.path} className="rounded-[1.25rem] border border-white/10 bg-white/[0.04] p-4">
                <div className="flex flex-col gap-2 md:flex-row md:items-center md:justify-between">
                  <div className="min-w-0">
                    <p className="font-semibold text-slate-50">{probe.label}</p>
                    <p className="truncate text-sm text-slate-400" title={probe.path}>{probe.path}</p>
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge variant="secondary" className={findingStyles[probe.finding]}>
                      {probe.finding}
                    </Badge>
                    <span className="text-sm font-semibold text-slate-200">
                      {probe.statusCode ? `${probe.statusCode} ${status?.label}` : "n/a"}
                    </span>
                  </div>
                </div>
                <p className="mt-3 text-sm text-slate-300">{probe.detail}</p>
                {status ? (
                  <p className="mt-1 text-xs leading-5 text-slate-400">
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
