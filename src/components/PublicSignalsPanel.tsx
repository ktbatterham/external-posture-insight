import { Radar } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { StatusAlert } from "@/components/ui/panel-primitives";
import { PublicSignalsInfo } from "@/types/analysis";

interface PublicSignalsPanelProps {
  publicSignals: PublicSignalsInfo;
}

const statusStyles = {
  preloaded: "bg-emerald-100 text-emerald-900",
  pending: "bg-sky-100 text-sky-900",
  eligible: "bg-amber-100 text-amber-900",
  not_preloaded: "bg-slate-200 text-slate-800",
  unknown: "bg-slate-200 text-slate-800",
} as const;

const formatStatus = (status: PublicSignalsInfo["hstsPreload"]["status"]) =>
  status
    .split("_")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");

export const PublicSignalsPanel = ({ publicSignals }: PublicSignalsPanelProps) => {
  return (
    <Card className="h-full border-slate-200 shadow-sm">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Radar className="h-5 w-5" />
          Public Trust Signals
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="min-w-0 rounded-2xl bg-slate-50 p-4">
          <div className="flex items-center justify-between gap-3">
            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">HSTS preload dataset</p>
            <span className={`rounded-full px-2.5 py-1 text-xs font-semibold ${statusStyles[publicSignals.hstsPreload.status]}`}>
              {formatStatus(publicSignals.hstsPreload.status)}
            </span>
          </div>
          <p className="mt-3 overflow-hidden break-words text-sm leading-6 text-slate-700">{publicSignals.hstsPreload.summary}</p>
          <a
            href={publicSignals.hstsPreload.sourceUrl}
            target="_blank"
            rel="noreferrer"
            className="mt-3 inline-flex text-sm font-medium text-sky-700 hover:text-sky-900"
          >
            Open dataset reference
          </a>
        </div>

        <div className="space-y-2">
          {publicSignals.strengths.map((strength) => (
            <StatusAlert key={strength} variant="success">{strength}</StatusAlert>
          ))}
          {publicSignals.issues.map((issue) => (
            <StatusAlert key={issue} variant="warning">{issue}</StatusAlert>
          ))}
        </div>
      </CardContent>
    </Card>
  );
};
