import { BellDot, Clock3, Play, Trash2 } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

export interface MonitoredTargetView {
  url: string;
  label: string;
  cadence: "daily" | "weekly";
  lastScannedAt: string | null;
  nextDueAt: string;
  due: boolean;
}

interface MonitoredTargetsPanelProps {
  targets: MonitoredTargetView[];
  currentUrl: string | null;
  monitoredCount: number;
  dueCount: number;
  embedded?: boolean;
  onAddDaily: () => void;
  onAddWeekly: () => void;
  onRunDue: () => void;
  onRunTarget: (url: string) => void;
  onRemove: (url: string) => void;
  busy: boolean;
}

export const MonitoredTargetsPanel = ({
  targets,
  currentUrl,
  monitoredCount,
  dueCount,
  embedded = false,
  onAddDaily,
  onAddWeekly,
  onRunDue,
  onRunTarget,
  onRemove,
  busy,
}: MonitoredTargetsPanelProps) => {
  return (
    <Card className={embedded ? "border-white/70 bg-white/60 shadow-sm" : "border-slate-200 shadow-sm"}>
      <CardHeader className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
        <div className="space-y-2">
          <CardTitle className="flex items-center gap-2">
            <BellDot className="h-5 w-5" />
            Monitoring Targets
          </CardTitle>
          <p className="max-w-2xl text-sm text-slate-500">
            Monitoring runs in this browser only. Saved targets and history persist locally, but due scans do not run in the background after you close the tab.
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <Button variant="outline" className="rounded-2xl" disabled={!currentUrl || busy} onClick={onAddDaily}>
            Monitor Daily
          </Button>
          <Button variant="outline" className="rounded-2xl" disabled={!currentUrl || busy} onClick={onAddWeekly}>
            Monitor Weekly
          </Button>
          <Button className="rounded-2xl" disabled={!targets.some((target) => target.due) || busy} onClick={onRunDue}>
            Run Due Scans
          </Button>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid gap-4 md:grid-cols-3">
          <div className="rounded-2xl border border-slate-200 bg-white px-4 py-3 shadow-sm">
            <div className="flex items-center gap-2 text-sm font-medium text-slate-500">
              <BellDot className="h-4 w-4" />
              Monitored
            </div>
            <div className="mt-2 text-2xl font-black text-slate-950">{monitoredCount}</div>
          </div>
          <div className="rounded-2xl border border-slate-200 bg-white px-4 py-3 shadow-sm">
            <div className="flex items-center gap-2 text-sm font-medium text-slate-500">
              <Clock3 className="h-4 w-4" />
              Due now
            </div>
            <div className="mt-2 text-2xl font-black text-slate-950">{dueCount}</div>
          </div>
          <div className="rounded-2xl border border-slate-200 bg-white px-4 py-3 shadow-sm">
            <p className="text-sm font-medium text-slate-500">Save current site</p>
            <div className="mt-3 flex flex-wrap gap-2">
              <Button
                variant="outline"
                className="h-9 rounded-2xl px-3 text-xs"
                disabled={!currentUrl || busy}
                onClick={onAddDaily}
              >
                Daily
              </Button>
              <Button
                variant="outline"
                className="h-9 rounded-2xl px-3 text-xs"
                disabled={!currentUrl || busy}
                onClick={onAddWeekly}
              >
                Weekly
              </Button>
            </div>
            {!currentUrl ? (
              <p className="mt-3 text-xs text-slate-400">Run or reopen a scan first.</p>
            ) : null}
          </div>
        </div>

        {targets.length ? (
          <div className={`grid gap-3 ${embedded ? "md:grid-cols-3" : ""}`}>
            {targets.map((target) => (
              <div key={target.url} className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm">
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <p className="truncate text-sm font-semibold text-slate-950">{target.label}</p>
                      <Badge
                        variant="secondary"
                        className={target.due ? "bg-amber-100 text-amber-900" : "bg-slate-200 text-slate-800"}
                      >
                        {target.due ? "due" : "scheduled"}
                      </Badge>
                    </div>
                    <p className="mt-2 truncate text-xs text-slate-500">{target.url}</p>
                    <div className="mt-3 flex flex-wrap items-center gap-2 text-xs text-slate-500">
                      <Badge variant="outline" className="rounded-full">
                        {target.cadence}
                      </Badge>
                      <span>Next: {new Date(target.nextDueAt).toLocaleDateString()}</span>
                    </div>
                    {!embedded ? (
                      <div className="mt-3 flex flex-wrap gap-4 text-xs text-slate-500">
                        <span className="inline-flex items-center gap-1">
                          <Clock3 className="h-3.5 w-3.5" />
                          Last: {target.lastScannedAt ? new Date(target.lastScannedAt).toLocaleString() : "Not yet run"}
                        </span>
                      </div>
                    ) : null}
                  </div>
                </div>
                <div className="mt-3 flex gap-2">
                  <Button
                    variant="outline"
                    className="h-9 flex-1 rounded-2xl px-3 text-xs"
                    disabled={busy}
                    onClick={() => onRunTarget(target.url)}
                  >
                    <Play className="mr-1.5 h-3.5 w-3.5" />
                    Run
                  </Button>
                  <Button
                    variant="outline"
                    className="h-9 rounded-2xl px-3 text-xs"
                    disabled={busy}
                    onClick={() => onRemove(target.url)}
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                  </Button>
                </div>
              </div>
            ))}
          </div>
        ) : null}
      </CardContent>
    </Card>
  );
};
