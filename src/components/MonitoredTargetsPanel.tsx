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
  onAddDaily,
  onAddWeekly,
  onRunDue,
  onRunTarget,
  onRemove,
  busy,
}: MonitoredTargetsPanelProps) => {
  return (
    <Card className="border-slate-200 shadow-sm">
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
        {targets.length ? (
          <div className="grid gap-3">
            {targets.map((target) => (
              <div key={target.url} className="rounded-2xl border border-slate-200 bg-white p-4">
                <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
                  <div>
                    <div className="flex flex-wrap items-center gap-2">
                      <p className="font-semibold text-slate-950">{target.label}</p>
                      <Badge variant="secondary" className={target.due ? "bg-amber-100 text-amber-900" : "bg-slate-200 text-slate-800"}>
                        {target.due ? "due" : "scheduled"}
                      </Badge>
                      <Badge variant="outline">{target.cadence}</Badge>
                    </div>
                    <p className="mt-2 text-sm text-slate-500">{target.url}</p>
                    <div className="mt-3 flex flex-wrap gap-4 text-xs text-slate-500">
                      <span className="inline-flex items-center gap-1">
                        <Clock3 className="h-3.5 w-3.5" />
                        Last: {target.lastScannedAt ? new Date(target.lastScannedAt).toLocaleString() : "Not yet run"}
                      </span>
                      <span>Next due: {new Date(target.nextDueAt).toLocaleString()}</span>
                    </div>
                  </div>
                  <div className="flex gap-2">
                    <Button variant="outline" className="rounded-2xl" disabled={busy} onClick={() => onRunTarget(target.url)}>
                      <Play className="mr-2 h-4 w-4" />
                      Run now
                    </Button>
                    <Button variant="outline" className="rounded-2xl" disabled={busy} onClick={() => onRemove(target.url)}>
                      <Trash2 className="mr-2 h-4 w-4" />
                      Remove
                    </Button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="rounded-2xl border border-dashed border-slate-300 bg-slate-50 px-4 py-6 text-sm text-slate-500">
            Save the current site as a daily or weekly monitoring target to keep an eye on regressions over time.
          </div>
        )}
      </CardContent>
    </Card>
  );
};
