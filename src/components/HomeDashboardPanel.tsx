import { BellDot, Clock3, Radar } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

interface HomeDashboardPanelProps {
  monitoredCount: number;
  dueCount: number;
  lastScanAt: string | null;
}

export const HomeDashboardPanel = ({
  monitoredCount,
  dueCount,
  lastScanAt,
}: HomeDashboardPanelProps) => {
  return (
    <Card className="border-white/10 bg-white/[0.04] shadow-[0_24px_60px_-36px_rgba(0,0,0,0.65)] backdrop-blur">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-slate-50">
          <Radar className="h-5 w-5" />
          Monitoring Dashboard
        </CardTitle>
      </CardHeader>
      <CardContent className="grid gap-4 md:grid-cols-3">
        <div className="rounded-[1.25rem] border border-white/10 bg-white/[0.04] p-4">
          <div className="flex items-center gap-2 text-sm font-medium text-slate-400">
            <BellDot className="h-4 w-4" />
            Monitored
          </div>
          <div className="mt-3 text-3xl font-black text-slate-50">{monitoredCount}</div>
        </div>
        <div className="rounded-[1.25rem] border border-white/10 bg-white/[0.04] p-4">
          <div className="flex items-center gap-2 text-sm font-medium text-slate-400">
            <Clock3 className="h-4 w-4" />
            Due now
          </div>
          <div className="mt-3 text-3xl font-black text-slate-50">{dueCount}</div>
        </div>
        <div className="rounded-[1.25rem] border border-white/10 bg-white/[0.04] p-4">
          <p className="text-sm font-medium text-slate-400">Last local scan</p>
          <div className="mt-3 text-sm font-semibold leading-6 text-slate-50">
            {lastScanAt ? new Date(lastScanAt).toLocaleString() : "No scans yet"}
          </div>
        </div>
      </CardContent>
    </Card>
  );
};
