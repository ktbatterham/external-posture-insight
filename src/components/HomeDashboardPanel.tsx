import { BellDot, Clock3, History, Radar } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

interface HomeDashboardPanelProps {
  monitoredCount: number;
  dueCount: number;
  recentCount: number;
  lastScanAt: string | null;
}

export const HomeDashboardPanel = ({
  monitoredCount,
  dueCount,
  recentCount,
  lastScanAt,
}: HomeDashboardPanelProps) => {
  return (
    <Card className="border-slate-200 bg-white/80 shadow-lg shadow-slate-200/40 backdrop-blur">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-slate-950">
          <Radar className="h-5 w-5" />
          Monitoring Dashboard
        </CardTitle>
      </CardHeader>
      <CardContent className="grid gap-4 md:grid-cols-4">
        <div className="rounded-2xl bg-slate-50 p-4">
          <div className="flex items-center gap-2 text-sm font-medium text-slate-500">
            <BellDot className="h-4 w-4" />
            Monitored
          </div>
          <div className="mt-3 text-3xl font-black text-slate-950">{monitoredCount}</div>
        </div>
        <div className="rounded-2xl bg-slate-50 p-4">
          <div className="flex items-center gap-2 text-sm font-medium text-slate-500">
            <Clock3 className="h-4 w-4" />
            Due now
          </div>
          <div className="mt-3 text-3xl font-black text-slate-950">{dueCount}</div>
        </div>
        <div className="rounded-2xl bg-slate-50 p-4">
          <div className="flex items-center gap-2 text-sm font-medium text-slate-500">
            <History className="h-4 w-4" />
            Recent scans
          </div>
          <div className="mt-3 text-3xl font-black text-slate-950">{recentCount}</div>
        </div>
        <div className="rounded-2xl bg-slate-50 p-4">
          <p className="text-sm font-medium text-slate-500">Last local scan</p>
          <div className="mt-3 text-sm font-semibold leading-6 text-slate-950">
            {lastScanAt ? new Date(lastScanAt).toLocaleString() : "No scans yet"}
          </div>
        </div>
      </CardContent>
    </Card>
  );
};
