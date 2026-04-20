import { BellRing } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { StatusAlert } from "@/components/ui/panel-primitives";
import { AnalysisResult, HistoryDiff } from "@/types/analysis";
import { getMonitoringAlerts } from "@/lib/priorities";

interface MonitoringPanelProps {
  analysis: AnalysisResult;
  diff: HistoryDiff | null;
}

const variantMap = {
  warning: "warning",
  info: "info",
} as const;

export const MonitoringPanel = ({ analysis, diff }: MonitoringPanelProps) => {
  const alerts = getMonitoringAlerts(analysis, diff);

  if (!alerts.length) {
    return null;
  }

  return (
    <Card className="rounded-[1.75rem] border-slate-200/80 bg-white/90 shadow-[0_10px_24px_-20px_rgba(15,23,42,0.35)]">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <BellRing className="h-5 w-5" />
          Monitoring Alerts
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        {alerts.map((alert) => (
          <StatusAlert
            key={`${alert.title}-${alert.detail}`}
            variant={variantMap[alert.severity]}
            className="py-4"
          >
            <div className="font-semibold">{alert.title}</div>
            <p className="mt-2 opacity-90">{alert.detail}</p>
          </StatusAlert>
        ))}
      </CardContent>
    </Card>
  );
};
