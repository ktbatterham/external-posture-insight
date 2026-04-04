import { BellRing } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { AnalysisResult, HistoryDiff } from "@/types/analysis";
import { getMonitoringAlerts } from "@/lib/priorities";

interface MonitoringPanelProps {
  analysis: AnalysisResult;
  diff: HistoryDiff | null;
}

const styles = {
  warning: "border-amber-200 bg-amber-50 text-amber-900",
  info: "border-sky-200 bg-sky-50 text-sky-900",
} as const;

export const MonitoringPanel = ({ analysis, diff }: MonitoringPanelProps) => {
  const alerts = getMonitoringAlerts(analysis, diff);

  if (!alerts.length) {
    return null;
  }

  return (
    <Card className="border-slate-200 shadow-sm">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <BellRing className="h-5 w-5" />
          Monitoring Alerts
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        {alerts.map((alert) => (
          <div key={`${alert.title}-${alert.detail}`} className={`rounded-2xl border px-4 py-4 text-sm ${styles[alert.severity]}`}>
            <div className="font-semibold">{alert.title}</div>
            <p className="mt-2 opacity-90">{alert.detail}</p>
          </div>
        ))}
      </CardContent>
    </Card>
  );
};
