import { BellRing, Minus, TrendingDown, TrendingUp } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { StatusAlert } from "@/components/ui/panel-primitives";
import { AnalysisResult, HistoryDiff, HistorySnapshot } from "@/types/analysis";
import { getMonitoringAlerts } from "@/lib/priorities";
import { getAreaScores } from "@/lib/posture";

interface MonitoringPanelProps {
  analysis: AnalysisResult;
  diff: HistoryDiff | null;
  history: Array<HistorySnapshot & {
    areaScores?: Array<{
      key: string;
      label: string;
      score: number;
      status: "strong" | "watch" | "weak";
    }>;
  }>;
}

const variantMap = {
  warning: "warning",
  info: "info",
} as const;

export const MonitoringPanel = ({ analysis, diff, history }: MonitoringPanelProps) => {
  const alerts = getMonitoringAlerts(analysis, diff);
  const scoreSeries = history
    .slice(0, 7)
    .reverse()
    .map((snapshot) => snapshot.score);
  const latestScore = scoreSeries.at(-1) ?? analysis.score;
  const firstScore = scoreSeries[0] ?? analysis.score;
  const trendDelta = latestScore - firstScore;
  const trendDirection = trendDelta > 1 ? "up" : trendDelta < -1 ? "down" : "flat";

  const currentAreaScores = getAreaScores(analysis);
  const previousAreaScores = history[1]?.areaScores ?? null;
  const areaDeltas = previousAreaScores
    ? currentAreaScores
        .map((area) => {
          const previousArea = previousAreaScores.find((item) => item.key === area.key);
          const delta = previousArea ? area.score - previousArea.score : 0;
          return { label: area.label, delta };
        })
        .filter((item) => item.delta !== 0)
        .sort((left, right) => Math.abs(right.delta) - Math.abs(left.delta))
        .slice(0, 3)
    : [];

  const sparklinePoints = (() => {
    if (scoreSeries.length < 2) {
      return "";
    }
    const width = 180;
    const height = 44;
    const max = Math.max(...scoreSeries);
    const min = Math.min(...scoreSeries);
    const range = Math.max(max - min, 1);
    return scoreSeries
      .map((score, index) => {
        const x = (index / (scoreSeries.length - 1)) * width;
        const y = height - ((score - min) / range) * height;
        return `${x.toFixed(2)},${y.toFixed(2)}`;
      })
      .join(" ");
  })();

  if (!alerts.length && scoreSeries.length === 0) {
    return null;
  }

  return (
    <Card className="rounded-[1.75rem] border-white/10 bg-white/[0.04] shadow-[0_24px_60px_-36px_rgba(0,0,0,0.65)]">
      <CardHeader className="pb-2">
        <CardTitle className="flex items-center gap-2">
          <BellRing className="h-5 w-5" />
          Monitoring Alerts
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {scoreSeries.length >= 2 ? (
          <div className="rounded-[1.35rem] border border-white/10 bg-white/[0.04] px-4 py-4 shadow-[0_12px_30px_-18px_rgba(0,0,0,0.55)]">
            <div className="flex items-center justify-between gap-3">
              <p className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-400">Score trend (last {scoreSeries.length} scans)</p>
              <div className="flex items-center gap-1 text-sm font-semibold text-slate-200">
                {trendDirection === "up" ? <TrendingUp className="h-4 w-4 text-[#e0b286]" /> : null}
                {trendDirection === "down" ? <TrendingDown className="h-4 w-4 text-[#c78455]" /> : null}
                {trendDirection === "flat" ? <Minus className="h-4 w-4 text-slate-400" /> : null}
                <span>
                  {trendDirection === "up" ? "Improving" : trendDirection === "down" ? "Degrading" : "Stable"}
                </span>
              </div>
            </div>
            <div className="mt-3 flex items-center justify-between gap-3">
              <svg
                viewBox="0 0 180 44"
                className="h-11 w-full max-w-[220px]"
                role="img"
                aria-label="Security score trend sparkline"
              >
                <polyline
                  fill="none"
                  stroke={trendDirection === "down" ? "#c78455" : trendDirection === "up" ? "#e0b286" : "#64748b"}
                  strokeWidth="2.5"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  points={sparklinePoints}
                />
              </svg>
              <p className="text-sm font-semibold text-slate-200">
                {trendDelta > 0 ? "+" : ""}
                {trendDelta} over window
              </p>
            </div>
            {areaDeltas.length ? (
              <div className="mt-3 border-t border-white/10 pt-3 text-xs text-slate-400">
                {areaDeltas.map((item) => (
                  <p key={item.label}>
                    {item.label}: {item.delta > 0 ? "+" : ""}
                    {item.delta} vs previous scan
                  </p>
                ))}
              </div>
            ) : null}
          </div>
        ) : (
          <div className="rounded-[1.35rem] border border-white/10 bg-white/[0.04] px-4 py-4 shadow-[0_12px_30px_-18px_rgba(0,0,0,0.55)]">
            <p className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-400">Score trend</p>
            <p className="mt-2 text-sm leading-6 text-slate-300">
              {scoreSeries.length === 1
                ? "One saved scan recorded. Trend will appear after the next scan."
                : "Trend will appear after at least two saved scans for this target."}
            </p>
          </div>
        )}
        {alerts.map((alert) => (
          <StatusAlert
            key={`${alert.title}-${alert.detail}`}
            variant={variantMap[alert.severity]}
            className="py-4"
          >
            <div className="font-semibold">{alert.title}</div>
            <p className="mt-2 text-sm leading-6 opacity-90">{alert.detail}</p>
          </StatusAlert>
        ))}
      </CardContent>
    </Card>
  );
};
