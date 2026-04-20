import { Download } from "lucide-react";
import { MonitoringPanel } from "@/components/MonitoringPanel";
import { PostureSummaryPanel } from "@/components/PostureSummaryPanel";
import { PriorityActionsPanel } from "@/components/PriorityActionsPanel";
import { Button } from "@/components/ui/button";
import { AnalysisResult, HistoryDiff } from "@/types/analysis";
import { getHttpStatusDetails } from "@/lib/httpStatus";
import { sectionTitleClass } from "./ReportSectionHeader";

const trafficLightStyles = {
  strong: {
    ring: "border-emerald-300/80",
    pill: "bg-emerald-600",
    text: "text-emerald-900",
  },
  watch: {
    ring: "border-amber-300/80",
    pill: "bg-amber-500",
    text: "text-amber-900",
  },
  weak: {
    ring: "border-rose-300/80",
    pill: "bg-rose-600",
    text: "text-rose-900",
  },
} as const;

const panelRaisedTileClass =
  "rounded-[1.5rem] border border-amber-200/60 bg-amber-50/90 px-5 py-5 shadow-[0_8px_18px_-14px_rgba(15,23,42,0.35),0_1px_0_rgba(255,255,255,0.65)_inset]";
const panelMetricValueClass = "mt-3 text-3xl font-semibold tracking-tight text-slate-950";
const panelMetricHintClass = "mt-2 text-xs font-semibold uppercase tracking-[0.16em] text-slate-500";

const healthcheckStyles = {
  strong: {
    tile: "border-emerald-300/70 bg-emerald-50/85",
    dot: "bg-emerald-600",
    grade: "text-emerald-700",
  },
  watch: {
    tile: "border-amber-300/70 bg-amber-50/85",
    dot: "bg-amber-500",
    grade: "text-amber-700",
  },
  weak: {
    tile: "border-rose-300/70 bg-rose-50/85",
    dot: "bg-rose-600",
    grade: "text-rose-700",
  },
} as const;

const healthcheckStatusForGrade = (grade: string): keyof typeof healthcheckStyles => {
  const normalized = grade.trim().toUpperCase();
  if (normalized === "A" || normalized === "B") return "strong";
  if (normalized === "C") return "watch";
  return "weak";
};

interface OverviewSectionProps {
  analysisData: AnalysisResult;
  historyDiff: HistoryDiff | null;
  areaScores: Array<{
    key: string;
    label: string;
    score: number;
    status: keyof typeof trafficLightStyles;
  }>;
  exportPdf: () => void;
  exportMarkdown: () => void;
  exportHtml: () => void;
  exportReport: () => void;
}

export const OverviewSection = ({
  analysisData,
  historyDiff,
  areaScores,
  exportPdf,
  exportMarkdown,
  exportHtml,
  exportReport,
}: OverviewSectionProps) => {
  const healthcheckStyle = healthcheckStyles[healthcheckStatusForGrade(analysisData.grade)];

  return (
    <div id="overview" className="space-y-6">
      {analysisData.assessmentLimitation.limited ? (
        <div className="rounded-[1.75rem] border border-amber-200 bg-amber-50 px-5 py-4 text-amber-950">
          <p className="text-xs font-semibold uppercase tracking-[0.18em] text-amber-700">
            {analysisData.assessmentLimitation.title}
          </p>
          <p className="mt-2 text-sm leading-7 text-amber-900">
            {analysisData.assessmentLimitation.detail}
          </p>
        </div>
      ) : null}

      <div className="space-y-4">
        <div className="rounded-[2rem] border border-amber-200 bg-gradient-to-br from-amber-50 to-white px-6 py-6 shadow-sm ring-1 ring-amber-200">
          <div className="grid gap-4 xl:grid-cols-[1.15fr_0.7fr_1.55fr] xl:items-start">
            <div>
              <p className={sectionTitleClass}>Target</p>
              <p className="mt-3 text-3xl font-semibold tracking-tight text-slate-950">{analysisData.host}</p>
              <p className="mt-2 break-all text-sm text-slate-500">{analysisData.finalUrl}</p>
            </div>
            <div className={panelRaisedTileClass}>
              <p className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">Scan timestamp</p>
              <p className="mt-3 text-sm font-semibold text-slate-950">
                {new Date(analysisData.scannedAt).toLocaleString()}
              </p>
            </div>

            <div className={panelRaisedTileClass}>
              <p className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">Analyst read</p>
              <p className="mt-3 text-base leading-8 text-slate-700">
                {analysisData.executiveSummary.overview}
              </p>
            </div>
          </div>

          <div className="mt-5 grid gap-3 xl:grid-cols-[0.58fr_0.58fr_0.58fr_1.55fr]">
            <div className={panelRaisedTileClass}>
              <p className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">Overall posture</p>
              <p className={`${panelMetricValueClass} capitalize`}>{analysisData.executiveSummary.posture}</p>
            </div>
            <div className={panelRaisedTileClass}>
              <p className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">HTTP status</p>
              <p className={panelMetricValueClass}>{analysisData.statusCode}</p>
              <p className={panelMetricHintClass}>{getHttpStatusDetails(analysisData.statusCode).label}</p>
            </div>
            <div className={panelRaisedTileClass}>
              <p className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">Response time</p>
              <p className={panelMetricValueClass}>{analysisData.responseTimeMs}ms</p>
            </div>
            <div className={panelRaisedTileClass}>
              <p className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">Main visible risk</p>
              <p className="mt-3 text-base font-semibold leading-7 text-slate-950">
                {analysisData.executiveSummary.mainRisk}
              </p>
            </div>
          </div>

          <div className="mt-5 border-t border-white/80 pt-5">
            <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
              <div className={`rounded-[1.5rem] border px-4 py-4 shadow-[0_8px_18px_-14px_rgba(15,23,42,0.35),0_1px_0_rgba(255,255,255,0.65)_inset] ${healthcheckStyle.tile}`}>
                <div className="flex items-center justify-between gap-3">
                  <p className="text-sm font-semibold text-slate-900">Healthcheck</p>
                  <span className={`inline-flex h-3 w-3 rounded-full ${healthcheckStyle.dot}`} aria-hidden="true" />
                </div>
                <div className="mt-4 flex items-baseline gap-3">
                  <span className={`text-4xl font-semibold leading-none ${healthcheckStyle.grade}`}>{analysisData.grade}</span>
                  <span className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">
                    Overall grade
                  </span>
                </div>
              </div>
              {areaScores.map((area) => {
                const style = trafficLightStyles[area.status];
                return (
                  <div
                    key={area.key}
                    className={`rounded-[1.5rem] border border-amber-200/60 bg-amber-50/90 px-4 py-4 shadow-[0_8px_18px_-14px_rgba(15,23,42,0.35),0_1px_0_rgba(255,255,255,0.65)_inset] ${style.ring}`}
                  >
                    <div className="flex items-center justify-between gap-3">
                      <p className="text-sm font-semibold text-slate-900">{area.label}</p>
                      <span className={`inline-flex h-3 w-3 rounded-full ${style.pill}`} aria-hidden="true" />
                    </div>
                    <div className="mt-4 flex items-baseline gap-3">
                      <span className={`text-4xl font-semibold leading-none ${style.text}`}>{area.score}%</span>
                      <span className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">
                        {area.status}
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          <div className="mt-5 border-t border-white/80 pt-5">
            <div className="mx-auto grid max-w-4xl gap-3 sm:grid-cols-2 xl:grid-cols-4">
              <Button variant="outline" className="h-11 w-full justify-center rounded-2xl font-medium" onClick={exportPdf}>
                Export PDF
              </Button>
              <Button variant="outline" className="h-11 w-full justify-center rounded-2xl font-medium" onClick={exportMarkdown}>
                Export Markdown
              </Button>
              <Button variant="outline" className="h-11 w-full justify-center rounded-2xl font-medium" onClick={exportHtml}>
                Export HTML
              </Button>
              <Button variant="outline" className="h-11 w-full justify-center rounded-2xl font-medium" onClick={exportReport}>
                <Download className="mr-2 h-4 w-4" />
                Export JSON
              </Button>
            </div>
          </div>
        </div>
      </div>

      <div className="space-y-4">
        <p className={sectionTitleClass}>Posture summary</p>
        <PostureSummaryPanel analysis={analysisData} />
      </div>

      <div className="space-y-4">
        <PriorityActionsPanel analysis={analysisData} />
        <MonitoringPanel analysis={analysisData} diff={historyDiff} />
      </div>
    </div>
  );
};
