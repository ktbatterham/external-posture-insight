import { Download } from "lucide-react";
import { MonitoringPanel } from "@/components/MonitoringPanel";
import { PostureSummaryPanel } from "@/components/PostureSummaryPanel";
import { PriorityActionsPanel } from "@/components/PriorityActionsPanel";
import { Button } from "@/components/ui/button";
import { AnalysisResult, HistoryDiff, HistorySnapshot } from "@/types/analysis";
import { getHttpStatusDetails } from "@/lib/httpStatus";
import { sectionTitleClass } from "./ReportSectionHeader";

const trafficLightStyles = {
  strong: {
    ring: "border-[#7aa6b6]/45",
    pill: "bg-[#7aa6b6]",
    text: "text-[#d7e7ee]",
  },
  watch: {
    ring: "border-[#b56a2c]/45",
    pill: "bg-[#b56a2c]",
    text: "text-[#f0d5bc]",
  },
  weak: {
    ring: "border-[#8e5c3b]/45",
    pill: "bg-[#8e5c3b]",
    text: "text-[#e2c0a2]",
  },
} as const;

const healthcheckStyles = {
  strong: {
    tile: "border-[#7aa6b6]/35 bg-[#7aa6b6]/12",
    dot: "bg-[#7aa6b6]",
    grade: "text-[#d7e7ee]",
  },
  watch: {
    tile: "border-[#b56a2c]/35 bg-[#b56a2c]/12",
    dot: "bg-[#b56a2c]",
    grade: "text-[#f0d5bc]",
  },
  weak: {
    tile: "border-[#8e5c3b]/35 bg-[#8e5c3b]/12",
    dot: "bg-[#8e5c3b]",
    grade: "text-[#e2c0a2]",
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
  history: Array<HistorySnapshot & {
    areaScores?: Array<{
      key: string;
      label: string;
      score: number;
      status: "strong" | "watch" | "weak";
    }>;
  }>;
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
  compact?: boolean;
}

export const OverviewSection = ({
  analysisData,
  historyDiff,
  history,
  areaScores,
  exportPdf,
  exportMarkdown,
  exportHtml,
  exportReport,
  compact = false,
}: OverviewSectionProps) => {
  const healthcheckStyle = healthcheckStyles[healthcheckStatusForGrade(analysisData.grade)];

  return (
    <div id="overview" className="space-y-6">
      {analysisData.assessmentLimitation.limited ? (
        <div className="rounded-[1.75rem] border border-[#b56a2c]/35 bg-[#b56a2c]/12 px-5 py-4 text-[#f4dfcd]">
          <p className="text-xs font-semibold uppercase tracking-[0.18em] text-[#d89a63]">
            {analysisData.assessmentLimitation.title}
          </p>
          <p className="mt-2 text-sm leading-7 text-[#f0d5bc]/90">
            {analysisData.assessmentLimitation.detail}
          </p>
        </div>
      ) : null}

      <div className="space-y-4">
        <div className="rounded-[2rem] border border-white/10 bg-[linear-gradient(135deg,rgba(11,18,32,0.95),rgba(16,24,39,0.92))] px-6 py-6 shadow-[0_30px_80px_-48px_rgba(0,0,0,0.8)] ring-1 ring-white/[0.04]">
          <div className="grid gap-4 xl:grid-cols-[1.15fr_0.7fr_1.55fr] xl:items-start">
            <div>
              <p className={sectionTitleClass}>Target</p>
              <p className="mt-3 text-3xl font-semibold tracking-tight text-white">{analysisData.host}</p>
              <p className="mt-2 break-all text-sm text-slate-400">{analysisData.finalUrl}</p>
            </div>
            <div className="rounded-[1.5rem] border border-white/10 bg-white/[0.04] px-5 py-5 shadow-[0_18px_40px_-30px_rgba(0,0,0,0.75)]">
              <p className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-400">Analyst read</p>
              <p className={`mt-3 text-base text-slate-300 ${compact ? "line-clamp-3 leading-7" : "leading-8"}`}>
                {analysisData.executiveSummary.overview}
              </p>
            </div>
          </div>

          <div className="mt-5 grid gap-3 xl:grid-cols-[0.58fr_0.58fr_0.58fr_1.55fr]">
            <div className="rounded-[1.5rem] border border-white/10 bg-white/[0.04] px-5 py-5 shadow-[0_18px_40px_-30px_rgba(0,0,0,0.75)]">
              <p className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-400">Scan timestamp</p>
              <p className="mt-3 text-sm font-semibold leading-7 text-white">
                {new Date(analysisData.scannedAt).toLocaleString()}
              </p>
            </div>
            <div className="rounded-[1.5rem] border border-white/10 bg-white/[0.04] px-5 py-5 shadow-[0_18px_40px_-30px_rgba(0,0,0,0.75)]">
              <p className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-400">HTTP status</p>
              <p className="mt-3 text-3xl font-semibold tracking-tight text-white">{analysisData.statusCode}</p>
              <p className="mt-2 text-xs font-semibold uppercase tracking-[0.16em] text-slate-500">{getHttpStatusDetails(analysisData.statusCode).label}</p>
            </div>
            <div className="rounded-[1.5rem] border border-white/10 bg-white/[0.04] px-5 py-5 shadow-[0_18px_40px_-30px_rgba(0,0,0,0.75)]">
              <p className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-400">Response time</p>
              <p className="mt-3 text-3xl font-semibold tracking-tight text-white">{analysisData.responseTimeMs}ms</p>
            </div>
            <div className="rounded-[1.5rem] border border-white/10 bg-white/[0.04] px-5 py-5 shadow-[0_18px_40px_-30px_rgba(0,0,0,0.75)]">
              <p className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-400">Main visible risk</p>
              <p className="mt-3 text-base font-semibold leading-7 text-white">
                {analysisData.executiveSummary.mainRisk}
              </p>
            </div>
          </div>

          <div className="mt-5 border-t border-white/10 pt-5">
            <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
              <div className={`rounded-[1.5rem] border px-4 py-4 shadow-[0_18px_40px_-30px_rgba(0,0,0,0.75)] ${healthcheckStyle.tile}`}>
                <div className="flex items-center justify-between gap-3">
                  <p className="text-sm font-semibold text-white">Healthcheck</p>
                  <span className={`inline-flex h-3 w-3 rounded-full ${healthcheckStyle.dot}`} aria-hidden="true" />
                </div>
                <div className="mt-4 flex items-baseline gap-3">
                  <span className={`text-4xl font-semibold leading-none ${healthcheckStyle.grade}`}>{analysisData.grade}</span>
                  <span className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-400">
                    Overall grade
                  </span>
                </div>
              </div>
              {areaScores.map((area) => {
                const style = trafficLightStyles[area.status];
                return (
                  <div
                    key={area.key}
                    className={`rounded-[1.5rem] border border-white/10 bg-white/[0.04] px-4 py-4 shadow-[0_18px_40px_-30px_rgba(0,0,0,0.75)] ${style.ring}`}
                  >
                    <div className="flex items-center justify-between gap-3">
                      <p className="text-sm font-semibold text-white">{area.label}</p>
                      <span className={`inline-flex h-3 w-3 rounded-full ${style.pill}`} aria-hidden="true" />
                    </div>
                    <div className="mt-4 flex items-baseline gap-3">
                      <span className={`text-4xl font-semibold leading-none ${style.text}`}>{area.score}%</span>
                      <span className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-400">
                        {area.status}
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          <div className="mt-5 border-t border-white/10 pt-5">
            <div className="mx-auto grid max-w-4xl gap-3 sm:grid-cols-2 xl:grid-cols-4">
              <Button variant="outline" className="h-11 w-full justify-center rounded-2xl border-white/10 bg-white/[0.04] font-medium text-slate-100 hover:bg-white/[0.08]" onClick={exportPdf}>
                Export PDF
              </Button>
              <Button variant="outline" className="h-11 w-full justify-center rounded-2xl border-white/10 bg-white/[0.04] font-medium text-slate-100 hover:bg-white/[0.08]" onClick={exportMarkdown}>
                Export Markdown
              </Button>
              <Button variant="outline" className="h-11 w-full justify-center rounded-2xl border-white/10 bg-white/[0.04] font-medium text-slate-100 hover:bg-white/[0.08]" onClick={exportHtml}>
                Export HTML
              </Button>
              <Button variant="outline" className="h-11 w-full justify-center rounded-2xl border-white/10 bg-white/[0.04] font-medium text-slate-100 hover:bg-white/[0.08]" onClick={exportReport}>
                <Download className="mr-2 h-4 w-4" />
                Export JSON
              </Button>
            </div>
          </div>
        </div>
      </div>

      {!compact ? (
        <>
          <div className="space-y-4">
            <p className={sectionTitleClass}>Posture summary</p>
            <PostureSummaryPanel analysis={analysisData} />
          </div>

          <div className="space-y-4">
            <PriorityActionsPanel analysis={analysisData} />
            <MonitoringPanel analysis={analysisData} diff={historyDiff} history={history} />
          </div>
        </>
      ) : null}
    </div>
  );
};
