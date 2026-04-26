import { ReactNode } from "react";
import { Shield, ShieldAlert, ShieldCheck } from "lucide-react";

interface SecurityGradeProps {
  grade: string;
  score: number;
  summary: string;
  context?: ReactNode;
  actions?: ReactNode;
  pulse?: ReactNode;
}

const gradeStyles: Record<string, { text: string; ring: string; bg: string; iconShell: string }> = {
  "A+": { text: "text-[#f0d5bc]", ring: "ring-[#b56a2c]/35", bg: "from-[#181b23] to-[#11151d]", iconShell: "bg-white/[0.06]" },
  A: { text: "text-[#f0d5bc]", ring: "ring-[#b56a2c]/35", bg: "from-[#181b23] to-[#11151d]", iconShell: "bg-white/[0.06]" },
  B: { text: "text-[#e0b286]", ring: "ring-[#9b774f]/35", bg: "from-[#181b23] to-[#11151d]", iconShell: "bg-white/[0.06]" },
  C: { text: "text-[#d89a63]", ring: "ring-[#b56a2c]/35", bg: "from-[#181b23] to-[#11151d]", iconShell: "bg-white/[0.06]" },
  D: { text: "text-[#c78455]", ring: "ring-[#b56a2c]/45", bg: "from-[#181b23] to-[#11151d]", iconShell: "bg-white/[0.06]" },
  E: { text: "text-[#c78455]", ring: "ring-[#b56a2c]/45", bg: "from-[#181b23] to-[#11151d]", iconShell: "bg-white/[0.06]" },
  F: { text: "text-[#c78455]", ring: "ring-[#b56a2c]/45", bg: "from-[#181b23] to-[#11151d]", iconShell: "bg-white/[0.06]" },
  U: { text: "text-slate-200", ring: "ring-white/15", bg: "from-[#181b23] to-[#11151d]", iconShell: "bg-white/[0.06]" },
};

export const SecurityGrade = ({ grade, score, summary, context, actions, pulse }: SecurityGradeProps) => {
  const style = gradeStyles[grade] ?? gradeStyles.U;
  const icon =
    grade === "A+" || grade === "A" ? (
      <ShieldCheck className="h-12 w-12" />
    ) : grade === "B" || grade === "C" ? (
      <Shield className="h-12 w-12" />
    ) : (
      <ShieldAlert className="h-12 w-12" />
    );

  return (
    <div className={`w-full rounded-[2rem] border border-white/10 bg-gradient-to-br ${style.bg} px-6 py-6 shadow-[0_24px_60px_-36px_rgba(0,0,0,0.65)] ring-1 ${style.ring}`}>
      {context ? <div className="mb-5">{context}</div> : null}

      <div className="flex flex-col gap-5 lg:flex-row lg:items-center lg:justify-between">
        <div className="flex min-w-0 items-center gap-4">
          <div className={`flex h-16 w-16 shrink-0 items-center justify-center rounded-2xl ${style.iconShell} shadow-sm ${style.text}`}>
            {icon}
          </div>
          <div className="min-w-0">
            <p className="text-[11px] font-semibold uppercase tracking-[0.24em] text-slate-400">
              Healthcheck
            </p>
            <div className="mt-2 flex items-end gap-3">
              <h2 className={`text-5xl font-black leading-none ${style.text}`}>{grade}</h2>
              <p className="pb-1 text-xl font-semibold text-slate-300">{score}/100</p>
            </div>
          </div>
        </div>

        <p className="max-w-2xl text-sm leading-7 text-slate-300">{summary}</p>
      </div>

      {pulse ? <div className="mt-5 border-t border-white/10 pt-5">{pulse}</div> : null}

      {actions ? (
        <div className="mt-5 border-t border-white/10 pt-5">
          <p className="text-[11px] font-semibold uppercase tracking-[0.24em] text-slate-400">Export</p>
          <div className="mt-3 flex flex-wrap gap-3">{actions}</div>
        </div>
      ) : null}
    </div>
  );
};
