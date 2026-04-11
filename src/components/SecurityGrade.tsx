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

const gradeStyles: Record<string, { text: string; ring: string; bg: string }> = {
  "A+": { text: "text-emerald-700", ring: "ring-emerald-200", bg: "from-emerald-50 to-white" },
  A: { text: "text-emerald-700", ring: "ring-emerald-200", bg: "from-emerald-50 to-white" },
  B: { text: "text-amber-700", ring: "ring-amber-200", bg: "from-amber-50 to-white" },
  C: { text: "text-orange-700", ring: "ring-orange-200", bg: "from-orange-50 to-white" },
  D: { text: "text-rose-700", ring: "ring-rose-200", bg: "from-rose-50 to-white" },
  F: { text: "text-rose-700", ring: "ring-rose-200", bg: "from-rose-50 to-white" },
};

export const SecurityGrade = ({ grade, score, summary, context, actions, pulse }: SecurityGradeProps) => {
  const style = gradeStyles[grade] ?? gradeStyles.F;
  const icon =
    grade === "A+" || grade === "A" ? (
      <ShieldCheck className="h-12 w-12" />
    ) : grade === "B" || grade === "C" ? (
      <Shield className="h-12 w-12" />
    ) : (
      <ShieldAlert className="h-12 w-12" />
    );

  return (
    <div className={`w-full rounded-[2rem] border bg-gradient-to-br ${style.bg} px-6 py-6 shadow-sm ring-1 ${style.ring}`}>
      {context ? <div className="mb-5">{context}</div> : null}

      <div className="flex flex-col gap-5 lg:flex-row lg:items-center lg:justify-between">
        <div className="flex min-w-0 items-center gap-4">
          <div className={`flex h-16 w-16 shrink-0 items-center justify-center rounded-2xl bg-white shadow-sm ${style.text}`}>
            {icon}
          </div>
          <div className="min-w-0">
            <p className="text-[11px] font-semibold uppercase tracking-[0.24em] text-slate-500">
              Healthcheck
            </p>
            <div className="mt-2 flex items-end gap-3">
              <h2 className={`text-5xl font-black leading-none ${style.text}`}>{grade}</h2>
              <p className="pb-1 text-xl font-semibold text-slate-600">{score}/100</p>
            </div>
          </div>
        </div>

        <p className="max-w-2xl text-sm leading-7 text-slate-600">{summary}</p>
      </div>

      {pulse ? <div className="mt-5 border-t border-white/80 pt-5">{pulse}</div> : null}

      {actions ? (
        <div className="mt-5 border-t border-white/80 pt-5">
          <p className="text-[11px] font-semibold uppercase tracking-[0.24em] text-slate-500">Export</p>
          <div className="mt-3 flex flex-wrap gap-3">{actions}</div>
        </div>
      ) : null}
    </div>
  );
};
