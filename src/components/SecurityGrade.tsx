import { Shield, ShieldAlert, ShieldCheck } from "lucide-react";

interface SecurityGradeProps {
  grade: string;
  score: number;
  summary: string;
}

const gradeStyles: Record<string, { text: string; ring: string; bg: string }> = {
  "A+": { text: "text-emerald-700", ring: "ring-emerald-200", bg: "from-emerald-50 to-white" },
  A: { text: "text-emerald-700", ring: "ring-emerald-200", bg: "from-emerald-50 to-white" },
  B: { text: "text-amber-700", ring: "ring-amber-200", bg: "from-amber-50 to-white" },
  C: { text: "text-orange-700", ring: "ring-orange-200", bg: "from-orange-50 to-white" },
  D: { text: "text-rose-700", ring: "ring-rose-200", bg: "from-rose-50 to-white" },
  F: { text: "text-rose-700", ring: "ring-rose-200", bg: "from-rose-50 to-white" },
};

export const SecurityGrade = ({ grade, score, summary }: SecurityGradeProps) => {
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
    <div
      className={`w-full rounded-3xl bg-gradient-to-br ${style.bg} p-8 shadow-sm ring-1 ${style.ring}`}
    >
      <div className="flex flex-col gap-6 md:flex-row md:items-center md:justify-between">
        <div className="flex items-center gap-4">
          <div className={`rounded-2xl bg-white/80 p-4 ${style.text}`}>{icon}</div>
          <div>
            <p className="text-sm font-medium uppercase tracking-[0.18em] text-slate-500">
              Security Grade
            </p>
            <div className="mt-1 flex items-end gap-3">
              <h2 className={`text-5xl font-black ${style.text}`}>{grade}</h2>
              <p className="pb-1 text-lg font-semibold text-slate-600">{score}/100</p>
            </div>
          </div>
        </div>

        <p className="max-w-xl text-sm leading-6 text-slate-600">{summary}</p>
      </div>
    </div>
  );
};
