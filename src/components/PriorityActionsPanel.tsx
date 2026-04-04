import { ListTodo } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { AnalysisResult } from "@/types/analysis";
import { getPriorityActions } from "@/lib/priorities";

interface PriorityActionsPanelProps {
  analysis: AnalysisResult;
}

const severityStyles = {
  critical: "border-rose-200 bg-rose-50 text-rose-900",
  warning: "border-amber-200 bg-amber-50 text-amber-900",
  info: "border-sky-200 bg-sky-50 text-sky-900",
} as const;

export const PriorityActionsPanel = ({ analysis }: PriorityActionsPanelProps) => {
  const actions = getPriorityActions(analysis);

  if (!actions.length) {
    return null;
  }

  return (
    <Card className="border-slate-200 shadow-sm">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <ListTodo className="h-5 w-5" />
          Priority Actions
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        {actions.map((action, index) => (
          <div
            key={`${action.area}-${action.title}`}
            className={`rounded-2xl border px-4 py-4 text-sm ${severityStyles[action.severity]}`}
          >
            <div className="flex items-center justify-between gap-3">
              <div className="font-semibold">
                {index + 1}. {action.title}
              </div>
              <span className="text-xs uppercase tracking-[0.16em] opacity-75">{action.area}</span>
            </div>
            <p className="mt-2 opacity-90">{action.detail}</p>
          </div>
        ))}
      </CardContent>
    </Card>
  );
};
