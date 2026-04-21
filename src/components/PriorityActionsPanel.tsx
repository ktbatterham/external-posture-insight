import { ListTodo } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { StatusAlert } from "@/components/ui/panel-primitives";
import { AnalysisResult } from "@/types/analysis";
import { getPriorityActions } from "@/lib/priorities";

interface PriorityActionsPanelProps {
  analysis: AnalysisResult;
}

const variantMap = {
  critical: "critical",
  warning: "warning",
  info: "info",
} as const;

export const PriorityActionsPanel = ({ analysis }: PriorityActionsPanelProps) => {
  const actions = getPriorityActions(analysis);

  if (!actions.length) {
    return null;
  }

  return (
    <Card className="rounded-[1.75rem] border-slate-200/80 bg-white/90 shadow-[0_10px_24px_-20px_rgba(15,23,42,0.35)]">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <ListTodo className="h-5 w-5" />
          Priority Actions
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        {actions.map((action, index) => (
          <StatusAlert
            key={`${action.area}-${action.title}`}
            variant={variantMap[action.severity]}
            className="py-4"
          >
            <div className="flex items-center justify-between gap-3">
              <div className="font-semibold">
                {index + 1}. {action.title}
              </div>
              <span className="text-xs uppercase tracking-[0.18em] opacity-75">{action.area}</span>
            </div>
            <p className="mt-2 opacity-90">{action.detail}</p>
            {action.priorityReason ? (
              <p className="mt-2 text-xs font-medium uppercase tracking-[0.14em] opacity-70">
                {action.priorityReason}
              </p>
            ) : null}
          </StatusAlert>
        ))}
      </CardContent>
    </Card>
  );
};
