import { AlertTriangle, Info, ShieldCheck, ShieldX } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { EmptyState, StatusAlert } from "@/components/ui/panel-primitives";
import { ScanIssue } from "@/types/analysis";

interface FindingsPanelProps {
  issues: ScanIssue[];
  strengths: string[];
}

const issueVariants = {
  critical: { variant: "critical", icon: <ShieldX /> },
  warning: { variant: "warning", icon: <AlertTriangle /> },
  info: { variant: "info", icon: <Info /> },
} as const;

const confidenceStyles = {
  high: "bg-slate-200 text-slate-800",
  medium: "bg-amber-100 text-amber-900",
  low: "bg-sky-100 text-sky-900",
} as const;

export const FindingsPanel = ({ issues, strengths }: FindingsPanelProps) => {
  const rankedIssues = [...issues].sort((left, right) => {
    const severityWeight = { critical: 0, warning: 1, info: 2 } as const;
    const confidenceWeight = { high: 0, medium: 1, low: 2 } as const;
    return (
      severityWeight[left.severity] - severityWeight[right.severity] ||
      confidenceWeight[left.confidence] - confidenceWeight[right.confidence]
    );
  });

  return (
    <Card className="border-slate-200 shadow-sm">
      <CardHeader>
        <CardTitle>Top Findings</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {strengths.slice(0, 3).map((strength) => (
          <StatusAlert key={strength} variant="success" icon={<ShieldCheck />}>{strength}</StatusAlert>
        ))}

        {rankedIssues.length ? (
          rankedIssues.slice(0, 6).map((issue) => {
            const { variant, icon } = issueVariants[issue.severity];
            return (
              <StatusAlert
                key={`${issue.area}-${issue.title}-${issue.detail}`}
                variant={variant}
                icon={icon}
              >
                <div className="flex flex-wrap items-center gap-2">
                  <div className="font-medium">{issue.title}</div>
                  <Badge variant="secondary" className={confidenceStyles[issue.confidence]}>
                    {issue.confidence} confidence
                  </Badge>
                  <Badge variant="outline" className="border-current/20 bg-transparent">
                    {issue.source}
                  </Badge>
                  {issue.owasp.map((label) => (
                    <Badge key={label} variant="outline" className="border-current/20 bg-transparent">
                      {label}
                    </Badge>
                  ))}
                  {issue.mitre.map((label) => (
                    <Badge key={label} variant="outline" className="border-current/20 bg-transparent">
                      MITRE: {label}
                    </Badge>
                  ))}
                </div>
                <p className="mt-1 opacity-90">{issue.detail}</p>
              </StatusAlert>
            );
          })
        ) : (
          <EmptyState>No obvious issues were detected in the scanned response.</EmptyState>
        )}
      </CardContent>
    </Card>
  );
};
