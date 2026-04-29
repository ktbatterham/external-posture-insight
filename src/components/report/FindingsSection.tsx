import { FindingsPanel } from "@/components/FindingsPanel";
import { RemediationPanel } from "@/components/RemediationPanel";
import { TaxonomySummaryPanel } from "@/components/TaxonomySummaryPanel";
import { AnalysisResult } from "@/types/analysis";
import { ReportSectionHeader, sectionTitleClass } from "./ReportSectionHeader";

interface FindingsSectionProps {
  analysisData: AnalysisResult;
  compact?: boolean;
}

export const FindingsSection = ({ analysisData, compact = false }: FindingsSectionProps) => (
  <div id="findings" className="space-y-6">
    {!compact ? <ReportSectionHeader eyebrow="Risks" title="What matters most" /> : null}
    <FindingsPanel issues={analysisData.issues} strengths={analysisData.strengths} />
    <div className="space-y-4">
      {!compact ? <p className={sectionTitleClass}>Risk themes</p> : null}
      <TaxonomySummaryPanel analysis={analysisData} />
    </div>
    <RemediationPanel remediation={analysisData.remediation} />
  </div>
);
