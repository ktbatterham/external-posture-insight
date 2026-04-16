import { FindingsPanel } from "@/components/FindingsPanel";
import { RemediationPanel } from "@/components/RemediationPanel";
import { TaxonomySummaryPanel } from "@/components/TaxonomySummaryPanel";
import { AnalysisResult } from "@/types/analysis";
import { ReportSectionHeader, sectionTitleClass } from "./ReportSectionHeader";

export const FindingsSection = ({ analysisData }: { analysisData: AnalysisResult }) => (
  <div id="findings" className="space-y-6">
    <ReportSectionHeader eyebrow="Risks" title="What matters most" />
    <FindingsPanel issues={analysisData.issues} strengths={analysisData.strengths} />
    <div className="space-y-4">
      <p className={sectionTitleClass}>Risk themes</p>
      <TaxonomySummaryPanel analysis={analysisData} />
    </div>
    <RemediationPanel remediation={analysisData.remediation} />
  </div>
);
