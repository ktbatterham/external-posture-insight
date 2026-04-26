import { ApiSurfacePanel } from "@/components/ApiSurfacePanel";
import { CorsSecurityPanel } from "@/components/CorsSecurityPanel";
import { ExposurePanel } from "@/components/ExposurePanel";
import { AnalysisResult } from "@/types/analysis";
import { ReportSectionHeader } from "./ReportSectionHeader";

interface ExposureSectionProps {
  analysisData: AnalysisResult;
  compact?: boolean;
}

export const ExposureSection = ({ analysisData, compact = false }: ExposureSectionProps) => (
  <div id="exposure" className="space-y-6">
    {!compact ? <ReportSectionHeader eyebrow="Exposure" title="Public endpoints and browser-facing attack surface" /> : null}
    <ExposurePanel exposure={analysisData.exposure} />
    <div className="space-y-8">
      <CorsSecurityPanel corsSecurity={analysisData.corsSecurity} />
      <ApiSurfacePanel apiSurface={analysisData.apiSurface} />
    </div>
  </div>
);
