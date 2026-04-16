import { ApiSurfacePanel } from "@/components/ApiSurfacePanel";
import { CorsSecurityPanel } from "@/components/CorsSecurityPanel";
import { ExposurePanel } from "@/components/ExposurePanel";
import { AnalysisResult } from "@/types/analysis";
import { ReportSectionHeader } from "./ReportSectionHeader";

export const ExposureSection = ({ analysisData }: { analysisData: AnalysisResult }) => (
  <div id="exposure" className="space-y-6">
    <ReportSectionHeader eyebrow="Exposure" title="Public endpoints and browser-facing attack surface" />
    <ExposurePanel exposure={analysisData.exposure} />
    <div className="space-y-8">
      <CorsSecurityPanel corsSecurity={analysisData.corsSecurity} />
      <ApiSurfacePanel apiSurface={analysisData.apiSurface} />
    </div>
  </div>
);
