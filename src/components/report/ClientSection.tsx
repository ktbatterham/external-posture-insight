import { AiSurfacePanel } from "@/components/AiSurfacePanel";
import { AuthSurfacePanel } from "@/components/AuthSurfacePanel";
import { ClientExposurePanel } from "@/components/ClientExposurePanel";
import { DataCollectionPanel } from "@/components/DataCollectionPanel";
import { HtmlSecurityPanel } from "@/components/HtmlSecurityPanel";
import { ThirdPartyTrustPanel } from "@/components/ThirdPartyTrustPanel";
import { AnalysisResult } from "@/types/analysis";
import { ReportSectionHeader } from "./ReportSectionHeader";

export const ClientSection = ({ analysisData }: { analysisData: AnalysisResult }) => (
  <div id="client" className="space-y-6">
    <ReportSectionHeader eyebrow="Client Surface" title="What the application reveals about itself" />
    <HtmlSecurityPanel htmlSecurity={analysisData.htmlSecurity} />
    <div className="space-y-8">
      <ClientExposurePanel htmlSecurity={analysisData.htmlSecurity} />
      <AiSurfacePanel aiSurface={analysisData.aiSurface} />
      <ThirdPartyTrustPanel thirdPartyTrust={analysisData.thirdPartyTrust} />
    </div>
    <div className="space-y-8">
      <AuthSurfacePanel htmlSecurity={analysisData.htmlSecurity} />
      <DataCollectionPanel htmlSecurity={analysisData.htmlSecurity} />
    </div>
  </div>
);
