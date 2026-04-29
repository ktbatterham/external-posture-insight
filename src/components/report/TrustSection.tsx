import { CtDiscoveryPanel } from "@/components/CtDiscoveryPanel";
import { DisclosureTrustPanel } from "@/components/DisclosureTrustPanel";
import { DomainSecurityPanel } from "@/components/DomainSecurityPanel";
import { IdentityProviderPanel } from "@/components/IdentityProviderPanel";
import { InfrastructurePanel } from "@/components/InfrastructurePanel";
import { PublicSignalsPanel } from "@/components/PublicSignalsPanel";
import { WafFingerprintPanel } from "@/components/WafFingerprintPanel";
import { AnalysisResult } from "@/types/analysis";
import { ReportSectionHeader, sectionTitleClass } from "./ReportSectionHeader";

interface TrustSectionProps {
  analysisData: AnalysisResult;
  compact?: boolean;
}

export const TrustSection = ({ analysisData, compact = false }: TrustSectionProps) => (
  <div id="trust" className="space-y-6">
    {!compact ? <ReportSectionHeader eyebrow="Trust" title="Domain, identity, and public trust posture" /> : null}
    <div className="space-y-4">
      {!compact ? <p className={sectionTitleClass}>Domain & email foundation</p> : null}
      <DomainSecurityPanel domainSecurity={analysisData.domainSecurity} />
    </div>
    <div className="space-y-8">
      <PublicSignalsPanel publicSignals={analysisData.publicSignals} />
      <DisclosureTrustPanel analysis={analysisData} />
    </div>
    <div className="space-y-8">
      <IdentityProviderPanel identityProvider={analysisData.identityProvider} />
      <InfrastructurePanel infrastructure={analysisData.infrastructure} />
      <WafFingerprintPanel wafFingerprint={analysisData.wafFingerprint} />
      <CtDiscoveryPanel ctDiscovery={analysisData.ctDiscovery} />
    </div>
  </div>
);
