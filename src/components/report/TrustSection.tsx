import { CtDiscoveryPanel } from "@/components/CtDiscoveryPanel";
import { DisclosureTrustPanel } from "@/components/DisclosureTrustPanel";
import { DomainSecurityPanel } from "@/components/DomainSecurityPanel";
import { IdentityProviderPanel } from "@/components/IdentityProviderPanel";
import { PublicSignalsPanel } from "@/components/PublicSignalsPanel";
import { WafFingerprintPanel } from "@/components/WafFingerprintPanel";
import { AnalysisResult } from "@/types/analysis";
import { ReportSectionHeader, sectionTitleClass } from "./ReportSectionHeader";

export const TrustSection = ({ analysisData }: { analysisData: AnalysisResult }) => (
  <div id="trust" className="space-y-6">
    <ReportSectionHeader eyebrow="Trust" title="Domain, identity, and public trust posture" />
    <div className="space-y-4">
      <p className={sectionTitleClass}>Domain & email foundation</p>
      <DomainSecurityPanel domainSecurity={analysisData.domainSecurity} />
    </div>
    <div className="space-y-8">
      <PublicSignalsPanel publicSignals={analysisData.publicSignals} />
      <DisclosureTrustPanel analysis={analysisData} />
    </div>
    <div className="space-y-8">
      <IdentityProviderPanel identityProvider={analysisData.identityProvider} />
      <WafFingerprintPanel wafFingerprint={analysisData.wafFingerprint} />
      <CtDiscoveryPanel ctDiscovery={analysisData.ctDiscovery} />
    </div>
  </div>
);
