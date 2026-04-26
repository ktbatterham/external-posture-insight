import { CertificateAnalysis } from "@/components/CertificateAnalysis";
import { CookieAnalysis } from "@/components/CookieAnalysis";
import { CrawlPanel } from "@/components/CrawlPanel";
import { HeadersTable } from "@/components/HeadersTable";
import { HistoryPanel } from "@/components/HistoryPanel";
import { RawHeadersPanel } from "@/components/RawHeadersPanel";
import { RedirectChain } from "@/components/RedirectChain";
import { SecurityTxtPanel } from "@/components/SecurityTxtPanel";
import { TechnologyStack } from "@/components/TechnologyStack";
import { AnalysisResult, HistoryDiff, HistorySnapshot } from "@/types/analysis";
import { ReportSectionHeader } from "./ReportSectionHeader";

interface EvidenceSectionProps {
  analysisData: AnalysisResult;
  history: HistorySnapshot[];
  historyDiff: HistoryDiff | null;
  compact?: boolean;
}

export const EvidenceSection = ({ analysisData, history, historyDiff, compact = false }: EvidenceSectionProps) => (
  <div id="evidence" className="space-y-6">
    {!compact ? <ReportSectionHeader eyebrow="Evidence" title="Supporting detail and raw evidence" /> : null}
    <div className="grid gap-8 xl:grid-cols-[1.15fr_0.85fr]">
      <div className="space-y-8">
        <div className="rounded-[2rem] border border-white/10 bg-white/[0.04] p-6 shadow-[0_24px_60px_-36px_rgba(0,0,0,0.65)]">
          <h2 className="mb-4 text-2xl font-semibold text-white">Security Headers</h2>
          <HeadersTable headers={analysisData.headers} />
        </div>
        <RawHeadersPanel headers={analysisData.rawHeaders} />
        <CrawlPanel crawl={analysisData.crawl} />
        <HistoryPanel history={history} diff={historyDiff} />
      </div>

      <div className="space-y-8">
        <SecurityTxtPanel securityTxt={analysisData.securityTxt} />
        <CertificateAnalysis certInfo={analysisData.certificate} />
        <RedirectChain redirects={analysisData.redirects} />
        <TechnologyStack technologies={analysisData.technologies} />
        <CookieAnalysis cookies={analysisData.cookies} />
      </div>
    </div>
  </div>
);
