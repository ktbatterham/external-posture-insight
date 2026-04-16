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
}

export const EvidenceSection = ({ analysisData, history, historyDiff }: EvidenceSectionProps) => (
  <div id="evidence" className="space-y-6">
    <ReportSectionHeader eyebrow="Evidence" title="Supporting detail and raw evidence" />
    <div className="grid gap-8 xl:grid-cols-[1.15fr_0.85fr]">
      <div className="space-y-8">
        <div className="rounded-[2rem] border border-slate-200 bg-white p-6 shadow-sm">
          <h2 className="mb-4 text-2xl font-bold text-slate-950">Security Headers</h2>
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
