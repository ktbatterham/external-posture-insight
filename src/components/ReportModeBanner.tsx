import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Copy, Presentation, X } from "lucide-react";

interface ReportModeBannerProps {
  shareUrl: string | null;
  onCopy: () => void;
  onExit: () => void;
}

export const ReportModeBanner = ({ shareUrl, onCopy, onExit }: ReportModeBannerProps) => {
  return (
    <Card className="border-white/10 bg-white/[0.04] shadow-[0_24px_60px_-36px_rgba(0,0,0,0.65)]">
      <CardContent className="flex flex-col gap-4 p-5 md:flex-row md:items-center md:justify-between">
        <div>
          <div className="flex items-center gap-2 text-sm font-semibold text-slate-100">
            <Presentation className="h-4 w-4" />
            Report mode
          </div>
          <p className="mt-2 text-sm text-slate-300">
            This link reopens the app in a cleaner report-first view and re-runs the same target.
          </p>
          {shareUrl ? <p className="mt-2 text-xs break-all text-slate-400">{shareUrl}</p> : null}
        </div>
        <div className="flex flex-wrap gap-2">
          <Button variant="outline" className="rounded-2xl border-white/10 bg-white/[0.04] text-slate-100 hover:bg-white/[0.08]" onClick={onCopy} disabled={!shareUrl}>
            <Copy className="mr-2 h-4 w-4" />
            Copy report link
          </Button>
          <Button variant="outline" className="rounded-2xl border-white/10 bg-white/[0.04] text-slate-100 hover:bg-white/[0.08]" onClick={onExit}>
            <X className="mr-2 h-4 w-4" />
            Exit report mode
          </Button>
        </div>
      </CardContent>
    </Card>
  );
};
