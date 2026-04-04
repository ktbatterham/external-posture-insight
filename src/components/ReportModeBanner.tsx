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
    <Card className="border-slate-200 shadow-sm">
      <CardContent className="flex flex-col gap-4 p-5 md:flex-row md:items-center md:justify-between">
        <div>
          <div className="flex items-center gap-2 text-sm font-semibold text-slate-900">
            <Presentation className="h-4 w-4" />
            Report mode
          </div>
          <p className="mt-2 text-sm text-slate-600">
            This link reopens the app in a cleaner report-first view and re-runs the same target.
          </p>
          {shareUrl ? <p className="mt-2 text-xs break-all text-slate-500">{shareUrl}</p> : null}
        </div>
        <div className="flex flex-wrap gap-2">
          <Button variant="outline" className="rounded-2xl" onClick={onCopy} disabled={!shareUrl}>
            <Copy className="mr-2 h-4 w-4" />
            Copy report link
          </Button>
          <Button variant="outline" className="rounded-2xl" onClick={onExit}>
            <X className="mr-2 h-4 w-4" />
            Exit report mode
          </Button>
        </div>
      </CardContent>
    </Card>
  );
};
