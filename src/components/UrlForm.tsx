import { FormEvent, useState } from "react";
import { Globe, Search } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { toast } from "sonner";

interface UrlFormProps {
  onSubmit: (url: string) => void;
  isLoading: boolean;
  initialValue?: string;
}

export const UrlForm = ({ onSubmit, isLoading, initialValue = "" }: UrlFormProps) => {
  const [url, setUrl] = useState(initialValue);

  const handleSubmit = (event: FormEvent) => {
    event.preventDefault();
    const trimmed = url.trim();

    if (!trimmed) {
      toast.error("Enter a URL to scan.");
      return;
    }

    try {
      const candidate = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
      new URL(candidate);
      onSubmit(candidate);
    } catch {
      toast.error("That URL does not look valid.");
    }
  };

  return (
    <form
      onSubmit={handleSubmit}
      className="w-full rounded-[2rem] border border-slate-200 bg-white/90 p-3 shadow-xl shadow-slate-200/40 backdrop-blur"
    >
      <div className="flex flex-col gap-3 md:flex-row md:items-center">
        <div className="flex flex-1 items-center gap-3 rounded-2xl bg-slate-50 px-4 py-3">
          <Globe className="h-5 w-5 text-slate-400" />
          <Input
            type="text"
            placeholder="example.com"
            value={url}
            onChange={(event) => setUrl(event.target.value)}
            className="border-0 bg-transparent px-0 text-base shadow-none focus-visible:ring-0"
          />
        </div>
        <Button type="submit" disabled={isLoading} className="h-12 rounded-2xl px-6 text-sm font-semibold">
          <Search className="mr-2 h-4 w-4" />
          {isLoading ? "Scanning..." : "Run Scan"}
        </Button>
      </div>
      <p className="px-2 pt-3 text-sm text-slate-500">
        Enter a domain or full URL. If you omit the scheme, the scanner will try HTTPS automatically.
      </p>
    </form>
  );
};
