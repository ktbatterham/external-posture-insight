import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useEffect } from "react";
import Index from "./pages/Index";
import { ReportPage } from "./pages/ReportPage";
import { PrivacyPage } from "./pages/PrivacyPage";
import { recordPageLoad } from "./lib/apiClient";
import { parseAppRoute } from "./lib/appRoute";

const queryClient = new QueryClient();

const App = () => {
  const route = parseAppRoute(window.location.pathname);

  useEffect(() => {
    recordPageLoad();
  }, []);

  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <Toaster />
        <Sonner />
        <div className="noise">
          {route.kind === "home" && <Index />}
          {route.kind === "report" && <ReportPage scanId={route.scanId} />}
          {route.kind === "privacy" && <PrivacyPage />}
        </div>
      </TooltipProvider>
    </QueryClientProvider>
  );
};

export default App;
