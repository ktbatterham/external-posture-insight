import { AiSurfaceInfo } from "@/types/analysis";

export const getAiSurfaceClassificationSummary = (aiSurface: AiSurfaceInfo) => {
  const hasAiVendor = aiSurface.vendors.some((vendor) => vendor.category === "ai_vendor");
  const hasAutomationVendor = aiSurface.vendors.some((vendor) => vendor.category === "support_automation");
  const hasAssistantUi =
    aiSurface.assistantVisible ||
    aiSurface.vendors.some((vendor) => vendor.category === "assistant_ui");

  if (!aiSurface.detected) {
    return "No visible AI or automation surface detected";
  }
  if (hasAiVendor) {
    return "AI vendor signals detected";
  }
  if (hasAssistantUi) {
    return "Assistant UI signals detected";
  }
  if (hasAutomationVendor) {
    return "Support automation signals detected";
  }
  return "AI-adjacent signals detected";
};
