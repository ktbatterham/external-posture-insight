import { inspectLink } from "../packages/core/dist/link-inspection.js";

export async function handleLinkInspectionRequest({
  request,
  response,
  requestUrl,
  authorizeAnalysisRequest,
  readJsonBody,
  checkTargetQuota,
  sendJson,
  sendMethodNotAllowed,
  classifyScanFailure,
  normalizeScanErrorMessage,
  telemetry,
}) {
  if (request.method !== "POST") {
    sendMethodNotAllowed(response, ["POST", "OPTIONS"]);
    return true;
  }
  const authState = await authorizeAnalysisRequest({
    request,
    response,
    requestPath: requestUrl.pathname,
    requireScanOwner: true,
  });
  if (!authState) return true;

  try {
    const body = await readJsonBody(request);
    const target = typeof body.url === "string" ? body.url : "";
    const targetQuota = await checkTargetQuota({
      requesterScope: authState.requesterScope,
      target,
      clientIp: authState.clientIp,
      requestPath: requestUrl.pathname,
      response,
    });
    if (!targetQuota.ok) return true;

    const inspection = await inspectLink(target);
    sendJson(response, 200, { apiVersion: "2026-08-14", inspection });
  } catch (error) {
    telemetry.recordFailure(classifyScanFailure(error));
    sendJson(response, 400, { error: normalizeScanErrorMessage(error) });
  }
  return true;
}
