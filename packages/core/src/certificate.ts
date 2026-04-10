import tls from "node:tls";
import { TLS_HANDSHAKE_TIMEOUT_MS } from "./scannerConfig.js";
import type { CertificateResult } from "./types.js";

export const OBSERVATIONAL_TLS_OPTIONS = {
  rejectUnauthorized: false,
};

export const scanTls = (targetUrl: URL): Promise<CertificateResult> => {
  if (targetUrl.protocol !== "https:") {
    return Promise.resolve({
      available: false,
      valid: false,
      authorized: false,
      issuer: null,
      subject: null,
      validFrom: null,
      validTo: null,
      daysRemaining: null,
      protocol: null,
      cipher: null,
      fingerprint: null,
      subjectAltName: [],
      issues: ["TLS certificate data is only available for HTTPS targets."],
    });
  }

  return new Promise((resolve, reject) => {
    const socket = tls.connect({
      host: targetUrl.hostname,
      port: Number(targetUrl.port || 443),
      servername: targetUrl.hostname,
      ...OBSERVATIONAL_TLS_OPTIONS,
      timeout: TLS_HANDSHAKE_TIMEOUT_MS,
    });

    socket.once("secureConnect", () => {
      const certificate = socket.getPeerCertificate(true);
      const protocol = socket.getProtocol?.() || null;
      const cipherInfo = socket.getCipher?.();
      const validTo = certificate?.valid_to || null;
      const validFrom = certificate?.valid_from || null;
      const daysRemaining = validTo
        ? Math.ceil((new Date(validTo).getTime() - Date.now()) / (1000 * 60 * 60 * 24))
        : null;
      const subjectAltName = typeof certificate?.subjectaltname === "string"
        ? certificate.subjectaltname.split(",").map((entry) => entry.trim().replace(/^DNS:/, ""))
        : [];
      const issues: string[] = [];

      if (!socket.authorized) {
        issues.push(
          typeof socket.authorizationError === "string"
            ? socket.authorizationError
            : "Certificate is not trusted.",
        );
      }
      if (daysRemaining !== null && daysRemaining <= 14) issues.push("Certificate expires very soon.");
      if (protocol && /tlsv1(\.0|\.1)?$/i.test(protocol)) issues.push("TLS protocol is outdated.");

      resolve({
        available: true,
        valid: Boolean(socket.authorized),
        authorized: Boolean(socket.authorized),
        issuer: certificate?.issuer?.O || certificate?.issuer?.CN || null,
        subject: certificate?.subject?.CN || null,
        validFrom,
        validTo,
        daysRemaining,
        protocol,
        cipher: cipherInfo?.name || null,
        fingerprint: certificate?.fingerprint256 || null,
        subjectAltName,
        issues,
      });

      socket.end();
    });

    socket.once("timeout", () => {
      socket.destroy(new Error("TLS handshake timed out."));
    });
    socket.once("error", reject);
  });
};
