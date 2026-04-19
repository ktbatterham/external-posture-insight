import tls from "node:tls";
import { TLS_HANDSHAKE_TIMEOUT_MS } from "./scannerConfig.js";
import type { CertificateResult } from "./types.js";

const firstStringValue = (value: unknown): string | null => {
  if (typeof value === "string") {
    return value;
  }
  if (Array.isArray(value)) {
    const first = value.find((item) => typeof item === "string");
    return typeof first === "string" ? first : null;
  }
  return null;
};

const allowInsecureTls = process.env.EXTERNAL_POSTURE_ALLOW_INSECURE_TLS === "1";

export const OBSERVATIONAL_TLS_OPTIONS = {
  // Keep certificate verification on by default.
  // Set EXTERNAL_POSTURE_ALLOW_INSECURE_TLS=1 only for controlled observational runs.
  rejectUnauthorized: !allowInsecureTls,
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
      if (allowInsecureTls) {
        issues.push("Insecure TLS observation mode is enabled via EXTERNAL_POSTURE_ALLOW_INSECURE_TLS.");
      }
      if (daysRemaining !== null && daysRemaining <= 14) issues.push("Certificate expires very soon.");
      if (protocol && /tlsv1(\.0|\.1)?$/i.test(protocol)) issues.push("TLS protocol is outdated.");

      resolve({
        available: true,
        valid: Boolean(socket.authorized),
        authorized: Boolean(socket.authorized),
        issuer: firstStringValue(certificate?.issuer?.O) ?? firstStringValue(certificate?.issuer?.CN),
        subject: firstStringValue(certificate?.subject?.CN),
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
