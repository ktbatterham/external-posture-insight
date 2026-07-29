import { createHash } from "node:crypto";
import { diffObservationLedgers } from "./observationDrift.js";
import { POSTURE_MANIFEST_SCHEMA } from "./postureManifest.js";
import type {
  PortableEvidenceBundle,
  PortableEvidenceComparison,
  PostureManifest,
} from "./types.js";

export interface BuildPortableEvidenceOptions {
  source: PortableEvidenceBundle["provenance"]["source"];
  producerVersion?: string | null;
  scanId?: string | null;
  generatedAt?: string;
  baseline?: PostureManifest | null;
}

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }
  if (value && typeof value === "object") {
    return `{${Object.entries(value)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, item]) => `${JSON.stringify(key)}:${canonicalJson(item)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

export function postureManifestSha256(manifest: PostureManifest): string {
  return createHash("sha256").update(canonicalJson(manifest)).digest("hex");
}

function buildComparison(
  current: PostureManifest,
  baseline: PostureManifest | null | undefined,
): PortableEvidenceComparison | null {
  if (!baseline) return null;
  if (baseline.target.host !== current.target.host) {
    throw new Error(
      `Portable evidence baseline host ${baseline.target.host} does not match current host ${current.target.host}.`,
    );
  }
  return {
    baseline: {
      manifestId: baseline.manifestId,
      manifestSha256: postureManifestSha256(baseline),
      scannedAt: baseline.scan.scannedAt,
      score: baseline.posture.score,
      grade: baseline.posture.grade,
      policyPassed: baseline.policy.evaluation.passed,
    },
    current: {
      manifestId: current.manifestId,
      scannedAt: current.scan.scannedAt,
      score: current.posture.score,
      grade: current.posture.grade,
      policyPassed: current.policy.evaluation.passed,
    },
    scoreDelta: current.posture.score - baseline.posture.score,
    policyChanged: current.policy.evaluation.passed !== baseline.policy.evaluation.passed,
    observationDrift: diffObservationLedgers(
      current.checks.observationLedger,
      baseline.checks.observationLedger,
    ),
  };
}

export function buildPortableEvidence(
  manifest: PostureManifest,
  options: BuildPortableEvidenceOptions,
): PortableEvidenceBundle {
  const manifestSha256 = postureManifestSha256(manifest);
  const generatedAt = options.generatedAt ?? manifest.generatedAt;
  const evidenceId = `pe_${createHash("sha256")
    .update(`${manifestSha256}\u0000${options.source}\u0000${options.scanId ?? ""}`)
    .digest("hex")
    .slice(0, 24)}`;

  return {
    version: "1.0",
    evidenceId,
    generatedAt,
    provenance: {
      producer: "securl",
      producerVersion: options.producerVersion ?? manifest.engine.version,
      source: options.source,
      scanId: options.scanId ?? null,
    },
    compatibility: {
      manifestVersion: manifest.version,
      manifestSchema: POSTURE_MANIFEST_SCHEMA.$id,
      minimumReaderVersion: "1.28.0",
    },
    integrity: {
      algorithm: "sha256",
      manifestSha256,
    },
    manifest,
    comparison: buildComparison(manifest, options.baseline),
  };
}

export function verifyPortableEvidence(bundle: PortableEvidenceBundle): boolean {
  return bundle.version === "1.0"
    && bundle.compatibility.manifestVersion === bundle.manifest.version
    && bundle.compatibility.manifestSchema === POSTURE_MANIFEST_SCHEMA.$id
    && bundle.integrity.algorithm === "sha256"
    && bundle.integrity.manifestSha256 === postureManifestSha256(bundle.manifest);
}

export const PORTABLE_EVIDENCE_SCHEMA = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  $id: "https://securl.online/schemas/portable-evidence-v1.json",
  title: "SecURL Portable Evidence v1",
  description: "Digest-verifiable envelope around a SecURL Posture Manifest.",
  type: "object",
  additionalProperties: false,
  required: [
    "version",
    "evidenceId",
    "generatedAt",
    "provenance",
    "compatibility",
    "integrity",
    "manifest",
    "comparison",
  ],
  properties: {
    version: { const: "1.0" },
    evidenceId: { type: "string", pattern: "^pe_[a-f0-9]{24}$" },
    generatedAt: { type: "string", format: "date-time" },
    provenance: {
      type: "object",
      additionalProperties: false,
      required: ["producer", "producerVersion", "source", "scanId"],
      properties: {
        producer: { const: "securl" },
        producerVersion: { type: ["string", "null"] },
        source: { enum: ["cli", "hosted"] },
        scanId: { type: ["string", "null"] },
      },
    },
    compatibility: {
      type: "object",
      additionalProperties: false,
      required: ["manifestVersion", "manifestSchema", "minimumReaderVersion"],
      properties: {
        manifestVersion: { const: "1.0" },
        manifestSchema: { const: POSTURE_MANIFEST_SCHEMA.$id },
        minimumReaderVersion: { type: "string", minLength: 1 },
      },
    },
    integrity: {
      type: "object",
      additionalProperties: false,
      required: ["algorithm", "manifestSha256"],
      properties: {
        algorithm: { const: "sha256" },
        manifestSha256: { type: "string", pattern: "^[a-f0-9]{64}$" },
      },
    },
    manifest: POSTURE_MANIFEST_SCHEMA,
    comparison: {
      type: ["object", "null"],
      additionalProperties: true,
    },
  },
} as const;
