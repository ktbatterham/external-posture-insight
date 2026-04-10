import dns from "node:dns/promises";
import type { MxRecord, CaaRecord } from "node:dns";
import type { DomainSecurityInfo } from "./types.js";
import { safeResolve } from "./utils.js";
import type { RequestTextFn } from "./network.js";

async function fetchMtaStsPolicy(host: string, requestText: RequestTextFn) {
  const policyHost = `mta-sts.${host}`;
  const policyUrl = new URL(`https://${policyHost}/.well-known/mta-sts.txt`);

  try {
    const response = await requestText(policyUrl);
    if (response.statusCode >= 200 && response.statusCode < 300 && response.body.trim()) {
      return { policyUrl: policyUrl.toString(), policy: response.body.trim() };
    }
  } catch {
    // Ignore fetch failure and return a null policy below.
  }

  return { policyUrl: policyUrl.toString(), policy: null };
}

export async function analyzeDomainSecurity(host: string, requestText: RequestTextFn): Promise<DomainSecurityInfo> {
  const apexHost = host.startsWith("www.") ? host.slice(4) : host;
  const candidateHosts = [...new Set([host, apexHost])];

  const [
    mxByHost,
    nsByHost,
    txtRootByHost,
    txtDmarcByHost,
    caaByHost,
    txtMtaStsByHost,
    dsByHost,
  ] = await Promise.all([
    Promise.all(candidateHosts.map((candidate) => safeResolve(() => dns.resolveMx(candidate)))),
    Promise.all(candidateHosts.map((candidate) => safeResolve(() => dns.resolveNs(candidate)))),
    Promise.all(candidateHosts.map((candidate) => safeResolve(() => dns.resolveTxt(candidate)))),
    Promise.all(candidateHosts.map((candidate) => safeResolve(() => dns.resolveTxt(`_dmarc.${candidate}`)))),
    Promise.all(candidateHosts.map((candidate) => safeResolve(() => dns.resolveCaa(candidate)))),
    Promise.all(candidateHosts.map((candidate) => safeResolve(() => dns.resolveTxt(`_mta-sts.${candidate}`)))),
    Promise.all(candidateHosts.map((candidate) => safeResolve<unknown[]>(() => dns.resolve(candidate, "DS") as Promise<unknown[]>))),
  ]);

  const pickFirst = (values: (unknown[] | null)[]) => values.find((value) => value && value.length) || null;
  const mxRecordsRaw = pickFirst(mxByHost) || [];
  const nsRecordsRaw = pickFirst(nsByHost) || [];
  const txtRoot = pickFirst(txtRootByHost) || [];
  const txtDmarc = pickFirst(txtDmarcByHost) || [];
  const caaRaw = pickFirst(caaByHost) || [];
  const txtMtaSts = pickFirst(txtMtaStsByHost) || [];
  const dsRaw = pickFirst(dsByHost) || [];

  type DsRecord = { keyTag: number; algorithm: number; digestType: number; digest: string };
  const mxRecords = (mxRecordsRaw as MxRecord[])
    .sort((a, b) => a.priority - b.priority)
    .map((record) => `${record.priority} ${record.exchange}`);
  const nsRecords = (nsRecordsRaw as string[]) || [];
  const txtValues = (txtRoot as string[][]).map((entry) => entry.join(""));
  const dmarcValues = (txtDmarc as string[][]).map((entry) => entry.join(""));
  const mtaStsValues = (txtMtaSts as string[][]).map((entry) => entry.join(""));
  const caaRecords = (caaRaw as CaaRecord[]).flatMap((record) =>
    Object.entries(record)
      .filter(([key]) => key !== "critical")
      .map(([tag, value]) => `${tag} ${value}`),
  );
  const dsRecords = (dsRaw as DsRecord[]).map((record) => `${record.keyTag} ${record.algorithm} ${record.digestType} ${record.digest}`);
  const spf = txtValues.find((value) => value.toLowerCase().startsWith("v=spf1")) || null;
  const dmarc = dmarcValues.find((value) => value.toLowerCase().startsWith("v=dmarc1")) || null;
  const mtaStsDns = mtaStsValues.find((value) => value.toLowerCase().startsWith("v=stsv1")) || null;
  const mtaStsTargetHost = txtMtaStsByHost[0]?.length ? candidateHosts[0] : candidateHosts[1] || candidateHosts[0];
  const mtaStsPolicy = mtaStsDns ? await fetchMtaStsPolicy(mtaStsTargetHost, requestText) : { policyUrl: null, policy: null };

  const issues: string[] = [];
  const strengths: string[] = [];

  if (!mxRecords.length) {
    issues.push("No MX records found.");
  } else {
    strengths.push("MX records are published.");
  }

  if (!spf) {
    issues.push("No SPF record detected at the zone apex.");
  } else if (!spf.includes("-all") && !spf.includes("~all")) {
    issues.push("SPF record does not define an explicit all-mechanism.");
  } else {
    strengths.push("SPF is published.");
  }

  if (!dmarc) {
    issues.push("No DMARC record detected.");
  } else if (!/p=(reject|quarantine)/i.test(dmarc)) {
    issues.push("DMARC policy is present but not enforcing quarantine or reject.");
  } else {
    strengths.push("DMARC is enforcing.");
  }

  if (!caaRecords.length) {
    issues.push("No CAA records found.");
  } else {
    strengths.push("CAA records restrict which certificate authorities may issue for the domain.");
  }

  if (!dsRecords.length) {
    issues.push("No DNSSEC DS records detected at the domain apex.");
  } else {
    strengths.push("DNSSEC DS records are published.");
  }

  if (!mtaStsDns) {
    issues.push("No MTA-STS DNS policy record detected.");
  } else if (!mtaStsPolicy.policy) {
    issues.push("MTA-STS DNS record exists, but the HTTPS policy file could not be fetched.");
  } else {
    strengths.push("MTA-STS is published.");
  }

  return {
    host: apexHost,
    mxRecords,
    nsRecords,
    caaRecords,
    dnssec: {
      enabled: dsRecords.length > 0,
      dsRecords,
      status: dsRecords.length > 0 ? "signed" : "not_signed",
    },
    spf,
    dmarc,
    mtaSts: {
      dns: mtaStsDns,
      policyUrl: mtaStsPolicy.policyUrl,
      policy: mtaStsPolicy.policy,
    },
    issues,
    strengths,
  };
}
