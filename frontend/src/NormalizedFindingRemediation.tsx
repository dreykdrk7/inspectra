import { useState } from "react";
import { ExternalLink } from "lucide-react";

import type { NormalizedFindingReference } from "./types";

type FindingRemediationActionsProps = {
  recommendation: string;
  references: NormalizedFindingReference[];
  onRequestNewSnapshot?: () => void;
  sourceUpdateLabel?: string;
};

type CopyState = "idle" | "copied" | "unavailable";

const cveIdentifier = /^CVE-\d{4}-\d{4,}$/i;
const ghsaIdentifier = /^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$/i;
const owaspIdentifier = /^(?:A\d{2}:\d{4}|OWASP-[A-Z0-9_.:-]+)$/i;

/**
 * Revalidates references from retained or older contracts before turning one
 * into a browser action. It intentionally accepts only the canonical public
 * destinations documented by the normalized-finding contract.
 */
export function safePublicReferenceUrl(reference: NormalizedFindingReference): string | null {
  const identifier = reference.id.trim();
  try {
    const parsed = new URL(reference.url);
    if (
      parsed.protocol !== "https:"
      || parsed.username
      || parsed.password
      || parsed.hash
      || parsed.port
    ) {
      return null;
    }

    const host = parsed.hostname.toLocaleLowerCase();
    const path = parsed.pathname.replace(/\/$/, "");
    const hasOnlyQuery = (key: string) => {
      const entries = Array.from(parsed.searchParams.entries());
      return entries.length === 1 && entries[0]?.[0] === key && entries[0]?.[1]?.toLocaleUpperCase() === identifier.toLocaleUpperCase();
    };

    if (reference.type === "cve" && cveIdentifier.test(identifier)) {
      const upperIdentifier = identifier.toLocaleUpperCase();
      if (host === "nvd.nist.gov" && path === `/vuln/detail/${upperIdentifier}` && !parsed.search) return parsed.toString();
      if (["cve.org", "www.cve.org"].includes(host) && path === "/CVERecord" && hasOnlyQuery("id")) return parsed.toString();
      if (host === "cve.mitre.org" && path === "/cgi-bin/cvename.cgi" && hasOnlyQuery("name")) return parsed.toString();
      return null;
    }

    if (reference.type === "ghsa" && ghsaIdentifier.test(identifier)) {
      return host === "github.com" && path === `/advisories/${identifier}` && !parsed.search ? parsed.toString() : null;
    }

    if (reference.type === "owasp" && owaspIdentifier.test(identifier)) {
      return ["owasp.org", "www.owasp.org"].includes(host) && Boolean(path) && !parsed.search ? parsed.toString() : null;
    }
  } catch {
    return null;
  }
  return null;
}

export function FindingRemediationActions({
  recommendation,
  references,
  onRequestNewSnapshot,
  sourceUpdateLabel = "Review a new snapshot",
}: FindingRemediationActionsProps) {
  const [copyState, setCopyState] = useState<CopyState>("idle");
  const safeReferences = references
    .map((reference) => ({ reference, url: safePublicReferenceUrl(reference) }))
    .filter((item): item is { reference: NormalizedFindingReference; url: string } => item.url !== null);
  const trimmedRecommendation = recommendation.trim();
  const hasCorrectionContext = Boolean(trimmedRecommendation) || safeReferences.length > 0;

  async function copyRecommendation() {
    if (!trimmedRecommendation || !navigator.clipboard?.writeText) {
      setCopyState("unavailable");
      return;
    }
    try {
      // Never append evidence, location, project identity, or source metadata.
      await navigator.clipboard.writeText(trimmedRecommendation);
      setCopyState("copied");
    } catch {
      setCopyState("unavailable");
    }
  }

  if (!hasCorrectionContext) {
    return <p className="muted remediation-unavailable">No retained correction guidance or validated public reference is available for this finding.</p>;
  }

  return (
    <section className="finding-remediation-actions" aria-label="Correction guidance">
      <p className="finding-remediation-boundary">
        Use this as guidance for a local review. It is not an exploitation verdict or proof that a change resolves the finding.
      </p>
      {trimmedRecommendation ? (
        <>
          <p className="project-finding-recommendation"><strong>Recommended next step:</strong> {trimmedRecommendation}</p>
          <div className="row-actions finding-remediation-controls">
            <button type="button" className="secondary-button" onClick={() => void copyRecommendation()}>
              {copyState === "copied" ? "Recommendation copied" : "Copy recommendation"}
            </button>
            {copyState === "unavailable" ? <span className="error-text" role="status">Copy is unavailable in this browser. Select the recommendation text instead.</span> : null}
          </div>
        </>
      ) : null}
      {safeReferences.length > 0 ? (
        <ul className="project-finding-references" aria-label="Validated public correction references">
          {safeReferences.map(({ reference, url }) => (
            <li key={`${reference.type}:${reference.id}`}>
              <a href={url} target="_blank" rel="noreferrer noopener">
                {reference.type.toUpperCase()}: {reference.id} <ExternalLink size={14} aria-hidden="true" />
              </a>
            </li>
          ))}
        </ul>
      ) : null}
      {onRequestNewSnapshot ? (
        <button type="button" className="secondary-button finding-remediation-snapshot" onClick={onRequestNewSnapshot}>
          {sourceUpdateLabel}
        </button>
      ) : null}
    </section>
  );
}
