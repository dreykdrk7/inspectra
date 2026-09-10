import type { JobListItem } from "./types";


const SAFE_SOURCE_REFERENCE = /^snapshot-[a-f0-9]{16}$/;

export function sourceReference(value: string | null | undefined): string {
  return typeof value === "string" && SAFE_SOURCE_REFERENCE.test(value) ? value : "Snapshot unavailable";
}

export function analysisSourceReference(analysis: Pick<JobListItem, "source_reference">): string {
  return sourceReference(analysis.source_reference);
}
