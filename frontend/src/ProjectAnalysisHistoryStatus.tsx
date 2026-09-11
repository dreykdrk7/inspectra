import type { JobListItem } from "./types";

type ProjectAnalysisHistoryStatusProps = {
  analyses: JobListItem[];
  totalCount: number;
  hasMore: boolean;
  loading: boolean;
  error: string | null;
  onLoadMore: () => void;
};

export function mergeProjectAnalyses(...pages: JobListItem[][]): JobListItem[] {
  const byId = new Map<string, JobListItem>();
  for (const page of pages) {
    for (const analysis of page) {
      byId.set(analysis.id, analysis);
    }
  }
  return Array.from(byId.values()).sort((left, right) => {
    const dateOrder = right.created_at.localeCompare(left.created_at);
    return dateOrder === 0 ? right.id.localeCompare(left.id) : dateOrder;
  });
}

export function ProjectAnalysisHistoryStatus({
  analyses,
  totalCount,
  hasMore,
  loading,
  error,
  onLoadMore,
}: ProjectAnalysisHistoryStatusProps) {
  if (totalCount <= analyses.length && totalCount <= 50 && !error) {
    return null;
  }

  return (
    <div className="table-actions project-analysis-history-actions">
      <p className="muted" role="status">
        Showing {analyses.length} of {totalCount} retained analyses in this selector.
      </p>
      {error ? <p className="error-text" role="alert">{error}</p> : null}
      {hasMore ? (
        <button className="secondary-button" type="button" onClick={onLoadMore} disabled={loading}>
          {loading ? "Loading older analyses" : "Load older analyses"}
        </button>
      ) : totalCount > 50 ? (
        <button className="secondary-button" type="button" disabled>
          All retained analyses loaded
        </button>
      ) : null}
    </div>
  );
}
