type ProjectAnalysisAvailabilityState = "analysis_pending" | "analysis_failed" | "analysis_cancelled";

const availabilityCopy = {
  analysis_pending: {
    title: "Analysis still in progress",
    detail: "Derived project views become available only after this analysis completes. Refresh the panel after it reaches a terminal state.",
  },
  analysis_failed: {
    title: "Analysis failed without a usable result",
    detail: "Choose a completed snapshot above, or use Retry from Project history. Inspectra does not expose internal runner errors here.",
  },
  analysis_cancelled: {
    title: "Analysis was cancelled",
    detail: "No result was retained for this attempt. Choose a completed snapshot above, or use Retry from Project history when you are ready.",
  },
} as const;

export function ProjectAnalysisAvailabilityNotice({ state }: { state: ProjectAnalysisAvailabilityState }) {
  const copy = availabilityCopy[state];
  return (
    <div className={`empty-state project-analysis-availability ${state}`} role="status">
      <strong>{copy.title}</strong>
      <span>{copy.detail}</span>
    </div>
  );
}
