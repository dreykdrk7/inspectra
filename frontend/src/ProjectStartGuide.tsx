import { FolderPlus } from "lucide-react";

import type { ProjectSummary } from "./types";

export function ProjectStartGuide({
  projects,
  onArchive,
  onSbom,
  onCi,
  onOpenProject,
}: {
  projects: ProjectSummary[];
  onArchive: () => void;
  onSbom: () => void;
  onCi: (project: ProjectSummary) => void;
  onOpenProject: (project: ProjectSummary) => void;
}) {
  const recentProjects = projects.slice(0, 3);
  const ciProject = projects.find((project) => project.project.source_type !== "sbom" && project.latest_job?.analysis_profile !== "sbom_import") ?? null;
  return (
    <section className="project-start-guide" aria-labelledby="project-start-title">
      <div className="project-start-copy">
        <p className="eyebrow">Start with your delivery workflow</p>
        <h2 id="project-start-title">Start a professional security review</h2>
        <p>
          Choose one authorized source. Inspectra does not execute project code, install dependencies, clone repositories, or send source contents to public vulnerability providers.
        </p>
        {recentProjects.length > 0 ? (
          <div className="recent-projects" aria-label="Recent projects">
            <strong>Continue a recent project</strong>
            {recentProjects.map((project) => (
              <button key={project.project.id} type="button" className="secondary-button" onClick={() => onOpenProject(project)}>
                {project.project.name} <span>{project.project.source_type === "sbom" ? "SBOM" : "Archive"}</span>
              </button>
            ))}
          </div>
        ) : <p className="empty-state compact-empty-state">No projects yet. Choose an onboarding path below.</p>}
      </div>
      <div className="product-entry-grid" aria-label="Project onboarding paths">
        <article>
          <span className="entry-kicker">Local repository</span>
          <h3>Analyze a source snapshot</h3>
          <p>Create a tracked-files archive locally, then upload the authorized ZIP or TAR without repository credentials.</p>
          <button type="button" onClick={onArchive}><FolderPlus size={16} aria-hidden="true" /> Prepare archive</button>
        </article>
        <article>
          <span className="entry-kicker">Continuous delivery</span>
          <h3>Connect CI securely</h3>
          <p>Use a project-bound, short-lived credential and an exact commit snapshot after the first archive project exists.</p>
          <button type="button" onClick={() => ciProject && onCi(ciProject)} disabled={!ciProject}>Open CI setup</button>
          {!ciProject ? <span className="entry-note">Create an archive project first.</span> : null}
        </article>
        <article>
          <span className="entry-kicker">Repository-free</span>
          <h3>Import an SBOM</h3>
          <p>Preflight CycloneDX or SPDX privately, review aggregate coverage, then attest only public package identities.</p>
          <button type="button" onClick={onSbom}>Preflight SBOM</button>
        </article>
      </div>
    </section>
  );
}
