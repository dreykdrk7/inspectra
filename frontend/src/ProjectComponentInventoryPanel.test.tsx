import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import axe from "axe-core";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ProjectComponentInventoryPanel } from "./ProjectComponentInventoryPanel";
import type { ProjectComponentInventoryResponse, ProjectSummary } from "./types";

const project = {
  project: {
    source_metadata_contract_version: "2026-09-06.1",
    source_name_disclosure: "withheld_use_files_view",
    source_digest_disclosure: "retained_server_side",
    id: "project-1",
    name: "Demo project",
    source_reference: "snapshot-aaaaaaaaaaaaaaaa",
    source_file_deleted_at: null,
    latest_job_id: "analysis-1",
    analysis_count: 1,
    created_at: "2026-09-05T09:00:00Z",
    updated_at: "2026-09-05T09:01:00Z"
  },
  latest_job: {
    id: "analysis-1",
    project_id: "project-1",
    source_reference: "snapshot-aaaaaaaaaaaaaaaa",
    analysis_profile: "project_archive_basic",
    audit_type: "project_archive_basic",
    file_id: "file-1",
    target_url: null,
    target_domain: null,
    status: "completed",
    created_at: "2026-09-05T09:00:00Z",
    updated_at: "2026-09-05T09:01:00Z",
    source_file_deleted_at: null,
    summary: null
  }
} satisfies ProjectSummary;

const inventory = {
  project: project.project,
  analysis: project.latest_job,
  state: "ready",
  contract_version: "2026-09-05.1",
  summary: {
    total_components: 2,
    exact_registry_components: 1,
    resolved_registry_components: 0,
    matched_lockfile_components: 0,
    unmatched_lockfile_components: 2,
    ambiguous_lockfile_components: 0,
    declared_range_components: 1,
    not_correlatable_components: 0,
    parsed_manifest_count: 1,
    supported_manifest_count: 2,
    skipped_manifest_count: 1,
    result_truncated: true,
    parsed_lockfile_count: 0,
    skipped_lockfile_count: 0,
    skipped_lockfile_reasons: [],
    resolution: "declared_only"
  },
  components: [
    {
      id: "component-react",
      ecosystem: "npm",
      name: "react",
      manifest_path: "apps/web/package.json",
      manifest_path_status: "reported",
      dependency_group: "dependencies",
      source_type: "registry",
      declared_version: "18.3.1",
      exact_version: "18.3.1",
      package_url: "pkg:npm/react@18.3.1",
      version_status: "exact_declared",
      correlation_eligible: true,
      resolution: "declared",
      lockfile_match_status: "not_matched",
      manifest_type: "package_json",
      lockfile_path: null,
      lockfile_path_status: "not_reported",
      lockfile_type: null
    },
    {
      id: "component-lodash",
      ecosystem: "npm",
      name: "lodash",
      manifest_path: "apps/web/package.json",
      manifest_path_status: "reported",
      dependency_group: "dependencies",
      source_type: "registry",
      declared_version: "^4.17.21",
      exact_version: null,
      version_status: "declared_range",
      correlation_eligible: false,
      resolution: "declared",
      lockfile_match_status: "not_matched",
      manifest_type: "package_json",
      lockfile_path: null,
      lockfile_path_status: "not_reported",
      lockfile_type: null
    }
  ]
} satisfies ProjectComponentInventoryResponse;

const lockfileInventory = {
  ...inventory,
  summary: {
    ...inventory.summary,
    exact_registry_components: 0,
    resolved_registry_components: 1,
    matched_lockfile_components: 1,
    unmatched_lockfile_components: 0,
    declared_range_components: 0,
    parsed_lockfile_count: 1,
    resolution: "declared_and_lockfile"
  },
  components: [
    {
      ...inventory.components[0],
      declared_version: "^18.0.0",
      exact_version: "18.3.1",
      version_status: "exact_resolved",
      resolution: "lockfile",
      lockfile_match_status: "matched",
      lockfile_path: "apps/web/package-lock.json",
      lockfile_path_status: "reported",
      lockfile_type: "npm_package_lock"
    }
  ]
} satisfies ProjectComponentInventoryResponse;

function jsonResponse(payload: unknown, status = 200): Response {
  return new Response(JSON.stringify(payload), { status, headers: { "content-type": "application/json" } });
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("ProjectComponentInventoryPanel", () => {
  it("shows safe declared coverage, searches components, and avoids a clean-vulnerability claim", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn((url: string) => {
        if (url.endsWith("/projects/project-1/analyses")) {
          return Promise.resolve(jsonResponse([project.latest_job]));
        }
        if (url.endsWith("/projects/project-1/components?analysis_id=analysis-1")) {
          return Promise.resolve(jsonResponse(inventory));
        }
        return Promise.resolve(jsonResponse({ detail: "Not found" }, 404));
      })
    );

    render(<ProjectComponentInventoryPanel project={project} />);

    expect(await screen.findByRole("heading", { name: "Component inventory" })).toBeInTheDocument();
    expect(screen.getByText(/Declared dependencies only/)).toBeInTheDocument();
    expect(screen.getByText(/Parsed 1 of 2 supported manifests/)).toBeInTheDocument();
    expect(screen.getByText(/This inventory is partial/)).toBeInTheDocument();
    expect(screen.getByText("react")).toBeInTheDocument();
    expect(screen.getByText("18.3.1")).toBeInTheDocument();
    expect(screen.getByText("Canonical package identity: pkg:npm/react@18.3.1")).toBeInTheDocument();
    expect(screen.getByText("Exact declaration")).toBeInTheDocument();
    expect(screen.getByText("Declared Range")).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText("Search components"), { target: { value: "lodash" } });
    expect(screen.queryByText("react")).not.toBeInTheDocument();
    expect(screen.getByText("lodash")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Search components"), { target: { value: "missing" } });
    expect(screen.getByText(/No components match this search/)).toBeInTheDocument();
  });

  it("uses an actionable error when inventory is unavailable", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn((url: string) => {
        if (url.endsWith("/projects/project-1/analyses")) {
          return Promise.resolve(jsonResponse([project.latest_job]));
        }
        return Promise.resolve(jsonResponse({ detail: "Not found" }, 404));
      })
    );

    render(<ProjectComponentInventoryPanel project={project} />);

    await waitFor(() => {
      expect(screen.getByRole("alert")).toHaveTextContent("This project analysis is no longer available.");
    });
  });

  it.each([
    ["failed", "analysis_failed", "Analysis failed without a usable result"],
    ["cancelled", "analysis_cancelled", "Analysis was cancelled"],
  ] as const)("renders an accessible %s terminal state without calling it active", async (status, responseState, title) => {
    const terminalAnalysis = { ...project.latest_job, status };
    const terminalPayload: ProjectComponentInventoryResponse = {
      project: project.project,
      analysis: terminalAnalysis,
      state: responseState,
      contract_version: null,
      components: [],
      summary: { ...inventory.summary, total_components: 0 },
      coverage_matrix: [],
    };
    vi.stubGlobal(
      "fetch",
      vi.fn((url: string) => {
        if (url.endsWith("/projects/project-1/analyses")) return Promise.resolve(jsonResponse([terminalAnalysis]));
        if (url.endsWith("/projects/project-1/components?analysis_id=analysis-1")) return Promise.resolve(jsonResponse(terminalPayload));
        return Promise.resolve(jsonResponse({ detail: "Not found" }, 404));
      })
    );

    const view = render(<ProjectComponentInventoryPanel project={{ ...project, latest_job: terminalAnalysis }} />);

    expect(await screen.findByText(title)).toBeInTheDocument();
    expect(screen.getByText(/Choose a completed snapshot above/)).toBeInTheDocument();
    expect(screen.queryByText(/still queued or running/i)).not.toBeInTheDocument();
    expect((await axe.run(view.container, { rules: { "color-contrast": { enabled: false } } })).violations).toEqual([]);
  });

  it("labels a supported lockfile resolution without claiming an advisory result", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn((url: string) => {
        if (url.endsWith("/projects/project-1/analyses")) {
          return Promise.resolve(jsonResponse([project.latest_job]));
        }
        if (url.endsWith("/projects/project-1/components?analysis_id=analysis-1")) {
          return Promise.resolve(jsonResponse(lockfileInventory));
        }
        return Promise.resolve(jsonResponse({ detail: "Not found" }, 404));
      })
    );

    render(<ProjectComponentInventoryPanel project={project} />);

    expect(await screen.findByText(/supported lockfile resolutions/i)).toBeInTheDocument();
    expect(screen.getByText("Lockfile resolutions")).toBeInTheDocument();
    expect(screen.getByText(/1 supported lockfile was parsed/i)).toBeInTheDocument();
    expect(screen.getByText("^18.0.0 → 18.3.1")).toBeInTheDocument();
    expect(screen.getByText("Exact lockfile resolution")).toBeInTheDocument();
    expect(screen.getByText(/has not installed packages or queried vulnerability sources/i)).toBeInTheDocument();
  });

  it("explains accepted, truncated, and divergent Go graph evidence accessibly", async () => {
    for (const graphState of ["accepted", "truncated", "divergent"] as const) {
      const goInventory = {
        ...lockfileInventory,
        components: [{
          ...lockfileInventory.components[0],
          ecosystem: "go" as const,
          name: "golang.org/x/text",
          manifest_path: "service/go.mod",
          manifest_type: "go_mod" as const,
          lockfile_path: "service/go.sum",
          lockfile_type: "go_sum" as const,
          dependency_scope: graphState === "accepted" ? "transitive" as const : "direct" as const,
          relationship_status: graphState === "accepted" ? "reported" as const : "truncated" as const,
        }],
        dependency_graph: {
          contract_version: "2026-09-10.1" as const,
          ecosystem: "go" as const,
          state: graphState,
          reason: graphState === "accepted" ? "none" as const : graphState === "truncated" ? "producer_truncated" as const : "root_set_mismatch" as const,
          artifact_sha256: "a".repeat(64),
          source_commit_sha: "c".repeat(40),
          source_binding_verified: true as const,
          nodes_reported: 3,
          edges_reported: 2,
          components_matched: graphState === "divergent" ? 2 : 3,
          components_unmatched: graphState === "divergent" ? 1 : 0,
          cycles_detected: graphState === "truncated",
          truncation_reason: graphState === "truncated" ? "producer_limit" as const : null,
        },
      } satisfies ProjectComponentInventoryResponse;
      vi.stubGlobal("fetch", vi.fn((url: string) => {
        if (url.endsWith("/projects/project-1/analyses")) return Promise.resolve(jsonResponse([project.latest_job]));
        if (url.endsWith("/projects/project-1/components?analysis_id=analysis-1")) return Promise.resolve(jsonResponse(goInventory));
        return Promise.resolve(jsonResponse({ detail: "Not found" }, 404));
      }));
      const view = render(<ProjectComponentInventoryPanel project={project} />);
      expect(await screen.findByRole("heading", { name: "Go dependency graph" })).toBeInTheDocument();
      expect(screen.getAllByText(new RegExp(graphState, "i")).length).toBeGreaterThan(0);
      expect(screen.getByText(/Verified commit cccccccccccc/)).toBeInTheDocument();
      expect((await axe.run(view.container, { rules: { "color-contrast": { enabled: false } } })).violations).toEqual([]);
      cleanup();
      vi.unstubAllGlobals();
    }
  });

  it("presents Cargo relationship, feature, and target aggregates without raw dimensions", async () => {
    const cargoInventory = {
      ...lockfileInventory,
      components: [{
        ...lockfileInventory.components[0],
        ecosystem: "cargo" as const,
        name: "serde",
        manifest_path: "service/Cargo.toml",
        manifest_type: "cargo_toml" as const,
        lockfile_path: "service/Cargo.lock",
        lockfile_type: "cargo_lock" as const,
        dependency_scope: "direct" as const,
        relationship_status: "reported" as const,
        enabled_feature_count: 2,
        target_variant_count: 1,
      }],
      cargo_dependency_graph: {
        contract_version: "2026-09-10.2" as const,
        ecosystem: "cargo" as const,
        state: "accepted" as const,
        reason: "none" as const,
        artifact_sha256: "b".repeat(64),
        source_commit_sha: "d".repeat(40),
        source_binding_verified: true as const,
        target_coverage: "all_locked_targets" as const,
        nodes_reported: 2,
        edges_reported: 1,
        features_reported: 2,
        targets_reported: 1,
        components_matched: 2,
        components_unmatched: 0,
        cycles_detected: false,
        truncation_reason: null,
      },
    } satisfies ProjectComponentInventoryResponse;
    vi.stubGlobal("fetch", vi.fn((url: string) => {
      if (url.endsWith("/projects/project-1/analyses")) return Promise.resolve(jsonResponse([project.latest_job]));
      if (url.endsWith("/projects/project-1/components?analysis_id=analysis-1")) return Promise.resolve(jsonResponse(cargoInventory));
      return Promise.resolve(jsonResponse({ detail: "Not found" }, 404));
    }));
    const view = render(<ProjectComponentInventoryPanel project={project} />);
    expect(await screen.findByRole("heading", { name: "Cargo dependency graph" })).toBeInTheDocument();
    expect(screen.getByText(/2 enabled feature records/)).toBeInTheDocument();
    expect(screen.getByText(/2 enabled features · 1 target variant/)).toBeInTheDocument();
    expect(screen.queryByText("linux_x86_64")).not.toBeInTheDocument();
    expect((await axe.run(view.container, { rules: { "color-contrast": { enabled: false } } })).violations).toEqual([]);
  });

  it("presents Composer relationship evidence without asserting Packagist provenance", async () => {
    const composerInventory = {
      ...lockfileInventory,
      components: [{
        ...lockfileInventory.components[0], ecosystem: "composer" as const, name: "vendor/package",
        manifest_path: "composer.json", manifest_type: "composer_json" as const,
        lockfile_path: "composer.lock", lockfile_type: "composer_lock" as const,
        dependency_scope: "direct" as const, relationship_status: "reported" as const,
      }],
      composer_dependency_graph: {
        contract_version: "2026-09-10.3" as const, ecosystem: "composer" as const,
        state: "accepted" as const, reason: "none" as const,
        artifact_sha256: "e".repeat(64), source_commit_sha: "f".repeat(40),
        source_binding_verified: true as const, nodes_reported: 2, edges_reported: 1,
        components_matched: 2, components_unmatched: 0, cycles_detected: false, truncation_reason: null,
      },
    } satisfies ProjectComponentInventoryResponse;
    vi.stubGlobal("fetch", vi.fn((url: string) => {
      if (url.endsWith("/projects/project-1/analyses")) return Promise.resolve(jsonResponse([project.latest_job]));
      if (url.endsWith("/projects/project-1/components?analysis_id=analysis-1")) return Promise.resolve(jsonResponse(composerInventory));
      return Promise.resolve(jsonResponse({ detail: "Not found" }, 404));
    }));
    const view = render(<ProjectComponentInventoryPanel project={project} />);
    expect(await screen.findByRole("heading", { name: "Composer dependency graph" })).toBeInTheDocument();
    expect(screen.getByText(/Registry provenance remains unverified/)).toBeInTheDocument();
    expect(screen.getByText("Not attested by relationship evidence")).toBeInTheDocument();
    expect((await axe.run(view.container, { rules: { "color-contrast": { enabled: false } } })).violations).toEqual([]);
  });

  it("presents source-bound Gradle scopes without asserting Maven Central provenance", async () => {
    const gradleInventory = {
      ...lockfileInventory,
      components: [{
        ...lockfileInventory.components[0], ecosystem: "maven" as const, name: "org.example:package",
        manifest_path: "service/build.gradle.kts", manifest_type: "gradle_build" as const,
        lockfile_path: "service/gradle.lockfile", lockfile_type: "gradle_lock" as const,
        dependency_scope: "direct" as const, relationship_status: "reported" as const,
        build_scope_count: 2,
      }],
      gradle_dependency_graph: {
        contract_version: "2026-09-10.4" as const, ecosystem: "maven" as const, producer: "gradle" as const,
        state: "accepted" as const, reason: "none" as const,
        artifact_sha256: "a".repeat(64), source_commit_sha: "b".repeat(40),
        source_binding_verified: true as const, relationship_origin: "ci_reported" as const,
        scope_coverage: ["compile", "runtime"] as const, nodes_reported: 2, edges_reported: 1,
        scope_assignments_reported: 3, components_matched: 2, components_unmatched: 0,
        cycles_detected: false, truncation_reason: null,
      },
    } satisfies ProjectComponentInventoryResponse;
    vi.stubGlobal("fetch", vi.fn((url: string) => {
      if (url.endsWith("/projects/project-1/analyses")) return Promise.resolve(jsonResponse([project.latest_job]));
      if (url.endsWith("/projects/project-1/components?analysis_id=analysis-1")) return Promise.resolve(jsonResponse(gradleInventory));
      return Promise.resolve(jsonResponse({ detail: "Not found" }, 404));
    }));
    const view = render(<ProjectComponentInventoryPanel project={project} />);
    expect(await screen.findByRole("heading", { name: "Gradle dependency graph" })).toBeInTheDocument();
    expect(screen.getByText(/Compile, Runtime · 3 node assignments/)).toBeInTheDocument();
    expect(screen.getByText(/present in 2 covered build scopes/)).toBeInTheDocument();
    expect(screen.getByText("Not attested by relationship evidence")).toBeInTheDocument();
    expect((await axe.run(view.container, { rules: { "color-contrast": { enabled: false } } })).violations).toEqual([]);
  });

  it("presents source-bound NuGet target coverage without exposing framework names", async () => {
    const nugetInventory = {
      ...lockfileInventory,
      components: [{
        ...lockfileInventory.components[0], ecosystem: "nuget" as const, name: "newtonsoft.json",
        manifest_path: "service/App.csproj", manifest_type: "dotnet_project" as const,
        lockfile_path: "service/packages.lock.json", lockfile_type: "nuget_packages_lock" as const,
        dependency_scope: "direct" as const, relationship_status: "reported" as const,
        target_variant_count: 2,
      }],
      nuget_dependency_graph: {
        contract_version: "2026-09-10.5" as const, ecosystem: "nuget" as const, producer: "nuget" as const,
        state: "accepted" as const, reason: "none" as const,
        artifact_sha256: "c".repeat(64), source_commit_sha: "d".repeat(40),
        source_binding_verified: true as const, relationship_origin: "ci_reported" as const,
        target_coverage: "all_locked_targets" as const, targets_reported: 2,
        target_assignments_reported: 3, nodes_reported: 2, edges_reported: 1,
        components_matched: 2, components_unmatched: 0, cycles_detected: false, truncation_reason: null,
      },
    } satisfies ProjectComponentInventoryResponse;
    vi.stubGlobal("fetch", vi.fn((url: string) => {
      if (url.endsWith("/projects/project-1/analyses")) return Promise.resolve(jsonResponse([project.latest_job]));
      if (url.endsWith("/projects/project-1/components?analysis_id=analysis-1")) return Promise.resolve(jsonResponse(nugetInventory));
      return Promise.resolve(jsonResponse({ detail: "Not found" }, 404));
    }));
    const view = render(<ProjectComponentInventoryPanel project={project} />);
    expect(await screen.findByRole("heading", { name: "NuGet dependency graph" })).toBeInTheDocument();
    expect(screen.getByText(/2 opaque variants · 3 node assignments/)).toBeInTheDocument();
    expect(screen.getByText(/present in 2 opaque target variants/)).toBeInTheDocument();
    expect(screen.getByText("Not attested by relationship evidence")).toBeInTheDocument();
    expect(document.body).not.toHaveTextContent("net8.0");
    expect((await axe.run(view.container, { rules: { "color-contrast": { enabled: false } } })).violations).toEqual([]);
  });

  it("shows a pnpm v9 resolution as local-only and excludes it from public-advisory identity", async () => {
    const pnpmInventory = {
      ...lockfileInventory,
      summary: {
        ...lockfileInventory.summary,
        resolved_registry_components: 0,
        unverified_lockfile_components: 1,
      },
      components: [
        {
          ...lockfileInventory.components[0],
          package_url: null,
          correlation_eligible: false,
          lockfile_path: "apps/web/pnpm-lock.yaml",
          lockfile_type: "pnpm_lock" as const,
        },
      ],
      coverage_matrix: [
        {
          id: "npm-pnpm-lock",
          coverage_contract_version: "2026-09-05.1",
          ecosystem: "npm",
          manager: "pnpm",
          manifest: "package.json",
          lockfile: "pnpm-lock.yaml",
          parser_version: "pnpm-lock-yaml-v9",
          direct_coverage: "exact_same_root_local_only",
          transitive_coverage: "not_available",
          manifest_status: "parsed",
          lockfile_status: "parsed",
          exclusion_reason: "none",
        },
      ],
    } satisfies ProjectComponentInventoryResponse;
    vi.stubGlobal(
      "fetch",
      vi.fn((url: string) => {
        if (url.endsWith("/projects/project-1/analyses")) return Promise.resolve(jsonResponse([project.latest_job]));
        if (url.endsWith("/projects/project-1/components?analysis_id=analysis-1")) return Promise.resolve(jsonResponse(pnpmInventory));
        return Promise.resolve(jsonResponse({ detail: "Not found" }, 404));
      })
    );

    render(<ProjectComponentInventoryPanel project={project} />);

    expect(await screen.findByText("Local-only lockfile resolutions")).toBeInTheDocument();
    expect(screen.getByText("Exact local pnpm resolution")).toBeInTheDocument();
    expect(screen.getByText("Registry origin unverified; never sent to public advisories")).toBeInTheDocument();
    expect(screen.getByText(/Direct: Exact Same Root Local Only/)).toBeInTheDocument();
    expect(screen.queryByText(/Canonical package identity:/)).not.toBeInTheDocument();
  });

  it("shows a Yarn Classic resolution as local-only and retains no public identity", async () => {
    const yarnInventory = {
      ...lockfileInventory,
      summary: {
        ...lockfileInventory.summary,
        resolved_registry_components: 0,
        unverified_lockfile_components: 1,
      },
      components: [
        {
          ...lockfileInventory.components[0],
          package_url: null,
          correlation_eligible: false,
          lockfile_path: "apps/web/yarn.lock",
          lockfile_type: "yarn_classic_lock" as const,
        },
      ],
      coverage_matrix: [
        {
          id: "npm-yarn-lock",
          coverage_contract_version: "2026-09-05.1",
          ecosystem: "npm",
          manager: "yarn",
          manifest: "package.json",
          lockfile: "yarn.lock",
          parser_version: "yarn-classic-lock-v1",
          direct_coverage: "exact_same_root_local_only",
          transitive_coverage: "not_available",
          manifest_status: "parsed",
          lockfile_status: "parsed",
          exclusion_reason: "none",
        },
      ],
    } satisfies ProjectComponentInventoryResponse;
    vi.stubGlobal(
      "fetch",
      vi.fn((url: string) => {
        if (url.endsWith("/projects/project-1/analyses")) return Promise.resolve(jsonResponse([project.latest_job]));
        if (url.endsWith("/projects/project-1/components?analysis_id=analysis-1")) return Promise.resolve(jsonResponse(yarnInventory));
        return Promise.resolve(jsonResponse({ detail: "Not found" }, 404));
      })
    );

    render(<ProjectComponentInventoryPanel project={project} />);

    expect(await screen.findByText("Exact local Yarn Classic resolution")).toBeInTheDocument();
    expect(screen.getByText("Registry origin unverified; never sent to public advisories")).toBeInTheDocument();
    expect(screen.getByText("Parser: Yarn Classic Lock V1 · contract 2026-09-05.1")).toBeInTheDocument();
    expect(screen.queryByText(/Canonical package identity:/)).not.toBeInTheDocument();
  });

  it("shows a Poetry v2.1 resolution as local-only and never as a public advisory identity", async () => {
    const poetryInventory = {
      ...lockfileInventory,
      summary: { ...lockfileInventory.summary, resolved_registry_components: 0, unverified_lockfile_components: 1 },
      components: [{
        ...lockfileInventory.components[0],
        ecosystem: "pypi" as const,
        name: "requests",
        manifest_path: "services/api/pyproject.toml",
        manifest_type: "pyproject_toml" as const,
        declared_version: "^2.0",
        exact_version: "2.32.3",
        package_url: null,
        correlation_eligible: false,
        lockfile_path: "services/api/poetry.lock",
        lockfile_type: "poetry_lock" as const,
      }],
      coverage_matrix: [{
        id: "pypi-poetry-lock" as const,
        coverage_contract_version: "2026-09-06.2",
        ecosystem: "pypi" as const,
        manager: "poetry" as const,
        manifest: "pyproject.toml" as const,
        lockfile: "poetry.lock" as const,
        parser_version: "poetry-lock-toml-v2.1" as const,
        direct_coverage: "exact_same_root_local_only" as const,
        transitive_coverage: "not_available" as const,
        manifest_status: "parsed" as const,
        lockfile_status: "parsed" as const,
        exclusion_reason: "none" as const,
      }],
    } satisfies ProjectComponentInventoryResponse;
    vi.stubGlobal("fetch", vi.fn((url: string) => {
      if (url.endsWith("/projects/project-1/analyses")) return Promise.resolve(jsonResponse([project.latest_job]));
      if (url.endsWith("/projects/project-1/components?analysis_id=analysis-1")) return Promise.resolve(jsonResponse(poetryInventory));
      return Promise.resolve(jsonResponse({ detail: "Not found" }, 404));
    }));

    render(<ProjectComponentInventoryPanel project={project} />);

    expect(await screen.findByText("Exact local Poetry resolution")).toBeInTheDocument();
    expect(screen.getByText("Registry origin unverified; never sent to public advisories")).toBeInTheDocument();
    expect(screen.getByText(/Direct: Exact Same Root Local Only/)).toBeInTheDocument();
  });

  it("shows a Pipfile.lock v6 resolution and group as local-only", async () => {
    const pipfileInventory = {
      ...lockfileInventory,
      summary: { ...lockfileInventory.summary, resolved_registry_components: 0, unverified_lockfile_components: 1 },
      components: [{
        ...lockfileInventory.components[0],
        ecosystem: "pypi" as const,
        name: "pytest",
        manifest_path: "services/api/Pipfile",
        manifest_type: "pipfile" as const,
        dependency_group: "dev-packages",
        declared_version: "*",
        exact_version: "8.3.2",
        package_url: null,
        correlation_eligible: false,
        lockfile_path: "services/api/Pipfile.lock",
        lockfile_type: "pipfile_lock" as const,
      }],
      coverage_matrix: [{
        id: "pypi-pipfile-lock" as const,
        coverage_contract_version: "2026-09-09.5",
        ecosystem: "pypi" as const,
        manager: "pipenv" as const,
        manifest: "Pipfile" as const,
        lockfile: "Pipfile.lock" as const,
        parser_version: "pipfile-lock-json-v6" as const,
        direct_coverage: "exact_same_root_local_only" as const,
        transitive_coverage: "not_available" as const,
        manifest_status: "parsed" as const,
        lockfile_status: "parsed" as const,
        exclusion_reason: "none" as const,
      }],
    } satisfies ProjectComponentInventoryResponse;
    vi.stubGlobal("fetch", vi.fn((url: string) => {
      if (url.endsWith("/projects/project-1/analyses")) return Promise.resolve(jsonResponse([project.latest_job]));
      if (url.endsWith("/projects/project-1/components?analysis_id=analysis-1")) return Promise.resolve(jsonResponse(pipfileInventory));
      return Promise.resolve(jsonResponse({ detail: "Not found" }, 404));
    }));

    render(<ProjectComponentInventoryPanel project={project} />);

    expect(await screen.findByText("Exact local Pipenv resolution")).toBeInTheDocument();
    expect(document.body).toHaveTextContent("pypi · dev-packages · services/api/Pipfile");
    expect(screen.getByText("Registry origin unverified; never sent to public advisories")).toBeInTheDocument();
    expect(screen.getByText(/Parser: Pipfile Lock Json V6/)).toBeInTheDocument();
  });

  it("explains that aliases and non-registry sources stay local-only", async () => {
    const nonRegistryInventory = {
      ...inventory,
      summary: { ...inventory.summary, total_components: 3, not_correlatable_components: 1 },
      components: [
        ...inventory.components,
        {
          ...inventory.components[0],
          id: "component-alias",
          name: "workspace-alias",
          source_type: "alias" as const,
          declared_version: null,
          exact_version: null,
          package_url: null,
          version_status: "not_correlatable" as const,
          correlation_eligible: false,
          lockfile_match_status: "not_applicable" as const,
        },
      ],
    } satisfies ProjectComponentInventoryResponse;
    vi.stubGlobal(
      "fetch",
      vi.fn((url: string) => {
        if (url.endsWith("/projects/project-1/analyses")) return Promise.resolve(jsonResponse([project.latest_job]));
        if (url.endsWith("/projects/project-1/components?analysis_id=analysis-1")) return Promise.resolve(jsonResponse(nonRegistryInventory));
        return Promise.resolve(jsonResponse({ detail: "Not found" }, 404));
      })
    );

    render(<ProjectComponentInventoryPanel project={project} />);

    expect(await screen.findByText("workspace-alias")).toBeInTheDocument();
    expect(screen.getByText("Not queried (Alias)")).toBeInTheDocument();
    expect(screen.getByText(/Aliases, workspaces, VCS, URL, local and editable sources stay local-only/i)).toBeInTheDocument();
    expect(screen.getByText(/never turns them into a public package lookup/i)).toBeInTheDocument();
  });

  it("filters optional dependencies without presenting them as direct", async () => {
    const optionalInventory = {
      ...inventory,
      summary: { ...inventory.summary, total_components: 3, optional_registry_components: 1 },
      components: [
        ...inventory.components,
        {
          ...inventory.components[0],
          id: "component-optional",
          name: "fsevents",
          dependency_group: "optionalDependencies",
          dependency_scope: "optional" as const,
          declared_version: "2.3.3",
          exact_version: "2.3.3",
        },
      ],
    } satisfies ProjectComponentInventoryResponse;
    vi.stubGlobal(
      "fetch",
      vi.fn((url: string) => {
        if (url.endsWith("/projects/project-1/analyses")) return Promise.resolve(jsonResponse([project.latest_job]));
        if (url.endsWith("/projects/project-1/components?analysis_id=analysis-1")) return Promise.resolve(jsonResponse(optionalInventory));
        return Promise.resolve(jsonResponse({ detail: "Not found" }, 404));
      })
    );

    render(<ProjectComponentInventoryPanel project={project} />);
    expect(await screen.findByText("Optional dependencies")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Dependency scope"), { target: { value: "optional" } });

    expect(screen.getByText("fsevents")).toBeInTheDocument();
    expect(screen.getByText("Optional dependency")).toBeInTheDocument();
    expect(screen.queryByText("react")).not.toBeInTheDocument();
  });

  it("explains an ambiguous lockfile association without claiming a resolved version", async () => {
    const ambiguousInventory = {
      ...lockfileInventory,
      summary: {
        ...lockfileInventory.summary,
        resolved_registry_components: 0,
        matched_lockfile_components: 0,
        ambiguous_lockfile_components: 1,
        resolution: "declared_and_lockfile" as const,
      },
      components: [
        {
          ...lockfileInventory.components[0],
          exact_version: null,
          version_status: "declared_range" as const,
          correlation_eligible: false,
          resolution: "declared" as const,
          lockfile_match_status: "ambiguous" as const,
          lockfile_path: null,
          lockfile_path_status: "not_reported" as const,
          lockfile_type: null,
        }
      ]
    } satisfies ProjectComponentInventoryResponse;
    vi.stubGlobal(
      "fetch",
      vi.fn((url: string) => {
        if (url.endsWith("/projects/project-1/analyses")) {
          return Promise.resolve(jsonResponse([project.latest_job]));
        }
        if (url.endsWith("/projects/project-1/components?analysis_id=analysis-1")) {
          return Promise.resolve(jsonResponse(ambiguousInventory));
        }
        return Promise.resolve(jsonResponse({ detail: "Not found" }, 404));
      })
    );

    render(<ProjectComponentInventoryPanel project={project} />);

    expect(await screen.findByText("Lockfile association: Ambiguous")).toBeInTheDocument();
    expect(screen.getByText(/1 component has an ambiguous lockfile association/i)).toBeInTheDocument();
    expect(screen.queryByText("Exact lockfile resolution")).not.toBeInTheDocument();
  });

  it("shows bounded transitive lockfile coverage without an advisory claim", async () => {
    const transitiveInventory = {
      ...lockfileInventory,
      summary: {
        ...lockfileInventory.summary,
        total_components: 2,
        transitive_registry_components: 1,
        lockfile_graph_truncated: true,
      },
      components: [
        ...lockfileInventory.components,
        {
          ...lockfileInventory.components[0],
          id: "component-transitive",
          name: "scheduler",
          declared_version: null,
          exact_version: "0.23.2",
          package_url: "pkg:npm/scheduler@0.23.2",
          dependency_group: "transitive",
          dependency_scope: "transitive" as const,
        }
      ]
    } satisfies ProjectComponentInventoryResponse;
    vi.stubGlobal(
      "fetch",
      vi.fn((url: string) => {
        if (url.endsWith("/projects/project-1/analyses")) {
          return Promise.resolve(jsonResponse([project.latest_job]));
        }
        if (url.endsWith("/projects/project-1/components?analysis_id=analysis-1")) {
          return Promise.resolve(jsonResponse(transitiveInventory));
        }
        return Promise.resolve(jsonResponse({ detail: "Not found" }, 404));
      })
    );

    render(<ProjectComponentInventoryPanel project={project} />);

    expect(await screen.findByText("Transitive resolutions")).toBeInTheDocument();
    expect(screen.getByText("Exact transitive resolution")).toBeInTheDocument();
    expect(screen.getByText(/transitive dependency/i)).toBeInTheDocument();
    expect(screen.getByText(/dependency graph reached a defensive node or edge limit/i)).toBeInTheDocument();
    expect(screen.getByText(/has not installed packages or queried vulnerability sources/i)).toBeInTheDocument();
  });

  it("does not present missing or truncated SBOM relationships as known dependency scope", async () => {
    const uncertainInventory = {
      ...lockfileInventory,
      summary: {
        ...lockfileInventory.summary,
        total_components: 2,
        relationship_reported_components: 0,
        relationship_not_reported_components: 1,
        relationship_truncated_components: 1,
      },
      components: [
        { ...lockfileInventory.components[0], id: "unknown", relationship_status: "not_reported" as const },
        { ...lockfileInventory.components[0], id: "truncated", name: "scheduler", relationship_status: "truncated" as const },
      ],
    } satisfies ProjectComponentInventoryResponse;
    vi.stubGlobal("fetch", vi.fn((url: string) => {
      if (url.endsWith("/projects/project-1/analyses")) return Promise.resolve(jsonResponse([project.latest_job]));
      if (url.endsWith("/projects/project-1/components?analysis_id=analysis-1")) return Promise.resolve(jsonResponse(uncertainInventory));
      return Promise.resolve(jsonResponse({ detail: "Not found" }, 404));
    }));

    render(<ProjectComponentInventoryPanel project={project} />);

    expect(await screen.findByText(/scope unknown; relationship not reported/i)).toBeInTheDocument();
    expect(screen.getByText(/scope inconclusive; relationship graph truncated/i)).toBeInTheDocument();
    expect(screen.getByText(/direct or transitive scope is unknown/i)).toBeInTheDocument();
    expect(screen.getByText(/scope-dependent conclusions are inconclusive/i)).toBeInTheDocument();
    expect(screen.queryByText("Exact transitive resolution")).not.toBeInTheDocument();
  });

  it("makes package-manager and lockfile coverage explicit without exposing a retained path", async () => {
    const matrixInventory = {
      ...lockfileInventory,
      coverage_matrix: [
        {
          id: "npm-package-lock",
          coverage_contract_version: "2026-09-05.1",
          ecosystem: "npm",
          manager: "npm",
          manifest: "package.json",
          lockfile: "package-lock.json",
          parser_version: "package-lock-json-v2-v3",
          direct_coverage: "exact_same_root_when_matched",
          transitive_coverage: "bounded_registry_graph",
          manifest_status: "parsed",
          lockfile_status: "parsed",
          exclusion_reason: "graph_truncated",
        },
        {
          id: "npm-pnpm-lock",
          coverage_contract_version: "2026-09-05.1",
          ecosystem: "npm",
          manager: "pnpm",
          manifest: "package.json",
          lockfile: "pnpm-lock.yaml",
          parser_version: "not_available",
          direct_coverage: "declared_manifest_only",
          transitive_coverage: "not_available",
          manifest_status: "parsed",
          lockfile_status: "detected_not_parsed",
          exclusion_reason: "unsupported_lockfile_parser",
        },
      ],
    } satisfies ProjectComponentInventoryResponse;
    vi.stubGlobal(
      "fetch",
      vi.fn((url: string) => {
        if (url.endsWith("/projects/project-1/analyses")) return Promise.resolve(jsonResponse([project.latest_job]));
        if (url.endsWith("/projects/project-1/components?analysis_id=analysis-1")) return Promise.resolve(jsonResponse(matrixInventory));
        return Promise.resolve(jsonResponse({ detail: "Not found" }, 404));
      })
    );

    render(<ProjectComponentInventoryPanel project={project} />);

    expect(await screen.findByRole("heading", { name: "Package manager coverage" })).toBeInTheDocument();
    expect(screen.getByText(/Detected, not parsed.*means Inspectra saw a known file/i)).toBeInTheDocument();
    expect(screen.getByText("Parser: Package Lock Json V2 V3 · contract 2026-09-05.1")).toBeInTheDocument();
    expect(screen.getByText("Lockfile: Detected, not parsed")).toBeInTheDocument();
    expect(screen.getByText(/this lockfile format is visible but not parsed yet/i)).toBeInTheDocument();
    expect(screen.queryByText(/private\/team/)).not.toBeInTheDocument();
  });

  it("continues a bounded analysis history before opening an older inventory", async () => {
    const older = {
      ...project.latest_job!,
      id: "analysis-old",
      source_reference: "snapshot-bbbbbbbbbbbbbbbb",
      created_at: "2026-08-01T09:00:00Z",
      updated_at: "2026-08-01T09:01:00Z",
    };
    const recent = Array.from({ length: 50 }, (_, index) => ({
      ...project.latest_job!,
      id: index === 0 ? "analysis-1" : `analysis-recent-${index}`,
      created_at: new Date(Date.parse(project.latest_job!.created_at) - index * 1_000).toISOString(),
      updated_at: new Date(Date.parse(project.latest_job!.updated_at) - index * 1_000).toISOString(),
    }));
    vi.stubGlobal("fetch", vi.fn((url: string, init?: RequestInit) => {
      if (url.endsWith("/projects/project-1/analyses/search")) {
        const body = JSON.parse(String(init?.body));
        return Promise.resolve(jsonResponse(body.cursor
          ? { contract_version: "2026-09-08.1", items: [older], returned_count: 1, total_count: 51, has_more: false, next_cursor: null }
          : { contract_version: "2026-09-08.1", items: recent, returned_count: 50, total_count: 51, has_more: true, next_cursor: "older-page" }));
      }
      if (url.includes("/components?analysis_id=analysis-old")) {
        return Promise.resolve(jsonResponse({ ...inventory, analysis: older, components: [] }));
      }
      if (url.includes("/components?analysis_id=analysis-1")) return Promise.resolve(jsonResponse(inventory));
      return Promise.resolve(jsonResponse({ detail: "Not found" }, 404));
    }));

    render(<ProjectComponentInventoryPanel project={project} />);

    expect(await screen.findByText("Showing 50 of 51 retained analyses in this selector.")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Load older analyses" }));
    expect(await screen.findByRole("button", { name: "All retained analyses loaded" })).toBeDisabled();
    fireEvent.change(screen.getByLabelText("Analysis snapshot"), { target: { value: "analysis-old" } });
    await waitFor(() => expect(screen.getByLabelText("Analysis snapshot")).toHaveValue("analysis-old"));
  });

  it("explains Go module coverage and its operator-attestation boundary", async () => {
    const goInventory = {
      ...inventory,
      summary: { ...inventory.summary, total_components: 1, parsed_lockfile_count: 1, resolution: "declared_and_lockfile" as const },
      components: [{
        ...inventory.components[0],
        id: "go-text",
        ecosystem: "go" as const,
        name: "golang.org/x/text",
        manifest_path: "services/api/go.mod",
        dependency_group: "require",
        declared_version: "v0.19.0",
        exact_version: "v0.19.0",
        package_url: "pkg:golang/golang.org/x/text@v0.19.0",
        version_status: "exact_resolved" as const,
        resolution: "lockfile" as const,
        lockfile_match_status: "matched" as const,
        manifest_type: "go_mod" as const,
        lockfile_path: "services/api/go.sum",
        lockfile_path_status: "reported" as const,
        lockfile_type: "go_sum" as const,
      }],
      coverage_matrix: [{
        id: "go-mod-sum" as const,
        coverage_contract_version: "2026-09-09.1",
        ecosystem: "go" as const,
        manager: "go-modules" as const,
        manifest: "go.mod" as const,
        lockfile: "go.sum" as const,
        parser_version: "go-mod-sum-v1" as const,
        direct_coverage: "exact_same_root_local_only" as const,
        transitive_coverage: "not_available" as const,
        manifest_status: "parsed" as const,
        lockfile_status: "parsed" as const,
        exclusion_reason: "none" as const,
      }],
    } satisfies ProjectComponentInventoryResponse;
    vi.stubGlobal("fetch", vi.fn((url: string) => {
      if (url.endsWith("/projects/project-1/analyses")) return Promise.resolve(jsonResponse([project.latest_job]));
      if (url.endsWith("/projects/project-1/components?analysis_id=analysis-1")) return Promise.resolve(jsonResponse(goInventory));
      return Promise.resolve(jsonResponse({ detail: "Not found" }, 404));
    }));

    render(<ProjectComponentInventoryPanel project={project} />);

    expect(await screen.findByText("golang.org/x/text")).toBeInTheDocument();
    expect(screen.getByText("Exact local Go module resolution")).toBeInTheDocument();
    expect(screen.getByText("Public origin requires an exact operator attestation")).toBeInTheDocument();
    expect(screen.getByText(/go-modules/i)).toBeInTheDocument();
    expect(screen.getByText(/pkg:golang\/golang.org\/x\/text@v0.19.0/i)).toBeInTheDocument();
  });

  it("explains Cargo coverage and the fixed crates.io provenance boundary", async () => {
    const cargoInventory = {
      ...inventory,
      summary: { ...inventory.summary, total_components: 1, parsed_lockfile_count: 1, resolution: "declared_and_lockfile" as const },
      components: [{
        ...inventory.components[0],
        id: "cargo-serde",
        ecosystem: "cargo" as const,
        name: "serde",
        manifest_path: "services/rust/Cargo.toml",
        dependency_group: "dependencies",
        declared_version: "1",
        exact_version: "1.0.210",
        package_url: "pkg:cargo/serde@1.0.210",
        version_status: "exact_resolved" as const,
        resolution: "lockfile" as const,
        lockfile_match_status: "matched" as const,
        manifest_type: "cargo_toml" as const,
        lockfile_path: "services/rust/Cargo.lock",
        lockfile_path_status: "reported" as const,
        lockfile_type: "cargo_lock" as const,
      }],
      coverage_matrix: [{
        id: "cargo-lock" as const,
        coverage_contract_version: "2026-09-09.1",
        ecosystem: "cargo" as const,
        manager: "cargo" as const,
        manifest: "Cargo.toml" as const,
        lockfile: "Cargo.lock" as const,
        parser_version: "cargo-lock-toml-v3-v4" as const,
        direct_coverage: "exact_same_root_when_matched" as const,
        transitive_coverage: "bounded_registry_graph" as const,
        manifest_status: "parsed" as const,
        lockfile_status: "parsed" as const,
        exclusion_reason: "none" as const,
      }],
    } satisfies ProjectComponentInventoryResponse;
    vi.stubGlobal("fetch", vi.fn((url: string) => {
      if (url.endsWith("/projects/project-1/analyses")) return Promise.resolve(jsonResponse([project.latest_job]));
      if (url.endsWith("/projects/project-1/components?analysis_id=analysis-1")) return Promise.resolve(jsonResponse(cargoInventory));
      return Promise.resolve(jsonResponse({ detail: "Not found" }, 404));
    }));

    render(<ProjectComponentInventoryPanel project={project} />);

    expect(await screen.findByText("serde")).toBeInTheDocument();
    expect(screen.getByText("Exact Cargo.lock resolution")).toBeInTheDocument();
    expect(screen.getByText("Official crates.io source proven by the supported lockfile")).toBeInTheDocument();
    expect(screen.getByText(/Cargo Lock Toml V3 V4/i)).toBeInTheDocument();
    expect(screen.getByText(/pkg:cargo\/serde@1.0.210/i)).toBeInTheDocument();
  });

  it("explains Composer coverage and its explicit Packagist attestation boundary", async () => {
    const composerInventory = {
      ...inventory,
      summary: { ...inventory.summary, total_components: 1, parsed_lockfile_count: 1, unverified_lockfile_components: 1, resolution: "declared_and_lockfile" as const },
      components: [{
        ...inventory.components[0],
        id: "composer-symfony",
        ecosystem: "composer" as const,
        name: "symfony/http-foundation",
        manifest_path: "services/php/composer.json",
        dependency_group: "require",
        declared_version: "^7.1",
        exact_version: "7.1.3",
        package_url: "pkg:composer/symfony/http-foundation@7.1.3",
        version_status: "exact_resolved" as const,
        resolution: "lockfile" as const,
        lockfile_match_status: "matched" as const,
        manifest_type: "composer_json" as const,
        lockfile_path: "services/php/composer.lock",
        lockfile_path_status: "reported" as const,
        lockfile_type: "composer_lock" as const,
      }],
      coverage_matrix: [{
        id: "composer-lock" as const,
        coverage_contract_version: "2026-09-09.1",
        ecosystem: "composer" as const,
        manager: "composer" as const,
        manifest: "composer.json" as const,
        lockfile: "composer.lock" as const,
        parser_version: "composer-lock-json-v1" as const,
        direct_coverage: "exact_same_root_local_only" as const,
        transitive_coverage: "bounded_registry_graph" as const,
        manifest_status: "parsed" as const,
        lockfile_status: "parsed" as const,
        exclusion_reason: "none" as const,
      }],
    } satisfies ProjectComponentInventoryResponse;
    vi.stubGlobal("fetch", vi.fn((url: string) => {
      if (url.endsWith("/projects/project-1/analyses")) return Promise.resolve(jsonResponse([project.latest_job]));
      if (url.endsWith("/projects/project-1/components?analysis_id=analysis-1")) return Promise.resolve(jsonResponse(composerInventory));
      return Promise.resolve(jsonResponse({ detail: "Not found" }, 404));
    }));

    render(<ProjectComponentInventoryPanel project={project} />);

    expect(await screen.findByText("symfony/http-foundation")).toBeInTheDocument();
    expect(screen.getByText("Exact local Composer resolution")).toBeInTheDocument();
    expect(screen.getByText("Packagist origin requires an exact operator attestation")).toBeInTheDocument();
    expect(screen.getByText(/Composer Lock Json V1/i)).toBeInTheDocument();
    expect(screen.getByText(/pkg:composer\/symfony\/http-foundation@7.1.3/i)).toBeInTheDocument();
  });

  it("presents Gradle lock coverage without claiming direct scope or Maven origin", async () => {
    const gradleInventory = {
      ...inventory,
      summary: { ...inventory.summary, total_components: 1, parsed_lockfile_count: 1, transitive_registry_components: 1, relationship_not_reported_components: 1, resolution: "declared_and_lockfile" as const },
      components: [{ ...inventory.components[0], id: "maven-lang3", ecosystem: "maven" as const, name: "org.apache.commons:commons-lang3", manifest_path: "services/jvm/build.gradle.kts", dependency_group: "locked", declared_version: null, exact_version: "3.14.0", package_url: "pkg:maven/org.apache.commons/commons-lang3@3.14.0", dependency_scope: "transitive" as const, relationship_status: "not_reported" as const, version_status: "exact_resolved" as const, resolution: "lockfile" as const, lockfile_match_status: "matched" as const, manifest_type: "gradle_build" as const, lockfile_path: "services/jvm/gradle.lockfile", lockfile_path_status: "reported" as const, lockfile_type: "gradle_lock" as const }],
      coverage_matrix: [{ id: "gradle-lock" as const, coverage_contract_version: "2026-09-09.3", ecosystem: "maven" as const, manager: "gradle" as const, manifest: "build.gradle" as const, lockfile: "gradle.lockfile" as const, parser_version: "gradle-lockfile-v1" as const, direct_coverage: "not_available" as const, transitive_coverage: "bounded_registry_graph" as const, manifest_status: "parsed" as const, lockfile_status: "parsed" as const, exclusion_reason: "none" as const }],
    } satisfies ProjectComponentInventoryResponse;
    vi.stubGlobal("fetch", vi.fn((url: string) => url.endsWith("/projects/project-1/analyses") ? Promise.resolve(jsonResponse([project.latest_job])) : url.endsWith("/projects/project-1/components?analysis_id=analysis-1") ? Promise.resolve(jsonResponse(gradleInventory)) : Promise.resolve(jsonResponse({}, 404))));
    render(<ProjectComponentInventoryPanel project={project} />);
    expect(await screen.findByText("org.apache.commons:commons-lang3")).toBeInTheDocument();
    expect(screen.getByText("Exact version; scope unknown")).toBeInTheDocument();
    expect(screen.getByText("Maven origin requires an exact operator attestation")).toBeInTheDocument();
    expect(screen.getByText(/scope unknown; relationship not reported/i)).toBeInTheDocument();
  });

  it("presents NuGet direct, ambiguous and local-project outcomes without claiming NuGet.org origin", async () => {
    const nugetInventory = {
      ...inventory,
      summary: { ...inventory.summary, total_components: 3, parsed_lockfile_count: 1, unverified_lockfile_components: 1, relationship_not_reported_components: 2, resolution: "declared_and_lockfile" as const },
      components: [
        { ...inventory.components[0], id: "nuget-public", ecosystem: "nuget" as const, name: "newtonsoft.json", manifest_path: "services/dotnet/App.csproj", dependency_group: "locked", declared_version: null, exact_version: "13.0.3", package_url: "pkg:nuget/newtonsoft.json@13.0.3", dependency_scope: "direct" as const, relationship_status: "reported" as const, version_status: "exact_resolved" as const, resolution: "lockfile" as const, lockfile_match_status: "matched" as const, manifest_type: "dotnet_project" as const, lockfile_path: "services/dotnet/packages.lock.json", lockfile_path_status: "reported" as const, lockfile_type: "nuget_packages_lock" as const },
        { ...inventory.components[0], id: "nuget-local", ecosystem: "nuget" as const, name: "private.project", source_type: "local" as const, manifest_path: "services/dotnet/App.csproj", dependency_group: "locked", declared_version: null, exact_version: "1.0.0", package_url: null, dependency_scope: "transitive" as const, relationship_status: "not_reported" as const, version_status: "not_correlatable" as const, correlation_eligible: false, resolution: "lockfile" as const, lockfile_match_status: "matched" as const, manifest_type: "dotnet_project" as const, lockfile_path: "services/dotnet/packages.lock.json", lockfile_path_status: "reported" as const, lockfile_type: "nuget_packages_lock" as const },
        { ...inventory.components[0], id: "nuget-ambiguous", ecosystem: "nuget" as const, name: "ambiguous.package", source_type: "unknown" as const, manifest_path: "services/dotnet/App.csproj", dependency_group: "locked", declared_version: null, exact_version: null, package_url: null, dependency_scope: "transitive" as const, relationship_status: "not_reported" as const, version_status: "not_correlatable" as const, correlation_eligible: false, resolution: "lockfile" as const, lockfile_match_status: "matched" as const, manifest_type: "dotnet_project" as const, lockfile_path: "services/dotnet/packages.lock.json", lockfile_path_status: "reported" as const, lockfile_type: "nuget_packages_lock" as const },
      ],
      coverage_matrix: [{ id: "nuget-packages-lock" as const, coverage_contract_version: "2026-09-09.4", ecosystem: "nuget" as const, manager: "nuget" as const, manifest: "*.csproj" as const, lockfile: "packages.lock.json" as const, parser_version: "nuget-packages-lock-json-v1" as const, direct_coverage: "exact_same_root_local_only" as const, transitive_coverage: "bounded_registry_graph" as const, manifest_status: "parsed" as const, lockfile_status: "parsed" as const, exclusion_reason: "none" as const }],
    } satisfies ProjectComponentInventoryResponse;
    vi.stubGlobal("fetch", vi.fn((url: string) => url.endsWith("/projects/project-1/analyses") ? Promise.resolve(jsonResponse([project.latest_job])) : url.endsWith("/projects/project-1/components?analysis_id=analysis-1") ? Promise.resolve(jsonResponse(nugetInventory)) : Promise.resolve(jsonResponse({}, 404))));
    render(<ProjectComponentInventoryPanel project={project} />);
    expect(await screen.findByText("newtonsoft.json")).toBeInTheDocument();
    expect(screen.getByText("Exact local NuGet lock resolution")).toBeInTheDocument();
    expect(screen.getAllByText("NuGet.org origin requires an exact operator attestation").length).toBeGreaterThan(0);
    expect(screen.getByText("No correlatable exact version")).toBeInTheDocument();
    expect(document.body.textContent).not.toContain("net8.0");
  });
});
