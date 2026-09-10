import { ChangeEvent, FormEvent, lazy, ReactNode, Suspense, useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Activity,
  Download,
  Eye,
  FilePlus2,
  FolderPlus,
  Globe2,
  LogOut,
  Network,
  Play,
  RefreshCw,
  ShieldCheck,
  Trash2,
  UploadCloud
} from "lucide-react";

import { ApiError, api } from "./api";
import { redactActiveDryRunText } from "./activeDryRunReport";
import { ActiveDnsInventoryPanel } from "./ActiveDnsInventoryPanel";
import { redactActiveDnsInventoryText } from "./activeDnsInventoryReport";
import { ActiveDnsOsintPanel } from "./ActiveDnsOsintPanel";
import { redactActiveDnsOsintText } from "./activeDnsOsintReport";
import { redactActiveHttpHeaderProbeText } from "./activeHttpHeaderProbeReport";
import { ActiveHttpBasicHeaderReviewPanel } from "./ActiveHttpBasicHeaderReviewPanel";
import { redactActiveHttpBasicHeaderReviewText } from "./activeHttpBasicHeaderReviewReport";
import { ActiveNmapBasicPanel } from "./ActiveNmapBasicPanel";
import { redactActiveNmapBasicText } from "./activeNmapBasicReport";
import { ActiveTlsBasicPanel } from "./ActiveTlsBasicPanel";
import { ProjectArchivePreflight } from "./ProjectArchivePreflight";
import { redactActiveTlsBasicText } from "./activeTlsBasicReport";
import {
  auditTypeCategoryLabel,
  auditTypeLabel,
  buildDashboardMetrics,
  fileKindLabel,
  filterFiles,
  filterJobs,
  JOB_TYPE_FILTERS,
  statusLabel,
  type FileKindFilter,
  type JobStatusFilter,
  type JobTypeFilter
} from "./dashboardFilters";
import type {
  ActiveDryRunRequest,
  ActiveHttpHeaderProbeRequest,
  AuthStatusResponse,
  FileRecord,
  HealthResponse,
  JobListItem,
  JobRecord,
  ProjectDeletionResponse,
  ProjectSummary,
  ReportFormat,
  SbomFormat
} from "./types";
import { inspectWebUrlQuery } from "./webUrl";

const JobResultReport = lazy(() => import("./JobResultReport"));
const ProjectComponentInventoryPanel = lazy(() =>
  import("./ProjectComponentInventoryPanel").then((module) => ({ default: module.ProjectComponentInventoryPanel }))
);
const ProjectComparisonPanel = lazy(() =>
  import("./ProjectComparisonPanel").then((module) => ({ default: module.ProjectComparisonPanel }))
);
const ProjectFindingsPanel = lazy(() =>
  import("./ProjectFindingsPanel").then((module) => ({ default: module.ProjectFindingsPanel }))
);
const ProjectSnapshotForm = lazy(() =>
  import("./ProjectSnapshotForm").then((module) => ({ default: module.ProjectSnapshotForm }))
);
const ProjectWorkspacePanel = lazy(() =>
  import("./ProjectWorkspacePanel").then((module) => ({ default: module.ProjectWorkspacePanel }))
);
const ProjectDeletionPanel = lazy(() =>
  import("./ProjectDeletionPanel").then((module) => ({ default: module.ProjectDeletionPanel }))
);
const TeamInvitationAcceptance = lazy(() =>
  import("./TeamInvitationAcceptance").then((module) => ({ default: module.TeamInvitationAcceptance }))
);
const TeamWorkspacePanel = lazy(() =>
  import("./TeamWorkspacePanel").then((module) => ({ default: module.TeamWorkspacePanel }))
);
const ProductAuditPanel = lazy(() =>
  import("./ProductAuditPanel").then((module) => ({ default: module.ProductAuditPanel }))
);
const RetentionPolicyPanel = lazy(() =>
  import("./RetentionPolicyPanel").then((module) => ({ default: module.RetentionPolicyPanel }))
);
const AutomationTokensPanel = lazy(() =>
  import("./AutomationTokensPanel").then((module) => ({ default: module.AutomationTokensPanel }))
);
const SbomImportPanel = lazy(() =>
  import("./SbomImportPanel").then((module) => ({ default: module.SbomImportPanel }))
);
const ProjectStartGuide = lazy(() =>
  import("./ProjectStartGuide").then((module) => ({ default: module.ProjectStartGuide }))
);
const ProjectPortfolioPanel = lazy(() =>
  import("./ProjectPortfolioPanel").then((module) => ({ default: module.ProjectPortfolioPanel }))
);
const ProjectActionInboxPanel = lazy(() =>
  import("./ProjectActionInboxPanel").then((module) => ({ default: module.ProjectActionInboxPanel }))
);
const RemediationCenterPanel = lazy(() =>
  import("./RemediationCenterPanel").then((module) => ({ default: module.RemediationCenterPanel }))
);
const ProjectRiskTrendsPanel = lazy(() =>
  import("./ProjectRiskTrendsPanel").then((module) => ({ default: module.ProjectRiskTrendsPanel }))
);
const ActiveOperationsCenter = lazy(() =>
  import("./ActiveOperationsCenter").then((module) => ({ default: module.ActiveOperationsCenter }))
);

type LoadState = {
  loading: boolean;
  error: string | null;
};

const initialLoadState: LoadState = { loading: false, error: null };
const ARCHIVE_ACTION_SCOPE_COPY =
  "Passive review: no execution, traffic, credential checks, or CVE query.";
const LOCAL_ALPHA_DEMO_COPY =
  "Optional local demo: manually select one synthetic archive from the synthetic fixtures in tests/fixtures/demo/passive-alpha/ to try the archive flow. Inspectra never reads or uploads a fixture automatically. Do not upload real secrets or production archives for demos.";
const LOCAL_ALPHA_DEMO_REDACTION_COPY =
  "Expect passive review indicators and [REDACTED], not a CVE or exploitability claim. Results redact [REDACTED]; original upload unchanged until you delete it. When finished, delete the uploaded fixture from Files and any demo jobs you do not need; retained project metadata follows its documented retention policy.";
const ACTIVE_DRY_RUN_AUTHORIZATION_STATEMENT = "I confirm I own or am authorized to test this target.";
const ACTIVE_HTTP_HEADER_PROBE_LIVE_TRAFFIC_STATEMENT = "I understand this will send one HTTP HEAD request to the target.";
const AUTH_SESSION_EXPIRED_MESSAGE = "Session expired. Sign in again.";
const AUTH_CSRF_FAILED_MESSAGE = "Session verification failed. Sign in again.";
const AUTH_RATE_LIMIT_MESSAGE = "Too many attempts. Try again later.";

const initialAuthStatus: AuthStatusResponse = {
  auth_mode: "trusted_local_no_auth",
  auth_required: false,
  configured: false,
  trusted_local: true,
  default_operator_id: "local-admin",
  login_available: false,
  authenticated: false,
  operator_id: null,
  username: null,
  organization_id: null,
  organization_name: null,
  role: null,
  csrf_required: false,
  csrf_token: null
};

type ArchiveAction = {
  label: string;
  onClick: () => void;
  disabled?: boolean;
};

type ArchiveActionGroup = {
  label: string;
  actions: ArchiveAction[];
};

type WorkflowStage = "prepare" | "run" | "monitor" | "review";

export function App() {
  const authFailureHandlerRef = useRef<(status: number) => void>(() => undefined);
  const [authStatus, setAuthStatus] = useState<AuthStatusResponse>(initialAuthStatus);
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [files, setFiles] = useState<FileRecord[]>([]);
  const [projects, setProjects] = useState<ProjectSummary[]>([]);
  const [projectsTotalCount, setProjectsTotalCount] = useState(0);
  const [projectsNextCursor, setProjectsNextCursor] = useState<string | null>(null);
  const [jobs, setJobs] = useState<JobListItem[]>([]);
  const [jobsTotalCount, setJobsTotalCount] = useState(0);
  const [jobsNextCursor, setJobsNextCursor] = useState<string | null>(null);
  const [selectedJob, setSelectedJob] = useState<JobRecord | null>(null);
  const [selectedProject, setSelectedProject] = useState<ProjectSummary | null>(null);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [authState, setAuthState] = useState<LoadState>(initialLoadState);
  const [uploadKind, setUploadKind] = useState<FileRecord["kind"]>("pdf");
  const [healthState, setHealthState] = useState<LoadState>(initialLoadState);
  const [filesState, setFilesState] = useState<LoadState>(initialLoadState);
  const [projectsState, setProjectsState] = useState<LoadState>(initialLoadState);
  const [jobsState, setJobsState] = useState<LoadState>(initialLoadState);
  const [uploadState, setUploadState] = useState<LoadState>(initialLoadState);
  const [loginPassword, setLoginPassword] = useState("");
  const [loginUsername, setLoginUsername] = useState("");
  const [loginState, setLoginState] = useState<LoadState>(initialLoadState);
  const [logoutState, setLogoutState] = useState<LoadState>(initialLoadState);
  const [actionError, setActionError] = useState<string | null>(null);
  const [creatingProjectFileId, setCreatingProjectFileId] = useState<string | null>(null);
  const [projectAuthorizationConfirmedFileId, setProjectAuthorizationConfirmedFileId] = useState<string | null>(null);
  const [snapshotProjectId, setSnapshotProjectId] = useState<string | null>(null);
  const [ciSetupProjectId, setCiSetupProjectId] = useState<string | null>(null);
  const [rerunningProjectId, setRerunningProjectId] = useState<string | null>(null);
  const [fileKindFilter, setFileKindFilter] = useState<FileKindFilter>("all");
  const [fileSearch, setFileSearch] = useState("");
  const [jobStatusFilter, setJobStatusFilter] = useState<JobStatusFilter>("all");
  const [jobTypeFilter, setJobTypeFilter] = useState<JobTypeFilter>("all");
  const [jobSearch, setJobSearch] = useState("");
  const [webUrl, setWebUrl] = useState("");
  const [webAuthorizationConfirmed, setWebAuthorizationConfirmed] = useState(false);
  const [webAuditState, setWebAuditState] = useState<LoadState>(initialLoadState);
  const [domainName, setDomainName] = useState("");
  const [domainAuthorizationConfirmed, setDomainAuthorizationConfirmed] = useState(false);
  const [domainAuditState, setDomainAuditState] = useState<LoadState>(initialLoadState);
  const [subdomainRootDomain, setSubdomainRootDomain] = useState("");
  const [subdomainCandidates, setSubdomainCandidates] = useState("");
  const [subdomainAuthorizationConfirmed, setSubdomainAuthorizationConfirmed] = useState(false);
  const [subdomainAuditState, setSubdomainAuditState] = useState<LoadState>(initialLoadState);
  const [activeDryRunTarget, setActiveDryRunTarget] = useState("");
  const [activeDryRunAuthorizationConfirmed, setActiveDryRunAuthorizationConfirmed] = useState(false);
  const [activeDryRunState, setActiveDryRunState] = useState<LoadState>(initialLoadState);
  const [activeHttpHeaderProbeTarget, setActiveHttpHeaderProbeTarget] = useState("");
  const [activeHttpHeaderProbeAuthorizationConfirmed, setActiveHttpHeaderProbeAuthorizationConfirmed] = useState(false);
  const [activeHttpHeaderProbeLiveTrafficConfirmed, setActiveHttpHeaderProbeLiveTrafficConfirmed] = useState(false);
  const [activeHttpHeaderProbeState, setActiveHttpHeaderProbeState] = useState<LoadState>(initialLoadState);
  const [advancedAuditsOpen, setAdvancedAuditsOpen] = useState(false);
  const [workflowNotice, setWorkflowNotice] = useState<string | null>(null);
  const [dashboardReady, setDashboardReady] = useState(false);
  const [activeContextRevision, setActiveContextRevision] = useState(0);
  const projectArchiveUploadRef = useRef<HTMLInputElement>(null);
  const jobResultRef = useRef<HTMLElement>(null);
  const jobTableRef = useRef<HTMLDivElement>(null);
  const projectFindingsRef = useRef<HTMLElement>(null);
  const restoredJobSelectionRef = useRef(false);
  const restoredProjectSelectionRef = useRef(false);
  const lastSelectedJobIdRef = useRef<string | null>(null);

  const clearPrivateUiState = useCallback(() => {
    setFiles([]);
    setProjects([]);
    setProjectsTotalCount(0);
    setProjectsNextCursor(null);
    setJobs([]);
    setJobsTotalCount(0);
    setJobsNextCursor(null);
    setSelectedJob(null);
    setSelectedProject(null);
    setSnapshotProjectId(null);
  }, []);

  const applyAuthStatus = useCallback((status: AuthStatusResponse) => {
    setAuthStatus(status);
    api.configureAuthContext({
      csrfRequired: status.csrf_required,
      csrfToken: status.csrf_token,
      onAuthFailure: (failureStatus) => {
        authFailureHandlerRef.current(failureStatus);
      }
    });
    if (status.auth_required && !status.authenticated) {
      clearPrivateUiState();
    }
    return status;
  }, [clearPrivateUiState]);

  const refreshAuthStatus = useCallback(async () => {
    setAuthState({ loading: true, error: null });
    try {
      const status = applyAuthStatus(await api.getAuthStatus());
      setAuthState({ loading: false, error: null });
      return status;
    } catch (error) {
      setAuthState({ loading: false, error: toErrorMessage(error) });
      return null;
    }
  }, [applyAuthStatus]);

  const handleAuthFailure = useCallback(async (status: number) => {
    const refreshed = await refreshAuthStatus();
    if (!refreshed || (refreshed.auth_required && !refreshed.authenticated)) {
      clearPrivateUiState();
      setActionError(status === 403 ? AUTH_CSRF_FAILED_MESSAGE : AUTH_SESSION_EXPIRED_MESSAGE);
    }
  }, [clearPrivateUiState, refreshAuthStatus]);

  useEffect(() => {
    authFailureHandlerRef.current = (status: number) => {
      void handleAuthFailure(status);
    };
  }, [handleAuthFailure]);

  const refreshHealth = useCallback(async () => {
    setHealthState({ loading: true, error: null });
    try {
      setHealth(await api.health());
      setHealthState({ loading: false, error: null });
    } catch (error) {
      setHealth(null);
      setHealthState({ loading: false, error: toErrorMessage(error) });
    }
  }, []);

  const refreshFiles = useCallback(async () => {
    setFilesState({ loading: true, error: null });
    try {
      setFiles(await api.listFiles());
      setFilesState({ loading: false, error: null });
    } catch (error) {
      setFilesState({ loading: false, error: toErrorMessage(error) });
    }
  }, []);

  const refreshProjects = useCallback(async (options: { quiet?: boolean } = {}) => {
    if (!options.quiet) {
      setProjectsState({ loading: true, error: null });
    }
    try {
      const page = await api.listProjectPage();
      setProjects(page.items);
      setProjectsTotalCount(page.total_count);
      setProjectsNextCursor(page.next_cursor);
      setProjectsState({ loading: false, error: null });
    } catch (error) {
      setProjectsState({ loading: false, error: toErrorMessage(error) });
    }
  }, []);

  const loadMoreProjects = useCallback(async () => {
    if (!projectsNextCursor || projectsState.loading) return;
    setProjectsState({ loading: true, error: null });
    try {
      const page = await api.listProjectPage(projectsNextCursor);
      setProjects((current) => {
        const retained = new Map(current.map((item) => [item.project.id, item]));
        page.items.forEach((item) => retained.set(item.project.id, item));
        return [...retained.values()];
      });
      setProjectsTotalCount(page.total_count);
      setProjectsNextCursor(page.next_cursor);
      setProjectsState({ loading: false, error: null });
    } catch (error) {
      setProjectsState({ loading: false, error: toErrorMessage(error) });
    }
  }, [projectsNextCursor, projectsState.loading]);

  const refreshJobs = useCallback(async (options: { quiet?: boolean } = {}) => {
    if (!options.quiet) {
      setJobsState({ loading: true, error: null });
    }
    try {
      const page = await api.listJobPage();
      setJobs(page.items);
      setJobsTotalCount(page.total_count);
      setJobsNextCursor(page.next_cursor);
      setJobsState({ loading: false, error: null });
    } catch (error) {
      setJobsState({ loading: false, error: toErrorMessage(error) });
    }
  }, []);

  const loadMoreJobs = useCallback(async () => {
    if (!jobsNextCursor || jobsState.loading) {
      return;
    }
    setJobsState({ loading: true, error: null });
    try {
      const page = await api.listJobPage(jobsNextCursor);
      setJobs((current) => {
        const known = new Set(current.map((job) => job.id));
        return [...current, ...page.items.filter((job) => !known.has(job.id))];
      });
      setJobsTotalCount(page.total_count);
      setJobsNextCursor(page.next_cursor);
      setJobsState({ loading: false, error: null });
      window.requestAnimationFrame(() => jobTableRef.current?.focus());
    } catch (error) {
      setJobsState({ loading: false, error: toErrorMessage(error) });
      window.requestAnimationFrame(() => jobTableRef.current?.focus());
    }
  }, [jobsNextCursor, jobsState.loading]);

  const refreshAll = useCallback(async () => {
    setActionError(null);
    const status = await refreshAuthStatus();
    if (!status || (status.auth_required && !status.authenticated)) {
      clearPrivateUiState();
      await refreshHealth();
      return;
    }
    await Promise.all([refreshHealth(), refreshFiles(), refreshProjects(), refreshJobs()]);
  }, [clearPrivateUiState, refreshAuthStatus, refreshFiles, refreshHealth, refreshJobs, refreshProjects]);

  useEffect(() => {
    void refreshAll().finally(() => setDashboardReady(true));
  }, [refreshAll]);

  const hasActiveJobs = useMemo(
    () => jobs.some((job) => job.status === "queued" || job.status === "running" || job.status === "cancelling"),
    [jobs]
  );
  const isRefreshing = authState.loading || healthState.loading || filesState.loading || projectsState.loading || jobsState.loading;
  const metrics = useMemo(() => buildDashboardMetrics(files, jobs), [files, jobs]);
  const filteredFiles = useMemo(
    () => filterFiles(files, fileKindFilter, fileSearch),
    [fileKindFilter, fileSearch, files]
  );
  const filteredJobs = useMemo(
    () => filterJobs(jobs, jobStatusFilter, jobTypeFilter, jobSearch),
    [jobSearch, jobStatusFilter, jobTypeFilter, jobs]
  );
  const selectedJobFile = useMemo(
    () => (selectedJob?.file_id ? files.find((file) => file.id === selectedJob.file_id) : undefined),
    [files, selectedJob]
  );
  const selectedProjectSummary = useMemo(
    () => (selectedProject ? projects.find((item) => item.project.id === selectedProject.project.id) ?? selectedProject : null),
    [projects, selectedProject]
  );
  const snapshotProject = useMemo(
    () => (snapshotProjectId ? projects.find((item) => item.project.id === snapshotProjectId) ?? null : null),
    [projects, snapshotProjectId]
  );
  const webQueryInspection = useMemo(() => inspectWebUrlQuery(webUrl), [webUrl]);
  const activeDryRunQueryInspection = useMemo(() => inspectWebUrlQuery(activeDryRunTarget), [activeDryRunTarget]);
  const activeDryRunHasUserinfo = useMemo(() => targetHasUserinfo(activeDryRunTarget), [activeDryRunTarget]);
  const activeHttpHeaderProbeQueryInspection = useMemo(() => inspectWebUrlQuery(activeHttpHeaderProbeTarget), [activeHttpHeaderProbeTarget]);
  const activeHttpHeaderProbeHasUserinfo = useMemo(() => targetHasUserinfo(activeHttpHeaderProbeTarget), [activeHttpHeaderProbeTarget]);
  const authBlocksDashboard = authStatus.auth_required && !authStatus.authenticated;
  const workflowStage = getWorkflowStage({ files, hasActiveJobs, selectedJob });
  const workflowMessage = getWorkflowMessage(workflowStage);

  useEffect(() => {
    if (!selectedJob) {
      return;
    }
    writeSelectedJobToLocation(selectedJob.id);
    if (lastSelectedJobIdRef.current !== selectedJob.id) {
      lastSelectedJobIdRef.current = selectedJob.id;
      setWorkflowNotice(`${auditTypeLabel(selectedJob.audit_type)} is ${selectedJob.status}. Its result is now selected below.`);
      jobResultRef.current?.focus({ preventScroll: false });
    }
  }, [selectedJob]);

  useEffect(() => {
    if (!selectedProjectSummary) {
      return;
    }
    writeSelectedProjectToLocation(selectedProjectSummary.project.id);
    if (ciSetupProjectId !== selectedProjectSummary.project.id) {
      projectFindingsRef.current?.focus({ preventScroll: false });
    }
  }, [ciSetupProjectId, selectedProjectSummary]);

  useEffect(() => {
    if (restoredJobSelectionRef.current || !dashboardReady || authBlocksDashboard) {
      return;
    }
    const jobId = selectedJobIdFromLocation();
    if (!jobId) {
      restoredJobSelectionRef.current = true;
      return;
    }
    restoredJobSelectionRef.current = true;
    void viewJob(jobId, { restoring: true });
  }, [authBlocksDashboard, dashboardReady]);

  useEffect(() => {
    if (restoredProjectSelectionRef.current || !dashboardReady || authBlocksDashboard) {
      return;
    }
    const projectId = selectedProjectIdFromLocation();
    if (!projectId) {
      restoredProjectSelectionRef.current = true;
      return;
    }
    const project = projects.find((item) => item.project.id === projectId);
    if (project) {
      restoredProjectSelectionRef.current = true;
      setSelectedProject(project);
      return;
    }
    if (projectsState.loading) return;
    restoredProjectSelectionRef.current = true;
    if (!/^[a-f0-9]{32}$/.test(projectId)) {
      clearSelectedProjectFromLocation();
      return;
    }
    void api.getProject(projectId).then((resolved) => {
      setSelectedProject(resolved);
    }).catch(() => {
      clearSelectedProjectFromLocation();
    });
  }, [authBlocksDashboard, dashboardReady, projects, projectsState.loading]);

  useEffect(() => {
    if (!selectedJob || !isActiveJob(selectedJob)) {
      return;
    }
    const refreshedSummary = jobs.find((job) => job.id === selectedJob.id);
    if (!refreshedSummary || refreshedSummary.status === selectedJob.status) {
      return;
    }
    void refreshSelectedJob(selectedJob.id);
  }, [jobs, selectedJob]);

  useEffect(() => {
    if (!hasActiveJobs) {
      return;
    }
    const interval = window.setInterval(() => {
      void Promise.all([refreshJobs({ quiet: true }), refreshProjects({ quiet: true })]);
    }, 3000);
    return () => window.clearInterval(interval);
  }, [hasActiveJobs, refreshJobs, refreshProjects]);

  async function handleLogin(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const password = loginPassword;
    setLoginPassword("");
    setLoginState({ loading: true, error: null });
    setActionError(null);
    try {
      await api.login(
        password,
        authStatus.auth_mode === "private_team_lightweight_users" ? loginUsername : undefined,
      );
      const status = await refreshAuthStatus();
      if (status && (!status.auth_required || status.authenticated)) {
        await Promise.all([refreshFiles(), refreshProjects(), refreshJobs()]);
      }
      setLoginState({ loading: false, error: null });
    } catch (error) {
      setLoginState({
        loading: false,
        error: error instanceof ApiError && error.status === 429 ? AUTH_RATE_LIMIT_MESSAGE : "Invalid credentials."
      });
    }
  }

  async function handleLogout() {
    setLogoutState({ loading: true, error: null });
    setActionError(null);
    try {
      await api.logout();
      api.configureAuthContext({ csrfRequired: false, csrfToken: null });
      setAuthStatus((current) => ({
        ...current,
        authenticated: false,
        operator_id: null,
        username: null,
        organization_id: null,
        organization_name: null,
        role: null,
        csrf_token: null
      }));
      clearPrivateUiState();
      await refreshAuthStatus();
      setLogoutState({ loading: false, error: null });
    } catch {
      api.configureAuthContext({ csrfRequired: false, csrfToken: null });
      clearPrivateUiState();
      await refreshAuthStatus();
      setLogoutState({ loading: false, error: AUTH_SESSION_EXPIRED_MESSAGE });
    }
  }

  async function handleUpload(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    if (!selectedFile) {
      setUploadState({ loading: false, error: uploadErrorForKind(uploadKind) });
      return;
    }

    setUploadState({ loading: true, error: null });
    setActionError(null);
    try {
      if (uploadKind === "pdf") {
        await api.uploadPdf(selectedFile);
      } else if (uploadKind === "image") {
        await api.uploadImage(selectedFile);
      } else if (uploadKind === "manifest") {
        await api.uploadManifest(selectedFile);
      } else {
        await api.uploadArchive(selectedFile);
      }
      setSelectedFile(null);
      form.reset();
      await refreshFiles();
      setWorkflowNotice("File uploaded. Choose an analysis from the Files list to create a review job.");
      setUploadState({ loading: false, error: null });
    } catch (error) {
      setUploadState({ loading: false, error: toErrorMessage(error) });
    }
  }

  function handleFileChange(event: ChangeEvent<HTMLInputElement>) {
    setSelectedFile(event.target.files?.[0] ?? null);
    setUploadState(initialLoadState);
  }

  async function launchAudit(file: FileRecord) {
    setActionError(null);
    try {
      const job =
        file.kind === "pdf"
          ? await api.launchPdfAudit(file.id)
          : file.kind === "image"
            ? await api.launchImageAudit(file.id)
            : file.kind === "manifest"
              ? await api.launchManifestAudit(file.id)
              : await api.launchArchiveAudit(file.id);
      setSelectedJob(job);
      await refreshJobs();
    } catch (error) {
      setActionError(toErrorMessage(error));
    }
  }

  async function launchProjectArchiveAudit(file: FileRecord) {
    setActionError(null);
    try {
      const job = await api.launchProjectArchiveAudit(file.id);
      setSelectedJob(job);
      await refreshJobs();
    } catch (error) {
      setActionError(toErrorMessage(error));
    }
  }

  async function createProjectFromArchive(file: FileRecord) {
    setActionError(null);
    setCreatingProjectFileId(file.id);
    try {
      const created = await api.createProject(file.id);
      setSelectedJob({ ...created.job, result: null, error: null });
      setProjectAuthorizationConfirmedFileId(null);
      await Promise.all([refreshProjects(), refreshJobs()]);
      setWorkflowNotice(`Project ${created.project.name} was created and its initial review is queued.`);
    } catch (error) {
      setActionError(toErrorMessage(error));
    } finally {
      setCreatingProjectFileId(null);
    }
  }

  async function rerunProjectAnalysis(project: ProjectSummary) {
    setActionError(null);
    setRerunningProjectId(project.project.id);
    try {
      const retryOf = project.latest_job && (project.latest_job.status === "failed" || project.latest_job.status === "cancelled")
        ? project.latest_job.id
        : undefined;
      const job = await api.launchProjectAnalysis(project.project.id, retryOf);
      setSelectedJob({ ...job, result: null, error: null });
      await Promise.all([refreshProjects(), refreshJobs()]);
      setWorkflowNotice(`A new analysis of ${project.project.name} is queued for its recorded source snapshot.`);
    } catch (error) {
      setActionError(toErrorMessage(error));
    } finally {
      setRerunningProjectId(null);
    }
  }

  function viewProjectFindings(project: ProjectSummary) {
    setSelectedProject(project);
    setWorkflowNotice(`Project findings for ${project.project.name} are open below.`);
  }

  function openProjectWorkspace(project: ProjectSummary) {
    setSelectedProject(project);
    setWorkflowNotice(`Project workspace for ${project.project.name} is open below.`);
  }

  function openProjectSnapshotForm(projectId: string) {
    setSnapshotProjectId(projectId);
    setWorkflowNotice("Choose an authorized corrected archive to create a new immutable snapshot, then compare the completed results.");
    const projectsRegion = document.getElementById("projects");
    if (projectsRegion && typeof projectsRegion.scrollIntoView === "function") {
      projectsRegion.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  }

  function openProjectSourceUpdate(project: ProjectSummary) {
    if (project.project.source_type !== "sbom" && project.latest_job?.analysis_profile !== "sbom_import") {
      openProjectSnapshotForm(project.project.id);
      return;
    }
    setSnapshotProjectId(null);
    setSelectedProject(project);
    setWorkflowNotice("Add an authorized SBOM revision from the project workspace. The original document will not be retained.");
    globalThis.setTimeout(() => document.getElementById("sbom-revision")?.focus(), 0);
  }

  async function handleProjectDeleted(result: ProjectDeletionResponse) {
    const deletedName = selectedProjectSummary?.project.id === result.project_id
      ? selectedProjectSummary.project.name
      : "the selected project";
    setProjects((current) => current.filter((item) => item.project.id !== result.project_id));
    setSelectedProject(null);
    setSnapshotProjectId((current) => current === result.project_id ? null : current);
    clearSelectedProjectFromLocation();
    if (selectedJob?.project_id === result.project_id) {
      setSelectedJob(null);
      clearSelectedJobFromLocation();
    }
    setWorkflowNotice(
      `${deletedName} and its derived records were deleted. Uploaded source files remain under the Files retention policy.`
    );
    await Promise.all([refreshProjects(), refreshJobs(), refreshFiles()]);
  }

  async function launchDjangoConfigAudit(file: FileRecord) {
    setActionError(null);
    try {
      const job = await api.launchDjangoConfigAudit(file.id);
      setSelectedJob(job);
      await refreshJobs();
    } catch (error) {
      setActionError(toErrorMessage(error));
    }
  }

  async function launchDockerConfigAudit(file: FileRecord) {
    setActionError(null);
    try {
      const job = await api.launchDockerConfigAudit(file.id);
      setSelectedJob(job);
      await refreshJobs();
    } catch (error) {
      setActionError(toErrorMessage(error));
    }
  }

  async function launchSecretsReviewAudit(file: FileRecord) {
    setActionError(null);
    try {
      const job = await api.launchSecretsReviewAudit(file.id);
      setSelectedJob(job);
      await refreshJobs();
    } catch (error) {
      setActionError(toErrorMessage(error));
    }
  }

  async function launchNodePackageConfigAudit(file: FileRecord) {
    setActionError(null);
    try {
      const job = await api.launchNodePackageConfigAudit(file.id);
      setSelectedJob(job);
      await refreshJobs();
    } catch (error) {
      setActionError(toErrorMessage(error));
    }
  }

  async function launchCiCdConfigAudit(file: FileRecord) {
    setActionError(null);
    try {
      const job = await api.launchCiCdConfigAudit(file.id);
      setSelectedJob(job);
      await refreshJobs();
    } catch (error) {
      setActionError(toErrorMessage(error));
    }
  }

  async function launchK8sConfigAudit(file: FileRecord) {
    setActionError(null);
    try {
      const job = await api.launchK8sConfigAudit(file.id);
      setSelectedJob(job);
      await refreshJobs();
    } catch (error) {
      setActionError(toErrorMessage(error));
    }
  }

  async function launchTerraformConfigAudit(file: FileRecord) {
    setActionError(null);
    try {
      const job = await api.launchTerraformConfigAudit(file.id);
      setSelectedJob(job);
      await refreshJobs();
    } catch (error) {
      setActionError(toErrorMessage(error));
    }
  }

  async function launchNginxConfigAudit(file: FileRecord) {
    setActionError(null);
    try {
      const job = await api.launchNginxConfigAudit(file.id);
      setSelectedJob(job);
      await refreshJobs();
    } catch (error) {
      setActionError(toErrorMessage(error));
    }
  }

  async function launchComposeConfigAudit(file: FileRecord) {
    setActionError(null);
    try {
      const job = await api.launchComposeConfigAudit(file.id);
      setSelectedJob(job);
      await refreshJobs();
    } catch (error) {
      setActionError(toErrorMessage(error));
    }
  }

  async function launchDatabaseConfigAudit(file: FileRecord) {
    setActionError(null);
    try {
      const job = await api.launchDatabaseConfigAudit(file.id);
      setSelectedJob(job);
      await refreshJobs();
    } catch (error) {
      setActionError(toErrorMessage(error));
    }
  }

  async function launchRedisConfigAudit(file: FileRecord) {
    setActionError(null);
    try {
      const job = await api.launchRedisConfigAudit(file.id);
      setSelectedJob(job);
      await refreshJobs();
    } catch (error) {
      setActionError(toErrorMessage(error));
    }
  }

  async function launchSqlDatabaseConfigAudit(file: FileRecord) {
    setActionError(null);
    try {
      const job = await api.launchSqlDatabaseConfigAudit(file.id);
      setSelectedJob(job);
      await refreshJobs();
    } catch (error) {
      setActionError(toErrorMessage(error));
    }
  }

  async function launchWebAudit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setActionError(null);
    setWebAuditState({ loading: true, error: null });
    try {
      const job = await api.launchWebBasicAudit(webUrl, webAuthorizationConfirmed);
      setSelectedJob(job);
      setWebUrl("");
      setWebAuthorizationConfirmed(false);
      await refreshJobs();
      setWebAuditState({ loading: false, error: null });
    } catch (error) {
      setWebAuditState({ loading: false, error: toErrorMessage(error) });
    }
  }

  async function launchDomainAudit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setActionError(null);
    setDomainAuditState({ loading: true, error: null });
    try {
      const job = await api.launchDomainBasicAudit(domainName, domainAuthorizationConfirmed);
      setSelectedJob(job);
      setDomainName("");
      setDomainAuthorizationConfirmed(false);
      await refreshJobs();
      setDomainAuditState({ loading: false, error: null });
    } catch (error) {
      setDomainAuditState({ loading: false, error: toErrorMessage(error) });
    }
  }

  async function launchSubdomainAudit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setActionError(null);
    setSubdomainAuditState({ loading: true, error: null });
    try {
      const candidates = parseSubdomainCandidates(subdomainCandidates);
      const job = await api.launchSubdomainInventoryAudit(subdomainRootDomain, candidates, subdomainAuthorizationConfirmed);
      setSelectedJob(job);
      setSubdomainRootDomain("");
      setSubdomainCandidates("");
      setSubdomainAuthorizationConfirmed(false);
      await refreshJobs();
      setSubdomainAuditState({ loading: false, error: null });
    } catch (error) {
      setSubdomainAuditState({ loading: false, error: toErrorMessage(error) });
    }
  }

  async function launchActiveDryRun(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setActionError(null);
    setActiveDryRunState({ loading: true, error: null });
    const request: ActiveDryRunRequest = {
      target: activeDryRunTarget,
      authorization: {
        confirmed: activeDryRunAuthorizationConfirmed,
        statement: ACTIVE_DRY_RUN_AUTHORIZATION_STATEMENT,
        scope: "single-target"
      },
      mode: "dry_run",
      profile: "http_header_probe_preview",
      limits: {
        max_requests: 0,
        timeout_seconds: 0,
        max_redirects: 0,
        response_size_bytes: 0
      }
    };
    try {
      const job = await api.createActiveNetworkDryRun(request);
      setSelectedJob(job);
      setActiveDryRunTarget("");
      setActiveDryRunAuthorizationConfirmed(false);
      await refreshJobs();
      setActiveDryRunState({ loading: false, error: null });
    } catch (error) {
      const message = toErrorMessage(error);
      const disabledMessage =
        message === "Active dry-run checks are disabled in this environment."
          ? `${message} Ask an administrator to enable the Active dry-run backend flag for this deployment.`
          : message;
      setActiveDryRunState({ loading: false, error: disabledMessage });
    }
  }

  async function launchActiveHttpHeaderProbe(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setActionError(null);
    setActiveHttpHeaderProbeState({ loading: true, error: null });
    const request: ActiveHttpHeaderProbeRequest = {
      target: activeHttpHeaderProbeTarget,
      authorization: {
        confirmed: activeHttpHeaderProbeAuthorizationConfirmed,
        live_traffic_confirmed: activeHttpHeaderProbeLiveTrafficConfirmed,
        statement: ACTIVE_DRY_RUN_AUTHORIZATION_STATEMENT,
        scope: "single-target"
      },
      mode: "live_header_probe",
      profile: "http_header_probe",
      limits: {
        max_targets: 1,
        max_requests: 1,
        timeout_seconds: 3,
        max_redirects: 0,
        response_body_bytes: 0,
        max_response_header_bytes: 32768,
        max_dns_answers: 8,
        retries: 0,
        concurrency: 1
      }
    };
    try {
      const job = await api.createActiveHttpHeaderProbe(request);
      setSelectedJob(job);
      setActiveHttpHeaderProbeTarget("");
      setActiveHttpHeaderProbeAuthorizationConfirmed(false);
      setActiveHttpHeaderProbeLiveTrafficConfirmed(false);
      await refreshJobs();
      setActiveHttpHeaderProbeState({ loading: false, error: null });
    } catch (error) {
      const message = toErrorMessage(error);
      const disabledMessage =
        message === "Active HTTP header probe is disabled in this environment."
          ? `${message} This deployment has not enabled live header probes.`
          : message;
      setActiveHttpHeaderProbeState({ loading: false, error: disabledMessage });
    }
  }

  async function handleActiveNmapBasicJobCreated(job: JobRecord) {
    setSelectedJob(job);
    await refreshJobs();
  }

  async function handleActiveHttpBasicHeaderReviewJobCreated(job: JobRecord) {
    setSelectedJob(job);
    await refreshJobs();
  }

  async function handleActiveTlsBasicJobCreated(job: JobRecord) {
    setSelectedJob(job);
    await refreshJobs();
  }

  async function handleActiveDnsInventoryJobCreated(job: JobRecord) {
    setSelectedJob(job);
    await refreshJobs();
  }

  async function handleActiveDnsOsintJobCreated(job: JobRecord) {
    setSelectedJob(job);
    await refreshJobs();
  }

  async function deleteFile(fileId: string) {
    setActionError(null);
    try {
      await api.deleteFile(fileId);
      await Promise.all([refreshFiles(), refreshProjects(), refreshJobs()]);
    } catch (error) {
      setActionError(toErrorMessage(error));
    }
  }

  function startProjectArchiveUpload() {
    setUploadKind("archive");
    projectArchiveUploadRef.current?.focus();
  }

  async function viewJob(jobId: string, options: { restoring?: boolean } = {}) {
    setActionError(null);
    try {
      setSelectedJob(await api.getJob(jobId));
    } catch (error) {
      if (options.restoring) {
        clearSelectedJobFromLocation();
        setWorkflowNotice("The job selected in the link is no longer available. Choose another job from the list.");
      } else {
        setActionError(toErrorMessage(error));
      }
    }
  }

  async function refreshSelectedJob(jobId: string) {
    try {
      setSelectedJob(await api.getJob(jobId));
      setWorkflowNotice("The selected job status changed. Its latest result is shown below.");
    } catch (error) {
      setActionError(toErrorMessage(error));
    }
  }

  function buildArchiveActionGroups(file: FileRecord): ArchiveActionGroup[] {
    return [
      {
        label: "Start here",
        actions: [
          {
            label: creatingProjectFileId === file.id ? "Creating project" : "Create project & analyze",
            onClick: () => void createProjectFromArchive(file),
            disabled: creatingProjectFileId !== null || projectAuthorizationConfirmedFileId !== file.id
          },
          { label: "Analyze archive", onClick: () => void launchAudit(file) },
          { label: "Analyze project manifests", onClick: () => void launchProjectArchiveAudit(file) }
        ]
      },
      {
        label: "Secrets",
        actions: [{ label: "Analyze secrets review", onClick: () => void launchSecretsReviewAudit(file) }]
      },
      {
        label: "Application",
        actions: [
          { label: "Analyze Django config", onClick: () => void launchDjangoConfigAudit(file) },
          { label: "Analyze Node package config", onClick: () => void launchNodePackageConfigAudit(file) }
        ]
      },
      {
        label: "Container & service wiring",
        actions: [
          { label: "Analyze Docker config", onClick: () => void launchDockerConfigAudit(file) },
          { label: "Analyze Compose config", onClick: () => void launchComposeConfigAudit(file) }
        ]
      },
      {
        label: "Deployment & IaC",
        actions: [
          { label: "Analyze CI/CD config", onClick: () => void launchCiCdConfigAudit(file) },
          { label: "Analyze Kubernetes config", onClick: () => void launchK8sConfigAudit(file) },
          { label: "Analyze Terraform config", onClick: () => void launchTerraformConfigAudit(file) }
        ]
      },
      {
        label: "Web edge",
        actions: [{ label: "Analyze Nginx config", onClick: () => void launchNginxConfigAudit(file) }]
      },
      {
        label: "Data layer",
        actions: [
          { label: "Analyze database config", onClick: () => void launchDatabaseConfigAudit(file) },
          { label: "Analyze Redis config", onClick: () => void launchRedisConfigAudit(file) },
          { label: "Analyze SQL DB config", onClick: () => void launchSqlDatabaseConfigAudit(file) }
        ]
      }
    ];
  }

  return (
    <main className="app-shell">
      <header className="app-header">
        <div>
          <p className="eyebrow">Defensive audits</p>
          <h1>Inspectra</h1>
        </div>
        <div className="header-actions">
          {authStatus.auth_required && authStatus.authenticated ? (
            <>
              <span className="status-pill ok">
                {authStatus.auth_mode === "private_team_lightweight_users"
                  ? `${authStatus.organization_name ?? "Team workspace"} · ${authStatus.role ?? "member"}`
                  : `Signed in as ${authStatus.operator_id ?? "local-admin"}`}
              </span>
              <button className="secondary-button" onClick={() => void handleLogout()} disabled={logoutState.loading}>
                <LogOut size={16} aria-hidden="true" />
                {logoutState.loading ? "Signing out" : "Sign out"}
              </button>
            </>
          ) : null}
          <button className="secondary-button" onClick={() => void refreshAll()} disabled={isRefreshing}>
            <RefreshCw size={16} aria-hidden="true" />
            {isRefreshing ? "Refreshing" : "Refresh data"}
          </button>
        </div>
      </header>

      <WorkflowNavigation stage={workflowStage} message={workflowMessage} />

      {workflowNotice ? <div className="workflow-notice" role="status">{workflowNotice}</div> : null}
      {actionError ? <div className="alert" role="alert">{actionError}</div> : null}
      {logoutState.error ? <div className="alert" role="alert">{logoutState.error}</div> : null}

      {authBlocksDashboard ? (
        <section className="auth-gate" aria-label="Authentication">
          <Panel title="Authentication required" icon={<ShieldCheck size={18} aria-hidden="true" />}>
            <p className="muted">
              {authStatus.auth_mode === "private_team_lightweight_users"
                ? "Sign in to your private team workspace. Access is limited by membership and role."
                : "Authentication required for this self-hosted instance."}
            </p>
            {authState.error ? <p className="error-text">{authState.error}</p> : null}
            {!authStatus.login_available ? (
              <div className="query-warning" role="status">
                Authentication is not available for this deployment.
              </div>
            ) : (
              <form className="auth-form" onSubmit={(event) => void handleLogin(event)}>
                {authStatus.auth_mode === "private_team_lightweight_users" ? (
                  <label className="auth-field">
                    <span>Username</span>
                    <input
                      value={loginUsername}
                      onChange={(event) => {
                        setLoginUsername(event.target.value);
                        setLoginState(initialLoadState);
                      }}
                      autoComplete="username"
                      minLength={3}
                      maxLength={64}
                      required
                    />
                  </label>
                ) : null}
                <label className="auth-field">
                  <span>Password</span>
                  <input
                    type="password"
                    value={loginPassword}
                    onChange={(event) => {
                      setLoginPassword(event.target.value);
                      setLoginState(initialLoadState);
                    }}
                    autoComplete="current-password"
                    required
                  />
                </label>
                <button
                  type="submit"
                  disabled={
                    loginState.loading
                    || !loginPassword
                    || (authStatus.auth_mode === "private_team_lightweight_users" && !loginUsername)
                  }
                >
                  <ShieldCheck size={16} aria-hidden="true" />
                  {loginState.loading ? "Signing in" : "Sign in"}
                </button>
                {loginState.error ? <p className="error-text">{loginState.error}</p> : null}
              </form>
            )}
            {authStatus.auth_mode === "private_team_lightweight_users" ? (
              <Suspense fallback={<p className="muted" role="status">Loading invitation setup…</p>}>
                <TeamInvitationAcceptance onAccepted={(username) => setLoginUsername(username)} />
              </Suspense>
            ) : null}
          </Panel>
        </section>
      ) : (
        <>

      <Suspense fallback={<p className="project-start-guide muted" role="status">Loading project onboarding…</p>}>
        <ProjectStartGuide
          projects={projects}
          onArchive={() => startProjectArchiveUpload()}
          onSbom={() => {
            document.getElementById("sbom-import")?.scrollIntoView?.({ behavior: "smooth", block: "start" });
            globalThis.setTimeout(() => document.getElementById("sbom-import-file")?.focus(), 0);
          }}
          onCi={(project) => {
            setCiSetupProjectId(project.project.id);
            openProjectWorkspace(project);
          }}
          onOpenProject={openProjectWorkspace}
        />
      </Suspense>

      <details className="workspace-controls-disclosure">
        <summary>Workspace administration and data controls</summary>
        <div className="workspace-controls-content">

      {authStatus.auth_mode === "private_team_lightweight_users" && authStatus.authenticated ? (
        <Suspense fallback={<p className="muted" role="status">Loading team workspace…</p>}>
          <TeamWorkspacePanel onWorkspaceChanged={async () => {
            clearPrivateUiState();
            await refreshAuthStatus();
            await Promise.all([refreshFiles(), refreshProjects(), refreshJobs()]);
            setActiveContextRevision((revision) => revision + 1);
          }} onMembershipChanged={() => setActiveContextRevision((revision) => revision + 1)} />
        </Suspense>
      ) : null}

      {authStatus.auth_mode === "self_hosted_single_admin" || authStatus.role === "administrator" ? (
        <Suspense fallback={<p className="muted" role="status">Loading product activity…</p>}>
          <ProductAuditPanel />
        </Suspense>
      ) : null}

      {authStatus.authenticated && (
        authStatus.auth_mode === "self_hosted_single_admin" || authStatus.role === "administrator"
      ) ? (
        <Suspense fallback={<p className="muted" role="status">Loading automation access…</p>}>
          <AutomationTokensPanel projects={projects} />
        </Suspense>
      ) : null}

      <Suspense fallback={<p className="muted" role="status">Loading data lifecycle…</p>}>
        <RetentionPolicyPanel />
      </Suspense>
        </div>
      </details>

      <Suspense fallback={<p className="muted" role="status">Loading SBOM import…</p>}>
        <SbomImportPanel onImported={(created) => {
          setSelectedProject({ project: created.project, latest_job: { ...created.job, summary: null } });
          void Promise.all([refreshFiles(), refreshProjects(), refreshJobs()]);
        }} />
      </Suspense>

      <Suspense fallback={<p className="muted" role="status">Loading Active operations…</p>}>
        <ActiveOperationsCenter
          canManage={authStatus.role !== "reader"}
          teamMode={authStatus.auth_mode === "private_team_lightweight_users"}
          currentUserId={authStatus.operator_id}
          currentRole={authStatus.role}
          refreshToken={activeContextRevision}
          onJobCreated={handleActiveNmapBasicJobCreated}
        />
      </Suspense>

      <section id="overview" className="metrics-grid" aria-label="Dashboard summary">
        <MetricCard label="Total files" value={metrics.totalFiles} />
        <MetricCard label="PDFs" value={metrics.pdfs} />
        <MetricCard label="Images" value={metrics.images} />
        <MetricCard label="Manifests" value={metrics.manifests} />
        <MetricCard label="Archives" value={metrics.archives} />
        <MetricCard label="Loaded jobs" value={metrics.totalJobs} />
        <MetricCard label="Completed" value={metrics.completedJobs} />
        <MetricCard label="Failed" value={metrics.failedJobs} />
        <MetricCard label="Active" value={metrics.activeJobs} />
      </section>

      <section id="start" className="dashboard-grid" aria-label="Create an audit">
        <Panel
          title="Backend"
          icon={<Activity size={18} aria-hidden="true" />}
          action={healthState.loading ? <span className="muted">Checking</span> : null}
        >
          <div className="health-row">
            <span className={health?.status === "ok" ? "status-pill ok" : "status-pill"}>{health?.status ?? "offline"}</span>
            <span className="muted">{health?.service ?? healthState.error ?? "No response yet"}</span>
            <span className="mono">{api.baseUrl()}</span>
          </div>
        </Panel>

        <Panel title={uploadKind === "archive" ? "Upload project archive" : "Upload File"} icon={<FilePlus2 size={18} aria-hidden="true" />}>
          <form className="upload-form" onSubmit={(event) => void handleUpload(event)}>
            <div className="segmented-control" aria-label="Upload type">
              <button type="button" aria-pressed={uploadKind === "pdf"} className={uploadKind === "pdf" ? "active" : ""} onClick={() => setUploadKind("pdf")}>
                PDF
              </button>
              <button type="button" aria-pressed={uploadKind === "image"} className={uploadKind === "image" ? "active" : ""} onClick={() => setUploadKind("image")}>
                Image
              </button>
              <button type="button" aria-pressed={uploadKind === "manifest"} className={uploadKind === "manifest" ? "active" : ""} onClick={() => setUploadKind("manifest")}>
                Manifest
              </button>
              <button type="button" aria-pressed={uploadKind === "archive"} className={uploadKind === "archive" ? "active" : ""} onClick={() => setUploadKind("archive")}>
                Archive
              </button>
            </div>
            <p id="project-upload-boundary" className="muted project-upload-guidance">
              {uploadKind === "archive"
                ? "Project source: upload an authorized ZIP or TAR snapshot. Inspectra analyzes it passively; it does not execute project code or install dependencies."
                : "To create a project with retained history, choose Archive and upload an authorized ZIP or TAR snapshot."}
            </p>
            <ProjectArchivePreflight active={uploadKind === "archive"} />
            <label className="auth-field upload-file-field">
              <span>File to upload</span>
              <input
                ref={projectArchiveUploadRef}
                type="file"
                accept={acceptForKind(uploadKind)}
                aria-describedby="project-upload-boundary"
                onChange={handleFileChange}
              />
            </label>
            <button type="submit" disabled={uploadState.loading}>
              <UploadCloud size={16} aria-hidden="true" />
              {uploadState.loading ? "Uploading" : uploadKind === "archive" ? "Upload project archive" : "Upload"}
            </button>
          </form>
          <div className="query-warning" role="note" aria-label="Local alpha demo fixture note">
            {LOCAL_ALPHA_DEMO_COPY} {LOCAL_ALPHA_DEMO_REDACTION_COPY}
          </div>
          {uploadState.error ? <p className="error-text">{uploadState.error}</p> : null}
        </Panel>

        <details className="specialist-audits-disclosure" open>
          <summary>Specialist URL, domain, and active audits</summary>
          <p className="muted">These optional workflows are separate from project source analysis and may require additional target authorization.</p>
          <div className="specialist-audits-grid">
        <Panel title="Web Audit" icon={<Globe2 size={18} aria-hidden="true" />}>
          <form className="web-audit-form" onSubmit={(event) => void launchWebAudit(event)}>
            <label className="auth-field">
              <span>URL to audit</span>
              <input
                className="search-input"
                type="url"
                placeholder="https://example.com"
                value={webUrl}
                onChange={(event) => setWebUrl(event.target.value)}
                required
              />
            </label>
            {webQueryInspection.hasQueryString ? (
              <div className="query-warning" role="status">
                {webQueryInspection.sensitiveParams.length > 0 ? (
                  <>
                    Possible sensitive parameters will be redacted from results and exports:{" "}
                    <span className="mono">{webQueryInspection.sensitiveParams.join(", ")}</span>
                  </>
                ) : (
                  "This URL includes a query string. Inspectra will use it for the authorized request, but will redact sensitive parameters from results and exports. Do not enter real secrets."
                )}
              </div>
            ) : null}
            <label className="checkbox-row">
              <input
                type="checkbox"
                checked={webAuthorizationConfirmed}
                onChange={(event) => setWebAuthorizationConfirmed(event.target.checked)}
              />
              I confirm I am authorized to audit this target.
            </label>
            <button type="submit" disabled={webAuditState.loading || !webAuthorizationConfirmed}>
              <Play size={16} aria-hidden="true" />
              {webAuditState.loading ? "Starting" : "Analyze URL"}
            </button>
          </form>
          {webAuditState.error ? <p className="error-text">{webAuditState.error}</p> : null}
        </Panel>

        <Panel title="Domain Baseline" icon={<Network size={18} aria-hidden="true" />}>
          <form className="web-audit-form" onSubmit={(event) => void launchDomainAudit(event)}>
            <label className="auth-field">
              <span>Domain to audit</span>
              <input
                className="search-input"
                type="text"
                placeholder="example.com"
                value={domainName}
                onChange={(event) => setDomainName(event.target.value)}
                required
              />
            </label>
            <label className="checkbox-row">
              <input
                type="checkbox"
                checked={domainAuthorizationConfirmed}
                onChange={(event) => setDomainAuthorizationConfirmed(event.target.checked)}
              />
              I confirm I am authorized to audit this domain.
            </label>
            <button type="submit" disabled={domainAuditState.loading || !domainAuthorizationConfirmed}>
              <Play size={16} aria-hidden="true" />
              {domainAuditState.loading ? "Starting" : "Analyze domain"}
            </button>
          </form>
          {domainAuditState.error ? <p className="error-text">{domainAuditState.error}</p> : null}
        </Panel>

        <Panel title="Subdomain Inventory" icon={<Network size={18} aria-hidden="true" />}>
          <form className="web-audit-form" onSubmit={(event) => void launchSubdomainAudit(event)}>
            <label className="auth-field">
              <span>Root domain</span>
              <input
                className="search-input"
                type="text"
                placeholder="example.com"
                value={subdomainRootDomain}
                onChange={(event) => setSubdomainRootDomain(event.target.value)}
                required
              />
            </label>
            <label className="auth-field">
              <span>Explicit subdomain candidates</span>
              <textarea
                className="search-input multiline-input"
                placeholder={"www\napi.example.com\nadmin"}
                value={subdomainCandidates}
                onChange={(event) => setSubdomainCandidates(event.target.value)}
                rows={4}
                required
              />
            </label>
            <label className="checkbox-row">
              <input
                type="checkbox"
                checked={subdomainAuthorizationConfirmed}
                onChange={(event) => setSubdomainAuthorizationConfirmed(event.target.checked)}
              />
              I confirm I am authorized to audit these subdomains.
            </label>
            <button type="submit" disabled={subdomainAuditState.loading || !subdomainAuthorizationConfirmed}>
              <Play size={16} aria-hidden="true" />
              {subdomainAuditState.loading ? "Starting" : "Analyze subdomains"}
            </button>
          </form>
          {subdomainAuditState.error ? <p className="error-text">{subdomainAuditState.error}</p> : null}
        </Panel>

        <div className="query-warning" role="note">
          Live Active checks are no longer started from free-form targets here. Register an exact asset in Active operations, then choose one of its explicitly authorized capabilities.
        </div>
          </div>
        </details>
      </section>

      <section id="projects" className="projects-grid" aria-label="Projects">
        <Suspense fallback={<p className="muted" role="status">Loading passive project actions…</p>}>
          <ProjectActionInboxPanel
            canRebuild={authStatus.role !== "reader"}
            onOpenProject={openProjectWorkspace}
          />
        </Suspense>
        <Suspense fallback={<p className="muted" role="status">Loading project portfolio…</p>}>
          <ProjectPortfolioPanel onOpenProject={openProjectWorkspace} />
        </Suspense>
        <Suspense fallback={<p className="muted" role="status">Loading remediation center…</p>}>
          <RemediationCenterPanel
            canManage={authStatus.role !== "reader"}
            currentUserId={authStatus.operator_id ?? authStatus.default_operator_id}
            members={authStatus.auth_mode === "private_team_lightweight_users" ? undefined : (
              authStatus.operator_id && authStatus.username && authStatus.role
                ? [{ user_id: authStatus.operator_id, username: authStatus.username, role: authStatus.role, joined_at: "" }]
                : []
            )}
            onOpenProject={openProjectWorkspace}
          />
        </Suspense>
        <Suspense fallback={<p className="muted" role="status">Loading risk trends…</p>}>
          <ProjectRiskTrendsPanel onOpenProject={openProjectWorkspace} />
        </Suspense>
        <Panel
          title="Projects"
          icon={<FolderPlus size={18} aria-hidden="true" />}
          action={projectsState.loading ? <span className="muted">Loading</span> : null}
        >
          <p className="muted">
            Projects retain either normalized SBOM revisions or uploaded ZIP/TAR snapshots. Inspectra never reads a server path, clones a repository, or requests repository credentials in this flow.
          </p>
          {projectsTotalCount > 0 ? (
            <p className="muted" role="status">
              Showing {projects.length} of {projectsTotalCount} projects.
            </p>
          ) : null}
          {projectsState.error ? <p className="error-text">{projectsState.error}</p> : null}
          {projects.length === 0 ? (
            <EmptyState text="Create a project from an authorized archive or preflighted SBOM to keep its analysis history together." />
          ) : (
            <div className="table-wrap" role="region" aria-label="Projects table. Scroll horizontally to view all fields." tabIndex={0}>
              <p className="table-scroll-hint" aria-hidden="true">Scroll horizontally to view all project fields.</p>
              <table>
                <caption className="sr-only">Projects</caption>
                <thead>
                  <tr>
                    <th scope="col">Project</th>
                    <th scope="col">Source revision</th>
                    <th scope="col">Latest analysis</th>
                    <th scope="col">Updated</th>
                    <th scope="col">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {projects.map(({ project, latest_job: latestJob }) => (
                    <tr key={project.id}>
                      <td>
                        <strong>{project.name}</strong>
                        <span className="subtle-id">{project.analysis_count} {project.analysis_count === 1 ? "analysis" : "analyses"}</span>
                      </td>
                      <td>
                        <span className="mono">{project.source_reference}</span>
                        <span className="subtle-id">
                          {project.source_type === "sbom" || latestJob?.analysis_profile === "sbom_import"
                            ? project.source_file_deleted_at ? "Normalized SBOM removed; history retained" : "Normalized SBOM retained; original discarded"
                            : project.source_file_deleted_at ? "Archive removed; history retained" : "Archive retained; filename withheld"}
                        </span>
                      </td>
                      <td>
                        {latestJob ? (
                          <>
                            <span className={`status-pill ${latestJob.status}`}>{latestJob.status}</span>
                            <span className="subtle-id">{auditTypeLabel(latestJob.audit_type)}</span>
                          </>
                        ) : (
                          <span className="muted">No retained analysis</span>
                        )}
                      </td>
                      <td>{formatDate(project.updated_at)}</td>
                      <td>
                        <div className="row-actions">
                          <button
                            aria-label={`Open workspace for ${project.name}`}
                            onClick={() => openProjectWorkspace({ project, latest_job: latestJob })}
                          >
                            <FolderPlus size={15} aria-hidden="true" /> Open workspace
                          </button>
                          {latestJob ? (
                            <button
                              className="secondary-button"
                              aria-label={`Explore findings for ${project.name}`}
                              onClick={() => viewProjectFindings({ project, latest_job: latestJob })}
                            >
                              <ShieldCheck size={15} aria-hidden="true" />
                              Findings
                            </button>
                          ) : null}
                          {latestJob ? (
                            <button
                              className="icon-button"
                              aria-label={`View latest analysis for ${project.name}`}
                              title="View latest analysis"
                              onClick={() => void viewJob(latestJob.id)}
                            >
                              <Eye size={16} aria-hidden="true" />
                            </button>
                          ) : null}
                          <button
                            aria-label={`Run recorded snapshot for ${project.name} again`}
                            disabled={
                              project.source_file_deleted_at !== null ||
                              rerunningProjectId !== null ||
                              (latestJob ? isActiveJob(latestJob) : false)
                            }
                            onClick={() => void rerunProjectAnalysis({ project, latest_job: latestJob })}
                          >
                            <Play size={15} aria-hidden="true" />
                            {rerunningProjectId === project.id ? "Starting" : "Run again"}
                          </button>
                          <button
                            className="secondary-button"
                            aria-label={`${project.source_type === "sbom" || latestJob?.analysis_profile === "sbom_import" ? "Add a compatible SBOM revision to" : "Add a new archive snapshot to"} ${project.name}`}
                            disabled={latestJob ? isActiveJob(latestJob) : false}
                            onClick={() => openProjectSourceUpdate({ project, latest_job: latestJob })}
                          >
                            <FilePlus2 size={15} aria-hidden="true" /> {project.source_type === "sbom" || latestJob?.analysis_profile === "sbom_import" ? "Add SBOM revision" : "Add archive snapshot"}
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {projectsNextCursor ? (
            <button
              className="secondary-button"
              disabled={projectsState.loading}
              onClick={() => void loadMoreProjects()}
            >
              {projectsState.loading ? "Loading more projects…" : "Load more projects"}
            </button>
          ) : null}
          {snapshotProject && snapshotProject.project.source_type !== "sbom" && snapshotProject.latest_job?.analysis_profile !== "sbom_import" ? (
            <Suspense fallback={<p className="muted" role="status">Loading snapshot form…</p>}>
              <ProjectSnapshotForm
                project={snapshotProject}
                files={files}
                onCompleted={async (created) => {
                  setSelectedJob({ ...created.job, result: null, error: null });
                  setSelectedProject({ project: created.project, latest_job: { ...created.job, summary: null } });
                  setSnapshotProjectId(null);
                  await Promise.all([refreshProjects(), refreshJobs()]);
                  setWorkflowNotice(`A new source snapshot for ${created.project.name} is queued for analysis.`);
                }}
                onCancel={() => setSnapshotProjectId(null)}
              />
            </Suspense>
          ) : null}
        </Panel>
      </section>

      {selectedProjectSummary ? (
        <section id="project-findings" className="project-findings-region" ref={projectFindingsRef} tabIndex={-1}>
          <Suspense fallback={<p className="muted" role="status">Loading project workspace…</p>}>
            <ProjectWorkspacePanel
              project={selectedProjectSummary}
              onOpenAnalysis={(analysisId) => void viewJob(analysisId)}
              showVulnerabilityIntelligence
              canManageAutomation={authStatus.auth_mode === "self_hosted_single_admin" || authStatus.role === "administrator"}
              focusCiSetup={ciSetupProjectId === selectedProjectSummary.project.id}
              canImportSbomRevision={authStatus.role !== "reader"}
              canManageResponsibility={authStatus.role !== "reader"}
              teamMode={authStatus.auth_mode === "private_team_lightweight_users"}
              currentOperator={{
                user_id: authStatus.operator_id ?? authStatus.default_operator_id,
                username: authStatus.username ?? "local-admin",
              }}
              onProjectUpdated={(updated) => {
                setSelectedProject((current) => current
                  ? { ...current, project: updated }
                  : current);
                setProjects((current) => current.map((item) => item.project.id === updated.id
                  ? { ...item, project: updated }
                  : item));
              }}
              onSbomRevisionImported={async (created) => {
                setSelectedJob({ ...created.job, result: null, error: null });
                setSelectedProject({ project: created.project, latest_job: { ...created.job, summary: null } });
                await Promise.all([refreshProjects(), refreshJobs()]);
                setWorkflowNotice(created.replayed
                  ? `The existing SBOM revision for ${created.project.name} is selected.`
                  : `A new immutable SBOM revision for ${created.project.name} is ready to review.`);
              }}
            />
          </Suspense>
          <Suspense fallback={<p className="muted" role="status">Loading project findings…</p>}>
            <ProjectFindingsPanel
              project={selectedProjectSummary}
              onOpenAnalysis={(analysisId) => void viewJob(analysisId)}
              onRequestNewSnapshot={() => openProjectSourceUpdate(selectedProjectSummary)}
              teamMode={authStatus.auth_mode === "private_team_lightweight_users"}
              currentRole={authStatus.role}
            />
          </Suspense>
          <Suspense fallback={<p className="muted" role="status">Loading component inventory…</p>}>
            <ProjectComponentInventoryPanel project={selectedProjectSummary} />
          </Suspense>
          <Suspense fallback={<p className="muted" role="status">Loading analysis comparison…</p>}>
            <ProjectComparisonPanel
              project={selectedProjectSummary}
              onOpenAnalysis={(analysisId) => void viewJob(analysisId)}
              onRequestNewSnapshot={() => openProjectSourceUpdate(selectedProjectSummary)}
            />
          </Suspense>
          <Suspense fallback={<p className="muted" role="status">Loading project data controls…</p>}>
            <ProjectDeletionPanel
              project={selectedProjectSummary}
              canDelete={authStatus.role !== "reader"}
              onDeleted={handleProjectDeleted}
            />
          </Suspense>
        </section>
      ) : null}

      <section id="jobs" className="content-grid" aria-label="Files and jobs">
        <Panel title="Files" action={filesState.loading ? <span className="muted">Loading</span> : null}>
          <div className="filter-bar">
            <div className="segmented-control" aria-label="File kind filter">
              {(["all", "pdf", "image", "manifest", "archive"] as FileKindFilter[]).map((kind) => (
                <button
                  type="button"
                  key={kind}
                  aria-pressed={fileKindFilter === kind}
                  className={fileKindFilter === kind ? "active" : ""}
                  onClick={() => setFileKindFilter(kind)}
                >
                  {fileKindLabel(kind)}
                </button>
              ))}
            </div>
            <label className="sr-only" htmlFor="file-search">Search files</label>
            <input
              id="file-search"
              className="search-input"
              type="search"
              placeholder="Search files"
              value={fileSearch}
              onChange={(event) => setFileSearch(event.target.value)}
            />
          </div>
          {filesState.error ? <p className="error-text">{filesState.error}</p> : null}
          {files.length === 0 ? (
            <EmptyState text="Upload a file or archive to start a passive review." />
          ) : filteredFiles.length === 0 ? (
            <EmptyState text="No files match the current filters." />
          ) : (
            <div className="table-wrap" role="region" aria-label="Files table. Scroll horizontally to view all fields." tabIndex={0}>
              <p className="table-scroll-hint" aria-hidden="true">Scroll horizontally to view all file fields.</p>
              <table>
                <caption className="sr-only">Files</caption>
                <thead>
                  <tr>
                    <th scope="col">Name</th>
                    <th scope="col">Kind</th>
                    <th scope="col">Size</th>
                    <th scope="col">SHA-256</th>
                    <th scope="col">Created</th>
                    <th scope="col">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredFiles.map((file) => (
                    <tr key={file.id}>
                      <td>
                        <strong>{file.original_filename}</strong>
                        <span className="subtle-id">{file.id}</span>
                      </td>
                      <td>
                        <span className={`status-pill ${kindClass(file.kind)}`}>{file.kind}</span>
                      </td>
                      <td>{formatBytes(file.size_bytes)}</td>
                      <td className="mono">{shortHash(file.sha256)}</td>
                      <td>{formatDate(file.created_at)}</td>
                      <td>
                        <div className="row-actions">
                          {file.kind === "archive" ? (
                            <ArchiveActionGroups
                              groups={buildArchiveActionGroups(file)}
                              projectAuthorizationConfirmed={projectAuthorizationConfirmedFileId === file.id}
                              onProjectAuthorizationChange={(confirmed) => {
                                setProjectAuthorizationConfirmedFileId(confirmed ? file.id : null);
                              }}
                            />
                          ) : (
                            <button onClick={() => void launchAudit(file)}>
                              <Play size={15} aria-hidden="true" />
                              {auditLabel(file.kind)}
                            </button>
                          )}
                          <button className="danger-button" onClick={() => void deleteFile(file.id)}>
                            <Trash2 size={15} aria-hidden="true" />
                            Delete
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>

        <Panel
          title="Jobs"
          action={jobsState.loading ? <span className="muted">Loading</span> : hasActiveJobs ? <span className="muted">Auto-refresh on</span> : null}
        >
          <div className="filter-stack">
            <div className="filter-bar">
              <div className="segmented-control" aria-label="Job status filter">
                {(["all", "queued", "running", "cancelling", "cancelled", "completed", "failed"] as JobStatusFilter[]).map((status) => (
                  <button
                    type="button"
                    key={status}
                    aria-pressed={jobStatusFilter === status}
                    className={jobStatusFilter === status ? "active" : ""}
                    onClick={() => setJobStatusFilter(status)}
                  >
                    {statusLabel(status)}
                  </button>
                ))}
              </div>
              <label className="sr-only" htmlFor="job-search">Search jobs</label>
              <input
                id="job-search"
                className="search-input"
                type="search"
                placeholder="Search jobs"
                value={jobSearch}
                onChange={(event) => setJobSearch(event.target.value)}
              />
            </div>
            <div className="segmented-control wide-control" aria-label="Job audit type filter">
              {JOB_TYPE_FILTERS.map((auditType) => (
                <button
                  type="button"
                  key={auditType}
                  aria-pressed={jobTypeFilter === auditType}
                  className={jobTypeFilter === auditType ? "active" : ""}
                  onClick={() => setJobTypeFilter(auditType)}
                >
                  {auditTypeLabel(auditType)}
                </button>
              ))}
            </div>
          </div>
          {jobsState.error ? <p className="error-text">{jobsState.error}</p> : null}
          {jobsTotalCount > jobs.length ? (
            <p className="muted" role="status">
              Showing {jobs.length} of {jobsTotalCount} jobs. Filters and search apply to loaded jobs; load more to expand the history.
            </p>
          ) : null}
          {jobs.length === 0 ? (
            <EmptyState text="Choose a passive archive review to create a job." />
          ) : filteredJobs.length === 0 ? (
            <EmptyState text="No jobs match the current filters." />
          ) : (
            <div ref={jobTableRef} className="table-wrap" role="region" aria-label="Jobs table. Scroll horizontally to view all fields." tabIndex={0}>
              <p className="table-scroll-hint" aria-hidden="true">Scroll horizontally to view all job fields.</p>
              <table>
                <caption className="sr-only">Jobs</caption>
                <thead>
                  <tr>
                    <th scope="col">Status</th>
                    <th scope="col">Type</th>
                    <th scope="col">Target</th>
                    <th scope="col">Updated</th>
                    <th scope="col">Summary</th>
                    <th scope="col">Detail</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredJobs.map((job) => (
                    <tr key={job.id}>
                      <td>
                        <span className={`status-pill ${job.status}`}>{job.status}</span>
                      </td>
                      <td>
                        {auditTypeLabel(job.audit_type)}
                        <span className="subtle-id">{auditTypeCategoryLabel(job.audit_type)}</span>
                      </td>
                      <td className="mono">{jobTargetDisplay(job)}</td>
                      <td>{formatDate(job.updated_at)}</td>
                      <td>{summarizeJob(job)}</td>
                      <td>
                        <button
                          className="icon-button"
                          aria-label={`View ${auditTypeLabel(job.audit_type)} job`}
                          title="View job"
                          onClick={() => void viewJob(job.id)}
                        >
                          <Eye size={16} aria-hidden="true" />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {jobsNextCursor ? (
                <div className="table-actions">
                  <button type="button" onClick={() => void loadMoreJobs()} disabled={jobsState.loading}>
                    {jobsState.loading ? "Loading more…" : "Load more jobs"}
                  </button>
                </div>
              ) : null}
            </div>
          )}
        </Panel>
      </section>

      <section id="results" className="job-result-region" ref={jobResultRef} tabIndex={-1} aria-live="polite">
      <Panel title="Job Result">
        {selectedJob ? (
          <>
            <ExportActions job={selectedJob} />
            <Suspense fallback={<p className="muted" role="status">Loading redacted job report…</p>}>
              <JobResultReport job={selectedJob} file={selectedJobFile} />
            </Suspense>
          </>
        ) : (
          <EmptyState text="Select a job to view its result." />
        )}
      </Panel>
      </section>
        </>
      )}
    </main>
  );
}

function WorkflowNavigation({ stage, message }: { stage: WorkflowStage; message: string }) {
  const steps: Array<{ id: WorkflowStage; label: string; href: string }> = [
    { id: "prepare", label: "1. Prepare", href: "#start" },
    { id: "run", label: "2. Run analysis", href: "#jobs" },
    { id: "monitor", label: "3. Follow progress", href: "#jobs" },
    { id: "review", label: "4. Review result", href: "#results" }
  ];

  return (
    <section className="workflow-guide" aria-label="Audit workflow">
      <nav className="workflow-nav" aria-label="Audit workflow steps">
        {steps.map((step) => (
          <a key={step.id} href={step.href} aria-current={stage === step.id ? "step" : undefined}>
            {step.label}
          </a>
        ))}
      </nav>
      <p className="workflow-message" role="status">
        <strong>Current step:</strong> {message}
      </p>
    </section>
  );
}

function getWorkflowStage({
  files,
  hasActiveJobs,
  selectedJob
}: {
  files: FileRecord[];
  hasActiveJobs: boolean;
  selectedJob: JobRecord | null;
}): WorkflowStage {
  if (selectedJob) {
    return "review";
  }
  if (hasActiveJobs) {
    return "monitor";
  }
  if (files.length > 0) {
    return "run";
  }
  return "prepare";
}

function getWorkflowMessage(stage: WorkflowStage): string {
  if (stage === "run") {
    return "For a project, confirm authorization in Files and select Create project & analyze. Individual file and target-based reviews remain available.";
  }
  if (stage === "monitor") {
    return "A job is running or queued. The Jobs list refreshes automatically every few seconds.";
  }
  if (stage === "review") {
    return "The selected job is open below. Use the Jobs list to switch context or the export actions to share a redacted report.";
  }
  return "To analyze a project, prepare an authorized archive; individual file and target-based reviews remain available.";
}

function isActiveJob(job: Pick<JobRecord, "status">): boolean {
  return job.status === "queued" || job.status === "running" || job.status === "cancelling";
}

function selectedJobIdFromLocation(): string | null {
  const hash = window.location.hash.startsWith("#") ? window.location.hash.slice(1) : window.location.hash;
  const jobId = new URLSearchParams(hash).get("job");
  return jobId?.trim() || null;
}

function selectedProjectIdFromLocation(): string | null {
  const hash = window.location.hash.startsWith("#") ? window.location.hash.slice(1) : window.location.hash;
  const projectId = new URLSearchParams(hash).get("project");
  return projectId?.trim() || null;
}

function writeSelectedJobToLocation(jobId: string): void {
  const params = new URLSearchParams(window.location.hash.slice(1));
  params.set("job", jobId);
  window.history.replaceState(null, "", `${window.location.pathname}${window.location.search}#${params.toString()}`);
}

function clearSelectedJobFromLocation(): void {
  const params = new URLSearchParams(window.location.hash.slice(1));
  params.delete("job");
  const suffix = params.toString() ? `#${params.toString()}` : "";
  window.history.replaceState(null, "", `${window.location.pathname}${window.location.search}${suffix}`);
}

function writeSelectedProjectToLocation(projectId: string): void {
  const params = new URLSearchParams(window.location.hash.slice(1));
  params.set("project", projectId);
  window.history.replaceState(null, "", `${window.location.pathname}${window.location.search}#${params.toString()}`);
}

function clearSelectedProjectFromLocation(): void {
  const params = new URLSearchParams(window.location.hash.slice(1));
  params.delete("project");
  const suffix = params.toString() ? `#${params.toString()}` : "";
  window.history.replaceState(null, "", `${window.location.pathname}${window.location.search}${suffix}`);
}

function ArchiveActionGroups({
  groups,
  projectAuthorizationConfirmed,
  onProjectAuthorizationChange
}: {
  groups: ArchiveActionGroup[];
  projectAuthorizationConfirmed: boolean;
  onProjectAuthorizationChange: (confirmed: boolean) => void;
}) {
  return (
    <div aria-label="Archive passive review actions">
      <p className="muted">{ARCHIVE_ACTION_SCOPE_COPY}</p>
      <label className="checkbox-row">
        <input
          type="checkbox"
          checked={projectAuthorizationConfirmed}
          onChange={(event) => onProjectAuthorizationChange(event.target.checked)}
        />
        I confirm I own or am authorized to analyze this archive as a project.
      </label>
      {groups.map((group) => (
        <div key={group.label} role="group" aria-label={group.label}>
          <span className="subtle-id">{group.label}</span>
          <div className="row-actions">
            {group.actions.map((action) => (
              <button key={action.label} onClick={action.onClick} disabled={action.disabled}>
                <Play size={15} aria-hidden="true" />
                {action.label}
              </button>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}

function Panel({
  title,
  icon,
  action,
  children
}: {
  title: string;
  icon?: ReactNode;
  action?: ReactNode;
  children: ReactNode;
}) {
  return (
    <section className="panel">
      <div className="panel-header">
        <h2>
          {icon}
          {title}
        </h2>
        {action}
      </div>
      {children}
    </section>
  );
}

function EmptyState({ text }: { text: string }) {
  return <p className="empty-state">{text}</p>;
}

function MetricCard({ label, value }: { label: string; value: number }) {
  return (
    <article className="metric-card">
      <span>{label}</span>
      <strong>{value}</strong>
    </article>
  );
}

function ExportActions({ job }: { job: JobRecord }) {
  const formats: Array<{ format: ReportFormat; label: string }> = [
    { format: "markdown", label: "Export Markdown" },
    { format: "html", label: "Export HTML" },
    { format: "xml", label: "Export XML" },
    { format: "pdf", label: "Export PDF" }
  ];
  const sbomFormats: Array<{ format: SbomFormat; label: string }> = [
    { format: "cyclonedx-json", label: "Export CycloneDX JSON" },
    { format: "spdx-json", label: "Export SPDX JSON" }
  ];

  return (
    <div className="export-actions" aria-label="Job export actions">
      {formats.map((item) => (
        <a key={item.format} className="export-link" href={api.jobExportUrl(job.id, item.format)}>
          <Download size={15} aria-hidden="true" />
          {item.label}
        </a>
      ))}
      {supportsSbomExport(job)
        ? sbomFormats.map((item) => (
            <a key={item.format} className="export-link" href={api.jobSbomUrl(job.id, item.format)}>
              <Download size={15} aria-hidden="true" />
              {item.label}
            </a>
          ))
        : null}
    </div>
  );
}

function supportsSbomExport(job: JobRecord): boolean {
  return job.status === "completed" && (job.audit_type === "manifest_basic" || job.audit_type === "project_archive_basic");
}

export function toErrorMessage(error: unknown): string {
  if (error instanceof ApiError) {
    return error.message;
  }
  return "Unable to complete the request. Refresh the page and try again.";
}

function parseSubdomainCandidates(value: string): string[] {
  return value
    .split(/[\n,]+/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function targetHasUserinfo(value: string): boolean {
  try {
    const parsed = new URL(value);
    return Boolean(parsed.username || parsed.password);
  } catch {
    return /^[a-z][a-z0-9+.-]*:\/\/[^/\s@]+:[^/\s@]+@/i.test(value);
  }
}

function formatDate(value: string): string {
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short"
  }).format(new Date(value));
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) {
    return `${bytes} B`;
  }
  if (bytes < 1024 * 1024) {
    return `${(bytes / 1024).toFixed(1)} KB`;
  }
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function shortHash(value: string): string {
  return `${value.slice(0, 12)}...${value.slice(-8)}`;
}

function shortId(value: string): string {
  return value.slice(0, 10);
}

function jobTargetDisplay(job: JobListItem): string {
  const summaryTarget = typeof job.summary?.target_display === "string" ? job.summary.target_display : null;
  const target = summaryTarget ?? job.target_url ?? job.target_domain ?? "N/A";
  if (job.file_id) {
    return shortId(job.file_id);
  }
  if (job.audit_type === "active_network_dry_run") {
    return redactActiveDryRunText(target);
  }
  if (job.audit_type === "active_http_header_probe") {
    return redactActiveHttpHeaderProbeText(target);
  }
  if (job.audit_type === "active_http_basic_header_review") {
    return redactActiveHttpBasicHeaderReviewText(target);
  }
  if (job.audit_type === "active_nmap_basic") {
    return redactActiveNmapBasicText(target);
  }
  if (job.audit_type === "active_tls_basic") {
    return redactActiveTlsBasicText(target);
  }
  if (job.audit_type === "active_dns_inventory") {
    return redactActiveDnsInventoryText(target);
  }
  if (job.audit_type === "active_dns_osint") {
    return redactActiveDnsOsintText(target);
  }
  return target;
}

function acceptForKind(kind: FileRecord["kind"]): string {
  if (kind === "pdf") {
    return "application/pdf,.pdf";
  }
  if (kind === "image") {
    return "image/jpeg,image/png,image/webp,.jpg,.jpeg,.png,.webp";
  }
  if (kind === "manifest") {
    return "application/json,text/plain,application/toml,.json,.txt,.toml";
  }
  return "application/zip,application/x-tar,application/gzip,.zip,.tar,.tar.gz,.tgz";
}

function uploadErrorForKind(kind: FileRecord["kind"]): string {
  if (kind === "pdf") {
    return "Selecciona un PDF.";
  }
  if (kind === "image") {
    return "Selecciona una imagen.";
  }
  if (kind === "manifest") {
    return "Selecciona un manifiesto.";
  }
  return "Selecciona un archivo comprimido.";
}

function kindClass(kind: FileRecord["kind"]): string {
  if (kind === "pdf") {
    return "pdf-kind";
  }
  if (kind === "image") {
    return "image-kind";
  }
  if (kind === "manifest") {
    return "manifest-kind";
  }
  return "archive-kind";
}

function auditLabel(kind: FileRecord["kind"]): string {
  if (kind === "archive") {
    return "Analyze archive";
  }
  if (kind === "manifest") {
    return "Analyze manifest";
  }
  if (kind === "image") {
    return "Analyze image";
  }
  return "Analyze PDF";
}

function summarizeJob(job: JobListItem): string {
  if (job.status_detail?.message) {
    return job.status_detail.message;
  }
  if (!job.summary) {
    return job.source_file_deleted_at ? "Source deleted" : "Pending";
  }
  const error = typeof job.summary.error === "string" ? job.summary.error : null;
  if (error) {
    return "Review failed.";
  }
  const warnings = Array.isArray(job.summary.warnings) ? job.summary.warnings.length : 0;
  const timedOut = Array.isArray(job.summary.timed_out_tools) ? job.summary.timed_out_tools.length : 0;
  const qpdfOk = typeof job.summary.qpdf_ok === "boolean" ? job.summary.qpdf_ok : undefined;
  const mimeType = typeof job.summary.mime_type === "string" ? job.summary.mime_type : null;
  const manifestType = typeof job.summary.manifest_type === "string" ? job.summary.manifest_type : null;
  const archiveType = typeof job.summary.archive_type === "string" ? job.summary.archive_type : null;
  const statusCode = typeof job.summary.status_code === "number" ? job.summary.status_code : null;
  const totalEntries = typeof job.summary.total_entries === "number" ? job.summary.total_entries : null;
  const totalDependencies = typeof job.summary.total_dependencies === "number" ? job.summary.total_dependencies : null;
  const findingsCount =
    typeof job.summary.informational_findings_count === "number"
      ? job.summary.informational_findings_count
      : typeof job.summary.findings_count === "number"
        ? job.summary.findings_count
        : null;
  if (job.audit_type === "image_basic") {
    return `${mimeType ?? "image"}, ${warnings} warnings, ${timedOut} timeouts`;
  }
  if (job.audit_type === "manifest_basic") {
    return `${manifestType ?? "manifest"}, ${totalDependencies ?? 0} deps, ${findingsCount ?? 0} findings`;
  }
  if (job.audit_type === "archive_basic") {
    return `${archiveType ?? "archive"}, ${totalEntries ?? 0} entries, ${findingsCount ?? 0} findings`;
  }
  if (job.audit_type === "project_archive_basic") {
    return `${archiveType ?? "archive"}, ${totalDependencies ?? 0} deps, ${findingsCount ?? 0} findings`;
  }
  if (job.audit_type === "web_basic") {
    return `HTTP ${statusCode ?? "pending"}, ${findingsCount ?? 0} findings`;
  }
  if (job.audit_type === "domain_basic") {
    const recordsFound = typeof job.summary.records_found_count === "number" ? job.summary.records_found_count : 0;
    return `${recordsFound} records, ${findingsCount ?? 0} findings`;
  }
  if (job.audit_type === "subdomain_inventory_basic") {
    const resolvedCount = typeof job.summary.resolved_count === "number" ? job.summary.resolved_count : 0;
    const acceptedCount = typeof job.summary.candidates_accepted === "number" ? job.summary.candidates_accepted : 0;
    return `${resolvedCount}/${acceptedCount} resolved, ${findingsCount ?? 0} findings`;
  }
  if (job.audit_type === "active_network_dry_run") {
    const allowed = typeof job.summary.allowed === "boolean" ? job.summary.allowed : null;
    const plannedChecks = typeof job.summary.planned_checks_count === "number" ? job.summary.planned_checks_count : 0;
    const blockedReasons = typeof job.summary.blocked_reasons_count === "number" ? job.summary.blocked_reasons_count : 0;
    const networkRequestsSent = typeof job.summary.network_requests_sent === "number" ? job.summary.network_requests_sent : 0;
    return `${allowed === false ? "blocked" : "dry-run"}, ${plannedChecks} planned, ${blockedReasons} blocked, ${networkRequestsSent} network requests`;
  }
  if (job.audit_type === "active_http_header_probe") {
    const allowed = typeof job.summary.allowed === "boolean" ? job.summary.allowed : null;
    const networkRequestsSent = typeof job.summary.network_requests_sent === "number" ? job.summary.network_requests_sent : 0;
    const redirectsFollowed = typeof job.summary.redirects_followed === "number" ? job.summary.redirects_followed : 0;
    const bodyBytesRead = typeof job.summary.body_bytes_read === "number" ? job.summary.body_bytes_read : 0;
    return `${allowed === false || networkRequestsSent === 0 ? "blocked" : "HEAD sent"}, ${networkRequestsSent} request, ${redirectsFollowed} redirects, ${bodyBytesRead} body bytes`;
  }
  if (job.audit_type === "active_http_basic_header_review") {
    const resultStatus = typeof job.summary.result_status === "string" ? job.summary.result_status : "not_executed";
    const method = typeof job.summary.method === "string" ? job.summary.method : "HEAD";
    const requestsSent = typeof job.summary.requests_sent === "number" ? job.summary.requests_sent : 0;
    const liveRequestPerformed = job.summary.live_request_performed === true;
    const redirectFollowed = job.summary.redirect_followed === true;
    const bodyRead = job.summary.body_read === true;
    const lifecycle =
      resultStatus === "not_executed"
        ? "no-live record stored"
        : resultStatus === "timed_out" || resultStatus === "request_failed" || resultStatus === "client_error_controlled"
          ? "controlled live result"
          : "live HEAD attempted";
    return `${resultStatus}, ${lifecycle}, ${method}, HTTP header review indicator, ${requestsSent} requests sent, live request performed ${String(liveRequestPerformed)}, redirect followed ${String(redirectFollowed)}, body read ${String(bodyRead)}, manual validation required`;
  }
  if (job.audit_type === "active_nmap_basic") {
    const lifecycleState =
      typeof job.summary.lifecycle_state === "string"
        ? job.summary.lifecycle_state
        : typeof job.summary.result_status === "string"
          ? job.summary.result_status
          : "not_executed";
    const networkRequestsSent = typeof job.summary.network_requests_sent === "number" ? job.summary.network_requests_sent : 0;
    const noLive = job.summary.no_live_lifecycle_record === true || lifecycleState === "completed_no_live" || lifecycleState === "not_executed";
    if (noLive) {
      return `${lifecycleState}, no Nmap executed, ${networkRequestsSent} network requests, no evidence`;
    }
    const observations = typeof job.summary.observation_count === "number" ? job.summary.observation_count : 0;
    return `${lifecycleState}, ${observations} review indicators`;
  }
  if (job.audit_type === "active_tls_basic") {
    const resultStatus =
      typeof job.summary.result_status === "string"
        ? job.summary.result_status
        : typeof job.summary.handshake_status === "string"
          ? job.summary.handshake_status
          : "tls_error_controlled";
    const protocol = typeof job.summary.protocol === "string" ? job.summary.protocol : "TLS";
    const daysUntilExpiry = typeof job.summary.days_until_expiry === "number" ? job.summary.days_until_expiry : null;
    return `${resultStatus}, ${protocol} review indicator, expiry ${daysUntilExpiry === null ? "N/A" : `${daysUntilExpiry} days`}`;
  }
  if (job.audit_type === "active_dns_inventory") {
    const coverageLevel = typeof job.summary.coverage_level === "string" ? job.summary.coverage_level : "partial_inventory";
    const recordCount = typeof job.summary.record_count === "number" ? job.summary.record_count : 0;
    const subdomainCount = typeof job.summary.subdomain_observed_count === "number" ? job.summary.subdomain_observed_count : 0;
    const spf = job.summary.spf_present === true ? "SPF present" : "SPF absent";
    const dmarc = job.summary.dmarc_present === true ? "DMARC present" : "DMARC absent";
    const caa = job.summary.caa_present === true ? "CAA present" : "CAA absent";
    return `${coverageLevel}, ${recordCount} redacted records, ${spf}, ${dmarc}, ${caa}, ${subdomainCount} bounded subdomains`;
  }
  if (job.audit_type === "active_dns_osint") {
    const coverageLevel = typeof job.summary.coverage_level === "string" ? job.summary.coverage_level : "osint_best_effort";
    const observedNamesCount = typeof job.summary.observed_names_count === "number" ? job.summary.observed_names_count : 0;
    const ctSourceStatus = typeof job.summary.ct_source_status === "string" ? job.summary.ct_source_status : "not_attempted";
    const passiveDnsStatus = typeof job.summary.passive_dns_status === "string" ? job.summary.passive_dns_status : "not_attempted";
    return `${coverageLevel}, CT ${ctSourceStatus}, ${observedNamesCount} redacted observed names, passive DNS ${passiveDnsStatus}`;
  }
  if (job.audit_type === "django_config_basic") {
    const filesRead = typeof job.summary.files_read === "number" ? job.summary.files_read : 0;
    return `${filesRead} files read, ${findingsCount ?? 0} findings`;
  }
  if (job.audit_type === "docker_config_basic") {
    const filesReviewed = typeof job.summary.files_reviewed === "number" ? job.summary.files_reviewed : 0;
    return `${filesReviewed} files reviewed, ${findingsCount ?? 0} findings`;
  }
  if (job.audit_type === "secrets_review_basic") {
    const filesReviewed = typeof job.summary.files_reviewed === "number" ? job.summary.files_reviewed : 0;
    const sensitiveFiles = typeof job.summary.sensitive_files_detected === "number" ? job.summary.sensitive_files_detected : 0;
    return `${filesReviewed} files reviewed, ${sensitiveFiles} sensitive files, ${findingsCount ?? 0} findings`;
  }
  if (job.audit_type === "node_package_config_basic") {
    const filesReviewed = typeof job.summary.files_reviewed === "number" ? job.summary.files_reviewed : 0;
    const packagesDetected = typeof job.summary.packages_detected === "number" ? job.summary.packages_detected : 0;
    const scriptsDetected = typeof job.summary.scripts_detected === "number" ? job.summary.scripts_detected : 0;
    return `${filesReviewed} files reviewed, ${packagesDetected} packages, ${scriptsDetected} scripts, ${findingsCount ?? 0} findings`;
  }
  if (job.audit_type === "ci_cd_config_basic") {
    const filesReviewed = typeof job.summary.files_reviewed === "number" ? job.summary.files_reviewed : 0;
    const workflowsDetected = typeof job.summary.workflow_files_detected === "number" ? job.summary.workflow_files_detected : 0;
    const jobsDetected = typeof job.summary.jobs_detected === "number" ? job.summary.jobs_detected : 0;
    return `${filesReviewed} files reviewed, ${workflowsDetected} workflows, ${jobsDetected} jobs, ${findingsCount ?? 0} findings`;
  }
  if (job.audit_type === "k8s_config_basic") {
    const filesReviewed = typeof job.summary.files_reviewed === "number" ? job.summary.files_reviewed : 0;
    const resourcesDetected = typeof job.summary.resources_detected === "number" ? job.summary.resources_detected : 0;
    const workloadsDetected = typeof job.summary.workloads_detected === "number" ? job.summary.workloads_detected : 0;
    return `${filesReviewed} files reviewed, ${resourcesDetected} resources, ${workloadsDetected} workloads, ${findingsCount ?? 0} findings`;
  }
  if (job.audit_type === "terraform_config_basic") {
    const filesReviewed = typeof job.summary.files_reviewed === "number" ? job.summary.files_reviewed : 0;
    const resourcesDetected = typeof job.summary.resources_detected === "number" ? job.summary.resources_detected : 0;
    const stateFilesDetected = typeof job.summary.state_files_detected === "number" ? job.summary.state_files_detected : 0;
    return `${filesReviewed} files reviewed, ${resourcesDetected} resources, ${stateFilesDetected} state files, ${findingsCount ?? 0} findings`;
  }
  if (job.audit_type === "nginx_config_basic") {
    const filesReviewed = typeof job.summary.files_reviewed === "number" ? job.summary.files_reviewed : 0;
    const serverBlocksDetected = typeof job.summary.server_blocks_detected === "number" ? job.summary.server_blocks_detected : 0;
    const includesDetected = typeof job.summary.includes_detected === "number" ? job.summary.includes_detected : 0;
    return `${filesReviewed} files reviewed, ${serverBlocksDetected} servers, ${includesDetected} includes, ${findingsCount ?? 0} findings`;
  }
  if (job.audit_type === "compose_config_basic") {
    const filesReviewed = typeof job.summary.files_reviewed === "number" ? job.summary.files_reviewed : 0;
    const servicesDetected = typeof job.summary.services_detected === "number" ? job.summary.services_detected : 0;
    const publishedPortsDetected = typeof job.summary.published_ports_detected === "number" ? job.summary.published_ports_detected : 0;
    return `${filesReviewed} files reviewed, ${servicesDetected} services, ${publishedPortsDetected} ports, ${findingsCount ?? 0} findings`;
  }
  if (job.audit_type === "database_config_basic") {
    const filesReviewed = typeof job.summary.files_reviewed === "number" ? job.summary.files_reviewed : 0;
    const enginesDetected = typeof job.summary.engines_detected === "number" ? job.summary.engines_detected : 0;
    const dumpFilesDetected = typeof job.summary.dump_or_backup_files_detected === "number" ? job.summary.dump_or_backup_files_detected : 0;
    return `${filesReviewed} files reviewed, ${enginesDetected} engines, ${dumpFilesDetected} dumps/backups, ${findingsCount ?? 0} findings`;
  }
  if (job.audit_type === "redis_config_basic") {
    const filesReviewed = typeof job.summary.files_reviewed === "number" ? job.summary.files_reviewed : 0;
    const redisFilesDetected = typeof job.summary.redis_files_detected === "number" ? job.summary.redis_files_detected : 0;
    const sentinelFilesDetected = typeof job.summary.sentinel_files_detected === "number" ? job.summary.sentinel_files_detected : 0;
    const dumpOrAofFilesDetected = typeof job.summary.dump_or_aof_files_detected === "number" ? job.summary.dump_or_aof_files_detected : 0;
    return `${filesReviewed} files reviewed, ${redisFilesDetected} Redis configs, ${sentinelFilesDetected} Sentinel configs, ${dumpOrAofFilesDetected} dumps/AOF, ${findingsCount ?? 0} findings`;
  }
  if (job.audit_type === "sql_database_config_basic") {
    const filesReviewed = typeof job.summary.files_reviewed === "number" ? job.summary.files_reviewed : 0;
    const postgresConfigsDetected = typeof job.summary.postgres_configs_detected === "number" ? job.summary.postgres_configs_detected : 0;
    const mysqlConfigsDetected = typeof job.summary.mysql_configs_detected === "number" ? job.summary.mysql_configs_detected : 0;
    const dumpOrBackupFilesDetected = typeof job.summary.dump_or_backup_files_detected === "number" ? job.summary.dump_or_backup_files_detected : 0;
    return `${filesReviewed} files reviewed, ${postgresConfigsDetected} PostgreSQL configs, ${mysqlConfigsDetected} MySQL configs, ${dumpOrBackupFilesDetected} dumps/backups, ${findingsCount ?? 0} findings`;
  }
  const validation = qpdfOk === undefined ? "unknown" : qpdfOk ? "valid" : "review";
  return `${validation}, ${warnings} warnings, ${timedOut} timeouts`;
}

export default App;
