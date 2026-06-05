from contextlib import asynccontextmanager
from typing import Any

from fastapi import BackgroundTasks, Body, FastAPI, File, HTTPException, Request, Response, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.auth import (
    ADMIN_CSRF_HEADER_NAME,
    ADMIN_SESSION_COOKIE_NAME,
    AdminSession,
    AdminSessionStore,
    LoginAttemptStore,
    build_session_cookie_settings,
    is_supported_admin_password_hash,
    verify_admin_csrf_token,
    verify_admin_password,
)
from app.auth_state_sqlite import SQLiteAdminSessionStore, SQLiteLoginAttemptStore
from app.config import (
    get_auth_mode,
    get_current_operator_for_trusted_local,
    is_auth_required,
    is_single_admin_auth_configured,
    load_settings,
)
from app.domain_security import normalize_domain, normalize_subdomain_candidates
from app.models import (
    DeletedFileResponse,
    DeletedJobResponse,
    DomainAuditRequest,
    AuthLoginRequest,
    AuthSessionResponse,
    AuthStatusResponse,
    JobListItem,
    JobRecord,
    StoredFile,
    SubdomainInventoryRequest,
    WebAuditRequest,
)
from app.reporting import (
    build_report_filename,
    public_job_error,
    public_job_target_url,
    public_result_for_job,
    redact_active_secret_text,
    render_html_report,
    render_markdown_report,
    render_pdf_report,
    render_xml_report,
)
from app.sbom import build_sbom_filename, generate_cyclonedx_json, generate_spdx_json
from app.services import (
    ArchiveAuditService,
    ActiveHttpHeaderProbeService,
    ActiveNetworkDryRunService,
    CiCdConfigAuditService,
    ComposeConfigAuditService,
    DatabaseConfigAuditService,
    DjangoConfigAuditService,
    DomainAuditService,
    DockerConfigAuditService,
    ImageAuditService,
    K8sConfigAuditService,
    ManifestAuditService,
    NodePackageConfigAuditService,
    NginxConfigAuditService,
    PdfAuditService,
    ProjectArchiveAuditService,
    RedisConfigAuditService,
    SecretsReviewAuditService,
    SqlDatabaseConfigAuditService,
    SubdomainInventoryAuditService,
    TerraformConfigAuditService,
    WebAuditService,
)
from app.storage import FileStore, JobStore
from app.web_security import redact_url_query, validate_web_target_url
from active_runner import ActiveDryRunRequest, ActiveHttpHeaderProbeRequest


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = load_settings()
    settings.ensure_directories()
    file_store = FileStore(settings)
    job_store = JobStore(settings)

    app.state.settings = settings
    app.state.auth_mode = get_auth_mode(settings)
    app.state.default_local_operator = get_current_operator_for_trusted_local(settings)
    app.state.single_admin_auth_configured = is_single_admin_auth_configured(settings)
    app.state.admin_sessions = create_admin_session_store(settings)
    app.state.login_attempts = create_login_attempt_store(settings)
    app.state.session_cookie_settings = build_session_cookie_settings(settings.session_ttl_seconds)
    app.state.files = file_store
    app.state.jobs = job_store
    app.state.pdf_audits = PdfAuditService(settings, file_store, job_store)
    app.state.image_audits = ImageAuditService(settings, file_store, job_store)
    app.state.manifest_audits = ManifestAuditService(settings, file_store, job_store)
    app.state.archive_audits = ArchiveAuditService(settings, file_store, job_store)
    app.state.project_archive_audits = ProjectArchiveAuditService(settings, file_store, job_store)
    app.state.django_config_audits = DjangoConfigAuditService(settings, file_store, job_store)
    app.state.docker_config_audits = DockerConfigAuditService(settings, file_store, job_store)
    app.state.secrets_review_audits = SecretsReviewAuditService(settings, file_store, job_store)
    app.state.node_package_config_audits = NodePackageConfigAuditService(settings, file_store, job_store)
    app.state.ci_cd_config_audits = CiCdConfigAuditService(settings, file_store, job_store)
    app.state.k8s_config_audits = K8sConfigAuditService(settings, file_store, job_store)
    app.state.terraform_config_audits = TerraformConfigAuditService(settings, file_store, job_store)
    app.state.nginx_config_audits = NginxConfigAuditService(settings, file_store, job_store)
    app.state.compose_config_audits = ComposeConfigAuditService(settings, file_store, job_store)
    app.state.database_config_audits = DatabaseConfigAuditService(settings, file_store, job_store)
    app.state.sql_database_config_audits = SqlDatabaseConfigAuditService(settings, file_store, job_store)
    app.state.redis_config_audits = RedisConfigAuditService(settings, file_store, job_store)
    app.state.active_network_dry_runs = ActiveNetworkDryRunService(settings, job_store)
    app.state.active_http_header_probes = ActiveHttpHeaderProbeService(settings, job_store)
    app.state.web_audits = WebAuditService(settings, file_store, job_store)
    app.state.domain_audits = DomainAuditService(settings, file_store, job_store)
    app.state.subdomain_inventory_audits = SubdomainInventoryAuditService(settings, file_store, job_store)
    yield


app = FastAPI(
    title="Inspectra",
    summary="Lightweight defensive security audit API.",
    version="0.1.0",
    lifespan=lifespan,
)

PUBLIC_ANONYMOUS_PATHS = {"/health", "/auth/status", "/auth/login"}
CSRF_REQUIRED_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
AUTH_REQUIRED_DETAIL = "Authentication required."
CSRF_REQUIRED_DETAIL = "CSRF validation failed."
INVALID_CREDENTIALS_DETAIL = "Invalid credentials."
RATE_LIMITED_DETAIL = "Too many attempts. Try again later."

app.add_middleware(
    CORSMiddleware,
    allow_origins=list(load_settings().cors_origins),
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["*"],
)


@app.middleware("http")
async def deny_anonymous_sensitive_routes(request: Request, call_next) -> Response:
    if request.method == "OPTIONS" or request.url.path in PUBLIC_ANONYMOUS_PATHS:
        return await call_next(request)

    settings = getattr(request.app.state, "settings", None) or load_settings()
    if not is_auth_required(settings):
        return await call_next(request)

    session = current_session_for_request(request)
    if session is None:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"detail": AUTH_REQUIRED_DETAIL},
        )

    if is_csrf_required_for_request(request) and not verify_csrf_token_for_request(request, session):
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={"detail": CSRF_REQUIRED_DETAIL},
        )

    return await call_next(request)


def current_owner_id_for_request(request: Request) -> str:
    session_operator_id = getattr(request.state, "current_operator_id", None)
    if isinstance(session_operator_id, str) and session_operator_id:
        return session_operator_id

    settings = getattr(request.app.state, "settings", None) or load_settings()
    if is_auth_required(settings):
        session = current_session_for_request(request)
        if session is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=AUTH_REQUIRED_DETAIL)
        return session.operator_id

    return request.app.state.default_local_operator.id


def current_session_for_request(request: Request) -> AdminSession | None:
    existing_session = getattr(request.state, "current_session", None)
    if isinstance(existing_session, AdminSession):
        return existing_session

    session_id = request.cookies.get(ADMIN_SESSION_COOKIE_NAME)
    session = request.app.state.admin_sessions.get_session(session_id)
    if session is not None:
        request.state.current_session = session
        request.state.current_operator_id = session.operator_id
    return session


def create_admin_session_store(settings) -> AdminSessionStore | SQLiteAdminSessionStore:
    if get_auth_mode(settings) == "self_hosted_single_admin" and settings.auth_state_store == "sqlite":
        return SQLiteAdminSessionStore(settings.resolved_auth_state_db_path, settings.session_ttl_seconds)
    return AdminSessionStore(settings.session_ttl_seconds)


def create_login_attempt_store(settings) -> LoginAttemptStore | SQLiteLoginAttemptStore:
    if get_auth_mode(settings) == "self_hosted_single_admin" and settings.auth_state_store == "sqlite":
        return SQLiteLoginAttemptStore(
            settings.resolved_auth_state_db_path,
            window_seconds=settings.login_attempt_window_seconds,
            max_failures=settings.login_attempt_max_failures,
            lockout_seconds=settings.login_lockout_seconds,
            max_keys=settings.login_attempt_max_keys,
        )
    return LoginAttemptStore(
        window_seconds=settings.login_attempt_window_seconds,
        max_failures=settings.login_attempt_max_failures,
        lockout_seconds=settings.login_lockout_seconds,
        max_keys=settings.login_attempt_max_keys,
    )


def is_login_available_for_settings(settings) -> bool:
    return get_auth_mode(settings) == "self_hosted_single_admin" and is_supported_admin_password_hash(
        settings.admin_password_hash
    )


def login_client_key_for_request(request: Request) -> str:
    client = request.client
    if client is None or not isinstance(client.host, str) or not client.host.strip():
        return "unknown"
    return client.host.strip()


def is_csrf_required_for_request(request: Request) -> bool:
    return request.method.upper() in CSRF_REQUIRED_METHODS


def csrf_token_for_session(request: Request, session: AdminSession | None) -> str | None:
    if session is None:
        return None
    token_provider = getattr(request.app.state.admin_sessions, "csrf_token_for_session", None)
    if callable(token_provider):
        return token_provider(session)
    return session.csrf_token


def verify_csrf_token_for_request(request: Request, session: AdminSession) -> bool:
    csrf_token = request.headers.get(ADMIN_CSRF_HEADER_NAME)
    verifier = getattr(request.app.state.admin_sessions, "verify_csrf_token", None)
    if callable(verifier):
        return verifier(session.session_id, csrf_token)
    return verify_admin_csrf_token(csrf_token, session)


def owned_by_current_request(request: Request, owner_id: str | None) -> bool:
    return owner_id == current_owner_id_for_request(request)


def require_file_owner(request: Request, stored_file: StoredFile) -> StoredFile:
    if not owned_by_current_request(request, stored_file.owner_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found.")
    return stored_file


def require_job_owner(request: Request, job: JobRecord) -> JobRecord:
    if not owned_by_current_request(request, job.owner_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Job not found.")
    return job


def get_file_for_current_owner(request: Request, file_id: str) -> StoredFile:
    return require_file_owner(request, request.app.state.files.get(file_id))


def get_job_for_current_owner(request: Request, job_id: str) -> JobRecord:
    return require_job_owner(request, request.app.state.jobs.get(job_id))


def owner_id_for_file_job(request: Request, stored_file: StoredFile) -> str:
    return stored_file.owner_id or current_owner_id_for_request(request)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "inspectra-backend"}


@app.get("/auth/status", response_model=AuthStatusResponse)
async def auth_status(request: Request) -> AuthStatusResponse:
    settings = request.app.state.settings
    operator = request.app.state.default_local_operator
    auth_mode = get_auth_mode(settings)
    auth_required = is_auth_required(settings)
    session = current_session_for_request(request) if auth_required else None
    return AuthStatusResponse(
        auth_mode=auth_mode,
        auth_required=auth_required,
        configured=is_single_admin_auth_configured(settings),
        trusted_local=auth_mode == "trusted_local_no_auth",
        default_operator_id=operator.id,
        login_available=is_login_available_for_settings(settings),
        authenticated=session is not None,
        operator_id=session.operator_id if session is not None else None,
        csrf_required=auth_required,
        csrf_token=csrf_token_for_session(request, session),
    )


@app.post("/auth/login", response_model=AuthSessionResponse)
async def auth_login(request: Request, response: Response, login_request: AuthLoginRequest = Body(...)) -> AuthSessionResponse:
    settings = request.app.state.settings
    auth_mode = get_auth_mode(settings)
    username = (login_request.username or "").strip()
    username_allowed = not username or username == "admin"
    password = login_request.password or ""
    login_attempts = request.app.state.login_attempts
    client_key = login_client_key_for_request(request)

    if auth_mode == "self_hosted_single_admin":
        login_attempts.purge_expired()
        if login_attempts.is_locked(client_key):
            retry_after = login_attempts.seconds_until_unlock(client_key)
            headers = {"Retry-After": str(retry_after)} if retry_after > 0 else None
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=RATE_LIMITED_DETAIL,
                headers=headers,
            )

    if (
        auth_mode != "self_hosted_single_admin"
        or not username_allowed
        or not verify_admin_password(password, settings.admin_password_hash)
    ):
        if auth_mode == "self_hosted_single_admin":
            login_attempts.record_failure(client_key)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=INVALID_CREDENTIALS_DETAIL)

    login_attempts.reset_success(client_key)
    session = request.app.state.admin_sessions.create_admin_session(
        request.app.state.default_local_operator.id,
        auth_mode=auth_mode,
    )
    cookie_settings = request.app.state.session_cookie_settings
    response.set_cookie(
        key=cookie_settings.name,
        value=session.session_id,
        max_age=cookie_settings.max_age_seconds,
        httponly=cookie_settings.httponly,
        secure=cookie_settings.secure,
        samesite=cookie_settings.samesite,
        path=cookie_settings.path,
    )
    return AuthSessionResponse(
        authenticated=True,
        operator_id=session.operator_id,
        auth_mode=auth_mode,
    )


@app.post("/auth/logout", response_model=AuthSessionResponse)
async def auth_logout(request: Request, response: Response) -> AuthSessionResponse:
    settings = request.app.state.settings
    auth_mode = get_auth_mode(settings)
    session_id = request.cookies.get(ADMIN_SESSION_COOKIE_NAME)
    request.app.state.admin_sessions.invalidate_session(session_id)
    cookie_settings = request.app.state.session_cookie_settings
    response.delete_cookie(
        key=cookie_settings.name,
        path=cookie_settings.path,
        secure=cookie_settings.secure,
        httponly=cookie_settings.httponly,
        samesite=cookie_settings.samesite,
    )
    return AuthSessionResponse(
        authenticated=False,
        operator_id=None,
        auth_mode=auth_mode,
    )


@app.post("/files/pdf", response_model=StoredFile, status_code=status.HTTP_201_CREATED)
async def upload_pdf(request: Request, file: UploadFile = File(...)) -> StoredFile:
    return await request.app.state.files.save_pdf(file, owner_id=current_owner_id_for_request(request))


@app.post("/files/image", response_model=StoredFile, status_code=status.HTTP_201_CREATED)
async def upload_image(request: Request, file: UploadFile = File(...)) -> StoredFile:
    return await request.app.state.files.save_image(file, owner_id=current_owner_id_for_request(request))


@app.post("/files/manifest", response_model=StoredFile, status_code=status.HTTP_201_CREATED)
async def upload_manifest(request: Request, file: UploadFile = File(...)) -> StoredFile:
    return await request.app.state.files.save_manifest(file, owner_id=current_owner_id_for_request(request))


@app.post("/files/archive", response_model=StoredFile, status_code=status.HTTP_201_CREATED)
async def upload_archive(request: Request, file: UploadFile = File(...)) -> StoredFile:
    return await request.app.state.files.save_archive(file, owner_id=current_owner_id_for_request(request))


@app.get("/files", response_model=list[StoredFile])
async def list_files(request: Request) -> list[StoredFile]:
    return request.app.state.files.list(owner_id=current_owner_id_for_request(request))


@app.get("/files/{file_id}", response_model=StoredFile)
async def get_file(request: Request, file_id: str) -> StoredFile:
    return get_file_for_current_owner(request, file_id)


@app.delete("/files/{file_id}", response_model=DeletedFileResponse)
async def delete_file(request: Request, file_id: str) -> DeletedFileResponse:
    owner_id = current_owner_id_for_request(request)
    deleted_file = request.app.state.files.delete(file_id, owner_id=owner_id)
    associated_jobs_marked = request.app.state.jobs.mark_file_deleted(file_id, owner_id=owner_id)
    return DeletedFileResponse(deleted_file=deleted_file, associated_jobs_marked=associated_jobs_marked)


@app.post("/audits/pdf/{file_id}", response_model=JobRecord, status_code=status.HTTP_202_ACCEPTED)
async def launch_pdf_audit(request: Request, file_id: str, background_tasks: BackgroundTasks) -> JobRecord:
    stored_file = get_file_for_current_owner(request, file_id)
    if stored_file.kind != "pdf":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="File is not a PDF.")
    job = request.app.state.jobs.create_pdf_job(file_id, owner_id=owner_id_for_file_job(request, stored_file))
    background_tasks.add_task(request.app.state.pdf_audits.run_pdf_analysis, job.id)
    return job


@app.post("/audits/image/{file_id}", response_model=JobRecord, status_code=status.HTTP_202_ACCEPTED)
async def launch_image_audit(request: Request, file_id: str, background_tasks: BackgroundTasks) -> JobRecord:
    stored_file = get_file_for_current_owner(request, file_id)
    if stored_file.kind != "image":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="File is not an image.")
    job = request.app.state.jobs.create_image_job(file_id, owner_id=owner_id_for_file_job(request, stored_file))
    background_tasks.add_task(request.app.state.image_audits.run_image_analysis, job.id)
    return job


@app.post("/audits/manifest/{file_id}", response_model=JobRecord, status_code=status.HTTP_202_ACCEPTED)
async def launch_manifest_audit(request: Request, file_id: str, background_tasks: BackgroundTasks) -> JobRecord:
    stored_file = get_file_for_current_owner(request, file_id)
    if stored_file.kind != "manifest":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="File is not a manifest.")
    job = request.app.state.jobs.create_manifest_job(file_id, owner_id=owner_id_for_file_job(request, stored_file))
    background_tasks.add_task(request.app.state.manifest_audits.run_manifest_analysis, job.id)
    return job


@app.post("/audits/archive/{file_id}", response_model=JobRecord, status_code=status.HTTP_202_ACCEPTED)
async def launch_archive_audit(request: Request, file_id: str, background_tasks: BackgroundTasks) -> JobRecord:
    stored_file = get_file_for_current_owner(request, file_id)
    if stored_file.kind != "archive":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="File is not an archive.")
    job = request.app.state.jobs.create_archive_job(file_id, owner_id=owner_id_for_file_job(request, stored_file))
    background_tasks.add_task(request.app.state.archive_audits.run_archive_analysis, job.id)
    return job


@app.post("/audits/project-archive/{file_id}", response_model=JobRecord, status_code=status.HTTP_202_ACCEPTED)
async def launch_project_archive_audit(request: Request, file_id: str, background_tasks: BackgroundTasks) -> JobRecord:
    stored_file = get_file_for_current_owner(request, file_id)
    if stored_file.kind != "archive":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="File is not an archive.")
    job = request.app.state.jobs.create_project_archive_job(file_id, owner_id=owner_id_for_file_job(request, stored_file))
    background_tasks.add_task(request.app.state.project_archive_audits.run_project_archive_analysis, job.id)
    return job


@app.post("/audits/django-config/{file_id}", response_model=JobRecord, status_code=status.HTTP_202_ACCEPTED)
async def launch_django_config_audit(request: Request, file_id: str, background_tasks: BackgroundTasks) -> JobRecord:
    stored_file = get_file_for_current_owner(request, file_id)
    if stored_file.kind != "archive":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="File is not an archive.")
    job = request.app.state.jobs.create_django_config_job(file_id, owner_id=owner_id_for_file_job(request, stored_file))
    background_tasks.add_task(request.app.state.django_config_audits.run_django_config_analysis, job.id)
    return job


@app.post("/audits/docker-config/{file_id}", response_model=JobRecord, status_code=status.HTTP_202_ACCEPTED)
async def launch_docker_config_audit(request: Request, file_id: str, background_tasks: BackgroundTasks) -> JobRecord:
    stored_file = get_file_for_current_owner(request, file_id)
    if stored_file.kind != "archive":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="File is not an archive.")
    job = request.app.state.jobs.create_docker_config_job(file_id, owner_id=owner_id_for_file_job(request, stored_file))
    background_tasks.add_task(request.app.state.docker_config_audits.run_docker_config_analysis, job.id)
    return job


@app.post("/audits/secrets-review/{file_id}", response_model=JobRecord, status_code=status.HTTP_202_ACCEPTED)
async def launch_secrets_review_audit(request: Request, file_id: str, background_tasks: BackgroundTasks) -> JobRecord:
    stored_file = get_file_for_current_owner(request, file_id)
    if stored_file.kind != "archive":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="File is not an archive.")
    job = request.app.state.jobs.create_secrets_review_job(file_id, owner_id=owner_id_for_file_job(request, stored_file))
    background_tasks.add_task(request.app.state.secrets_review_audits.run_secrets_review_analysis, job.id)
    return job


@app.post("/audits/node-package-config/{file_id}", response_model=JobRecord, status_code=status.HTTP_202_ACCEPTED)
async def launch_node_package_config_audit(request: Request, file_id: str, background_tasks: BackgroundTasks) -> JobRecord:
    stored_file = get_file_for_current_owner(request, file_id)
    if stored_file.kind != "archive":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="File is not an archive.")
    job = request.app.state.jobs.create_node_package_config_job(file_id, owner_id=owner_id_for_file_job(request, stored_file))
    background_tasks.add_task(request.app.state.node_package_config_audits.run_node_package_config_analysis, job.id)
    return job


@app.post("/audits/ci-cd-config/{file_id}", response_model=JobRecord, status_code=status.HTTP_202_ACCEPTED)
async def launch_ci_cd_config_audit(request: Request, file_id: str, background_tasks: BackgroundTasks) -> JobRecord:
    stored_file = get_file_for_current_owner(request, file_id)
    if stored_file.kind != "archive":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="File is not an archive.")
    job = request.app.state.jobs.create_ci_cd_config_job(file_id, owner_id=owner_id_for_file_job(request, stored_file))
    background_tasks.add_task(request.app.state.ci_cd_config_audits.run_ci_cd_config_analysis, job.id)
    return job


@app.post("/audits/k8s-config/{file_id}", response_model=JobRecord, status_code=status.HTTP_202_ACCEPTED)
async def launch_k8s_config_audit(request: Request, file_id: str, background_tasks: BackgroundTasks) -> JobRecord:
    stored_file = get_file_for_current_owner(request, file_id)
    if stored_file.kind != "archive":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="File is not an archive.")
    job = request.app.state.jobs.create_k8s_config_job(file_id, owner_id=owner_id_for_file_job(request, stored_file))
    background_tasks.add_task(request.app.state.k8s_config_audits.run_k8s_config_analysis, job.id)
    return job


@app.post("/audits/terraform-config/{file_id}", response_model=JobRecord, status_code=status.HTTP_202_ACCEPTED)
async def launch_terraform_config_audit(request: Request, file_id: str, background_tasks: BackgroundTasks) -> JobRecord:
    stored_file = get_file_for_current_owner(request, file_id)
    if stored_file.kind != "archive":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="File is not an archive.")
    job = request.app.state.jobs.create_terraform_config_job(file_id, owner_id=owner_id_for_file_job(request, stored_file))
    background_tasks.add_task(request.app.state.terraform_config_audits.run_terraform_config_analysis, job.id)
    return job


@app.post("/audits/nginx-config/{file_id}", response_model=JobRecord, status_code=status.HTTP_202_ACCEPTED)
async def launch_nginx_config_audit(request: Request, file_id: str, background_tasks: BackgroundTasks) -> JobRecord:
    stored_file = get_file_for_current_owner(request, file_id)
    if stored_file.kind != "archive":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="File is not an archive.")
    job = request.app.state.jobs.create_nginx_config_job(file_id, owner_id=owner_id_for_file_job(request, stored_file))
    background_tasks.add_task(request.app.state.nginx_config_audits.run_nginx_config_analysis, job.id)
    return job


@app.post("/audits/compose-config/{file_id}", response_model=JobRecord, status_code=status.HTTP_202_ACCEPTED)
async def launch_compose_config_audit(request: Request, file_id: str, background_tasks: BackgroundTasks) -> JobRecord:
    stored_file = get_file_for_current_owner(request, file_id)
    if stored_file.kind != "archive":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="File is not an archive.")
    job = request.app.state.jobs.create_compose_config_job(file_id, owner_id=owner_id_for_file_job(request, stored_file))
    background_tasks.add_task(request.app.state.compose_config_audits.run_compose_config_analysis, job.id)
    return job


@app.post("/audits/database-config/{file_id}", response_model=JobRecord, status_code=status.HTTP_202_ACCEPTED)
async def launch_database_config_audit(request: Request, file_id: str, background_tasks: BackgroundTasks) -> JobRecord:
    stored_file = get_file_for_current_owner(request, file_id)
    if stored_file.kind != "archive":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="File is not an archive.")
    job = request.app.state.jobs.create_database_config_job(file_id, owner_id=owner_id_for_file_job(request, stored_file))
    background_tasks.add_task(request.app.state.database_config_audits.run_database_config_analysis, job.id)
    return job


@app.post("/audits/sql-database-config/{file_id}", response_model=JobRecord, status_code=status.HTTP_202_ACCEPTED)
async def launch_sql_database_config_audit(request: Request, file_id: str, background_tasks: BackgroundTasks) -> JobRecord:
    stored_file = get_file_for_current_owner(request, file_id)
    if stored_file.kind != "archive":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="File is not an archive.")
    job = request.app.state.jobs.create_sql_database_config_job(file_id, owner_id=owner_id_for_file_job(request, stored_file))
    background_tasks.add_task(request.app.state.sql_database_config_audits.run_sql_database_config_analysis, job.id)
    return job


@app.post("/audits/redis-config/{file_id}", response_model=JobRecord, status_code=status.HTTP_202_ACCEPTED)
async def launch_redis_config_audit(request: Request, file_id: str, background_tasks: BackgroundTasks) -> JobRecord:
    stored_file = get_file_for_current_owner(request, file_id)
    if stored_file.kind != "archive":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="File is not an archive.")
    job = request.app.state.jobs.create_redis_config_job(file_id, owner_id=owner_id_for_file_job(request, stored_file))
    background_tasks.add_task(request.app.state.redis_config_audits.run_redis_config_analysis, job.id)
    return job


@app.post("/active/network/dry-run", response_model=JobRecord, status_code=status.HTTP_202_ACCEPTED)
async def launch_active_network_dry_run(
    request: Request,
    background_tasks: BackgroundTasks,
    payload: Any = Body(...),
) -> JobRecord:
    if not request.app.state.settings.active_dry_run_enabled:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Active dry-run checks are disabled in this environment.")
    if not isinstance(payload, dict):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Active dry-run request body must be a JSON object.")
    if "target" not in payload or not str(payload.get("target", "")).strip():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Active dry-run target is required.")
    try:
        active_request = ActiveDryRunRequest.from_mapping(payload)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid active dry-run request: {exc}") from exc

    target_display = redact_active_secret_text(str(payload.get("target", ""))) if payload.get("target") is not None else ""
    job = request.app.state.jobs.create_active_network_dry_run_job(target_display, owner_id=current_owner_id_for_request(request))
    background_tasks.add_task(request.app.state.active_network_dry_runs.run_active_network_dry_run_analysis, job.id, active_request)
    return job


@app.post("/active/network/http-header-probe", response_model=JobRecord, status_code=status.HTTP_202_ACCEPTED)
async def launch_active_http_header_probe(
    request: Request,
    background_tasks: BackgroundTasks,
    payload: Any = Body(...),
) -> JobRecord:
    if not request.app.state.settings.active_http_header_probe_enabled:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Active HTTP header probe is disabled in this environment.")
    if not isinstance(payload, dict):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Active HTTP header probe request body must be a JSON object.")
    if "target" not in payload or not str(payload.get("target", "")).strip():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Active HTTP header probe target is required.")
    try:
        active_request = ActiveHttpHeaderProbeRequest.from_mapping(payload)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid active HTTP header probe request: {exc}") from exc

    target_display = redact_active_secret_text(str(payload.get("target", ""))) if payload.get("target") is not None else ""
    job = request.app.state.jobs.create_active_http_header_probe_job(target_display, owner_id=current_owner_id_for_request(request))
    background_tasks.add_task(request.app.state.active_http_header_probes.run_active_http_header_probe_analysis, job.id, active_request)
    return job


@app.post("/audits/web/basic", response_model=JobRecord, status_code=status.HTTP_202_ACCEPTED)
async def launch_web_basic_audit(request: Request, payload: WebAuditRequest, background_tasks: BackgroundTasks) -> JobRecord:
    if not payload.authorization_confirmed:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Authorization confirmation is required.")
    normalized_url = validate_web_target_url(
        payload.url,
        allow_private_targets=request.app.state.settings.web_allow_private_targets,
        allowed_ports=request.app.state.settings.web_allowed_ports,
    )
    job = request.app.state.jobs.create_web_job(redact_url_query(normalized_url), owner_id=current_owner_id_for_request(request))
    background_tasks.add_task(request.app.state.web_audits.run_web_analysis, job.id, normalized_url)
    return job


@app.post("/audits/domain/basic", response_model=JobRecord, status_code=status.HTTP_202_ACCEPTED)
async def launch_domain_basic_audit(request: Request, payload: DomainAuditRequest, background_tasks: BackgroundTasks) -> JobRecord:
    if not payload.authorization_confirmed:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Authorization confirmation is required.")
    normalized_domain = normalize_domain(payload.domain)
    job = request.app.state.jobs.create_domain_job(normalized_domain, owner_id=current_owner_id_for_request(request))
    background_tasks.add_task(request.app.state.domain_audits.run_domain_analysis, job.id)
    return job


@app.post("/audits/subdomains/basic", response_model=JobRecord, status_code=status.HTTP_202_ACCEPTED)
async def launch_subdomain_inventory_basic_audit(
    request: Request,
    payload: SubdomainInventoryRequest,
    background_tasks: BackgroundTasks,
) -> JobRecord:
    if not payload.authorization_confirmed:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Authorization confirmation is required.")
    normalized_root = normalize_domain(payload.root_domain)
    normalize_subdomain_candidates(
        normalized_root,
        payload.subdomains,
        request.app.state.settings.subdomain_max_candidates,
    )
    job = request.app.state.jobs.create_subdomain_inventory_job(normalized_root, owner_id=current_owner_id_for_request(request))
    background_tasks.add_task(
        request.app.state.subdomain_inventory_audits.run_subdomain_inventory_analysis,
        job.id,
        payload.subdomains,
    )
    return job


@app.get("/jobs", response_model=list[JobListItem])
async def list_jobs(request: Request) -> list[JobListItem]:
    return request.app.state.jobs.list(owner_id=current_owner_id_for_request(request))


@app.get("/jobs/{job_id}", response_model=JobRecord)
async def get_job(request: Request, job_id: str) -> JobRecord:
    job = get_job_for_current_owner(request, job_id)
    if job.audit_type in {
        "ci_cd_config_basic",
        "k8s_config_basic",
        "terraform_config_basic",
        "nginx_config_basic",
        "compose_config_basic",
        "database_config_basic",
        "sql_database_config_basic",
        "redis_config_basic",
        "active_network_dry_run",
        "active_http_header_probe",
    }:
        return job.model_copy(
            update={
                "target_url": public_job_target_url(job) or None,
                "result": public_result_for_job(job, job.result or {}),
                "error": public_job_error(job) or None,
            }
        )
    return job


@app.delete("/jobs/{job_id}", response_model=DeletedJobResponse)
async def delete_job(request: Request, job_id: str) -> DeletedJobResponse:
    deleted_job = request.app.state.jobs.delete(job_id, owner_id=current_owner_id_for_request(request))
    return DeletedJobResponse(job_id=deleted_job.id, deleted=True)


@app.get("/jobs/{job_id}/export/markdown")
async def export_job_markdown(request: Request, job_id: str) -> Response:
    job = get_job_for_current_owner(request, job_id)
    return export_response(render_markdown_report(job), "text/markdown; charset=utf-8", build_report_filename(job, "md"))


@app.get("/jobs/{job_id}/export/html")
async def export_job_html(request: Request, job_id: str) -> Response:
    job = get_job_for_current_owner(request, job_id)
    return export_response(render_html_report(job), "text/html; charset=utf-8", build_report_filename(job, "html"))


@app.get("/jobs/{job_id}/export/xml")
async def export_job_xml(request: Request, job_id: str) -> Response:
    job = get_job_for_current_owner(request, job_id)
    return export_response(render_xml_report(job), "application/xml; charset=utf-8", build_report_filename(job, "xml"))


@app.get("/jobs/{job_id}/export/pdf")
async def export_job_pdf(request: Request, job_id: str) -> Response:
    job = get_job_for_current_owner(request, job_id)
    return export_response(render_pdf_report(job), "application/pdf", build_report_filename(job, "pdf"))


@app.get("/jobs/{job_id}/sbom/cyclonedx-json")
async def export_job_cyclonedx_sbom(request: Request, job_id: str) -> Response:
    job = get_job_for_current_owner(request, job_id)
    return export_response(
        generate_cyclonedx_json(job),
        "application/vnd.cyclonedx+json; charset=utf-8",
        build_sbom_filename(job, "cyclonedx"),
    )


@app.get("/jobs/{job_id}/sbom/spdx-json")
async def export_job_spdx_sbom(request: Request, job_id: str) -> Response:
    job = get_job_for_current_owner(request, job_id)
    return export_response(
        generate_spdx_json(job),
        "application/spdx+json; charset=utf-8",
        build_sbom_filename(job, "spdx"),
    )


def export_response(content: str | bytes, media_type: str, filename: str) -> Response:
    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
