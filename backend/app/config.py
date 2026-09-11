import base64
from dataclasses import dataclass, field
import os
from pathlib import Path
import re
import stat
from typing import Literal, cast
from urllib.parse import urlsplit

from app.auth import is_supported_admin_password_hash


DEFAULT_MAX_UPLOAD_BYTES = 20 * 1024 * 1024
DEFAULT_UPLOAD_RETENTION_DAYS = 30
DEFAULT_JOB_RETENTION_DAYS = 30
DEFAULT_AUDIT_MAX_CONCURRENCY = 4
MAX_AUDIT_MAX_CONCURRENCY = 16
DEFAULT_AUDIT_MAX_INFLIGHT_JOBS = 128
MAX_AUDIT_MAX_INFLIGHT_JOBS = 1_024
DEFAULT_AUDIT_MAX_INFLIGHT_JOBS_PER_OWNER = 32
MAX_AUDIT_MAX_INFLIGHT_JOBS_PER_OWNER = 256
DEFAULT_ACTIVE_MAX_INFLIGHT_JOBS = 16
MAX_ACTIVE_MAX_INFLIGHT_JOBS = 256
DEFAULT_ACTIVE_MAX_INFLIGHT_JOBS_PER_ORGANIZATION = 4
MAX_ACTIVE_MAX_INFLIGHT_JOBS_PER_ORGANIZATION = 64
DEFAULT_ACTIVE_MAX_INFLIGHT_JOBS_PER_ASSET = 2
MAX_ACTIVE_MAX_INFLIGHT_JOBS_PER_ASSET = 16
DEFAULT_ACTIVE_MAX_INFLIGHT_JOBS_PER_CAPABILITY = 4
MAX_ACTIVE_MAX_INFLIGHT_JOBS_PER_CAPABILITY = 64
DEFAULT_PROJECT_ARCHIVE_TIMEOUT_SECONDS = 60.0
MAX_PROJECT_ARCHIVE_TIMEOUT_SECONDS = 300.0
DEFAULT_EXECUTION_WORKSPACE_MAX_BYTES = DEFAULT_MAX_UPLOAD_BYTES
MAX_EXECUTION_WORKSPACE_MAX_BYTES = 1024 * 1024 * 1024
DEFAULT_PROJECT_ARCHIVE_MAX_TOTAL_UNCOMPRESSED_BYTES = 200 * 1024 * 1024
DEFAULT_PROJECT_ARCHIVE_MAX_ARCHIVE_ENTRIES = 5_000
DEFAULT_PROJECT_ARCHIVE_MAX_MANIFESTS = 25
DEFAULT_PROJECT_ARCHIVE_MAX_MANIFEST_BYTES = 1024 * 1024
DEFAULT_PROJECT_ARCHIVE_MAX_TOTAL_MANIFEST_BYTES = 5 * 1024 * 1024
DEFAULT_PROJECT_ARCHIVE_MAX_LOCKFILES = 5
DEFAULT_PROJECT_ARCHIVE_MAX_LOCKFILE_PACKAGES = 2_000
DEFAULT_PROJECT_ARCHIVE_MAX_LOCKFILE_EDGES = 4_000
DEFAULT_PROJECT_MAX_SOURCE_SNAPSHOTS = 100
DEFAULT_LICENSE_REVIEW_DENIED_IDENTIFIERS: tuple[str, ...] = ()
MAX_PROJECT_MAX_SOURCE_SNAPSHOTS = 10_000
DEFAULT_READINESS_TIMEOUT_SECONDS = 2.0
MAX_READINESS_TIMEOUT_SECONDS = 5.0
DEFAULT_TOOL_RUNNER_URL = "http://audit-tools:8081"
DEFAULT_NETWORK_TOOL_RUNNER_URL = "http://network-tools:8081"
DEFAULT_AUTH_MODE = "trusted_local_no_auth"
DEFAULT_DEPLOYMENT_PROFILE = "trusted_local"
DEFAULT_CORS_ORIGINS = ("http://localhost:5173",)
DEFAULT_CORS_ALLOWED_METHODS = ("GET", "POST", "PUT", "DELETE")
DEFAULT_CORS_ALLOWED_HEADERS = (
    "Content-Type",
    "X-CSRF-Token",
    "X-Inspectra-Active-Approval",
)
SUPPORTED_CORS_ALLOWED_METHODS = frozenset(DEFAULT_CORS_ALLOWED_METHODS)
CORS_ALLOWED_HEADER_CANONICAL_NAMES = {
    value.lower(): value for value in DEFAULT_CORS_ALLOWED_HEADERS
}
SUPPORTED_CORS_ALLOWED_HEADERS = frozenset(CORS_ALLOWED_HEADER_CANONICAL_NAMES)
DEFAULT_WEB_ALLOW_PRIVATE_TARGETS = False
DEFAULT_WEB_TIMEOUT_SECONDS = 10.0
DEFAULT_WEB_MAX_RESPONSE_BYTES = 1_048_576
DEFAULT_WEB_MAX_REDIRECTS = 5
DEFAULT_WEB_ALLOWED_PORTS = (80, 443)
DEFAULT_DOMAIN_DNS_TIMEOUT_SECONDS = 5.0
DEFAULT_SUBDOMAIN_MAX_CANDIDATES = 100
DEFAULT_SUBDOMAIN_WILDCARD_CHECKS = 2
DEFAULT_SUBDOMAIN_GLOBAL_DEADLINE_SECONDS = 30.0
DEFAULT_DJANGO_CONFIG_MAX_FILES = 100
DEFAULT_DJANGO_CONFIG_MAX_FILE_BYTES = 524_288
DEFAULT_DJANGO_CONFIG_MAX_TOTAL_BYTES = 2_097_152
DEFAULT_DOCKER_CONFIG_MAX_FILES = 100
DEFAULT_DOCKER_CONFIG_MAX_FILE_BYTES = 524_288
DEFAULT_DOCKER_CONFIG_MAX_TOTAL_BYTES = 2_097_152
DEFAULT_SECRETS_REVIEW_MAX_FILES = 100
DEFAULT_SECRETS_REVIEW_MAX_FILE_BYTES = 524_288
DEFAULT_SECRETS_REVIEW_MAX_TOTAL_BYTES = 2_097_152
DEFAULT_NODE_PACKAGE_CONFIG_MAX_FILES = 100
DEFAULT_NODE_PACKAGE_CONFIG_MAX_FILE_BYTES = 524_288
DEFAULT_NODE_PACKAGE_CONFIG_MAX_TOTAL_BYTES = 2_097_152
DEFAULT_CI_CD_CONFIG_MAX_FILES = 100
DEFAULT_CI_CD_CONFIG_MAX_FILE_BYTES = 524_288
DEFAULT_CI_CD_CONFIG_MAX_TOTAL_BYTES = 2_097_152
DEFAULT_K8S_CONFIG_MAX_FILES = 100
DEFAULT_K8S_CONFIG_MAX_FILE_BYTES = 524_288
DEFAULT_K8S_CONFIG_MAX_TOTAL_BYTES = 2_097_152
DEFAULT_TERRAFORM_CONFIG_MAX_FILES = 100
DEFAULT_TERRAFORM_CONFIG_MAX_FILE_BYTES = 524_288
DEFAULT_TERRAFORM_CONFIG_MAX_TOTAL_BYTES = 2_097_152
DEFAULT_NGINX_CONFIG_MAX_FILES = 100
DEFAULT_NGINX_CONFIG_MAX_FILE_BYTES = 524_288
DEFAULT_NGINX_CONFIG_MAX_TOTAL_BYTES = 2_097_152
DEFAULT_COMPOSE_CONFIG_MAX_FILES = 100
DEFAULT_COMPOSE_CONFIG_MAX_FILE_BYTES = 524_288
DEFAULT_COMPOSE_CONFIG_MAX_TOTAL_BYTES = 2_097_152
DEFAULT_DATABASE_CONFIG_MAX_FILES = 100
DEFAULT_DATABASE_CONFIG_MAX_FILE_BYTES = 524_288
DEFAULT_DATABASE_CONFIG_MAX_TOTAL_BYTES = 2_097_152
DEFAULT_SQL_DATABASE_CONFIG_MAX_FILES = 100
DEFAULT_SQL_DATABASE_CONFIG_MAX_FILE_BYTES = 524_288
DEFAULT_SQL_DATABASE_CONFIG_MAX_TOTAL_BYTES = 2_097_152
DEFAULT_REDIS_CONFIG_MAX_FILES = 100
DEFAULT_REDIS_CONFIG_MAX_FILE_BYTES = 524_288
DEFAULT_REDIS_CONFIG_MAX_TOTAL_BYTES = 2_097_152
DEFAULT_ACTIVE_DRY_RUN_ENABLED = False
DEFAULT_ACTIVE_HTTP_HEADER_PROBE_ENABLED = False
DEFAULT_ACTIVE_HTTP_BASIC_HEADER_REVIEW_ENABLED = False
DEFAULT_ACTIVE_HTTP_BASIC_HEADER_REVIEW_LIVE_HEAD_ENABLED = False
DEFAULT_ACTIVE_NMAP_BASIC_ENABLED = False
DEFAULT_ACTIVE_TLS_BASIC_ENABLED = False
DEFAULT_ACTIVE_DNS_INVENTORY_ENABLED = False
DEFAULT_ACTIVE_DNS_OSINT_ENABLED = False
DEFAULT_ACTIVE_DNS_OSINT_CT_SOURCE_ENABLED = False
DEFAULT_ACTIVE_LEGACY_FREE_TARGETS_ENABLED = False
DEFAULT_ACTIVE_ASSET_VERIFICATION_ENABLED = False
DEFAULT_ACTIVE_RECURRENCE_ENABLED = False
DEFAULT_ACTIVE_FOUR_EYES_ENABLED = False
DEFAULT_ACTIVE_DNS_OSINT_CT_SOURCE_URL = ""
DEFAULT_ACTIVE_DNS_OSINT_CT_SOURCE_TIMEOUT_SECONDS = 5.0
DEFAULT_ACTIVE_DNS_OSINT_CT_SOURCE_MAX_RESPONSE_BYTES = 262_144
DEFAULT_ACTIVE_DNS_OSINT_CT_SOURCE_MAX_NAMES_PARSED = 500
MAX_ACTIVE_DNS_OSINT_CT_SOURCE_TIMEOUT_SECONDS = 10.0
MAX_ACTIVE_DNS_OSINT_CT_SOURCE_MAX_RESPONSE_BYTES = 1_048_576
MAX_ACTIVE_DNS_OSINT_CT_SOURCE_MAX_NAMES_PARSED = 1_000
DEFAULT_PUBLIC_ADVISORY_EGRESS_ENABLED = False
DEFAULT_PUBLIC_ADVISORY_NVD_ENABLED = False
DEFAULT_PUBLIC_ADVISORY_TIMEOUT_SECONDS = 5.0
# The CISA KEV catalog was 1,696,769 bytes on 2026-09-05. The bounded default
# must accommodate the approved fixed feed or the opt-in KEV vertical would
# deterministically fail. It remains capped at exactly 2 MiB.
DEFAULT_PUBLIC_ADVISORY_MAX_RESPONSE_BYTES = 2_097_152
DEFAULT_PUBLIC_ADVISORY_MAX_CONCURRENCY = 2
DEFAULT_PUBLIC_ADVISORY_MAX_RETRIES = 1
DEFAULT_PUBLIC_ADVISORY_CACHE_TTL_SECONDS = 86_400
# Responses may be used as a clearly-labelled stale fallback only within this
# bounded window. It is deliberately separate from TTL: an expired response is
# never presented as current, but it can prevent a provider outage from erasing
# the last normalized evidence.
DEFAULT_PUBLIC_ADVISORY_CACHE_RETENTION_SECONDS = 604_800
DEFAULT_PUBLIC_ADVISORY_MAX_BATCH_COMPONENTS = 25
DEFAULT_PUBLIC_ADVISORY_PRIVATE_PACKAGE_RULES: tuple[str, ...] = ()
# PyPI identities need an explicit deployment-level attestation before their
# name/version can leave the instance. An empty default preserves npm-only
# egress and prevents a Poetry/default-index assumption from leaking a private
# package name.
DEFAULT_PUBLIC_ADVISORY_PUBLIC_PYPI_PACKAGES: tuple[str, ...] = ()
DEFAULT_PUBLIC_ADVISORY_PUBLIC_GO_MODULES: tuple[str, ...] = ()
DEFAULT_PUBLIC_ADVISORY_PUBLIC_COMPOSER_PACKAGES: tuple[str, ...] = ()
DEFAULT_PUBLIC_ADVISORY_PUBLIC_MAVEN_PACKAGES: tuple[str, ...] = ()
DEFAULT_PUBLIC_ADVISORY_PUBLIC_NUGET_PACKAGES: tuple[str, ...] = ()
_PUBLIC_ADVISORY_NPM_PACKAGE_RULE_VALUE = re.compile(r"^(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*$")
_PUBLIC_ADVISORY_PYPI_PACKAGE_RULE_VALUE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
_PUBLIC_ADVISORY_GO_MODULE_RULE_VALUE = re.compile(r"^[a-z0-9][a-z0-9._~-]*(?:/[a-z0-9][a-z0-9._~+\-]*)+$")
_PUBLIC_ADVISORY_CARGO_PACKAGE_RULE_VALUE = re.compile(r"^[a-z0-9][a-z0-9_-]*$")
_PUBLIC_ADVISORY_COMPOSER_PACKAGE_RULE_VALUE = re.compile(r"^[a-z0-9][a-z0-9_.-]*/[a-z0-9][a-z0-9_.-]*$")
_PUBLIC_ADVISORY_MAVEN_PACKAGE_RULE_VALUE = re.compile(r"^[a-z0-9][a-z0-9_.-]*:[a-z0-9][a-z0-9_.-]*$")
_PUBLIC_ADVISORY_NUGET_PACKAGE_RULE_VALUE = re.compile(r"^[a-z0-9][a-z0-9_.-]*$")
_PUBLIC_ADVISORY_NPM_SCOPE_RULE_VALUE = re.compile(r"^@[a-z0-9][a-z0-9._-]*/$")
MAX_PUBLIC_ADVISORY_TIMEOUT_SECONDS = 10.0
MAX_PUBLIC_ADVISORY_MAX_RESPONSE_BYTES = 2_097_152
MAX_PUBLIC_ADVISORY_MAX_CONCURRENCY = 4
MAX_PUBLIC_ADVISORY_MAX_RETRIES = 2
MAX_PUBLIC_ADVISORY_CACHE_TTL_SECONDS = 604_800
MAX_PUBLIC_ADVISORY_CACHE_RETENTION_SECONDS = 2_592_000
MAX_PUBLIC_ADVISORY_MAX_BATCH_COMPONENTS = 100
DEFAULT_ACTIVE_TOOLS_URL = ""
DEFAULT_ACTIVE_TOOLS_HEALTH_TIMEOUT_SECONDS = 2.0
DEFAULT_SESSION_TTL_SECONDS = 3600
DEFAULT_SESSION_COOKIE_SECURE = False
DEFAULT_LOGIN_ATTEMPT_WINDOW_SECONDS = 600
DEFAULT_LOGIN_ATTEMPT_MAX_FAILURES = 5
DEFAULT_LOGIN_LOCKOUT_SECONDS = 900
DEFAULT_LOGIN_ATTEMPT_MAX_KEYS = 1024
DEFAULT_AUTH_STATE_STORE = "memory"
DEFAULT_TEAM_ORGANIZATION_NAME = "Inspectra team"
DEFAULT_TEAM_INVITATION_TTL_SECONDS = 86_400
MAX_TEAM_INVITATION_TTL_SECONDS = 604_800
DEFAULT_TEAM_INVITATION_RETENTION_DAYS = 30
MAX_TEAM_INVITATION_RETENTION_DAYS = 365
DEFAULT_PRODUCT_AUDIT_RETENTION_DAYS = 90
MAX_PRODUCT_AUDIT_RETENTION_DAYS = 3_650
DEFAULT_PRODUCT_AUDIT_MAX_EVENTS = 50_000
MAX_PRODUCT_AUDIT_MAX_EVENTS = 1_000_000
DEFAULT_AUTOMATION_TOKEN_RETENTION_DAYS = 30
MAX_AUTOMATION_TOKEN_RETENTION_DAYS = 365
DEFAULT_ADOPTION_METRICS_ENABLED = False
DEFAULT_INTEGRATION_EVENTS_ENABLED = False
DEFAULT_INTEGRATION_EVENT_TIMEOUT_SECONDS = 5.0
DEFAULT_INTEGRATION_EVENT_MAX_CONCURRENCY = 2
MAX_INTEGRATION_EVENT_TIMEOUT_SECONDS = 10.0
MAX_INTEGRATION_EVENT_MAX_CONCURRENCY = 4
PORTFOLIO_INDEX_HMAC_KEY_BYTES = 32
OIDC_SUBJECT_HMAC_KEY_BYTES = 32
PRIVATE_TLS_STORAGE_FORBIDDEN_MODE_BITS = stat.S_IRWXG | stat.S_IRWXO
SUPPORTED_AUTH_MODES = (
    "trusted_local_no_auth",
    "self_hosted_single_admin",
    "private_team_lightweight_users",
    "public_community_limited_instance",
)
SUPPORTED_DEPLOYMENT_PROFILES = ("trusted_local", "private_tls_proxy")
SUPPORTED_AUTH_STATE_STORES = ("memory", "sqlite")

AuthMode = Literal[
    "trusted_local_no_auth",
    "self_hosted_single_admin",
    "private_team_lightweight_users",
    "public_community_limited_instance",
]
DeploymentProfile = Literal["trusted_local", "private_tls_proxy"]
AuthStateStore = Literal["memory", "sqlite"]


@dataclass(frozen=True)
class LocalOperator:
    id: str
    label: str
    kind: str


DEFAULT_LOCAL_OPERATOR = LocalOperator(
    id="local-admin",
    label="Default local/admin operator",
    kind="local_admin",
)


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    tool_runner_url: str
    network_tool_runner_url: str = DEFAULT_NETWORK_TOOL_RUNNER_URL
    auth_mode: AuthMode = DEFAULT_AUTH_MODE
    deployment_profile: DeploymentProfile = DEFAULT_DEPLOYMENT_PROFILE
    admin_password_hash: str | None = None
    max_upload_bytes: int = DEFAULT_MAX_UPLOAD_BYTES
    upload_retention_days: int = DEFAULT_UPLOAD_RETENTION_DAYS
    job_retention_days: int = DEFAULT_JOB_RETENTION_DAYS
    audit_max_concurrency: int = DEFAULT_AUDIT_MAX_CONCURRENCY
    audit_max_inflight_jobs: int = DEFAULT_AUDIT_MAX_INFLIGHT_JOBS
    audit_max_inflight_jobs_per_owner: int = DEFAULT_AUDIT_MAX_INFLIGHT_JOBS_PER_OWNER
    active_max_inflight_jobs: int = DEFAULT_ACTIVE_MAX_INFLIGHT_JOBS
    active_max_inflight_jobs_per_organization: int = DEFAULT_ACTIVE_MAX_INFLIGHT_JOBS_PER_ORGANIZATION
    active_max_inflight_jobs_per_asset: int = DEFAULT_ACTIVE_MAX_INFLIGHT_JOBS_PER_ASSET
    active_max_inflight_jobs_per_capability: int = DEFAULT_ACTIVE_MAX_INFLIGHT_JOBS_PER_CAPABILITY
    project_archive_timeout_seconds: float = DEFAULT_PROJECT_ARCHIVE_TIMEOUT_SECONDS
    execution_workspace_max_bytes: int = DEFAULT_EXECUTION_WORKSPACE_MAX_BYTES
    project_archive_max_total_uncompressed_bytes: int = DEFAULT_PROJECT_ARCHIVE_MAX_TOTAL_UNCOMPRESSED_BYTES
    project_archive_max_archive_entries: int = DEFAULT_PROJECT_ARCHIVE_MAX_ARCHIVE_ENTRIES
    project_archive_max_manifests: int = DEFAULT_PROJECT_ARCHIVE_MAX_MANIFESTS
    project_archive_max_manifest_bytes: int = DEFAULT_PROJECT_ARCHIVE_MAX_MANIFEST_BYTES
    project_archive_max_total_manifest_bytes: int = DEFAULT_PROJECT_ARCHIVE_MAX_TOTAL_MANIFEST_BYTES
    project_archive_max_lockfiles: int = DEFAULT_PROJECT_ARCHIVE_MAX_LOCKFILES
    project_archive_max_lockfile_packages: int = DEFAULT_PROJECT_ARCHIVE_MAX_LOCKFILE_PACKAGES
    project_archive_max_lockfile_edges: int = DEFAULT_PROJECT_ARCHIVE_MAX_LOCKFILE_EDGES
    project_max_source_snapshots: int = DEFAULT_PROJECT_MAX_SOURCE_SNAPSHOTS
    license_review_denied_identifiers: tuple[str, ...] = DEFAULT_LICENSE_REVIEW_DENIED_IDENTIFIERS
    readiness_timeout_seconds: float = DEFAULT_READINESS_TIMEOUT_SECONDS
    cors_origins: tuple[str, ...] = DEFAULT_CORS_ORIGINS
    cors_allowed_methods: tuple[str, ...] = DEFAULT_CORS_ALLOWED_METHODS
    cors_allowed_headers: tuple[str, ...] = DEFAULT_CORS_ALLOWED_HEADERS
    web_allow_private_targets: bool = DEFAULT_WEB_ALLOW_PRIVATE_TARGETS
    web_timeout_seconds: float = DEFAULT_WEB_TIMEOUT_SECONDS
    web_max_response_bytes: int = DEFAULT_WEB_MAX_RESPONSE_BYTES
    web_max_redirects: int = DEFAULT_WEB_MAX_REDIRECTS
    web_allowed_ports: tuple[int, ...] = DEFAULT_WEB_ALLOWED_PORTS
    domain_dns_timeout_seconds: float = DEFAULT_DOMAIN_DNS_TIMEOUT_SECONDS
    subdomain_max_candidates: int = DEFAULT_SUBDOMAIN_MAX_CANDIDATES
    subdomain_wildcard_checks: int = DEFAULT_SUBDOMAIN_WILDCARD_CHECKS
    subdomain_global_deadline_seconds: float = DEFAULT_SUBDOMAIN_GLOBAL_DEADLINE_SECONDS
    django_config_max_files: int = DEFAULT_DJANGO_CONFIG_MAX_FILES
    django_config_max_file_bytes: int = DEFAULT_DJANGO_CONFIG_MAX_FILE_BYTES
    django_config_max_total_bytes: int = DEFAULT_DJANGO_CONFIG_MAX_TOTAL_BYTES
    docker_config_max_files: int = DEFAULT_DOCKER_CONFIG_MAX_FILES
    docker_config_max_file_bytes: int = DEFAULT_DOCKER_CONFIG_MAX_FILE_BYTES
    docker_config_max_total_bytes: int = DEFAULT_DOCKER_CONFIG_MAX_TOTAL_BYTES
    secrets_review_max_files: int = DEFAULT_SECRETS_REVIEW_MAX_FILES
    secrets_review_max_file_bytes: int = DEFAULT_SECRETS_REVIEW_MAX_FILE_BYTES
    secrets_review_max_total_bytes: int = DEFAULT_SECRETS_REVIEW_MAX_TOTAL_BYTES
    node_package_config_max_files: int = DEFAULT_NODE_PACKAGE_CONFIG_MAX_FILES
    node_package_config_max_file_bytes: int = DEFAULT_NODE_PACKAGE_CONFIG_MAX_FILE_BYTES
    node_package_config_max_total_bytes: int = DEFAULT_NODE_PACKAGE_CONFIG_MAX_TOTAL_BYTES
    ci_cd_config_max_files: int = DEFAULT_CI_CD_CONFIG_MAX_FILES
    ci_cd_config_max_file_bytes: int = DEFAULT_CI_CD_CONFIG_MAX_FILE_BYTES
    ci_cd_config_max_total_bytes: int = DEFAULT_CI_CD_CONFIG_MAX_TOTAL_BYTES
    k8s_config_max_files: int = DEFAULT_K8S_CONFIG_MAX_FILES
    k8s_config_max_file_bytes: int = DEFAULT_K8S_CONFIG_MAX_FILE_BYTES
    k8s_config_max_total_bytes: int = DEFAULT_K8S_CONFIG_MAX_TOTAL_BYTES
    terraform_config_max_files: int = DEFAULT_TERRAFORM_CONFIG_MAX_FILES
    terraform_config_max_file_bytes: int = DEFAULT_TERRAFORM_CONFIG_MAX_FILE_BYTES
    terraform_config_max_total_bytes: int = DEFAULT_TERRAFORM_CONFIG_MAX_TOTAL_BYTES
    nginx_config_max_files: int = DEFAULT_NGINX_CONFIG_MAX_FILES
    nginx_config_max_file_bytes: int = DEFAULT_NGINX_CONFIG_MAX_FILE_BYTES
    nginx_config_max_total_bytes: int = DEFAULT_NGINX_CONFIG_MAX_TOTAL_BYTES
    compose_config_max_files: int = DEFAULT_COMPOSE_CONFIG_MAX_FILES
    compose_config_max_file_bytes: int = DEFAULT_COMPOSE_CONFIG_MAX_FILE_BYTES
    compose_config_max_total_bytes: int = DEFAULT_COMPOSE_CONFIG_MAX_TOTAL_BYTES
    database_config_max_files: int = DEFAULT_DATABASE_CONFIG_MAX_FILES
    database_config_max_file_bytes: int = DEFAULT_DATABASE_CONFIG_MAX_FILE_BYTES
    database_config_max_total_bytes: int = DEFAULT_DATABASE_CONFIG_MAX_TOTAL_BYTES
    sql_database_config_max_files: int = DEFAULT_SQL_DATABASE_CONFIG_MAX_FILES
    sql_database_config_max_file_bytes: int = DEFAULT_SQL_DATABASE_CONFIG_MAX_FILE_BYTES
    sql_database_config_max_total_bytes: int = DEFAULT_SQL_DATABASE_CONFIG_MAX_TOTAL_BYTES
    redis_config_max_files: int = DEFAULT_REDIS_CONFIG_MAX_FILES
    redis_config_max_file_bytes: int = DEFAULT_REDIS_CONFIG_MAX_FILE_BYTES
    redis_config_max_total_bytes: int = DEFAULT_REDIS_CONFIG_MAX_TOTAL_BYTES
    active_dry_run_enabled: bool = DEFAULT_ACTIVE_DRY_RUN_ENABLED
    active_http_header_probe_enabled: bool = DEFAULT_ACTIVE_HTTP_HEADER_PROBE_ENABLED
    active_http_basic_header_review_enabled: bool = DEFAULT_ACTIVE_HTTP_BASIC_HEADER_REVIEW_ENABLED
    active_http_basic_header_review_live_head_enabled: bool = DEFAULT_ACTIVE_HTTP_BASIC_HEADER_REVIEW_LIVE_HEAD_ENABLED
    active_nmap_basic_enabled: bool = DEFAULT_ACTIVE_NMAP_BASIC_ENABLED
    active_tls_basic_enabled: bool = DEFAULT_ACTIVE_TLS_BASIC_ENABLED
    active_dns_inventory_enabled: bool = DEFAULT_ACTIVE_DNS_INVENTORY_ENABLED
    active_dns_osint_enabled: bool = DEFAULT_ACTIVE_DNS_OSINT_ENABLED
    active_dns_osint_ct_source_enabled: bool = DEFAULT_ACTIVE_DNS_OSINT_CT_SOURCE_ENABLED
    active_legacy_free_targets_enabled: bool = DEFAULT_ACTIVE_LEGACY_FREE_TARGETS_ENABLED
    active_asset_verification_enabled: bool = DEFAULT_ACTIVE_ASSET_VERIFICATION_ENABLED
    active_recurrence_enabled: bool = DEFAULT_ACTIVE_RECURRENCE_ENABLED
    active_four_eyes_enabled: bool = DEFAULT_ACTIVE_FOUR_EYES_ENABLED
    active_dns_osint_ct_source_url: str = DEFAULT_ACTIVE_DNS_OSINT_CT_SOURCE_URL
    active_dns_osint_ct_source_timeout_seconds: float = DEFAULT_ACTIVE_DNS_OSINT_CT_SOURCE_TIMEOUT_SECONDS
    active_dns_osint_ct_source_max_response_bytes: int = DEFAULT_ACTIVE_DNS_OSINT_CT_SOURCE_MAX_RESPONSE_BYTES
    active_dns_osint_ct_source_max_names_parsed: int = DEFAULT_ACTIVE_DNS_OSINT_CT_SOURCE_MAX_NAMES_PARSED
    public_advisory_egress_enabled: bool = DEFAULT_PUBLIC_ADVISORY_EGRESS_ENABLED
    public_advisory_nvd_enabled: bool = DEFAULT_PUBLIC_ADVISORY_NVD_ENABLED
    public_advisory_timeout_seconds: float = DEFAULT_PUBLIC_ADVISORY_TIMEOUT_SECONDS
    public_advisory_max_response_bytes: int = DEFAULT_PUBLIC_ADVISORY_MAX_RESPONSE_BYTES
    public_advisory_max_concurrency: int = DEFAULT_PUBLIC_ADVISORY_MAX_CONCURRENCY
    public_advisory_max_retries: int = DEFAULT_PUBLIC_ADVISORY_MAX_RETRIES
    public_advisory_cache_ttl_seconds: int = DEFAULT_PUBLIC_ADVISORY_CACHE_TTL_SECONDS
    public_advisory_cache_retention_seconds: int = DEFAULT_PUBLIC_ADVISORY_CACHE_RETENTION_SECONDS
    public_advisory_max_batch_components: int = DEFAULT_PUBLIC_ADVISORY_MAX_BATCH_COMPONENTS
    public_advisory_private_package_rules: tuple[str, ...] = DEFAULT_PUBLIC_ADVISORY_PRIVATE_PACKAGE_RULES
    public_advisory_public_pypi_packages: tuple[str, ...] = DEFAULT_PUBLIC_ADVISORY_PUBLIC_PYPI_PACKAGES
    public_advisory_public_go_modules: tuple[str, ...] = DEFAULT_PUBLIC_ADVISORY_PUBLIC_GO_MODULES
    public_advisory_public_composer_packages: tuple[str, ...] = DEFAULT_PUBLIC_ADVISORY_PUBLIC_COMPOSER_PACKAGES
    public_advisory_public_maven_packages: tuple[str, ...] = DEFAULT_PUBLIC_ADVISORY_PUBLIC_MAVEN_PACKAGES
    public_advisory_public_nuget_packages: tuple[str, ...] = DEFAULT_PUBLIC_ADVISORY_PUBLIC_NUGET_PACKAGES
    active_tools_url: str = DEFAULT_ACTIVE_TOOLS_URL
    active_tools_health_timeout_seconds: float = DEFAULT_ACTIVE_TOOLS_HEALTH_TIMEOUT_SECONDS
    session_ttl_seconds: int = DEFAULT_SESSION_TTL_SECONDS
    session_cookie_secure: bool = DEFAULT_SESSION_COOKIE_SECURE
    login_attempt_window_seconds: int = DEFAULT_LOGIN_ATTEMPT_WINDOW_SECONDS
    login_attempt_max_failures: int = DEFAULT_LOGIN_ATTEMPT_MAX_FAILURES
    login_lockout_seconds: int = DEFAULT_LOGIN_LOCKOUT_SECONDS
    login_attempt_max_keys: int = DEFAULT_LOGIN_ATTEMPT_MAX_KEYS
    auth_state_store: AuthStateStore = DEFAULT_AUTH_STATE_STORE
    auth_state_db_path: Path | None = None
    team_organization_name: str = DEFAULT_TEAM_ORGANIZATION_NAME
    team_invitation_ttl_seconds: int = DEFAULT_TEAM_INVITATION_TTL_SECONDS
    team_invitation_retention_days: int = DEFAULT_TEAM_INVITATION_RETENTION_DAYS
    product_audit_retention_days: int = DEFAULT_PRODUCT_AUDIT_RETENTION_DAYS
    product_audit_max_events: int = DEFAULT_PRODUCT_AUDIT_MAX_EVENTS
    automation_token_retention_days: int = DEFAULT_AUTOMATION_TOKEN_RETENTION_DAYS
    adoption_metrics_enabled: bool = DEFAULT_ADOPTION_METRICS_ENABLED
    integration_events_enabled: bool = DEFAULT_INTEGRATION_EVENTS_ENABLED
    integration_event_endpoint: str | None = None
    integration_event_allowed_host: str | None = None
    integration_event_signing_key: bytes | None = field(default=None, repr=False)
    integration_event_signing_key_id: str | None = None
    integration_event_timeout_seconds: float = DEFAULT_INTEGRATION_EVENT_TIMEOUT_SECONDS
    integration_event_max_concurrency: int = DEFAULT_INTEGRATION_EVENT_MAX_CONCURRENCY
    portfolio_index_hmac_key: bytes | None = field(default=None, repr=False)
    oidc_issuer: str | None = None
    oidc_authorization_endpoint: str | None = None
    oidc_token_endpoint: str | None = None
    oidc_jwks_uri: str | None = None
    oidc_client_id: str | None = None
    oidc_client_secret: str | None = field(default=None, repr=False)
    oidc_redirect_uri: str | None = None
    oidc_post_login_redirect_uri: str | None = None
    oidc_organization_id: str | None = None
    oidc_reader_group: str | None = None
    oidc_maintainer_group: str | None = None
    oidc_subject_hmac_key: bytes | None = field(default=None, repr=False)
    oidc_tenant_claim: str | None = None
    oidc_expected_tenant: str | None = None

    @property
    def upload_dir(self) -> Path:
        return self.data_dir / "uploads"

    @property
    def results_dir(self) -> Path:
        return self.data_dir / "results"

    @property
    def jobs_dir(self) -> Path:
        return self.results_dir / "jobs"

    @property
    def projects_dir(self) -> Path:
        return self.results_dir / "projects"

    @property
    def public_advisories_dir(self) -> Path:
        return self.results_dir / "public_advisories"

    @property
    def finding_decisions_dir(self) -> Path:
        return self.results_dir / "finding_decisions"

    @property
    def remediation_batches_dir(self) -> Path:
        return self.results_dir / "remediation_batches"

    @property
    def remediation_saved_views_dir(self) -> Path:
        return self.results_dir / "remediation_saved_views"

    @property
    def project_action_inbox_dir(self) -> Path:
        return self.results_dir / "project_action_inbox"

    @property
    def remediation_plan_jobs_dir(self) -> Path:
        return self.results_dir / "remediation_plan_jobs"

    @property
    def remediation_plan_artifacts_dir(self) -> Path:
        return self.results_dir / "remediation_plan_artifacts"

    @property
    def product_audit_dir(self) -> Path:
        return self.results_dir / "product_audit"

    @property
    def active_change_approvals_dir(self) -> Path:
        return self.results_dir / "active_change_approvals"

    @property
    def active_weekly_review_receipts_dir(self) -> Path:
        return self.results_dir / "active_weekly_review_receipts"

    @property
    def project_snapshot_admissions_dir(self) -> Path:
        return self.runtime_dir / "project_snapshot_admissions"

    @property
    def project_deletions_dir(self) -> Path:
        return self.runtime_dir / "project_deletions"

    @property
    def remediation_batch_journals_dir(self) -> Path:
        return self.runtime_dir / "remediation_batches"

    @property
    def active_asset_deletions_dir(self) -> Path:
        return self.runtime_dir / "active_asset_deletions"

    @property
    def execution_workspaces_dir(self) -> Path:
        return self.data_dir / "workspaces"

    @property
    def default_auth_state_db_path(self) -> Path:
        return self.runtime_dir / "auth_state.sqlite3"

    @property
    def runtime_dir(self) -> Path:
        return self.data_dir / "runtime"

    @property
    def integration_event_outbox_path(self) -> Path:
        return self.runtime_dir / "integration_event_outbox.sqlite3"

    @property
    def resolved_auth_state_db_path(self) -> Path:
        return self.auth_state_db_path or self.default_auth_state_db_path

    def ensure_directories(self) -> None:
        directories = (
            self.data_dir,
            self.upload_dir,
            self.results_dir,
            self.jobs_dir,
            self.projects_dir,
            self.public_advisories_dir,
            self.finding_decisions_dir,
            self.remediation_batches_dir,
            self.remediation_saved_views_dir,
            self.project_action_inbox_dir,
            self.remediation_plan_jobs_dir,
            self.remediation_plan_artifacts_dir,
            self.product_audit_dir,
            self.active_change_approvals_dir,
            self.active_weekly_review_receipts_dir,
            self.execution_workspaces_dir,
            self.runtime_dir,
            self.project_snapshot_admissions_dir,
            self.project_deletions_dir,
            self.remediation_batch_journals_dir,
            self.active_asset_deletions_dir,
        )
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.deployment_profile == "private_tls_proxy":
            _validate_private_storage_directory_permissions(directories)


def load_settings() -> Settings:
    data_dir = Path(os.getenv("INSPECTRA_DATA_DIR", "data")).resolve()
    tool_runner_url = _fixed_internal_runner_url_from_env("INSPECTRA_TOOL_RUNNER_URL", DEFAULT_TOOL_RUNNER_URL)
    network_tool_runner_url = _fixed_internal_runner_url_from_env(
        "INSPECTRA_NETWORK_TOOL_RUNNER_URL",
        DEFAULT_NETWORK_TOOL_RUNNER_URL,
    )
    auth_mode = _auth_mode_from_env("INSPECTRA_AUTH_MODE", DEFAULT_AUTH_MODE)
    deployment_profile = _deployment_profile_from_env(
        "INSPECTRA_DEPLOYMENT_PROFILE",
        DEFAULT_DEPLOYMENT_PROFILE,
    )
    auth_state_store = _auth_state_store_from_env("INSPECTRA_AUTH_STATE_STORE", DEFAULT_AUTH_STATE_STORE)
    admin_password_hash = _optional_secret_from_env("INSPECTRA_ADMIN_PASSWORD_HASH")
    max_upload_bytes = _positive_int_from_env("INSPECTRA_MAX_UPLOAD_BYTES", DEFAULT_MAX_UPLOAD_BYTES)
    upload_retention_days = _non_negative_int_from_env(
        "INSPECTRA_UPLOAD_RETENTION_DAYS",
        DEFAULT_UPLOAD_RETENTION_DAYS,
    )
    job_retention_days = _non_negative_int_from_env(
        "INSPECTRA_JOB_RETENTION_DAYS",
        DEFAULT_JOB_RETENTION_DAYS,
    )
    audit_max_concurrency = _bounded_positive_int_from_env(
        "INSPECTRA_AUDIT_MAX_CONCURRENCY",
        DEFAULT_AUDIT_MAX_CONCURRENCY,
        MAX_AUDIT_MAX_CONCURRENCY,
    )
    audit_max_inflight_jobs = _bounded_positive_int_from_env(
        "INSPECTRA_AUDIT_MAX_INFLIGHT_JOBS",
        DEFAULT_AUDIT_MAX_INFLIGHT_JOBS,
        MAX_AUDIT_MAX_INFLIGHT_JOBS,
    )
    audit_max_inflight_jobs_per_owner = _bounded_positive_int_from_env(
        "INSPECTRA_AUDIT_MAX_INFLIGHT_JOBS_PER_OWNER",
        DEFAULT_AUDIT_MAX_INFLIGHT_JOBS_PER_OWNER,
        MAX_AUDIT_MAX_INFLIGHT_JOBS_PER_OWNER,
    )
    if audit_max_inflight_jobs_per_owner > audit_max_inflight_jobs:
        raise ValueError("INSPECTRA_AUDIT_MAX_INFLIGHT_JOBS_PER_OWNER must not exceed INSPECTRA_AUDIT_MAX_INFLIGHT_JOBS.")
    active_max_inflight_jobs = _bounded_positive_int_from_env(
        "INSPECTRA_ACTIVE_MAX_INFLIGHT_JOBS",
        min(DEFAULT_ACTIVE_MAX_INFLIGHT_JOBS, audit_max_inflight_jobs),
        MAX_ACTIVE_MAX_INFLIGHT_JOBS,
    )
    active_max_inflight_jobs_per_organization = _bounded_positive_int_from_env(
        "INSPECTRA_ACTIVE_MAX_INFLIGHT_JOBS_PER_ORGANIZATION",
        min(DEFAULT_ACTIVE_MAX_INFLIGHT_JOBS_PER_ORGANIZATION, active_max_inflight_jobs),
        MAX_ACTIVE_MAX_INFLIGHT_JOBS_PER_ORGANIZATION,
    )
    active_max_inflight_jobs_per_asset = _bounded_positive_int_from_env(
        "INSPECTRA_ACTIVE_MAX_INFLIGHT_JOBS_PER_ASSET",
        min(DEFAULT_ACTIVE_MAX_INFLIGHT_JOBS_PER_ASSET, active_max_inflight_jobs_per_organization),
        MAX_ACTIVE_MAX_INFLIGHT_JOBS_PER_ASSET,
    )
    active_max_inflight_jobs_per_capability = _bounded_positive_int_from_env(
        "INSPECTRA_ACTIVE_MAX_INFLIGHT_JOBS_PER_CAPABILITY",
        min(DEFAULT_ACTIVE_MAX_INFLIGHT_JOBS_PER_CAPABILITY, active_max_inflight_jobs),
        MAX_ACTIVE_MAX_INFLIGHT_JOBS_PER_CAPABILITY,
    )
    if active_max_inflight_jobs > audit_max_inflight_jobs:
        raise ValueError("INSPECTRA_ACTIVE_MAX_INFLIGHT_JOBS must not exceed INSPECTRA_AUDIT_MAX_INFLIGHT_JOBS.")
    if active_max_inflight_jobs_per_organization > active_max_inflight_jobs:
        raise ValueError("INSPECTRA_ACTIVE_MAX_INFLIGHT_JOBS_PER_ORGANIZATION must not exceed INSPECTRA_ACTIVE_MAX_INFLIGHT_JOBS.")
    if active_max_inflight_jobs_per_asset > active_max_inflight_jobs_per_organization:
        raise ValueError("INSPECTRA_ACTIVE_MAX_INFLIGHT_JOBS_PER_ASSET must not exceed INSPECTRA_ACTIVE_MAX_INFLIGHT_JOBS_PER_ORGANIZATION.")
    if active_max_inflight_jobs_per_capability > active_max_inflight_jobs:
        raise ValueError("INSPECTRA_ACTIVE_MAX_INFLIGHT_JOBS_PER_CAPABILITY must not exceed INSPECTRA_ACTIVE_MAX_INFLIGHT_JOBS.")
    project_archive_timeout_seconds = _bounded_positive_float_from_env(
        "INSPECTRA_PROJECT_ARCHIVE_TIMEOUT_SECONDS",
        DEFAULT_PROJECT_ARCHIVE_TIMEOUT_SECONDS,
        MAX_PROJECT_ARCHIVE_TIMEOUT_SECONDS,
    )
    execution_workspace_max_bytes = _bounded_positive_int_from_env(
        "INSPECTRA_EXECUTION_WORKSPACE_MAX_BYTES",
        DEFAULT_EXECUTION_WORKSPACE_MAX_BYTES,
        MAX_EXECUTION_WORKSPACE_MAX_BYTES,
    )
    project_archive_max_total_uncompressed_bytes = _positive_int_from_env(
        "INSPECTRA_PROJECT_ARCHIVE_MAX_TOTAL_UNCOMPRESSED_BYTES",
        DEFAULT_PROJECT_ARCHIVE_MAX_TOTAL_UNCOMPRESSED_BYTES,
    )
    project_archive_max_archive_entries = _positive_int_from_env(
        "INSPECTRA_PROJECT_ARCHIVE_MAX_ARCHIVE_ENTRIES",
        DEFAULT_PROJECT_ARCHIVE_MAX_ARCHIVE_ENTRIES,
    )
    project_archive_max_manifests = _positive_int_from_env(
        "INSPECTRA_PROJECT_ARCHIVE_MAX_MANIFESTS",
        DEFAULT_PROJECT_ARCHIVE_MAX_MANIFESTS,
    )
    project_archive_max_manifest_bytes = _positive_int_from_env(
        "INSPECTRA_PROJECT_ARCHIVE_MAX_MANIFEST_BYTES",
        DEFAULT_PROJECT_ARCHIVE_MAX_MANIFEST_BYTES,
    )
    project_archive_max_total_manifest_bytes = _positive_int_from_env(
        "INSPECTRA_PROJECT_ARCHIVE_MAX_TOTAL_MANIFEST_BYTES",
        DEFAULT_PROJECT_ARCHIVE_MAX_TOTAL_MANIFEST_BYTES,
    )
    project_archive_max_lockfiles = _positive_int_from_env(
        "INSPECTRA_PROJECT_ARCHIVE_MAX_LOCKFILES",
        DEFAULT_PROJECT_ARCHIVE_MAX_LOCKFILES,
    )
    project_archive_max_lockfile_packages = _positive_int_from_env(
        "INSPECTRA_PROJECT_ARCHIVE_MAX_LOCKFILE_PACKAGES",
        DEFAULT_PROJECT_ARCHIVE_MAX_LOCKFILE_PACKAGES,
    )
    project_archive_max_lockfile_edges = _positive_int_from_env(
        "INSPECTRA_PROJECT_ARCHIVE_MAX_LOCKFILE_EDGES",
        DEFAULT_PROJECT_ARCHIVE_MAX_LOCKFILE_EDGES,
    )
    project_max_source_snapshots = _bounded_positive_int_from_env(
        "INSPECTRA_PROJECT_MAX_SOURCE_SNAPSHOTS",
        DEFAULT_PROJECT_MAX_SOURCE_SNAPSHOTS,
        MAX_PROJECT_MAX_SOURCE_SNAPSHOTS,
    )
    license_review_denied_identifiers = _license_identifiers_from_env(
        "INSPECTRA_LICENSE_REVIEW_DENIED_IDENTIFIERS",
        DEFAULT_LICENSE_REVIEW_DENIED_IDENTIFIERS,
    )
    readiness_timeout_seconds = _bounded_positive_float_from_env(
        "INSPECTRA_READINESS_TIMEOUT_SECONDS",
        DEFAULT_READINESS_TIMEOUT_SECONDS,
        MAX_READINESS_TIMEOUT_SECONDS,
    )
    cors_origins = _cors_origins_from_env("INSPECTRA_CORS_ORIGINS", DEFAULT_CORS_ORIGINS)
    cors_allowed_methods = _cors_methods_from_env("INSPECTRA_CORS_ALLOWED_METHODS", DEFAULT_CORS_ALLOWED_METHODS)
    cors_allowed_headers = _cors_headers_from_env("INSPECTRA_CORS_ALLOWED_HEADERS", DEFAULT_CORS_ALLOWED_HEADERS)
    web_allow_private_targets = _bool_from_env("INSPECTRA_WEB_ALLOW_PRIVATE_TARGETS", DEFAULT_WEB_ALLOW_PRIVATE_TARGETS)
    web_timeout_seconds = _positive_float_from_env("INSPECTRA_WEB_TIMEOUT_SECONDS", DEFAULT_WEB_TIMEOUT_SECONDS)
    web_max_response_bytes = _positive_int_from_env("INSPECTRA_WEB_MAX_RESPONSE_BYTES", DEFAULT_WEB_MAX_RESPONSE_BYTES)
    web_max_redirects = _positive_int_from_env("INSPECTRA_WEB_MAX_REDIRECTS", DEFAULT_WEB_MAX_REDIRECTS)
    web_allowed_ports = _ports_from_env("INSPECTRA_WEB_ALLOWED_PORTS", DEFAULT_WEB_ALLOWED_PORTS)
    domain_dns_timeout_seconds = _positive_float_from_env(
        "INSPECTRA_DOMAIN_DNS_TIMEOUT_SECONDS",
        DEFAULT_DOMAIN_DNS_TIMEOUT_SECONDS,
    )
    subdomain_max_candidates = _positive_int_from_env(
        "INSPECTRA_SUBDOMAIN_MAX_CANDIDATES",
        DEFAULT_SUBDOMAIN_MAX_CANDIDATES,
    )
    subdomain_wildcard_checks = _non_negative_int_from_env(
        "INSPECTRA_SUBDOMAIN_WILDCARD_CHECKS",
        DEFAULT_SUBDOMAIN_WILDCARD_CHECKS,
    )
    subdomain_global_deadline_seconds = _positive_float_from_env(
        "INSPECTRA_SUBDOMAIN_GLOBAL_DEADLINE_SECONDS",
        DEFAULT_SUBDOMAIN_GLOBAL_DEADLINE_SECONDS,
    )
    django_config_max_files = _positive_int_from_env(
        "INSPECTRA_DJANGO_CONFIG_MAX_FILES",
        DEFAULT_DJANGO_CONFIG_MAX_FILES,
    )
    django_config_max_file_bytes = _positive_int_from_env(
        "INSPECTRA_DJANGO_CONFIG_MAX_FILE_BYTES",
        DEFAULT_DJANGO_CONFIG_MAX_FILE_BYTES,
    )
    django_config_max_total_bytes = _positive_int_from_env(
        "INSPECTRA_DJANGO_CONFIG_MAX_TOTAL_BYTES",
        DEFAULT_DJANGO_CONFIG_MAX_TOTAL_BYTES,
    )
    docker_config_max_files = _positive_int_from_env(
        "INSPECTRA_DOCKER_CONFIG_MAX_FILES",
        DEFAULT_DOCKER_CONFIG_MAX_FILES,
    )
    docker_config_max_file_bytes = _positive_int_from_env(
        "INSPECTRA_DOCKER_CONFIG_MAX_FILE_BYTES",
        DEFAULT_DOCKER_CONFIG_MAX_FILE_BYTES,
    )
    docker_config_max_total_bytes = _positive_int_from_env(
        "INSPECTRA_DOCKER_CONFIG_MAX_TOTAL_BYTES",
        DEFAULT_DOCKER_CONFIG_MAX_TOTAL_BYTES,
    )
    secrets_review_max_files = _positive_int_from_env(
        "INSPECTRA_SECRETS_REVIEW_MAX_FILES",
        DEFAULT_SECRETS_REVIEW_MAX_FILES,
    )
    secrets_review_max_file_bytes = _positive_int_from_env(
        "INSPECTRA_SECRETS_REVIEW_MAX_FILE_BYTES",
        DEFAULT_SECRETS_REVIEW_MAX_FILE_BYTES,
    )
    secrets_review_max_total_bytes = _positive_int_from_env(
        "INSPECTRA_SECRETS_REVIEW_MAX_TOTAL_BYTES",
        DEFAULT_SECRETS_REVIEW_MAX_TOTAL_BYTES,
    )
    node_package_config_max_files = _positive_int_from_env(
        "INSPECTRA_NODE_PACKAGE_CONFIG_MAX_FILES",
        DEFAULT_NODE_PACKAGE_CONFIG_MAX_FILES,
    )
    node_package_config_max_file_bytes = _positive_int_from_env(
        "INSPECTRA_NODE_PACKAGE_CONFIG_MAX_FILE_BYTES",
        DEFAULT_NODE_PACKAGE_CONFIG_MAX_FILE_BYTES,
    )
    node_package_config_max_total_bytes = _positive_int_from_env(
        "INSPECTRA_NODE_PACKAGE_CONFIG_MAX_TOTAL_BYTES",
        DEFAULT_NODE_PACKAGE_CONFIG_MAX_TOTAL_BYTES,
    )
    ci_cd_config_max_files = _positive_int_from_env(
        "INSPECTRA_CI_CD_CONFIG_MAX_FILES",
        DEFAULT_CI_CD_CONFIG_MAX_FILES,
    )
    ci_cd_config_max_file_bytes = _positive_int_from_env(
        "INSPECTRA_CI_CD_CONFIG_MAX_FILE_BYTES",
        DEFAULT_CI_CD_CONFIG_MAX_FILE_BYTES,
    )
    ci_cd_config_max_total_bytes = _positive_int_from_env(
        "INSPECTRA_CI_CD_CONFIG_MAX_TOTAL_BYTES",
        DEFAULT_CI_CD_CONFIG_MAX_TOTAL_BYTES,
    )
    k8s_config_max_files = _positive_int_from_env(
        "INSPECTRA_K8S_CONFIG_MAX_FILES",
        DEFAULT_K8S_CONFIG_MAX_FILES,
    )
    k8s_config_max_file_bytes = _positive_int_from_env(
        "INSPECTRA_K8S_CONFIG_MAX_FILE_BYTES",
        DEFAULT_K8S_CONFIG_MAX_FILE_BYTES,
    )
    k8s_config_max_total_bytes = _positive_int_from_env(
        "INSPECTRA_K8S_CONFIG_MAX_TOTAL_BYTES",
        DEFAULT_K8S_CONFIG_MAX_TOTAL_BYTES,
    )
    terraform_config_max_files = _positive_int_from_env(
        "INSPECTRA_TERRAFORM_CONFIG_MAX_FILES",
        DEFAULT_TERRAFORM_CONFIG_MAX_FILES,
    )
    terraform_config_max_file_bytes = _positive_int_from_env(
        "INSPECTRA_TERRAFORM_CONFIG_MAX_FILE_BYTES",
        DEFAULT_TERRAFORM_CONFIG_MAX_FILE_BYTES,
    )
    terraform_config_max_total_bytes = _positive_int_from_env(
        "INSPECTRA_TERRAFORM_CONFIG_MAX_TOTAL_BYTES",
        DEFAULT_TERRAFORM_CONFIG_MAX_TOTAL_BYTES,
    )
    nginx_config_max_files = _positive_int_from_env(
        "INSPECTRA_NGINX_CONFIG_MAX_FILES",
        DEFAULT_NGINX_CONFIG_MAX_FILES,
    )
    nginx_config_max_file_bytes = _positive_int_from_env(
        "INSPECTRA_NGINX_CONFIG_MAX_FILE_BYTES",
        DEFAULT_NGINX_CONFIG_MAX_FILE_BYTES,
    )
    nginx_config_max_total_bytes = _positive_int_from_env(
        "INSPECTRA_NGINX_CONFIG_MAX_TOTAL_BYTES",
        DEFAULT_NGINX_CONFIG_MAX_TOTAL_BYTES,
    )
    compose_config_max_files = _positive_int_from_env(
        "INSPECTRA_COMPOSE_CONFIG_MAX_FILES",
        DEFAULT_COMPOSE_CONFIG_MAX_FILES,
    )
    compose_config_max_file_bytes = _positive_int_from_env(
        "INSPECTRA_COMPOSE_CONFIG_MAX_FILE_BYTES",
        DEFAULT_COMPOSE_CONFIG_MAX_FILE_BYTES,
    )
    compose_config_max_total_bytes = _positive_int_from_env(
        "INSPECTRA_COMPOSE_CONFIG_MAX_TOTAL_BYTES",
        DEFAULT_COMPOSE_CONFIG_MAX_TOTAL_BYTES,
    )
    database_config_max_files = _positive_int_from_env(
        "INSPECTRA_DATABASE_CONFIG_MAX_FILES",
        DEFAULT_DATABASE_CONFIG_MAX_FILES,
    )
    database_config_max_file_bytes = _positive_int_from_env(
        "INSPECTRA_DATABASE_CONFIG_MAX_FILE_BYTES",
        DEFAULT_DATABASE_CONFIG_MAX_FILE_BYTES,
    )
    database_config_max_total_bytes = _positive_int_from_env(
        "INSPECTRA_DATABASE_CONFIG_MAX_TOTAL_BYTES",
        DEFAULT_DATABASE_CONFIG_MAX_TOTAL_BYTES,
    )
    sql_database_config_max_files = _positive_int_from_env(
        "INSPECTRA_SQL_DATABASE_CONFIG_MAX_FILES",
        DEFAULT_SQL_DATABASE_CONFIG_MAX_FILES,
    )
    sql_database_config_max_file_bytes = _positive_int_from_env(
        "INSPECTRA_SQL_DATABASE_CONFIG_MAX_FILE_BYTES",
        DEFAULT_SQL_DATABASE_CONFIG_MAX_FILE_BYTES,
    )
    sql_database_config_max_total_bytes = _positive_int_from_env(
        "INSPECTRA_SQL_DATABASE_CONFIG_MAX_TOTAL_BYTES",
        DEFAULT_SQL_DATABASE_CONFIG_MAX_TOTAL_BYTES,
    )
    redis_config_max_files = _positive_int_from_env(
        "INSPECTRA_REDIS_CONFIG_MAX_FILES",
        DEFAULT_REDIS_CONFIG_MAX_FILES,
    )
    redis_config_max_file_bytes = _positive_int_from_env(
        "INSPECTRA_REDIS_CONFIG_MAX_FILE_BYTES",
        DEFAULT_REDIS_CONFIG_MAX_FILE_BYTES,
    )
    redis_config_max_total_bytes = _positive_int_from_env(
        "INSPECTRA_REDIS_CONFIG_MAX_TOTAL_BYTES",
        DEFAULT_REDIS_CONFIG_MAX_TOTAL_BYTES,
    )
    active_dry_run_enabled = _bool_from_env("INSPECTRA_ACTIVE_DRY_RUN_ENABLED", DEFAULT_ACTIVE_DRY_RUN_ENABLED)
    active_http_header_probe_enabled = _bool_from_env(
        "INSPECTRA_ACTIVE_HTTP_HEADER_PROBE_ENABLED",
        DEFAULT_ACTIVE_HTTP_HEADER_PROBE_ENABLED,
    )
    active_http_basic_header_review_enabled = _bool_from_env(
        "INSPECTRA_ACTIVE_HTTP_BASIC_HEADER_REVIEW_ENABLED",
        DEFAULT_ACTIVE_HTTP_BASIC_HEADER_REVIEW_ENABLED,
    )
    active_http_basic_header_review_live_head_enabled = _bool_from_env(
        "INSPECTRA_ACTIVE_HTTP_BASIC_HEADER_REVIEW_LIVE_HEAD_ENABLED",
        DEFAULT_ACTIVE_HTTP_BASIC_HEADER_REVIEW_LIVE_HEAD_ENABLED,
    )
    active_nmap_basic_enabled = _bool_from_env(
        "INSPECTRA_ACTIVE_NMAP_BASIC_ENABLED",
        DEFAULT_ACTIVE_NMAP_BASIC_ENABLED,
    )
    active_tls_basic_enabled = _bool_from_env(
        "INSPECTRA_ACTIVE_TLS_BASIC_ENABLED",
        DEFAULT_ACTIVE_TLS_BASIC_ENABLED,
    )
    active_dns_inventory_enabled = _bool_from_env(
        "INSPECTRA_ACTIVE_DNS_INVENTORY_ENABLED",
        DEFAULT_ACTIVE_DNS_INVENTORY_ENABLED,
    )
    active_dns_osint_enabled = _bool_from_env(
        "INSPECTRA_ACTIVE_DNS_OSINT_ENABLED",
        DEFAULT_ACTIVE_DNS_OSINT_ENABLED,
    )
    active_dns_osint_ct_source_enabled = _bool_from_env(
        "INSPECTRA_ACTIVE_DNS_OSINT_CT_SOURCE_ENABLED",
        DEFAULT_ACTIVE_DNS_OSINT_CT_SOURCE_ENABLED,
    )
    active_legacy_free_targets_enabled = _bool_from_env(
        "INSPECTRA_ACTIVE_LEGACY_FREE_TARGETS_ENABLED",
        DEFAULT_ACTIVE_LEGACY_FREE_TARGETS_ENABLED,
    )
    active_asset_verification_enabled = _bool_from_env(
        "INSPECTRA_ACTIVE_ASSET_VERIFICATION_ENABLED",
        DEFAULT_ACTIVE_ASSET_VERIFICATION_ENABLED,
    )
    active_recurrence_enabled = _bool_from_env(
        "INSPECTRA_ACTIVE_RECURRENCE_ENABLED",
        DEFAULT_ACTIVE_RECURRENCE_ENABLED,
    )
    active_four_eyes_enabled = _bool_from_env(
        "INSPECTRA_ACTIVE_FOUR_EYES_ENABLED",
        DEFAULT_ACTIVE_FOUR_EYES_ENABLED,
    )
    active_dns_osint_ct_source_url = os.getenv(
        "INSPECTRA_ACTIVE_DNS_OSINT_CT_SOURCE_URL",
        DEFAULT_ACTIVE_DNS_OSINT_CT_SOURCE_URL,
    ).strip()
    active_dns_osint_ct_source_timeout_seconds = _bounded_positive_float_from_env(
        "INSPECTRA_ACTIVE_DNS_OSINT_CT_SOURCE_TIMEOUT_SECONDS",
        DEFAULT_ACTIVE_DNS_OSINT_CT_SOURCE_TIMEOUT_SECONDS,
        MAX_ACTIVE_DNS_OSINT_CT_SOURCE_TIMEOUT_SECONDS,
    )
    active_dns_osint_ct_source_max_response_bytes = _bounded_positive_int_from_env(
        "INSPECTRA_ACTIVE_DNS_OSINT_CT_SOURCE_MAX_RESPONSE_BYTES",
        DEFAULT_ACTIVE_DNS_OSINT_CT_SOURCE_MAX_RESPONSE_BYTES,
        MAX_ACTIVE_DNS_OSINT_CT_SOURCE_MAX_RESPONSE_BYTES,
    )
    active_dns_osint_ct_source_max_names_parsed = _bounded_positive_int_from_env(
        "INSPECTRA_ACTIVE_DNS_OSINT_CT_SOURCE_MAX_NAMES_PARSED",
        DEFAULT_ACTIVE_DNS_OSINT_CT_SOURCE_MAX_NAMES_PARSED,
        MAX_ACTIVE_DNS_OSINT_CT_SOURCE_MAX_NAMES_PARSED,
    )
    public_advisory_egress_enabled = _bool_from_env(
        "INSPECTRA_PUBLIC_ADVISORY_EGRESS_ENABLED",
        DEFAULT_PUBLIC_ADVISORY_EGRESS_ENABLED,
    )
    public_advisory_nvd_enabled = _bool_from_env(
        "INSPECTRA_PUBLIC_ADVISORY_NVD_ENABLED",
        DEFAULT_PUBLIC_ADVISORY_NVD_ENABLED,
    )
    public_advisory_timeout_seconds = _bounded_positive_float_from_env(
        "INSPECTRA_PUBLIC_ADVISORY_TIMEOUT_SECONDS",
        DEFAULT_PUBLIC_ADVISORY_TIMEOUT_SECONDS,
        MAX_PUBLIC_ADVISORY_TIMEOUT_SECONDS,
    )
    public_advisory_max_response_bytes = _bounded_positive_int_from_env(
        "INSPECTRA_PUBLIC_ADVISORY_MAX_RESPONSE_BYTES",
        DEFAULT_PUBLIC_ADVISORY_MAX_RESPONSE_BYTES,
        MAX_PUBLIC_ADVISORY_MAX_RESPONSE_BYTES,
    )
    public_advisory_max_concurrency = _bounded_positive_int_from_env(
        "INSPECTRA_PUBLIC_ADVISORY_MAX_CONCURRENCY",
        DEFAULT_PUBLIC_ADVISORY_MAX_CONCURRENCY,
        MAX_PUBLIC_ADVISORY_MAX_CONCURRENCY,
    )
    public_advisory_max_retries = _bounded_non_negative_int_from_env(
        "INSPECTRA_PUBLIC_ADVISORY_MAX_RETRIES",
        DEFAULT_PUBLIC_ADVISORY_MAX_RETRIES,
        MAX_PUBLIC_ADVISORY_MAX_RETRIES,
    )
    public_advisory_cache_ttl_seconds = _bounded_positive_int_from_env(
        "INSPECTRA_PUBLIC_ADVISORY_CACHE_TTL_SECONDS",
        DEFAULT_PUBLIC_ADVISORY_CACHE_TTL_SECONDS,
        MAX_PUBLIC_ADVISORY_CACHE_TTL_SECONDS,
    )
    public_advisory_cache_retention_seconds = _bounded_positive_int_from_env(
        "INSPECTRA_PUBLIC_ADVISORY_CACHE_RETENTION_SECONDS",
        DEFAULT_PUBLIC_ADVISORY_CACHE_RETENTION_SECONDS,
        MAX_PUBLIC_ADVISORY_CACHE_RETENTION_SECONDS,
    )
    if public_advisory_cache_retention_seconds < public_advisory_cache_ttl_seconds:
        raise ValueError(
            "INSPECTRA_PUBLIC_ADVISORY_CACHE_RETENTION_SECONDS must be greater than or equal to "
            "INSPECTRA_PUBLIC_ADVISORY_CACHE_TTL_SECONDS."
        )
    public_advisory_max_batch_components = _bounded_positive_int_from_env(
        "INSPECTRA_PUBLIC_ADVISORY_MAX_BATCH_COMPONENTS",
        DEFAULT_PUBLIC_ADVISORY_MAX_BATCH_COMPONENTS,
        MAX_PUBLIC_ADVISORY_MAX_BATCH_COMPONENTS,
    )
    public_advisory_private_package_rules = _public_advisory_private_package_rules_from_env(
        "INSPECTRA_PUBLIC_ADVISORY_PRIVATE_PACKAGE_RULES",
        DEFAULT_PUBLIC_ADVISORY_PRIVATE_PACKAGE_RULES,
    )
    public_advisory_public_pypi_packages = _public_advisory_public_pypi_packages_from_env(
        "INSPECTRA_PUBLIC_ADVISORY_PUBLIC_PYPI_PACKAGES",
        DEFAULT_PUBLIC_ADVISORY_PUBLIC_PYPI_PACKAGES,
    )
    public_advisory_public_go_modules = _public_advisory_public_go_modules_from_env(
        "INSPECTRA_PUBLIC_ADVISORY_PUBLIC_GO_MODULES",
        DEFAULT_PUBLIC_ADVISORY_PUBLIC_GO_MODULES,
    )
    public_advisory_public_composer_packages = _public_advisory_public_composer_packages_from_env(
        "INSPECTRA_PUBLIC_ADVISORY_PUBLIC_COMPOSER_PACKAGES",
        DEFAULT_PUBLIC_ADVISORY_PUBLIC_COMPOSER_PACKAGES,
    )
    public_advisory_public_maven_packages = _public_advisory_public_maven_packages_from_env(
        "INSPECTRA_PUBLIC_ADVISORY_PUBLIC_MAVEN_PACKAGES",
        DEFAULT_PUBLIC_ADVISORY_PUBLIC_MAVEN_PACKAGES,
    )
    public_advisory_public_nuget_packages = _public_advisory_public_nuget_packages_from_env(
        "INSPECTRA_PUBLIC_ADVISORY_PUBLIC_NUGET_PACKAGES",
        DEFAULT_PUBLIC_ADVISORY_PUBLIC_NUGET_PACKAGES,
    )
    active_tools_url = os.getenv("INSPECTRA_ACTIVE_TOOLS_URL", DEFAULT_ACTIVE_TOOLS_URL).strip().rstrip("/")
    active_tools_health_timeout_seconds = _positive_float_from_env(
        "INSPECTRA_ACTIVE_TOOLS_HEALTH_TIMEOUT_SECONDS",
        DEFAULT_ACTIVE_TOOLS_HEALTH_TIMEOUT_SECONDS,
    )
    session_ttl_seconds = _positive_int_from_env("INSPECTRA_SESSION_TTL_SECONDS", DEFAULT_SESSION_TTL_SECONDS)
    session_cookie_secure = _bool_from_env("INSPECTRA_SESSION_COOKIE_SECURE", DEFAULT_SESSION_COOKIE_SECURE)
    login_attempt_window_seconds = _positive_int_from_env(
        "INSPECTRA_LOGIN_ATTEMPT_WINDOW_SECONDS",
        DEFAULT_LOGIN_ATTEMPT_WINDOW_SECONDS,
    )
    login_attempt_max_failures = _positive_int_from_env(
        "INSPECTRA_LOGIN_ATTEMPT_MAX_FAILURES",
        DEFAULT_LOGIN_ATTEMPT_MAX_FAILURES,
    )
    login_lockout_seconds = _positive_int_from_env(
        "INSPECTRA_LOGIN_LOCKOUT_SECONDS",
        DEFAULT_LOGIN_LOCKOUT_SECONDS,
    )
    login_attempt_max_keys = _positive_int_from_env(
        "INSPECTRA_LOGIN_ATTEMPT_MAX_KEYS",
        DEFAULT_LOGIN_ATTEMPT_MAX_KEYS,
    )
    auth_state_db_path = _optional_path_from_env("INSPECTRA_AUTH_STATE_DB_PATH")
    team_organization_name = _safe_display_name_from_env(
        "INSPECTRA_TEAM_ORGANIZATION_NAME",
        DEFAULT_TEAM_ORGANIZATION_NAME,
    )
    team_invitation_ttl_seconds = _bounded_positive_int_from_env(
        "INSPECTRA_TEAM_INVITATION_TTL_SECONDS",
        DEFAULT_TEAM_INVITATION_TTL_SECONDS,
        MAX_TEAM_INVITATION_TTL_SECONDS,
    )
    team_invitation_retention_days = _bounded_positive_int_from_env(
        "INSPECTRA_TEAM_INVITATION_RETENTION_DAYS",
        DEFAULT_TEAM_INVITATION_RETENTION_DAYS,
        MAX_TEAM_INVITATION_RETENTION_DAYS,
    )
    product_audit_retention_days = _bounded_positive_int_from_env(
        "INSPECTRA_PRODUCT_AUDIT_RETENTION_DAYS",
        DEFAULT_PRODUCT_AUDIT_RETENTION_DAYS,
        MAX_PRODUCT_AUDIT_RETENTION_DAYS,
    )
    product_audit_max_events = _bounded_positive_int_from_env(
        "INSPECTRA_PRODUCT_AUDIT_MAX_EVENTS",
        DEFAULT_PRODUCT_AUDIT_MAX_EVENTS,
        MAX_PRODUCT_AUDIT_MAX_EVENTS,
    )
    automation_token_retention_days = _bounded_positive_int_from_env(
        "INSPECTRA_AUTOMATION_TOKEN_RETENTION_DAYS",
        DEFAULT_AUTOMATION_TOKEN_RETENTION_DAYS,
        MAX_AUTOMATION_TOKEN_RETENTION_DAYS,
    )
    adoption_metrics_enabled = _bool_from_env(
        "INSPECTRA_ADOPTION_METRICS_ENABLED",
        DEFAULT_ADOPTION_METRICS_ENABLED,
    )
    integration_events_enabled = _bool_from_env(
        "INSPECTRA_INTEGRATION_EVENTS_ENABLED",
        DEFAULT_INTEGRATION_EVENTS_ENABLED,
    )
    integration_event_endpoint = _optional_secret_from_env("INSPECTRA_INTEGRATION_EVENT_ENDPOINT")
    integration_event_allowed_host = _optional_secret_from_env("INSPECTRA_INTEGRATION_EVENT_ALLOWED_HOST")
    integration_event_signing_key = _base64url_32_byte_key_from_env(
        "INSPECTRA_INTEGRATION_EVENT_SIGNING_KEY"
    )
    integration_event_signing_key_id = _optional_secret_from_env("INSPECTRA_INTEGRATION_EVENT_SIGNING_KEY_ID")
    integration_event_timeout_seconds = _bounded_positive_float_from_env(
        "INSPECTRA_INTEGRATION_EVENT_TIMEOUT_SECONDS",
        DEFAULT_INTEGRATION_EVENT_TIMEOUT_SECONDS,
        MAX_INTEGRATION_EVENT_TIMEOUT_SECONDS,
    )
    integration_event_max_concurrency = _bounded_positive_int_from_env(
        "INSPECTRA_INTEGRATION_EVENT_MAX_CONCURRENCY",
        DEFAULT_INTEGRATION_EVENT_MAX_CONCURRENCY,
        MAX_INTEGRATION_EVENT_MAX_CONCURRENCY,
    )
    portfolio_index_hmac_key = _portfolio_index_hmac_key_from_env(
        "INSPECTRA_PORTFOLIO_INDEX_HMAC_KEY"
    )
    oidc_issuer = _optional_secret_from_env("INSPECTRA_OIDC_ISSUER")
    oidc_authorization_endpoint = _optional_secret_from_env("INSPECTRA_OIDC_AUTHORIZATION_ENDPOINT")
    oidc_token_endpoint = _optional_secret_from_env("INSPECTRA_OIDC_TOKEN_ENDPOINT")
    oidc_jwks_uri = _optional_secret_from_env("INSPECTRA_OIDC_JWKS_URI")
    oidc_client_id = _optional_secret_from_env("INSPECTRA_OIDC_CLIENT_ID")
    oidc_client_secret = _optional_secret_from_env("INSPECTRA_OIDC_CLIENT_SECRET")
    oidc_redirect_uri = _optional_secret_from_env("INSPECTRA_OIDC_REDIRECT_URI")
    oidc_post_login_redirect_uri = _optional_secret_from_env("INSPECTRA_OIDC_POST_LOGIN_REDIRECT_URI")
    oidc_organization_id = _optional_secret_from_env("INSPECTRA_OIDC_ORGANIZATION_ID")
    oidc_reader_group = _optional_secret_from_env("INSPECTRA_OIDC_READER_GROUP")
    oidc_maintainer_group = _optional_secret_from_env("INSPECTRA_OIDC_MAINTAINER_GROUP")
    oidc_subject_hmac_key = _base64url_32_byte_key_from_env("INSPECTRA_OIDC_SUBJECT_HMAC_KEY")
    oidc_tenant_claim = _optional_secret_from_env("INSPECTRA_OIDC_TENANT_CLAIM")
    oidc_expected_tenant = _optional_secret_from_env("INSPECTRA_OIDC_EXPECTED_TENANT")
    _validate_team_auth_mode(
        auth_mode=auth_mode,
        admin_password_hash=admin_password_hash,
        auth_state_store=auth_state_store,
    )
    _validate_oidc_settings(
        auth_mode=auth_mode,
        values=(
            oidc_issuer,
            oidc_authorization_endpoint,
            oidc_token_endpoint,
            oidc_jwks_uri,
            oidc_client_id,
            oidc_client_secret,
            oidc_redirect_uri,
            oidc_post_login_redirect_uri,
            oidc_organization_id,
            oidc_reader_group,
            oidc_maintainer_group,
            oidc_subject_hmac_key,
        ),
        tenant_claim=oidc_tenant_claim,
        expected_tenant=oidc_expected_tenant,
    )
    _validate_integration_event_settings(
        enabled=integration_events_enabled,
        endpoint=integration_event_endpoint,
        allowed_host=integration_event_allowed_host,
        signing_key=integration_event_signing_key,
        signing_key_id=integration_event_signing_key_id,
    )
    _validate_deployment_profile(
        deployment_profile=deployment_profile,
        auth_mode=auth_mode,
        admin_password_hash=admin_password_hash,
        cors_origins=cors_origins,
        session_cookie_secure=session_cookie_secure,
        upload_retention_days=upload_retention_days,
        job_retention_days=job_retention_days,
        data_dir=data_dir,
        auth_state_store=auth_state_store,
        auth_state_db_path=auth_state_db_path,
    )
    return Settings(
        data_dir=data_dir,
        tool_runner_url=tool_runner_url,
        network_tool_runner_url=network_tool_runner_url,
        auth_mode=auth_mode,
        deployment_profile=deployment_profile,
        auth_state_store=auth_state_store,
        auth_state_db_path=auth_state_db_path,
        admin_password_hash=admin_password_hash,
        team_organization_name=team_organization_name,
        team_invitation_ttl_seconds=team_invitation_ttl_seconds,
        team_invitation_retention_days=team_invitation_retention_days,
        product_audit_retention_days=product_audit_retention_days,
        product_audit_max_events=product_audit_max_events,
        automation_token_retention_days=automation_token_retention_days,
        adoption_metrics_enabled=adoption_metrics_enabled,
        integration_events_enabled=integration_events_enabled,
        integration_event_endpoint=integration_event_endpoint,
        integration_event_allowed_host=integration_event_allowed_host,
        integration_event_signing_key=integration_event_signing_key,
        integration_event_signing_key_id=integration_event_signing_key_id,
        integration_event_timeout_seconds=integration_event_timeout_seconds,
        integration_event_max_concurrency=integration_event_max_concurrency,
        portfolio_index_hmac_key=portfolio_index_hmac_key,
        oidc_issuer=oidc_issuer,
        oidc_authorization_endpoint=oidc_authorization_endpoint,
        oidc_token_endpoint=oidc_token_endpoint,
        oidc_jwks_uri=oidc_jwks_uri,
        oidc_client_id=oidc_client_id,
        oidc_client_secret=oidc_client_secret,
        oidc_redirect_uri=oidc_redirect_uri,
        oidc_post_login_redirect_uri=oidc_post_login_redirect_uri,
        oidc_organization_id=oidc_organization_id,
        oidc_reader_group=oidc_reader_group,
        oidc_maintainer_group=oidc_maintainer_group,
        oidc_subject_hmac_key=oidc_subject_hmac_key,
        oidc_tenant_claim=oidc_tenant_claim,
        oidc_expected_tenant=oidc_expected_tenant,
        max_upload_bytes=max_upload_bytes,
        upload_retention_days=upload_retention_days,
        job_retention_days=job_retention_days,
        audit_max_concurrency=audit_max_concurrency,
        audit_max_inflight_jobs=audit_max_inflight_jobs,
        audit_max_inflight_jobs_per_owner=audit_max_inflight_jobs_per_owner,
        active_max_inflight_jobs=active_max_inflight_jobs,
        active_max_inflight_jobs_per_organization=active_max_inflight_jobs_per_organization,
        active_max_inflight_jobs_per_asset=active_max_inflight_jobs_per_asset,
        active_max_inflight_jobs_per_capability=active_max_inflight_jobs_per_capability,
        project_archive_timeout_seconds=project_archive_timeout_seconds,
        execution_workspace_max_bytes=execution_workspace_max_bytes,
        project_archive_max_total_uncompressed_bytes=project_archive_max_total_uncompressed_bytes,
        project_archive_max_archive_entries=project_archive_max_archive_entries,
        project_archive_max_manifests=project_archive_max_manifests,
        project_archive_max_manifest_bytes=project_archive_max_manifest_bytes,
        project_archive_max_total_manifest_bytes=project_archive_max_total_manifest_bytes,
        project_archive_max_lockfiles=project_archive_max_lockfiles,
        project_archive_max_lockfile_packages=project_archive_max_lockfile_packages,
        project_archive_max_lockfile_edges=project_archive_max_lockfile_edges,
        project_max_source_snapshots=project_max_source_snapshots,
        license_review_denied_identifiers=license_review_denied_identifiers,
        readiness_timeout_seconds=readiness_timeout_seconds,
        cors_origins=cors_origins,
        cors_allowed_methods=cors_allowed_methods,
        cors_allowed_headers=cors_allowed_headers,
        web_allow_private_targets=web_allow_private_targets,
        web_timeout_seconds=web_timeout_seconds,
        web_max_response_bytes=web_max_response_bytes,
        web_max_redirects=web_max_redirects,
        web_allowed_ports=web_allowed_ports,
        domain_dns_timeout_seconds=domain_dns_timeout_seconds,
        subdomain_max_candidates=subdomain_max_candidates,
        subdomain_wildcard_checks=subdomain_wildcard_checks,
        subdomain_global_deadline_seconds=subdomain_global_deadline_seconds,
        django_config_max_files=django_config_max_files,
        django_config_max_file_bytes=django_config_max_file_bytes,
        django_config_max_total_bytes=django_config_max_total_bytes,
        docker_config_max_files=docker_config_max_files,
        docker_config_max_file_bytes=docker_config_max_file_bytes,
        docker_config_max_total_bytes=docker_config_max_total_bytes,
        secrets_review_max_files=secrets_review_max_files,
        secrets_review_max_file_bytes=secrets_review_max_file_bytes,
        secrets_review_max_total_bytes=secrets_review_max_total_bytes,
        node_package_config_max_files=node_package_config_max_files,
        node_package_config_max_file_bytes=node_package_config_max_file_bytes,
        node_package_config_max_total_bytes=node_package_config_max_total_bytes,
        ci_cd_config_max_files=ci_cd_config_max_files,
        ci_cd_config_max_file_bytes=ci_cd_config_max_file_bytes,
        ci_cd_config_max_total_bytes=ci_cd_config_max_total_bytes,
        k8s_config_max_files=k8s_config_max_files,
        k8s_config_max_file_bytes=k8s_config_max_file_bytes,
        k8s_config_max_total_bytes=k8s_config_max_total_bytes,
        terraform_config_max_files=terraform_config_max_files,
        terraform_config_max_file_bytes=terraform_config_max_file_bytes,
        terraform_config_max_total_bytes=terraform_config_max_total_bytes,
        nginx_config_max_files=nginx_config_max_files,
        nginx_config_max_file_bytes=nginx_config_max_file_bytes,
        nginx_config_max_total_bytes=nginx_config_max_total_bytes,
        compose_config_max_files=compose_config_max_files,
        compose_config_max_file_bytes=compose_config_max_file_bytes,
        compose_config_max_total_bytes=compose_config_max_total_bytes,
        database_config_max_files=database_config_max_files,
        database_config_max_file_bytes=database_config_max_file_bytes,
        database_config_max_total_bytes=database_config_max_total_bytes,
        sql_database_config_max_files=sql_database_config_max_files,
        sql_database_config_max_file_bytes=sql_database_config_max_file_bytes,
        sql_database_config_max_total_bytes=sql_database_config_max_total_bytes,
        redis_config_max_files=redis_config_max_files,
        redis_config_max_file_bytes=redis_config_max_file_bytes,
        redis_config_max_total_bytes=redis_config_max_total_bytes,
        active_dry_run_enabled=active_dry_run_enabled,
        active_http_header_probe_enabled=active_http_header_probe_enabled,
        active_http_basic_header_review_enabled=active_http_basic_header_review_enabled,
        active_http_basic_header_review_live_head_enabled=active_http_basic_header_review_live_head_enabled,
        active_nmap_basic_enabled=active_nmap_basic_enabled,
        active_tls_basic_enabled=active_tls_basic_enabled,
        active_dns_inventory_enabled=active_dns_inventory_enabled,
        active_dns_osint_enabled=active_dns_osint_enabled,
        active_dns_osint_ct_source_enabled=active_dns_osint_ct_source_enabled,
        active_legacy_free_targets_enabled=active_legacy_free_targets_enabled,
        active_asset_verification_enabled=active_asset_verification_enabled,
        active_recurrence_enabled=active_recurrence_enabled,
        active_four_eyes_enabled=active_four_eyes_enabled,
        active_dns_osint_ct_source_url=active_dns_osint_ct_source_url,
        active_dns_osint_ct_source_timeout_seconds=active_dns_osint_ct_source_timeout_seconds,
        active_dns_osint_ct_source_max_response_bytes=active_dns_osint_ct_source_max_response_bytes,
        active_dns_osint_ct_source_max_names_parsed=active_dns_osint_ct_source_max_names_parsed,
        public_advisory_egress_enabled=public_advisory_egress_enabled,
        public_advisory_nvd_enabled=public_advisory_nvd_enabled,
        public_advisory_timeout_seconds=public_advisory_timeout_seconds,
        public_advisory_max_response_bytes=public_advisory_max_response_bytes,
        public_advisory_max_concurrency=public_advisory_max_concurrency,
        public_advisory_max_retries=public_advisory_max_retries,
        public_advisory_cache_ttl_seconds=public_advisory_cache_ttl_seconds,
        public_advisory_cache_retention_seconds=public_advisory_cache_retention_seconds,
        public_advisory_max_batch_components=public_advisory_max_batch_components,
        public_advisory_private_package_rules=public_advisory_private_package_rules,
        public_advisory_public_pypi_packages=public_advisory_public_pypi_packages,
        public_advisory_public_go_modules=public_advisory_public_go_modules,
        public_advisory_public_composer_packages=public_advisory_public_composer_packages,
        public_advisory_public_maven_packages=public_advisory_public_maven_packages,
        public_advisory_public_nuget_packages=public_advisory_public_nuget_packages,
        active_tools_url=active_tools_url,
        active_tools_health_timeout_seconds=active_tools_health_timeout_seconds,
        session_ttl_seconds=session_ttl_seconds,
        session_cookie_secure=session_cookie_secure,
        login_attempt_window_seconds=login_attempt_window_seconds,
        login_attempt_max_failures=login_attempt_max_failures,
        login_lockout_seconds=login_lockout_seconds,
        login_attempt_max_keys=login_attempt_max_keys,
    )


def get_auth_mode(settings: Settings | None = None) -> AuthMode:
    return (settings or load_settings()).auth_mode


def get_current_operator_for_trusted_local(settings: Settings | None = None) -> LocalOperator:
    get_auth_mode(settings)
    return DEFAULT_LOCAL_OPERATOR


def is_auth_required(settings: Settings | None = None) -> bool:
    return get_auth_mode(settings) != "trusted_local_no_auth"


def is_single_admin_auth_configured(settings: Settings | None = None) -> bool:
    resolved_settings = settings or load_settings()
    return resolved_settings.auth_mode == "self_hosted_single_admin" and bool(resolved_settings.admin_password_hash)


def is_auth_configured(settings: Settings | None = None) -> bool:
    resolved_settings = settings or load_settings()
    if resolved_settings.auth_mode == "private_team_lightweight_users":
        return (
            resolved_settings.auth_state_store == "sqlite"
            and is_supported_admin_password_hash(resolved_settings.admin_password_hash)
        )
    return is_single_admin_auth_configured(resolved_settings)


def _auth_mode_from_env(name: str, default: AuthMode) -> AuthMode:
    raw_value = os.getenv(name)
    if raw_value is None:
        return default
    normalized = raw_value.strip().lower().replace("-", "_")
    if normalized in SUPPORTED_AUTH_MODES:
        return cast(AuthMode, normalized)
    allowed = ", ".join(SUPPORTED_AUTH_MODES)
    raise ValueError(f"{name} must be one of: {allowed}.")


def _deployment_profile_from_env(name: str, default: DeploymentProfile) -> DeploymentProfile:
    raw_value = os.getenv(name)
    if raw_value is None:
        return default
    normalized = raw_value.strip().lower().replace("-", "_")
    if normalized in SUPPORTED_DEPLOYMENT_PROFILES:
        return cast(DeploymentProfile, normalized)
    allowed = ", ".join(SUPPORTED_DEPLOYMENT_PROFILES)
    raise ValueError(f"{name} must be one of: {allowed}.")


def _validate_deployment_profile(
    *,
    deployment_profile: DeploymentProfile,
    auth_mode: AuthMode,
    admin_password_hash: str | None,
    cors_origins: tuple[str, ...],
    session_cookie_secure: bool,
    upload_retention_days: int,
    job_retention_days: int,
    data_dir: Path,
    auth_state_store: AuthStateStore,
    auth_state_db_path: Path | None,
) -> None:
    if deployment_profile != "private_tls_proxy":
        return
    if auth_mode not in {"self_hosted_single_admin", "private_team_lightweight_users"}:
        raise ValueError(
            "INSPECTRA_DEPLOYMENT_PROFILE=private_tls_proxy requires self_hosted_single_admin "
            "or private_team_lightweight_users auth."
        )
    if not is_supported_admin_password_hash(admin_password_hash):
        raise ValueError(
            "INSPECTRA_DEPLOYMENT_PROFILE=private_tls_proxy requires a supported INSPECTRA_ADMIN_PASSWORD_HASH."
        )
    if any(not origin.startswith("https://") for origin in cors_origins):
        raise ValueError(
            "INSPECTRA_DEPLOYMENT_PROFILE=private_tls_proxy requires HTTPS INSPECTRA_CORS_ORIGINS."
        )
    if not session_cookie_secure:
        raise ValueError(
            "INSPECTRA_DEPLOYMENT_PROFILE=private_tls_proxy requires INSPECTRA_SESSION_COOKIE_SECURE=true."
        )
    if upload_retention_days == 0 or job_retention_days == 0:
        raise ValueError(
            "INSPECTRA_DEPLOYMENT_PROFILE=private_tls_proxy requires non-zero upload and job retention periods."
        )
    if auth_state_store != "sqlite":
        raise ValueError(
            "INSPECTRA_DEPLOYMENT_PROFILE=private_tls_proxy requires INSPECTRA_AUTH_STATE_STORE=sqlite."
        )
    resolved_auth_state_db_path = auth_state_db_path or data_dir / "runtime" / "auth_state.sqlite3"
    if not _path_is_within(data_dir, resolved_auth_state_db_path):
        raise ValueError(
            "INSPECTRA_DEPLOYMENT_PROFILE=private_tls_proxy requires INSPECTRA_AUTH_STATE_DB_PATH inside INSPECTRA_DATA_DIR."
        )


def _validate_team_auth_mode(
    *,
    auth_mode: AuthMode,
    admin_password_hash: str | None,
    auth_state_store: AuthStateStore,
) -> None:
    if auth_mode != "private_team_lightweight_users":
        return
    if auth_state_store != "sqlite":
        raise ValueError("private_team_lightweight_users requires INSPECTRA_AUTH_STATE_STORE=sqlite.")
    if not is_supported_admin_password_hash(admin_password_hash):
        raise ValueError("private_team_lightweight_users requires a supported INSPECTRA_ADMIN_PASSWORD_HASH.")


def _validate_oidc_settings(
    *,
    auth_mode: AuthMode,
    values: tuple[object | None, ...],
    tenant_claim: str | None,
    expected_tenant: str | None,
) -> None:
    configured = [value is not None for value in values]
    if any(configured) and not all(configured):
        raise ValueError("OIDC federation configuration must be complete or omitted.")
    if any(configured) and auth_mode != "private_team_lightweight_users":
        raise ValueError("OIDC federation requires private_team_lightweight_users auth.")
    if bool(tenant_claim) != bool(expected_tenant):
        raise ValueError("OIDC tenant claim and expected value must be configured together.")


def _validate_integration_event_settings(
    *,
    enabled: bool,
    endpoint: str | None,
    allowed_host: str | None,
    signing_key: bytes | None,
    signing_key_id: str | None,
) -> None:
    configured = (endpoint, allowed_host, signing_key, signing_key_id)
    if enabled and any(value is None for value in configured):
        raise ValueError("Integration events require endpoint, allowed host, signing key and key id.")
    if not enabled and any(value is not None for value in configured):
        raise ValueError("Integration event secrets and destination require INSPECTRA_INTEGRATION_EVENTS_ENABLED=true.")
    if enabled:
        from app.integration_events import IntegrationEventConfig

        IntegrationEventConfig(
            endpoint=endpoint or "",
            host=allowed_host or "",
            signing_key=signing_key or b"",
            signing_key_id=signing_key_id or "",
        )


def _validate_private_storage_directory_permissions(directories: tuple[Path, ...]) -> None:
    for directory in directories:
        try:
            mode = stat.S_IMODE(directory.stat().st_mode)
        except OSError as exc:
            raise ValueError(
                "INSPECTRA_DEPLOYMENT_PROFILE=private_tls_proxy could not inspect persistent storage permissions."
            ) from exc
        if mode & PRIVATE_TLS_STORAGE_FORBIDDEN_MODE_BITS:
            raise ValueError(
                "INSPECTRA_DEPLOYMENT_PROFILE=private_tls_proxy requires persistent storage without group or world permissions."
            )


def _path_is_within(parent: Path, child: Path) -> bool:
    try:
        child.relative_to(parent)
    except ValueError:
        return False
    return True


def _auth_state_store_from_env(name: str, default: AuthStateStore) -> AuthStateStore:
    raw_value = os.getenv(name)
    if raw_value is None:
        return default
    normalized = raw_value.strip().lower().replace("-", "_")
    if normalized in SUPPORTED_AUTH_STATE_STORES:
        return cast(AuthStateStore, normalized)
    allowed = ", ".join(SUPPORTED_AUTH_STATE_STORES)
    raise ValueError(f"{name} must be one of: {allowed}.")


def _optional_secret_from_env(name: str) -> str | None:
    raw_value = os.getenv(name)
    if raw_value is None:
        return None
    value = raw_value.strip()
    if not value:
        return None
    return value


def _portfolio_index_hmac_key_from_env(name: str) -> bytes | None:
    return _base64url_32_byte_key_from_env(name)


def _base64url_32_byte_key_from_env(name: str) -> bytes | None:
    raw_value = os.getenv(name)
    if raw_value is None or not raw_value.strip():
        return None
    value = raw_value.strip()
    if re.fullmatch(r"[A-Za-z0-9_-]{43}", value) is None:
        raise ValueError(f"{name} must be an unpadded base64url-encoded 32-byte secret.")
    try:
        decoded = base64.urlsafe_b64decode(value + "=")
    except ValueError as exc:
        raise ValueError(f"{name} must be an unpadded base64url-encoded 32-byte secret.") from exc
    canonical = base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii")
    if len(decoded) != OIDC_SUBJECT_HMAC_KEY_BYTES or canonical != value:
        raise ValueError(f"{name} must be an unpadded base64url-encoded 32-byte secret.")
    return decoded


def _optional_path_from_env(name: str) -> Path | None:
    raw_value = os.getenv(name)
    if raw_value is None:
        return None
    value = raw_value.strip()
    if not value:
        return None
    return Path(value).expanduser().resolve()


def _safe_display_name_from_env(name: str, default: str) -> str:
    raw_value = os.getenv(name, default)
    normalized = " ".join(raw_value.strip().split())
    if not 3 <= len(normalized) <= 80:
        raise ValueError(f"{name} must contain between 3 and 80 characters.")
    if any(ord(character) < 32 or character in {"/", "\\"} for character in normalized):
        raise ValueError(f"{name} contains unsupported characters.")
    return normalized


def _fixed_internal_runner_url_from_env(name: str, expected: str) -> str:
    """Reject alternate destinations before any project source is transported."""

    value = os.getenv(name, expected).strip().rstrip("/")
    if value != expected:
        raise ValueError(f"{name} must use the fixed internal Inspectra service destination.")
    return expected


def _positive_int_from_env(name: str, default: int) -> int:
    raw_value = os.getenv(name)
    if raw_value is None:
        return default
    try:
        value = int(raw_value)
    except ValueError as exc:
        raise ValueError(f"{name} must be a positive integer.") from exc
    if value <= 0:
        raise ValueError(f"{name} must be greater than zero.")
    return value


def _positive_float_from_env(name: str, default: float) -> float:
    raw_value = os.getenv(name)
    if raw_value is None:
        return default
    try:
        value = float(raw_value)
    except ValueError as exc:
        raise ValueError(f"{name} must be a positive number.") from exc
    if value <= 0:
        raise ValueError(f"{name} must be greater than zero.")
    return value


def _bounded_positive_int_from_env(name: str, default: int, maximum: int) -> int:
    value = _positive_int_from_env(name, default)
    if value > maximum:
        raise ValueError(f"{name} must be less than or equal to {maximum}.")
    return value


def _bounded_positive_float_from_env(name: str, default: float, maximum: float) -> float:
    value = _positive_float_from_env(name, default)
    if value > maximum:
        raise ValueError(f"{name} must be less than or equal to {maximum}.")
    return value


def _bounded_non_negative_int_from_env(name: str, default: int, maximum: int) -> int:
    value = _non_negative_int_from_env(name, default)
    if value > maximum:
        raise ValueError(f"{name} must be less than or equal to {maximum}.")
    return value


def _non_negative_int_from_env(name: str, default: int) -> int:
    raw_value = os.getenv(name)
    if raw_value is None:
        return default
    try:
        value = int(raw_value)
    except ValueError as exc:
        raise ValueError(f"{name} must be a non-negative integer.") from exc
    if value < 0:
        raise ValueError(f"{name} must be zero or greater.")
    return value


def _bool_from_env(name: str, default: bool) -> bool:
    raw_value = os.getenv(name)
    if raw_value is None:
        return default
    normalized = raw_value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{name} must be a boolean value.")


def _cors_origins_from_env(name: str, default: tuple[str, ...]) -> tuple[str, ...]:
    raw_value = os.getenv(name)
    raw_values = default if raw_value is None else tuple(value.strip() for value in raw_value.split(",") if value.strip())
    if not raw_values:
        raise ValueError(f"{name} must include at least one origin.")

    normalized_origins = tuple(sorted({_normalize_cors_origin(name, value) for value in raw_values}))
    return normalized_origins


def _normalize_cors_origin(name: str, value: str) -> str:
    if value == "*":
        raise ValueError(f"{name} must not contain a wildcard origin when credentials are enabled.")
    parsed = urlsplit(value)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(f"{name} entries must be absolute HTTP(S) origins without paths, credentials, queries, or fragments.")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"{name} contains an invalid origin port.") from exc

    hostname = parsed.hostname.lower()
    rendered_host = f"[{hostname}]" if ":" in hostname else hostname
    if port is not None and port not in {80 if parsed.scheme == "http" else 443}:
        rendered_host = f"{rendered_host}:{port}"
    return f"{parsed.scheme}://{rendered_host}"


def _cors_methods_from_env(name: str, default: tuple[str, ...]) -> tuple[str, ...]:
    raw_value = os.getenv(name)
    if raw_value is None:
        return default
    values = tuple(sorted({value.strip().upper() for value in raw_value.split(",") if value.strip()}))
    if not values or any(value not in SUPPORTED_CORS_ALLOWED_METHODS for value in values):
        allowed = ", ".join(DEFAULT_CORS_ALLOWED_METHODS)
        raise ValueError(f"{name} must contain one or more of: {allowed}.")
    return values


def _cors_headers_from_env(name: str, default: tuple[str, ...]) -> tuple[str, ...]:
    raw_value = os.getenv(name)
    if raw_value is None:
        return default
    normalized_values = {value.strip().lower() for value in raw_value.split(",") if value.strip()}
    if not normalized_values or any(value not in SUPPORTED_CORS_ALLOWED_HEADERS for value in normalized_values):
        allowed = ", ".join(DEFAULT_CORS_ALLOWED_HEADERS)
        raise ValueError(f"{name} must contain one or more of: {allowed}.")
    return tuple(sorted(CORS_ALLOWED_HEADER_CANONICAL_NAMES[value] for value in normalized_values))


def _license_identifiers_from_env(name: str, default: tuple[str, ...]) -> tuple[str, ...]:
    """Load a bounded set of exact SPDX-like identifiers, never free-form policy."""

    raw_value = os.getenv(name)
    if raw_value is None:
        return default
    values = tuple(sorted({value.strip() for value in raw_value.split(",") if value.strip()}))
    if len(values) > 64 or any(not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+-]{0,63}", value) for value in values):
        raise ValueError(f"{name} must contain at most 64 exact SPDX-like identifiers separated by commas.")
    return values


def _public_advisory_private_package_rules_from_env(name: str, default: tuple[str, ...]) -> tuple[str, ...]:
    """Load only non-sensitive, bounded package-name exclusion rules.

    Rules intentionally describe package names, never registry locations.  The
    egress client performs the ecosystem-specific normalization before using
    them.  Keeping the parser here makes an unsafe deployment configuration
    fail at startup, rather than silently broadening public egress.
    """

    raw_value = os.getenv(name)
    if raw_value is None or not raw_value.strip():
        return default
    values = tuple(value.strip().lower() for value in raw_value.split(","))
    if len(values) > 100 or any(len(value) > 200 for value in values):
        raise ValueError(f"{name} must contain at most 100 bounded package-name rules.")
    for value in values:
        match = re.fullmatch(r"(npm|pypi|go|cargo|composer|maven|nuget):(exact|prefix):(.+)", value)
        if value.startswith("npm:scope:"):
            if _PUBLIC_ADVISORY_NPM_SCOPE_RULE_VALUE.fullmatch(value.removeprefix("npm:scope:")):
                continue
        elif match is not None:
            ecosystem, _kind, package_name = match.groups()
            valid_name = {
                "npm": _PUBLIC_ADVISORY_NPM_PACKAGE_RULE_VALUE,
                "pypi": _PUBLIC_ADVISORY_PYPI_PACKAGE_RULE_VALUE,
                "go": _PUBLIC_ADVISORY_GO_MODULE_RULE_VALUE,
                "cargo": _PUBLIC_ADVISORY_CARGO_PACKAGE_RULE_VALUE,
                "composer": _PUBLIC_ADVISORY_COMPOSER_PACKAGE_RULE_VALUE,
                "maven": _PUBLIC_ADVISORY_MAVEN_PACKAGE_RULE_VALUE,
                "nuget": _PUBLIC_ADVISORY_NUGET_PACKAGE_RULE_VALUE,
            }[ecosystem].fullmatch(package_name)
            if valid_name is not None:
                continue
        # Do not include an invalid entry in an error; configuration itself can
        # name a private product and startup diagnostics are often retained.
        raise ValueError(
            f"{name} entries must use an ecosystem-specific exact/prefix package name or npm:scope:@scope/; "
            "wildcards, URLs, paths, credentials, and empty entries are not allowed."
        )
    return tuple(sorted(set(values)))


def _public_advisory_public_pypi_packages_from_env(name: str, default: tuple[str, ...]) -> tuple[str, ...]:
    """Load an operator attestation for exact *public* PyPI package names.

    This is deliberately an exact name allowlist, not a registry URL or a
    wildcard. It is a deployment decision kept out of project data, provider
    payloads, cached requests and logs. A typo must fail closed at startup.
    """

    raw_value = os.getenv(name)
    if raw_value is None or not raw_value.strip():
        return default
    raw_values = tuple(value.strip().lower() for value in raw_value.split(","))
    if len(raw_values) > 100 or any(len(value) > 200 or not _PUBLIC_ADVISORY_PYPI_PACKAGE_RULE_VALUE.fullmatch(value) for value in raw_values):
        raise ValueError(f"{name} must contain at most 100 exact PyPI package names; URLs, paths, credentials, wildcards, and empty entries are not allowed.")
    return tuple(sorted({re.sub(r"[-_.]+", "-", value) for value in raw_values}))


def _public_advisory_public_go_modules_from_env(name: str, default: tuple[str, ...]) -> tuple[str, ...]:
    """Load exact public Go module attestations without accepting locators."""

    raw_value = os.getenv(name)
    if raw_value is None or not raw_value.strip():
        return default
    raw_values = tuple(value.strip() for value in raw_value.split(","))
    if len(raw_values) > 500 or any(
        len(value) > 300
        or value != value.lower()
        or not _PUBLIC_ADVISORY_GO_MODULE_RULE_VALUE.fullmatch(value)
        or "." not in value.split("/", 1)[0]
        for value in raw_values
    ):
        raise ValueError(
            f"{name} must contain at most 500 exact lowercase Go module paths; URLs with schemes, credentials, wildcards, and empty entries are not allowed."
        )
    return tuple(sorted(set(raw_values)))


def _public_advisory_public_composer_packages_from_env(name: str, default: tuple[str, ...]) -> tuple[str, ...]:
    """Load exact public Packagist package attestations without locators."""

    raw_value = os.getenv(name)
    if raw_value is None or not raw_value.strip():
        return default
    raw_values = tuple(value.strip() for value in raw_value.split(","))
    if len(raw_values) > 500 or any(
        len(value) > 200
        or value != value.lower()
        or not _PUBLIC_ADVISORY_COMPOSER_PACKAGE_RULE_VALUE.fullmatch(value)
        for value in raw_values
    ):
        raise ValueError(
            f"{name} must contain at most 500 exact lowercase Composer package names; URLs, credentials, wildcards, paths, and empty entries are not allowed."
        )
    return tuple(sorted(set(raw_values)))


def _public_advisory_public_maven_packages_from_env(name: str, default: tuple[str, ...]) -> tuple[str, ...]:
    """Load exact public Maven coordinates without accepting repository data."""

    raw_value = os.getenv(name)
    if raw_value is None or not raw_value.strip():
        return default
    raw_values = tuple(value.strip() for value in raw_value.split(","))
    if len(raw_values) > 500 or any(
        len(value) > 321 or not _PUBLIC_ADVISORY_MAVEN_PACKAGE_RULE_VALUE.fullmatch(value)
        for value in raw_values
    ):
        raise ValueError(
            f"{name} must contain at most 500 exact group:artifact coordinates; URLs, credentials, wildcards, paths, and empty entries are not allowed."
        )
    return tuple(sorted(set(raw_values)))


def _public_advisory_public_nuget_packages_from_env(name: str, default: tuple[str, ...]) -> tuple[str, ...]:
    """Load exact public NuGet package attestations without a feed URL."""

    raw_value = os.getenv(name)
    if raw_value is None or not raw_value.strip():
        return default
    raw_values = tuple(value.strip().lower() for value in raw_value.split(","))
    if len(raw_values) > 500 or any(
        len(value) > 200 or not _PUBLIC_ADVISORY_NUGET_PACKAGE_RULE_VALUE.fullmatch(value)
        for value in raw_values
    ):
        raise ValueError(
            f"{name} must contain at most 500 exact NuGet package names; URLs, credentials, wildcards, paths, and empty entries are not allowed."
        )
    return tuple(sorted(set(raw_values)))


def _ports_from_env(name: str, default: tuple[int, ...]) -> tuple[int, ...]:
    raw_value = os.getenv(name)
    if raw_value is None:
        return default
    ports: list[int] = []
    for item in raw_value.split(","):
        value = item.strip()
        if not value:
            continue
        try:
            port = int(value)
        except ValueError as exc:
            raise ValueError(f"{name} must be a comma-separated list of TCP ports.") from exc
        if port < 1 or port > 65535:
            raise ValueError(f"{name} ports must be between 1 and 65535.")
        ports.append(port)
    if not ports:
        raise ValueError(f"{name} must include at least one TCP port.")
    return tuple(sorted(set(ports)))
