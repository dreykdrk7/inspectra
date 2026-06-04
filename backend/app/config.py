from dataclasses import dataclass
import os
from pathlib import Path
from typing import Literal, cast


DEFAULT_MAX_UPLOAD_BYTES = 20 * 1024 * 1024
DEFAULT_AUTH_MODE = "trusted_local_no_auth"
DEFAULT_CORS_ORIGINS = ("http://localhost:5173",)
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
SUPPORTED_AUTH_MODES = (
    "trusted_local_no_auth",
    "self_hosted_single_admin",
    "private_team_lightweight_users",
    "public_community_limited_instance",
)

AuthMode = Literal[
    "trusted_local_no_auth",
    "self_hosted_single_admin",
    "private_team_lightweight_users",
    "public_community_limited_instance",
]


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
    auth_mode: AuthMode = DEFAULT_AUTH_MODE
    admin_password_hash: str | None = None
    max_upload_bytes: int = DEFAULT_MAX_UPLOAD_BYTES
    cors_origins: tuple[str, ...] = DEFAULT_CORS_ORIGINS
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

    @property
    def upload_dir(self) -> Path:
        return self.data_dir / "uploads"

    @property
    def results_dir(self) -> Path:
        return self.data_dir / "results"

    @property
    def jobs_dir(self) -> Path:
        return self.results_dir / "jobs"

    def ensure_directories(self) -> None:
        self.upload_dir.mkdir(parents=True, exist_ok=True)
        self.jobs_dir.mkdir(parents=True, exist_ok=True)


def load_settings() -> Settings:
    data_dir = Path(os.getenv("INSPECTRA_DATA_DIR", "data")).resolve()
    tool_runner_url = os.getenv("INSPECTRA_TOOL_RUNNER_URL", "http://audit-tools:8081").rstrip("/")
    auth_mode = _auth_mode_from_env("INSPECTRA_AUTH_MODE", DEFAULT_AUTH_MODE)
    admin_password_hash = _optional_secret_from_env("INSPECTRA_ADMIN_PASSWORD_HASH")
    max_upload_bytes = _positive_int_from_env("INSPECTRA_MAX_UPLOAD_BYTES", DEFAULT_MAX_UPLOAD_BYTES)
    cors_origins = _csv_from_env("INSPECTRA_CORS_ORIGINS", DEFAULT_CORS_ORIGINS)
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
    return Settings(
        data_dir=data_dir,
        tool_runner_url=tool_runner_url,
        auth_mode=auth_mode,
        admin_password_hash=admin_password_hash,
        max_upload_bytes=max_upload_bytes,
        cors_origins=cors_origins,
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


def _auth_mode_from_env(name: str, default: AuthMode) -> AuthMode:
    raw_value = os.getenv(name)
    if raw_value is None:
        return default
    normalized = raw_value.strip().lower().replace("-", "_")
    if normalized in SUPPORTED_AUTH_MODES:
        return cast(AuthMode, normalized)
    allowed = ", ".join(SUPPORTED_AUTH_MODES)
    raise ValueError(f"{name} must be one of: {allowed}.")


def _optional_secret_from_env(name: str) -> str | None:
    raw_value = os.getenv(name)
    if raw_value is None:
        return None
    value = raw_value.strip()
    if not value:
        return None
    return value


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


def _csv_from_env(name: str, default: tuple[str, ...]) -> tuple[str, ...]:
    raw_value = os.getenv(name)
    if raw_value is None:
        return default
    values = tuple(value.strip() for value in raw_value.split(",") if value.strip())
    if not values:
        raise ValueError(f"{name} must include at least one origin.")
    return values


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
