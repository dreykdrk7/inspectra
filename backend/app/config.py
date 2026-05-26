from dataclasses import dataclass
import os
from pathlib import Path


DEFAULT_MAX_UPLOAD_BYTES = 20 * 1024 * 1024
DEFAULT_CORS_ORIGINS = ("http://localhost:5173",)
DEFAULT_WEB_ALLOW_PRIVATE_TARGETS = False
DEFAULT_WEB_TIMEOUT_SECONDS = 10.0
DEFAULT_WEB_MAX_RESPONSE_BYTES = 1_048_576
DEFAULT_WEB_MAX_REDIRECTS = 5
DEFAULT_WEB_ALLOWED_PORTS = (80, 443)
DEFAULT_DOMAIN_DNS_TIMEOUT_SECONDS = 5.0


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    tool_runner_url: str
    max_upload_bytes: int = DEFAULT_MAX_UPLOAD_BYTES
    cors_origins: tuple[str, ...] = DEFAULT_CORS_ORIGINS
    web_allow_private_targets: bool = DEFAULT_WEB_ALLOW_PRIVATE_TARGETS
    web_timeout_seconds: float = DEFAULT_WEB_TIMEOUT_SECONDS
    web_max_response_bytes: int = DEFAULT_WEB_MAX_RESPONSE_BYTES
    web_max_redirects: int = DEFAULT_WEB_MAX_REDIRECTS
    web_allowed_ports: tuple[int, ...] = DEFAULT_WEB_ALLOWED_PORTS
    domain_dns_timeout_seconds: float = DEFAULT_DOMAIN_DNS_TIMEOUT_SECONDS

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
    return Settings(
        data_dir=data_dir,
        tool_runner_url=tool_runner_url,
        max_upload_bytes=max_upload_bytes,
        cors_origins=cors_origins,
        web_allow_private_targets=web_allow_private_targets,
        web_timeout_seconds=web_timeout_seconds,
        web_max_response_bytes=web_max_response_bytes,
        web_max_redirects=web_max_redirects,
        web_allowed_ports=web_allowed_ports,
        domain_dns_timeout_seconds=domain_dns_timeout_seconds,
    )


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
