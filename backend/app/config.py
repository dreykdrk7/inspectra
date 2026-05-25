from dataclasses import dataclass
import os
from pathlib import Path


DEFAULT_MAX_UPLOAD_BYTES = 20 * 1024 * 1024


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    tool_runner_url: str
    max_upload_bytes: int = DEFAULT_MAX_UPLOAD_BYTES

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
    return Settings(data_dir=data_dir, tool_runner_url=tool_runner_url, max_upload_bytes=max_upload_bytes)


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
