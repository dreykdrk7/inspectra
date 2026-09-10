"""Strict, secret-free local profiles for recurrent CLI use."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any

from inspectra_cli.client import ApiClientError, _validate_base_url


CONFIG_CONTRACT_VERSION = "2026-09-08.1"
MAX_CONFIG_BYTES = 64 * 1024
MAX_PROFILES = 32
PROFILE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
PROJECT_ID = re.compile(r"^[a-f0-9]{32}$")
TOP_LEVEL_FIELDS = {"contract_version", "profiles"}
PROFILE_FIELDS = {"api_url", "web_url", "project_id", "policy", "timeout", "http_timeout"}
SENSITIVE_KEY_PARTS = ("token", "secret", "password", "credential", "authorization", "cookie")
BUILTIN_DEFAULTS: dict[str, Any] = {
    "api_url": "http://127.0.0.1:8000",
    "web_url": None,
    "project_id": None,
    "policy": "observe",
    "timeout": 120.0,
    "http_timeout": 15.0,
}
ENVIRONMENT_FIELDS = {
    "api_url": "INSPECTRA_API_URL",
    "web_url": "INSPECTRA_WEB_URL",
    "project_id": "INSPECTRA_PROJECT_ID",
    "policy": "INSPECTRA_POLICY",
    "timeout": "INSPECTRA_TIMEOUT",
    "http_timeout": "INSPECTRA_HTTP_TIMEOUT",
}


class ConfigError(ValueError):
    """A local configuration failed closed before repository access."""


def default_config_path(*, platform_name: str | None = None, environment: dict[str, str] | None = None) -> Path:
    platform_name = platform_name or sys.platform
    environment = environment if environment is not None else dict(os.environ)
    override = environment.get("INSPECTRA_CONFIG_FILE")
    if override:
        return Path(override).expanduser()
    if platform_name == "win32":
        root = Path(environment.get("APPDATA") or (Path.home() / "AppData" / "Roaming"))
        return root / "Inspectra" / "config.json"
    if platform_name == "darwin":
        return Path.home() / "Library" / "Application Support" / "Inspectra" / "config.json"
    root = Path(environment.get("XDG_CONFIG_HOME") or (Path.home() / ".config"))
    return root / "inspectra" / "config.json"


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ConfigError("The Inspectra config contains a duplicate key.")
        result[key] = value
    return result


def _contains_sensitive_key(value: Any) -> bool:
    if isinstance(value, dict):
        return any(
            any(part in str(key).lower() for part in SENSITIVE_KEY_PARTS) or _contains_sensitive_key(item)
            for key, item in value.items()
        )
    if isinstance(value, list):
        return any(_contains_sensitive_key(item) for item in value)
    return False


def _read_config(path: Path) -> dict[str, Any]:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ConfigError("The selected Inspectra config cannot be read.") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ConfigError("The Inspectra config must be a regular file, not a symlink.")
    if os.name != "nt" and metadata.st_mode & 0o077:
        raise ConfigError("The Inspectra config permissions are unsafe; use mode 0600.")
    if metadata.st_size > MAX_CONFIG_BYTES:
        raise ConfigError("The Inspectra config exceeds 65536 bytes.")
    try:
        raw = path.read_bytes()
        payload = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except ConfigError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ConfigError("The Inspectra config is not valid UTF-8 JSON.") from exc
    if not isinstance(payload, dict) or set(payload) != TOP_LEVEL_FIELDS:
        raise ConfigError("The Inspectra config top-level schema is invalid.")
    if payload.get("contract_version") != CONFIG_CONTRACT_VERSION:
        raise ConfigError("The Inspectra config contract is unsupported.")
    if _contains_sensitive_key(payload):
        raise ConfigError("Secrets and credentials are forbidden in Inspectra profile files.")
    profiles = payload.get("profiles")
    if not isinstance(profiles, dict) or not 1 <= len(profiles) <= MAX_PROFILES:
        raise ConfigError("The Inspectra config must contain between 1 and 32 profiles.")
    for name, profile in profiles.items():
        if not isinstance(name, str) or not PROFILE_NAME.fullmatch(name):
            raise ConfigError("An Inspectra profile name is invalid.")
        if not isinstance(profile, dict) or not set(profile).issubset(PROFILE_FIELDS):
            raise ConfigError("An Inspectra profile contains unsupported fields.")
        _validate_profile(profile)
    return payload


def _validate_profile(profile: dict[str, Any]) -> None:
    for field in ("api_url", "web_url"):
        value = profile.get(field)
        if value is not None:
            if not isinstance(value, str) or len(value) > 512:
                raise ConfigError(f"Profile field {field} is invalid.")
            try:
                _validate_base_url(value)
            except ApiClientError as exc:
                raise ConfigError(f"Profile field {field} is invalid.") from exc
    project_id = profile.get("project_id")
    if project_id is not None and (not isinstance(project_id, str) or not PROJECT_ID.fullmatch(project_id)):
        raise ConfigError("Profile field project_id is invalid.")
    policy = profile.get("policy")
    if policy is not None and policy not in {"observe", "standard", "strict"}:
        raise ConfigError("Profile field policy is invalid.")
    for field, minimum, maximum in (("timeout", 1, 900), ("http_timeout", 1, 60)):
        value = profile.get(field)
        if value is not None and (not isinstance(value, (int, float)) or isinstance(value, bool) or not minimum <= value <= maximum):
            raise ConfigError(f"Profile field {field} is invalid.")


def load_profile(name: str | None, config_path: Path | None) -> tuple[dict[str, Any], Path | None]:
    if not name and config_path is None:
        return {}, None
    selected_name = name or "default"
    if not PROFILE_NAME.fullmatch(selected_name):
        raise ConfigError("The selected Inspectra profile name is invalid.")
    path = config_path.expanduser() if config_path is not None else default_config_path()
    payload = _read_config(path)
    profile = payload["profiles"].get(selected_name)
    if not isinstance(profile, dict):
        raise ConfigError("The selected Inspectra profile does not exist.")
    return profile, path


def _environment_value(field: str) -> Any:
    raw = os.environ.get(ENVIRONMENT_FIELDS[field])
    if raw is None or raw == "":
        return None
    if field in {"timeout", "http_timeout"}:
        try:
            return float(raw)
        except ValueError as exc:
            raise ConfigError(f"Environment variable {ENVIRONMENT_FIELDS[field]} is invalid.") from exc
    return raw


def resolve_scan_configuration(arguments: argparse.Namespace) -> dict[str, str]:
    profile, path = load_profile(getattr(arguments, "profile", None), getattr(arguments, "config", None))
    sources: dict[str, str] = {}
    for field, fallback in BUILTIN_DEFAULTS.items():
        flag_value = getattr(arguments, field, None)
        environment_value = _environment_value(field)
        if flag_value is not None:
            value, source = flag_value, "flag"
        elif environment_value is not None:
            value, source = environment_value, "environment"
        elif field in profile:
            value, source = profile[field], "profile"
        else:
            value, source = fallback, "default"
        setattr(arguments, field, value)
        sources[field] = source
    _validate_profile({field: getattr(arguments, field) for field in PROFILE_FIELDS if getattr(arguments, field) is not None})
    arguments.config_path = path
    arguments.config_sources = sources
    return sources


def show_profile(name: str | None, config_path: Path | None) -> dict[str, Any]:
    namespace = argparse.Namespace(
        profile=name,
        config=config_path,
        **{field: None for field in PROFILE_FIELDS},
    )
    sources = resolve_scan_configuration(namespace)
    values = {field: getattr(namespace, field) for field in sorted(PROFILE_FIELDS)}
    return {
        "contract_version": CONFIG_CONTRACT_VERSION,
        "status": "valid",
        "profile": name or "default",
        "values": values,
        "sources": sources,
        "automation_token": "present_in_environment" if os.environ.get("INSPECTRA_TOKEN") else "not_present",
    }
