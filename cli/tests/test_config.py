from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

from inspectra_cli.config import ConfigError, default_config_path, resolve_scan_configuration, show_profile


def _write_config(path: Path, profiles: dict[str, object]) -> Path:
    path.write_text(
        json.dumps({"contract_version": "2026-09-08.1", "profiles": profiles}),
        encoding="utf-8",
    )
    path.chmod(0o600)
    return path


def _namespace(path: Path, **overrides: object) -> argparse.Namespace:
    values = {
        "profile": "team",
        "config": path,
        "api_url": None,
        "web_url": None,
        "project_id": None,
        "policy": None,
        "timeout": None,
        "http_timeout": None,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


def test_profile_precedence_is_flag_then_environment_then_profile(monkeypatch, tmp_path: Path) -> None:
    config = _write_config(
        tmp_path / "config.json",
        {"team": {"api_url": "https://profile.example", "policy": "standard", "timeout": 200}},
    )
    monkeypatch.setenv("INSPECTRA_API_URL", "https://environment.example")
    arguments = _namespace(config, policy="strict")

    sources = resolve_scan_configuration(arguments)

    assert arguments.api_url == "https://environment.example"
    assert arguments.policy == "strict"
    assert arguments.timeout == 200
    assert arguments.http_timeout == 15.0
    assert sources == {
        "api_url": "environment",
        "web_url": "default",
        "project_id": "default",
        "policy": "flag",
        "timeout": "profile",
        "http_timeout": "default",
    }


@pytest.mark.parametrize("field", ["token", "api_token", "password", "credential_file", "cookie"])
def test_profile_rejects_sensitive_or_unknown_fields(field: str, tmp_path: Path) -> None:
    config = _write_config(tmp_path / "config.json", {"team": {field: "must-not-persist"}})

    with pytest.raises(ConfigError, match="forbidden|unsupported"):
        resolve_scan_configuration(_namespace(config))


def test_profile_rejects_symlink_and_group_readable_file(tmp_path: Path) -> None:
    target = _write_config(tmp_path / "target.json", {"team": {"policy": "observe"}})
    link = tmp_path / "link.json"
    link.symlink_to(target)
    with pytest.raises(ConfigError, match="symlink"):
        resolve_scan_configuration(_namespace(link))

    target.chmod(0o640)
    with pytest.raises(ConfigError, match="permissions"):
        resolve_scan_configuration(_namespace(target))


def test_config_show_never_returns_token_value(monkeypatch, tmp_path: Path) -> None:
    config = _write_config(tmp_path / "config.json", {"team": {"policy": "observe"}})
    monkeypatch.setenv("INSPECTRA_TOKEN", "sensitive-token-value")

    payload = show_profile("team", config)

    serialized = json.dumps(payload)
    assert payload["automation_token"] == "present_in_environment"
    assert "sensitive-token-value" not in serialized


def test_default_paths_are_platform_specific_without_claiming_runtime_support(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    assert default_config_path(platform_name="linux", environment={}) == tmp_path / ".config/inspectra/config.json"
    assert default_config_path(platform_name="darwin", environment={}) == tmp_path / "Library/Application Support/Inspectra/config.json"
    assert default_config_path(platform_name="win32", environment={}) == tmp_path / "AppData/Roaming/Inspectra/config.json"
