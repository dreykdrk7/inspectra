"""Check runtime third-party notices against the reproducible lockfiles."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
from pathlib import Path
import re
from urllib.parse import urlsplit


_PYTHON_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+!-]{0,127}$")
_LICENSE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+() -]{0,127}$")
_REVIEWED_SPDX_LICENSES = frozenset(
    {
        "Apache-2.0",
        "BSD-2-Clause",
        "BSD-3-Clause",
        "ISC",
        "LGPL-3.0-or-later",
        "MIT",
        "MIT-0",
        "MPL-2.0",
        "PSF-2.0",
    }
)


@dataclass(frozen=True, order=True)
class RuntimeComponent:
    runtime: str
    name: str
    version: str


def _normalize_python_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _python_components(path: Path) -> set[RuntimeComponent]:
    components: set[RuntimeComponent] = set()
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.count("==") != 1:
            raise ValueError(f"unsupported Python lock entry at line {line_number}")
        name, version = line.split("==", 1)
        if not _PYTHON_NAME.fullmatch(name) or not _VERSION.fullmatch(version):
            raise ValueError(f"invalid Python lock entry at line {line_number}")
        component = RuntimeComponent("Python", _normalize_python_name(name), version)
        if component in components:
            raise ValueError(f"duplicate Python lock component at line {line_number}")
        components.add(component)
    return components


def _npm_components(path: Path) -> set[RuntimeComponent]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    packages = payload.get("packages")
    if not isinstance(packages, dict):
        raise ValueError("frontend lock has no packages object")
    components: set[RuntimeComponent] = set()
    for package_path, record in packages.items():
        if not isinstance(package_path, str) or not package_path.startswith("node_modules/"):
            continue
        if not isinstance(record, dict) or record.get("dev") is True:
            continue
        name = package_path.rsplit("node_modules/", 1)[-1]
        version = record.get("version")
        if not name or not isinstance(version, str) or not _VERSION.fullmatch(version):
            raise ValueError(f"invalid npm production component at {package_path!r}")
        components.add(RuntimeComponent("npm", name, version))
    return components


def _notice_components(path: Path) -> tuple[set[RuntimeComponent], list[str]]:
    components: set[RuntimeComponent] = set()
    errors: list[str] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not (line.startswith("| Python |") or line.startswith("| npm |")):
            continue
        columns = [column.strip() for column in line.strip().strip("|").split("|")]
        if len(columns) != 5:
            errors.append(f"THIRD_PARTY_NOTICES.md:{line_number} tiene columnas inválidas.")
            continue
        runtime, name, version, license_expression, source = columns
        normalized_name = _normalize_python_name(name) if runtime == "Python" else name
        component = RuntimeComponent(runtime, normalized_name, version)
        if component in components:
            errors.append(f"THIRD_PARTY_NOTICES.md duplica {runtime} {name} {version}.")
        components.add(component)
        license_ids = {
            token.strip("()")
            for token in re.split(r"\s+(?:AND|OR)\s+", license_expression)
        }
        if (
            not _LICENSE.fullmatch(license_expression)
            or not license_ids
            or not license_ids.issubset(_REVIEWED_SPDX_LICENSES)
        ):
            errors.append(f"THIRD_PARTY_NOTICES.md:{line_number} no tiene licencia cerrada válida.")
        parsed_source = urlsplit(source)
        if parsed_source.scheme != "https" or not parsed_source.hostname or parsed_source.username:
            errors.append(f"THIRD_PARTY_NOTICES.md:{line_number} no tiene fuente HTTPS segura.")
    return components, errors


def validate_notices(root: Path) -> list[str]:
    expected = _python_components(root / "backend/requirements.lock") | _npm_components(
        root / "frontend/package-lock.json"
    )
    observed, errors = _notice_components(root / "THIRD_PARTY_NOTICES.md")
    for component in sorted(expected - observed):
        errors.append(
            f"Falta aviso para {component.runtime} {component.name} {component.version}."
        )
    for component in sorted(observed - expected):
        errors.append(
            f"Aviso extra o con versión obsoleta: {component.runtime} {component.name} {component.version}."
        )
    return sorted(errors)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("."))
    args = parser.parse_args(argv)
    try:
        errors = validate_notices(args.root.resolve())
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        print(f"No se pudieron validar los avisos de terceros: {exc}")
        return 2
    if errors:
        print("Avisos de terceros incoherentes:")
        for error in errors:
            print(f"- {error}")
        return 1
    print("Avisos de terceros coherentes con los locks de producción.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
