"""Verify candidate version and canonical release documents without modifying them."""

from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path
import re

from third_party_notices import validate_notices


SEMVER_PATTERN = re.compile(
    r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
)
ACCEPTANCE_HEADING = "## Estado canónico actual"
ACCEPTANCE_GO_MARKER = "**Última aceptación real de proyecto: GO acotado.**"
ACCEPTANCE_REVALIDATION_MARKER = "**Cambios posteriores: requieren una aceptación nueva.**"
LEGACY_ACCEPTANCE_HEADER = "Estado: **aceptación real ejecutada; NO-GO para despliegue**"


def _python_assignment(path: Path, name: str) -> str | None:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in tree.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if isinstance(target, ast.Name) and target.id == name:
            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                return node.value.value
    return None


def validate_release(root: Path) -> list[str]:
    errors: list[str] = []
    version = (root / "VERSION").read_text(encoding="utf-8").strip()
    if not SEMVER_PATTERN.fullmatch(version):
        errors.append(f"VERSION no contiene SemVer válido: {version!r}.")

    observed: dict[str, str | None] = {
        "backend/app/version.py": _python_assignment(
            root / "backend/app/version.py", "PRODUCT_VERSION"
        ),
        "cli/inspectra_cli/__init__.py": _python_assignment(
            root / "cli/inspectra_cli/__init__.py", "__version__"
        ),
    }
    package = json.loads((root / "frontend/package.json").read_text(encoding="utf-8"))
    package_lock = json.loads(
        (root / "frontend/package-lock.json").read_text(encoding="utf-8")
    )
    observed["frontend/package.json"] = package.get("version")
    observed["frontend/package-lock.json"] = package_lock.get("version")
    observed['frontend/package-lock.json packages[""]'] = package_lock.get(
        "packages", {}
    ).get("", {}).get("version")

    for source, value in observed.items():
        if value != version:
            errors.append(f"{source} declara {value!r}; se esperaba {version!r}.")

    backend_main = (root / "backend/app/main.py").read_text(encoding="utf-8")
    capabilities = (root / "backend/app/client_capabilities.py").read_text(
        encoding="utf-8"
    )
    if "version=PRODUCT_VERSION" not in backend_main:
        errors.append("FastAPI no usa PRODUCT_VERSION como versión pública.")
    if "SERVER_VERSION = PRODUCT_VERSION" not in capabilities:
        errors.append("El contrato de capacidades no usa PRODUCT_VERSION.")

    required_documents = (
        root / "README.md",
        root / "CHANGELOG.md",
        root / "docs/releases/0.3.0-beta.1-local.md",
        root / "docs/feature-matrix.md",
        root / "DEPLOYMENT_ACCEPTANCE.md",
    )
    for path in required_documents:
        if not path.is_file():
            errors.append(f"Falta el documento canónico {path.relative_to(root)}.")
        elif version not in path.read_text(encoding="utf-8"):
            errors.append(f"{path.relative_to(root)} no identifica la versión {version}.")

    acceptance_path = root / "DEPLOYMENT_ACCEPTANCE.md"
    if acceptance_path.is_file():
        acceptance = acceptance_path.read_text(encoding="utf-8")
        for marker in (
            ACCEPTANCE_HEADING,
            ACCEPTANCE_GO_MARKER,
            ACCEPTANCE_REVALIDATION_MARKER,
        ):
            if marker not in acceptance:
                errors.append(
                    f"DEPLOYMENT_ACCEPTANCE.md no contiene el marcador canónico {marker!r}."
                )
        preamble = acceptance.split("## Alcance de la candidatura", 1)[0]
        if LEGACY_ACCEPTANCE_HEADER in preamble:
            errors.append(
                "DEPLOYMENT_ACCEPTANCE.md presenta el NO-GO histórico como estado actual."
            )
    notices_path = root / "THIRD_PARTY_NOTICES.md"
    if not notices_path.is_file():
        errors.append("Falta el documento canónico THIRD_PARTY_NOTICES.md.")
    else:
        errors.extend(validate_notices(root))
    return sorted(errors)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("."))
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        errors = validate_release(args.root.resolve())
    except (OSError, UnicodeError, json.JSONDecodeError, SyntaxError, ValueError) as exc:
        print(f"No se pudo validar la candidatura: {exc}")
        return 2
    if errors:
        print("Candidatura incoherente:")
        for error in errors:
            print(f"- {error}")
        return 1
    version = (args.root / "VERSION").read_text(encoding="utf-8").strip()
    print(f"Candidatura coherente: {version}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
