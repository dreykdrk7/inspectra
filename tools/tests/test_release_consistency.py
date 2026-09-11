import json
from pathlib import Path

from release_consistency import main, validate_release


def _candidate(tmp_path: Path) -> Path:
    files = {
        "VERSION": "0.3.0-beta.1\n",
        "backend/app/version.py": 'PRODUCT_VERSION = "0.3.0-beta.1"\n',
        "backend/app/main.py": "version=PRODUCT_VERSION\n",
        "backend/app/client_capabilities.py": "SERVER_VERSION = PRODUCT_VERSION\n",
        "backend/requirements.lock": "fastapi==0.141.1\n",
        "cli/inspectra_cli/__init__.py": '__version__ = "0.3.0-beta.1"\n',
        "README.md": "Inspectra 0.3.0-beta.1\n",
        "CHANGELOG.md": "0.3.0-beta.1\n",
        "docs/releases/0.3.0-beta.1-local.md": "0.3.0-beta.1\n",
        "docs/feature-matrix.md": "0.3.0-beta.1\n",
        "DEPLOYMENT_ACCEPTANCE.md": (
            "# Acceptance 0.3.0-beta.1\n\n"
            "## Estado canónico actual\n\n"
            "**Última aceptación real de proyecto: GO acotado.**\n\n"
            "**Cambios posteriores: requieren una aceptación nueva.**\n\n"
            "## Alcance de la candidatura\n"
        ),
        "THIRD_PARTY_NOTICES.md": (
            "| Runtime | Paquete | Versión | Licencia | Distribución/fuente |\n"
            "| --- | --- | --- | --- | --- |\n"
            "| Python | fastapi | 0.141.1 | MIT | https://pypi.org/project/fastapi/0.141.1/ |\n"
        ),
    }
    for relative, content in files.items():
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    package = {"version": "0.3.0-beta.1"}
    (tmp_path / "frontend").mkdir()
    (tmp_path / "frontend/package.json").write_text(json.dumps(package), encoding="utf-8")
    (tmp_path / "frontend/package-lock.json").write_text(
        json.dumps({**package, "packages": {"": package}}), encoding="utf-8"
    )
    return tmp_path


def test_accepts_synchronized_candidate(tmp_path: Path) -> None:
    assert validate_release(_candidate(tmp_path)) == []


def test_detects_version_drift(tmp_path: Path) -> None:
    root = _candidate(tmp_path)
    (root / "frontend/package.json").write_text(
        json.dumps({"version": "0.3.0-beta.2"}), encoding="utf-8"
    )
    assert any("frontend/package.json" in error for error in validate_release(root))


def test_cli_reports_document_gap(tmp_path: Path, capsys) -> None:
    root = _candidate(tmp_path)
    (root / "CHANGELOG.md").unlink()
    assert main(["--root", str(root)]) == 1
    assert "Falta el documento canónico CHANGELOG.md" in capsys.readouterr().out


def test_reports_missing_third_party_notice_without_crashing(tmp_path: Path) -> None:
    root = _candidate(tmp_path)
    (root / "THIRD_PARTY_NOTICES.md").unlink()

    assert validate_release(root) == [
        "Falta el documento canónico THIRD_PARTY_NOTICES.md."
    ]


def test_detects_missing_canonical_acceptance_state(tmp_path: Path) -> None:
    root = _candidate(tmp_path)
    (root / "DEPLOYMENT_ACCEPTANCE.md").write_text(
        "# Acceptance 0.3.0-beta.1\n", encoding="utf-8"
    )

    errors = validate_release(root)

    assert any("Estado canónico actual" in error for error in errors)
    assert any("Última aceptación real" in error for error in errors)
    assert any("Cambios posteriores" in error for error in errors)


def test_detects_historical_no_go_presented_as_current(tmp_path: Path) -> None:
    root = _candidate(tmp_path)
    acceptance = root / "DEPLOYMENT_ACCEPTANCE.md"
    acceptance.write_text(
        acceptance.read_text(encoding="utf-8").replace(
            "## Estado canónico actual\n",
            "## Estado canónico actual\n"
            "Estado: **aceptación real ejecutada; NO-GO para despliegue**\n",
        ),
        encoding="utf-8",
    )

    assert any("NO-GO histórico" in error for error in validate_release(root))
