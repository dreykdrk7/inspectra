import json
from pathlib import Path

from release_consistency import main, validate_release


def _candidate(tmp_path: Path) -> Path:
    files = {
        "VERSION": "0.3.0-beta.1\n",
        "backend/app/version.py": 'PRODUCT_VERSION = "0.3.0-beta.1"\n',
        "backend/app/main.py": "version=PRODUCT_VERSION\n",
        "backend/app/client_capabilities.py": "SERVER_VERSION = PRODUCT_VERSION\n",
        "cli/inspectra_cli/__init__.py": '__version__ = "0.3.0-beta.1"\n',
        "README.md": "Inspectra 0.3.0-beta.1\n",
        "CHANGELOG.md": "0.3.0-beta.1\n",
        "docs/releases/0.3.0-beta.1-local.md": "0.3.0-beta.1\n",
        "docs/feature-matrix.md": "0.3.0-beta.1\n",
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
