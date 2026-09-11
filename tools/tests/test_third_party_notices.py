import json
from pathlib import Path

from third_party_notices import main, validate_notices


def _runtime_candidate(tmp_path: Path) -> Path:
    backend = tmp_path / "backend"
    frontend = tmp_path / "frontend"
    backend.mkdir()
    frontend.mkdir()
    (backend / "requirements.lock").write_text(
        "fastapi==0.141.1\ncvss==3.6\n", encoding="utf-8"
    )
    (frontend / "package-lock.json").write_text(
        json.dumps(
            {
                "packages": {
                    "": {"version": "1.0.0"},
                    "node_modules/react": {"version": "18.3.1"},
                    "node_modules/vite": {"version": "6.4.3", "dev": True},
                }
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "THIRD_PARTY_NOTICES.md").write_text(
        """| Runtime | Paquete | Versión | Licencia | Distribución/fuente |
| --- | --- | --- | --- | --- |
| Python | fastapi | 0.141.1 | MIT | https://pypi.org/project/fastapi/0.141.1/ |
| Python | cvss | 3.6 | LGPL-3.0-or-later | https://pypi.org/project/cvss/3.6/ |
| npm | react | 18.3.1 | MIT | https://www.npmjs.com/package/react/v/18.3.1 |
""",
        encoding="utf-8",
    )
    return tmp_path


def test_accepts_exact_production_inventory_and_excludes_dev(tmp_path: Path) -> None:
    assert validate_notices(_runtime_candidate(tmp_path)) == []


def test_reports_missing_and_obsolete_versions(tmp_path: Path) -> None:
    root = _runtime_candidate(tmp_path)
    notices = root / "THIRD_PARTY_NOTICES.md"
    notices.write_text(
        notices.read_text(encoding="utf-8")
        .replace("| Python | cvss | 3.6 |", "| Python | cvss | 3.5 |")
        .replace("| npm | react | 18.3.1 | MIT | https://www.npmjs.com/package/react/v/18.3.1 |\n", ""),
        encoding="utf-8",
    )

    errors = validate_notices(root)

    assert any("Falta aviso para Python cvss 3.6" in error for error in errors)
    assert any("Falta aviso para npm react 18.3.1" in error for error in errors)
    assert any("Aviso extra o con versión obsoleta: Python cvss 3.5" in error for error in errors)


def test_reports_duplicate_and_non_https_source(tmp_path: Path) -> None:
    root = _runtime_candidate(tmp_path)
    notices = root / "THIRD_PARTY_NOTICES.md"
    line = "| Python | cvss | 3.6 | LGPL-3.0-or-later | http://example.test/cvss |\n"
    notices.write_text(notices.read_text(encoding="utf-8") + line, encoding="utf-8")

    errors = validate_notices(root)

    assert any("duplica Python cvss 3.6" in error for error in errors)
    assert any("no tiene fuente HTTPS segura" in error for error in errors)


def test_cli_reports_a_lock_drift(tmp_path: Path, capsys) -> None:
    root = _runtime_candidate(tmp_path)
    with (root / "backend/requirements.lock").open("a", encoding="utf-8") as output:
        output.write("httpx==0.28.1\n")

    assert main(["--root", str(root)]) == 1
    assert "Falta aviso para Python httpx 0.28.1" in capsys.readouterr().out


def test_rejects_unknown_license_text_even_when_its_shape_is_safe(tmp_path: Path) -> None:
    root = _runtime_candidate(tmp_path)
    notices = root / "THIRD_PARTY_NOTICES.md"
    notices.write_text(
        notices.read_text(encoding="utf-8").replace(
            "| Python | fastapi | 0.141.1 | MIT |",
            "| Python | fastapi | 0.141.1 | UNKNOWN |",
        ),
        encoding="utf-8",
    )

    assert any("no tiene licencia cerrada válida" in error for error in validate_notices(root))
