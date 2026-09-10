from pathlib import Path

from release_inventory import classify_path, parse_porcelain, render_markdown, InventoryEntry


def test_classifies_required_and_excluded_release_paths() -> None:
    assert classify_path("backend/app/main.py") == ("código", "incluir")
    assert classify_path("frontend/src/App.test.tsx") == ("prueba", "incluir")
    assert classify_path("deploy/private/Caddyfile") == ("configuración", "incluir")
    assert classify_path("backend/requirements.lock") == (
        "artefacto reproducible requerido",
        "incluir",
    )
    assert classify_path("tests/fixtures/unsafe/private.key") == (
        "fixture",
        "incluir tras escaneo",
    )
    assert classify_path(".venv-312/pyvenv.cfg") == ("caché o entorno", "excluir")
    assert classify_path("data/.locks/storage.lock") == ("dato runtime", "excluir")


def test_parses_nul_porcelain_and_rename() -> None:
    parsed = parse_porcelain(b" M README.md\0?? new.py\0R  current.py\0old.py\0")
    assert parsed == [
        (" M", "README.md"),
        ("??", "new.py"),
        ("R ", "old.py -> current.py"),
    ]


def test_render_is_content_free_and_deterministic(monkeypatch, tmp_path: Path) -> None:
    def fake_check_output(command, **_kwargs):
        return "base\n" if command[-1] == "HEAD" else "release-prep\n"

    monkeypatch.setattr("release_inventory.subprocess.check_output", fake_check_output)
    entries = [
        InventoryEntry("??", "safe.py", "código", "incluir", "archivo regular", "0644")
    ]
    first = render_markdown(tmp_path, entries)
    assert first == render_markdown(tmp_path, entries)
    assert "safe.py" in first
    assert "actual-secret-value" not in first
