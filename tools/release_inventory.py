"""Create a content-free inventory of changes considered for a local release cut."""

from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
import stat
import subprocess


@dataclass(frozen=True)
class InventoryEntry:
    status: str
    path: str
    category: str
    disposition: str
    kind: str
    mode: str


def classify_path(path: str) -> tuple[str, str]:
    """Return the closed release category and intended disposition for ``path``."""

    pure = PurePosixPath(path)
    lowered = path.lower()
    name = pure.name.lower()
    parts = tuple(part.lower() for part in pure.parts)

    if (
        lowered.startswith((".venv/", ".venv-", "venv/", "frontend/node_modules/"))
        or "__pycache__" in parts
        or parts[:1] in ((".pytest_cache",), (".mypy_cache",), (".ruff_cache",))
    ):
        return "caché o entorno", "excluir"
    if lowered.startswith("data/") and name not in {".gitkeep"}:
        return "dato runtime", "excluir"
    if name.startswith(".env") or name.endswith(
        (".pem", ".p12", ".pfx", ".crt", ".cookie", ".sqlite", ".sqlite3", ".db")
    ):
        if "fixtures" in parts or "tests" in parts:
            return "fixture", "incluir tras escaneo"
        return "credencial o material sensible", "excluir"
    if "fixtures" in parts:
        return "fixture", "incluir tras escaneo"
    if (
        "tests" in parts
        or name.startswith("test_")
        or ".test." in name
        or name.endswith("_test.py")
    ):
        return "prueba", "incluir"
    if name in {
        "package-lock.json",
        "requirements.lock",
        "requirements-dev.lock",
        "requirements-build.lock",
        "requirements-test.lock",
        "requirements-audit.lock",
    } or name.endswith(".schema.json"):
        return "artefacto reproducible requerido", "incluir"
    if name.endswith((".md", ".rst")):
        return "documentación", "incluir"
    if (
        name
        in {
            "makefile",
            "dockerfile",
            "caddyfile",
            ".dockerignore",
            ".gitignore",
            ".gitleaks.toml",
            ".gitleaksignore",
            "package.json",
            "tsconfig.json",
            "vite.config.ts",
            "version",
        }
        or lowered.startswith(".github/workflows/")
        or name.startswith("docker-compose")
        or name.startswith("requirements")
        or name.endswith((".yml", ".yaml", ".toml"))
    ):
        return "configuración", "incluir"
    if name.endswith((".py", ".ts", ".tsx", ".css", ".html", ".sh", ".mjs")):
        return "código", "incluir"
    if name.endswith((".json", ".svg", ".png", ".ico", ".pdf", ".zip", ".tar")):
        return "artefacto reproducible requerido", "revisar/incluir"
    return "ambiguo", "no preparar hasta revisar"


def parse_porcelain(data: bytes) -> list[tuple[str, str]]:
    records = data.split(b"\0")
    parsed: list[tuple[str, str]] = []
    index = 0
    while index < len(records) and records[index]:
        record = records[index].decode("utf-8", "surrogateescape")
        status_code = record[:2]
        path = record[3:]
        if status_code[0] in "RC" or status_code[1] in "RC":
            index += 1
            previous = records[index].decode("utf-8", "surrogateescape")
            path = f"{previous} -> {path}"
        parsed.append((status_code, path))
        index += 1
    return parsed


def _file_metadata(root: Path, path: str) -> tuple[str, str]:
    target = root / path.split(" -> ")[-1]
    try:
        metadata = target.lstat()
    except FileNotFoundError:
        return "ausente", "-"
    mode = stat.S_IMODE(metadata.st_mode)
    if stat.S_ISLNK(metadata.st_mode):
        return "enlace simbólico", f"{mode:04o}"
    if stat.S_ISREG(metadata.st_mode):
        return "archivo regular", f"{mode:04o}"
    if stat.S_ISDIR(metadata.st_mode):
        return "directorio", f"{mode:04o}"
    return "otro", f"{mode:04o}"


def collect_inventory(root: Path, extra_excluded: list[str]) -> list[InventoryEntry]:
    result = subprocess.run(
        ["git", "status", "--porcelain=v1", "-z", "--untracked-files=all"],
        cwd=root,
        check=True,
        stdout=subprocess.PIPE,
    )
    rows = parse_porcelain(result.stdout)
    known = {path for _, path in rows}
    rows.extend(("!!", path) for path in extra_excluded if path not in known)

    entries: list[InventoryEntry] = []
    for status_code, path in sorted(rows, key=lambda row: row[1]):
        category, disposition = classify_path(path)
        kind, mode = _file_metadata(root, path)
        entries.append(
            InventoryEntry(status_code, path, category, disposition, kind, mode)
        )
    return entries


def _escape(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def render_markdown(root: Path, entries: list[InventoryEntry]) -> str:
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    branch = subprocess.check_output(
        ["git", "branch", "--show-current"], cwd=root, text=True
    ).strip()
    counts = Counter((entry.category, entry.disposition) for entry in entries)
    lines = [
        "# Inventario de consolidación 0.3.0-beta.1",
        "",
        f"- Rama local: `{branch}`.",
        f"- Commit base: `{head}`.",
        f"- Rutas clasificadas: {len(entries)}.",
        "- El inventario no conserva contenido, secretos ni digests de archivos.",
        "- `!!` identifica material local excluido expresamente del candidato.",
        "",
        "## Resumen",
        "",
        "| Categoría | Disposición | Cantidad |",
        "| --- | --- | ---: |",
    ]
    lines.extend(
        f"| {_escape(category)} | {_escape(disposition)} | {count} |"
        for (category, disposition), count in sorted(counts.items())
    )
    lines.extend(
        [
            "",
            "## Clasificación archivo por archivo",
            "",
            "| Estado | Categoría | Disposición | Tipo / modo | Ruta |",
            "| --- | --- | --- | --- | --- |",
        ]
    )
    lines.extend(
        "| {status} | {category} | {disposition} | {kind} `{mode}` | `{path}` |".format(
            status=_escape(entry.status),
            category=_escape(entry.category),
            disposition=_escape(entry.disposition),
            kind=_escape(entry.kind),
            mode=_escape(entry.mode),
            path=_escape(entry.path).replace("`", "\\`"),
        )
        for entry in entries
    )
    lines.append("")
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--output", type=Path)
    parser.add_argument("--extra-excluded", action="append", default=[])
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = args.root.resolve()
    entries = collect_inventory(root, args.extra_excluded)
    rendered = render_markdown(root, entries)
    if args.output is None:
        print(rendered, end="")
    else:
        output = args.output if args.output.is_absolute() else root / args.output
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
