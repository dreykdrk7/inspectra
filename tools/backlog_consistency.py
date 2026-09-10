"""Read-only consistency checks for Inspectra's two operational backlogs."""

from __future__ import annotations

import argparse
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
import re
import sys
from typing import Iterable


TASK_ID_PATTERN = r"(?:PROD-\d{3}|SEC-\d{3})"
PRIORITIES = frozenset({"P0", "P1", "P2", "P3"})
STATUSES = frozenset({"pendiente", "en progreso", "bloqueada", "completada"})
PROTECTED_BLOCKED_TASKS = frozenset({"SEC-012", "PROD-130", "PROD-167"})

_SUMMARY_ROW = re.compile(
    rf"^\| (?P<id>{TASK_ID_PATTERN}) \| (?P<priority>P[0-3]) \| "
    r"(?P<status>pendiente|en progreso|bloqueada|completada) \|"
)
_RICH_ROW = re.compile(
    rf"^\| \*\*(?P<id>{TASK_ID_PATTERN}) — (?P<priority>P[0-3]) — "
    r"(?P<status>pendiente|en progreso|bloqueada|completada)\*\*"
)
_HEADING = re.compile(rf"^### (?P<id>{TASK_ID_PATTERN})\b.*$")
_FIELD = re.compile(r"^- \*\*(?P<label>[^*]+):\*\*\s*(?P<value>.+?)\s*$")


@dataclass(frozen=True)
class TaskRecord:
    task_id: str
    priority: str
    status: str
    line: int
    representation: str


@dataclass(frozen=True)
class ParsedBacklog:
    path: Path
    summaries: tuple[TaskRecord, ...]
    details: tuple[TaskRecord, ...]


def _heading_record(lines: list[str], index: int, task_id: str) -> TaskRecord | None:
    fields: dict[str, str] = {}
    end = index + 1
    while end < len(lines) and not lines[end].startswith("### "):
        match = _FIELD.match(lines[end])
        if match:
            fields[match.group("label").strip().lower()] = match.group("value").strip()
        end += 1

    combined = fields.get("prioridad / estado / tamaño")
    if combined:
        parts = [part.strip().rstrip(".") for part in combined.split("/")]
        if len(parts) >= 2 and parts[0] in PRIORITIES and parts[1] in STATUSES:
            return TaskRecord(task_id, parts[0], parts[1], index + 1, "ficha")

    priority = fields.get("prioridad")
    status = fields.get("estado")
    if priority in PRIORITIES and status in STATUSES:
        return TaskRecord(task_id, priority, status, index + 1, "ficha")
    return None


def parse_backlog(path: Path) -> ParsedBacklog:
    lines = path.read_text(encoding="utf-8").splitlines()
    summaries: list[TaskRecord] = []
    details: list[TaskRecord] = []
    for index, line in enumerate(lines):
        if match := _SUMMARY_ROW.match(line):
            summaries.append(
                TaskRecord(
                    match.group("id"),
                    match.group("priority"),
                    match.group("status"),
                    index + 1,
                    "resumen",
                )
            )
            continue
        if match := _RICH_ROW.match(line):
            details.append(
                TaskRecord(
                    match.group("id"),
                    match.group("priority"),
                    match.group("status"),
                    index + 1,
                    "ficha",
                )
            )
            continue
        if match := _HEADING.match(line):
            if record := _heading_record(lines, index, match.group("id")):
                details.append(record)
    return ParsedBacklog(path=path, summaries=tuple(summaries), details=tuple(details))


def _index_records(
    parsed: ParsedBacklog,
    records: Iterable[TaskRecord],
    representation: str,
    errors: list[str],
) -> dict[str, TaskRecord]:
    grouped: dict[str, list[TaskRecord]] = defaultdict(list)
    for record in records:
        grouped[record.task_id].append(record)
    for task_id, occurrences in sorted(grouped.items()):
        if len(occurrences) > 1:
            lines = ", ".join(str(item.line) for item in occurrences)
            errors.append(
                f"{parsed.path}: {task_id} aparece {len(occurrences)} veces en "
                f"{representation} (líneas {lines})."
            )
    return {task_id: occurrences[0] for task_id, occurrences in grouped.items()}


def _canonical_records(parsed: ParsedBacklog, errors: list[str]) -> dict[str, TaskRecord]:
    summaries = _index_records(parsed, parsed.summaries, "el resumen", errors)
    details = _index_records(parsed, parsed.details, "las fichas", errors)
    for task_id in sorted(summaries.keys() & details.keys()):
        summary = summaries[task_id]
        detail = details[task_id]
        if (summary.priority, summary.status) != (detail.priority, detail.status):
            errors.append(
                f"{parsed.path}: {task_id} contradice resumen línea {summary.line} "
                f"({summary.priority}, {summary.status}) y ficha línea {detail.line} "
                f"({detail.priority}, {detail.status})."
            )
    return {**details, **summaries}


def validate_backlogs(todo_path: Path, product_path: Path) -> list[str]:
    errors: list[str] = []
    todo = parse_backlog(todo_path)
    product = parse_backlog(product_path)
    todo_records = _canonical_records(todo, errors)
    product_records = _canonical_records(product, errors)

    todo_product = {key: value for key, value in todo_records.items() if key.startswith("PROD-")}
    product_product = {
        key: value for key, value in product_records.items() if key.startswith("PROD-")
    }
    for task_id in sorted(todo_product.keys() - product_product.keys()):
        errors.append(f"{product.path}: falta {task_id}, presente en {todo.path}.")
    for task_id in sorted(product_product.keys() - todo_product.keys()):
        errors.append(f"{todo.path}: falta {task_id}, presente en {product.path}.")
    for task_id in sorted(todo_product.keys() & product_product.keys()):
        left = todo_product[task_id]
        right = product_product[task_id]
        if (left.priority, left.status) != (right.priority, right.status):
            errors.append(
                f"{task_id} contradice {todo.path}:{left.line} "
                f"({left.priority}, {left.status}) y {product.path}:{right.line} "
                f"({right.priority}, {right.status})."
            )

    for task_id in sorted(PROTECTED_BLOCKED_TASKS):
        expected_documents = (todo,) if task_id.startswith("SEC-") else (todo, product)
        for document in expected_documents:
            records = todo_records if document is todo else product_records
            record = records.get(task_id)
            if record is None:
                errors.append(f"{document.path}: falta la tarea protegida {task_id}.")
            elif record.status != "bloqueada":
                errors.append(
                    f"{document.path}:{record.line}: la tarea protegida {task_id} debe "
                    f"seguir bloqueada; estado detectado: {record.status}."
                )

    if not todo_product:
        errors.append(f"{todo.path}: no contiene tareas PROD canónicas.")
    if not product_product:
        errors.append(f"{product.path}: no contiene tareas PROD canónicas.")
    return sorted(set(errors))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Comprueba TODO.md y TODO_PRODUCTO.md sin modificarlos."
    )
    parser.add_argument("--todo", type=Path, default=Path("TODO.md"))
    parser.add_argument("--product", type=Path, default=Path("TODO_PRODUCTO.md"))
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        errors = validate_backlogs(args.todo, args.product)
    except (OSError, UnicodeError) as exc:
        print(f"No se pudieron leer los backlogs: {exc}", file=sys.stderr)
        return 2
    if errors:
        print("Backlogs inconsistentes:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print("Backlogs coherentes: IDs, prioridades, estados y bloqueos protegidos coinciden.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
