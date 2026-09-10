from pathlib import Path

import pytest

from backlog_consistency import main, validate_backlogs


@pytest.fixture
def valid_backlogs(tmp_path: Path) -> tuple[Path, Path]:
    todo = tmp_path / "TODO.md"
    product = tmp_path / "TODO_PRODUCTO.md"
    todo.write_text(
        """# TODO
### SEC-012 — Protected
- **Prioridad:** P2
- **Estado:** bloqueada
### PROD-001 — First
- **Prioridad:** P0
- **Estado:** completada
| PROD-129 | P1 | bloqueada | L |
| PROD-130 | P1 | bloqueada | M |
| PROD-167 | P2 | bloqueada | M |
""",
        encoding="utf-8",
    )
    product.write_text(
        """# Product
| PROD-001 | P0 | completada | First |
| PROD-129 | P1 | bloqueada | Cut |
| PROD-130 | P1 | bloqueada | CI |
| PROD-167 | P2 | bloqueada | Platforms |
| **PROD-001 — P0 — completada**<br>First | detail |
""",
        encoding="utf-8",
    )
    return todo, product


def test_accepts_consistent_mixed_backlog_representations(valid_backlogs) -> None:
    todo, product = valid_backlogs
    assert validate_backlogs(todo, product) == []


def test_detects_missing_task_between_documents(valid_backlogs) -> None:
    todo, product = valid_backlogs
    product.write_text(
        product.read_text(encoding="utf-8").replace(
            "| PROD-001 | P0 | completada | First |\n", ""
        ).replace("| **PROD-001 — P0 — completada**<br>First | detail |\n", ""),
        encoding="utf-8",
    )
    errors = validate_backlogs(todo, product)
    assert any("falta PROD-001" in error for error in errors)


def test_detects_duplicate_summary_id_with_lines(valid_backlogs) -> None:
    todo, product = valid_backlogs
    product.write_text(
        product.read_text(encoding="utf-8")
        + "| PROD-001 | P0 | completada | Duplicate |\n",
        encoding="utf-8",
    )
    errors = validate_backlogs(todo, product)
    assert any("PROD-001 aparece 2 veces en el resumen" in error for error in errors)
    assert any("líneas" in error for error in errors)


@pytest.mark.parametrize("field", ["priority", "status"])
def test_detects_summary_detail_priority_or_status_conflict(valid_backlogs, field) -> None:
    todo, product = valid_backlogs
    old = "| **PROD-001 — P0 — completada**"
    replacement = (
        "| **PROD-001 — P1 — completada**"
        if field == "priority"
        else "| **PROD-001 — P0 — pendiente**"
    )
    product.write_text(
        product.read_text(encoding="utf-8").replace(old, replacement),
        encoding="utf-8",
    )
    errors = validate_backlogs(todo, product)
    assert any("PROD-001 contradice resumen" in error for error in errors)


@pytest.mark.parametrize("task_id", ["SEC-012", "PROD-167"])
def test_protected_task_must_remain_blocked(valid_backlogs, task_id) -> None:
    todo, product = valid_backlogs
    target = todo if task_id == "SEC-012" else product
    current = target.read_text(encoding="utf-8")
    if task_id == "SEC-012":
        mutated = current.replace("- **Estado:** bloqueada", "- **Estado:** pendiente")
    else:
        mutated = current.replace(
            f"| {task_id} | " + ("P2" if task_id == "PROD-167" else "P1") + " | bloqueada |",
            f"| {task_id} | " + ("P2" if task_id == "PROD-167" else "P1") + " | pendiente |",
        )
    target.write_text(
        mutated,
        encoding="utf-8",
    )
    errors = validate_backlogs(todo, product)
    assert any(
        task_id in error and "debe seguir bloqueada" in error for error in errors
    )


def test_authorized_release_cut_may_progress_when_both_backlogs_agree(
    valid_backlogs,
) -> None:
    todo, product = valid_backlogs
    for path in (todo, product):
        path.write_text(
            path.read_text(encoding="utf-8").replace(
                "| PROD-129 | P1 | bloqueada |",
                "| PROD-129 | P1 | en progreso |",
            ),
            encoding="utf-8",
        )
    assert validate_backlogs(todo, product) == []


def test_authorized_remote_ci_may_progress_when_both_backlogs_agree(
    valid_backlogs,
) -> None:
    todo, product = valid_backlogs
    for path in (todo, product):
        path.write_text(
            path.read_text(encoding="utf-8").replace(
                "| PROD-130 | P1 | bloqueada |",
                "| PROD-130 | P1 | en progreso |",
            ),
            encoding="utf-8",
        )
    assert validate_backlogs(todo, product) == []


def test_cli_is_read_only_and_output_is_deterministic(valid_backlogs, capsys) -> None:
    todo, product = valid_backlogs
    before = (todo.read_bytes(), product.read_bytes())
    arguments = ["--todo", str(todo), "--product", str(product)]
    assert main(arguments) == 0
    first = capsys.readouterr()
    assert main(arguments) == 0
    second = capsys.readouterr()
    assert first.out == second.out
    assert first.err == second.err == ""
    assert before == (todo.read_bytes(), product.read_bytes())
