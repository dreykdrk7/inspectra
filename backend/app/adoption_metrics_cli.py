"""Offline stdout export for the opt-in aggregate adoption metrics store."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

from app.adoption_metrics import AdoptionMetricsError, AdoptionMetricsStore
from app.config import Settings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m app.adoption_metrics_cli",
        description="Export local aggregate Inspectra adoption metrics as JSON.",
    )
    parser.add_argument("--data-dir", required=True, type=Path)
    parser.add_argument("--local-export-confirmed", action="store_true")
    args = parser.parse_args(argv)
    if not args.local_export_confirmed:
        parser.error("--local-export-confirmed is required")
    try:
        root = args.data_dir
        if root.is_symlink() or not root.is_dir():
            raise AdoptionMetricsError("adoption_metrics_invalid")
        store = AdoptionMetricsStore(
            Settings(
                data_dir=root,
                tool_runner_url="http://audit-tools:8081",
                adoption_metrics_enabled=True,
            )
        )
        sys.stdout.buffer.write(store.export())
    except (OSError, AdoptionMetricsError):
        print("Adoption metrics are unavailable.", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
