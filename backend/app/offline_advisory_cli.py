"""Operator-only CLI for checksum-bound public advisory snapshot imports."""

from __future__ import annotations

import argparse
from datetime import datetime
import json
from pathlib import Path
import sys

from app.offline_advisory_snapshots import (
    OfflineAdvisorySnapshotError,
    activate_offline_advisory_snapshot,
    get_active_offline_advisory_snapshot,
    import_offline_advisory_bundle,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Inspectra offline public advisory snapshots")
    commands = parser.add_subparsers(dest="command", required=True)

    import_command = commands.add_parser("import", help="Validate and atomically activate a local bundle")
    import_command.add_argument("--bundle", type=Path, required=True)
    import_command.add_argument("--expected-sha256", required=True)
    import_command.add_argument("--advisories-dir", type=Path, required=True)
    import_command.add_argument("--operator-confirmed", action="store_true")

    activate = commands.add_parser("activate", help="Activate a previously retained snapshot by exact ID")
    activate.add_argument("--snapshot-id", required=True)
    activate.add_argument("--advisories-dir", type=Path, required=True)
    activate.add_argument("--operator-confirmed", action="store_true")

    status = commands.add_parser("status", help="Show only safe active-snapshot metadata")
    status.add_argument("--advisories-dir", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None, *, now: datetime | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "import":
            if not args.operator_confirmed:
                raise OfflineAdvisorySnapshotError("operator_confirmation_required")
            summary = import_offline_advisory_bundle(
                args.bundle,
                args.advisories_dir,
                expected_sha256=args.expected_sha256,
                now=now,
            )
        elif args.command == "activate":
            if not args.operator_confirmed:
                raise OfflineAdvisorySnapshotError("operator_confirmation_required")
            summary = activate_offline_advisory_snapshot(
                args.advisories_dir,
                args.snapshot_id,
                now=now,
            )
        else:
            summary = get_active_offline_advisory_snapshot(args.advisories_dir)
            if summary is None:
                print(json.dumps({"status": "not_configured"}, sort_keys=True))
                return 0
    except OfflineAdvisorySnapshotError as exc:
        print(json.dumps({"status": "failed", "code": exc.code}, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps({"status": "succeeded", "operation": args.command, **summary}, sort_keys=True))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
