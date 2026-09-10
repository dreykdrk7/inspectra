"""Operator-only command line entrypoint for offline backup and restore."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from app.backup import BackupError, create_backup, restore_backup, verify_backup
from app.recovery_drill import RecoveryDrillError, run_recovery_drill


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Inspectra offline backup and restore")
    commands = parser.add_subparsers(dest="command", required=True)

    create = commands.add_parser("create", help="Create a full backup in a new directory")
    create.add_argument("--data-dir", type=Path, required=True)
    create.add_argument("--destination", type=Path, required=True)
    create.add_argument("--auth-state-relative-path", default="runtime/auth_state.sqlite3")
    create.add_argument("--offline-confirmed", action="store_true")
    create.add_argument("--sensitive-data-confirmed", action="store_true")
    create.add_argument("--encrypted-destination-confirmed", action="store_true")

    verify = commands.add_parser("verify", help="Verify a backup without restoring it")
    verify.add_argument("--backup", type=Path, required=True)
    verify.add_argument("--sensitive-data-confirmed", action="store_true")

    restore = commands.add_parser("restore", help="Restore into a new data directory")
    restore.add_argument("--backup", type=Path, required=True)
    restore.add_argument("--target-data-dir", type=Path, required=True)
    restore.add_argument("--offline-confirmed", action="store_true")
    restore.add_argument("--sensitive-data-confirmed", action="store_true")

    drill = commands.add_parser("drill", help="Run a self-cleaning synthetic recovery drill")
    drill.add_argument("--workspace-parent", type=Path, required=True)
    drill.add_argument("--offline-confirmed", action="store_true")
    drill.add_argument("--synthetic-data-only-confirmed", action="store_true")
    drill.add_argument("--encrypted-workspace-confirmed", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "create":
            summary = create_backup(
                args.data_dir,
                args.destination,
                offline_confirmed=args.offline_confirmed,
                sensitive_data_confirmed=args.sensitive_data_confirmed,
                encrypted_destination_confirmed=args.encrypted_destination_confirmed,
                auth_state_relative_path=args.auth_state_relative_path,
            )
        elif args.command == "verify":
            summary = verify_backup(args.backup, sensitive_data_confirmed=args.sensitive_data_confirmed)
        elif args.command == "restore":
            summary = restore_backup(
                args.backup,
                args.target_data_dir,
                offline_confirmed=args.offline_confirmed,
                sensitive_data_confirmed=args.sensitive_data_confirmed,
            )
        else:
            summary = run_recovery_drill(
                args.workspace_parent,
                offline_confirmed=args.offline_confirmed,
                synthetic_data_only_confirmed=args.synthetic_data_only_confirmed,
                encrypted_workspace_confirmed=args.encrypted_workspace_confirmed,
            )
    except (BackupError, RecoveryDrillError) as exc:
        print(json.dumps({"status": "failed", "code": exc.code}, sort_keys=True), file=sys.stderr)
        return 2
    print(
        json.dumps(
            {"status": "succeeded", "operation": args.command, **summary.model_dump(mode="json")},
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
