from __future__ import annotations

import json
import socket

import pytest

from app.backup_cli import main
from app.recovery_drill import RecoveryDrillError, run_recovery_drill


def test_recovery_drill_verifies_restore_boundaries_measurements_and_cleanup(tmp_path, monkeypatch):
    def reject_network(*_args, **_kwargs):
        raise AssertionError("The recovery drill must not open a network connection.")

    monkeypatch.setattr(socket, "create_connection", reject_network)
    monkeypatch.setattr(socket.socket, "connect", reject_network)
    summary = run_recovery_drill(
        tmp_path,
        offline_confirmed=True,
        synthetic_data_only_confirmed=True,
        encrypted_workspace_confirmed=True,
    )

    assert summary.status == "succeeded"
    assert summary.retention_contract_version == "2026-09-10.7"
    assert summary.data_scope == "synthetic_two_owner_fixture"
    assert summary.project_count == summary.analysis_count == summary.source_count == 2
    assert summary.backup_file_count > 8
    assert summary.backup_total_bytes > 0
    assert summary.restored_sessions_revoked == 1
    assert summary.restored_invitations_revoked == 1
    assert summary.checksum_rejection_verified is True
    assert summary.corrupt_restore_not_published is True
    assert summary.owner_boundaries_verified is True
    assert summary.source_integrity_verified is True
    assert summary.retained_records_verified is True
    assert summary.source_rollback_preserved is True
    assert summary.egress_disabled_verified is True
    assert summary.external_configuration_restore_required is True
    assert summary.active_instance_modified is False
    assert summary.external_network_used is False
    assert summary.workspace_cleanup_verified is True
    assert summary.observed_data_loss_records == 0
    assert summary.measurements_are_sla is False
    assert all(value >= 0 for value in summary.timings.model_dump().values())
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize(
    ("offline", "synthetic", "encrypted", "code"),
    [
        (False, True, True, "offline_confirmation_required"),
        (True, False, True, "synthetic_data_confirmation_required"),
        (True, True, False, "encrypted_workspace_confirmation_required"),
    ],
)
def test_recovery_drill_requires_all_operator_attestations(tmp_path, offline, synthetic, encrypted, code):
    with pytest.raises(RecoveryDrillError, match=code):
        run_recovery_drill(
            tmp_path,
            offline_confirmed=offline,
            synthetic_data_only_confirmed=synthetic,
            encrypted_workspace_confirmed=encrypted,
        )
    assert list(tmp_path.iterdir()) == []


def test_recovery_drill_rejects_unsafe_parent_without_echoing_it(tmp_path, capsys):
    marker = "private-recovery-workspace-marker"
    missing = tmp_path / marker

    exit_code = main([
        "drill",
        "--workspace-parent",
        str(missing),
        "--offline-confirmed",
        "--synthetic-data-only-confirmed",
        "--encrypted-workspace-confirmed",
    ])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert captured.out == ""
    assert marker not in captured.err
    assert json.loads(captured.err) == {"code": "invalid_workspace_parent", "status": "failed"}


def test_recovery_drill_cli_emits_only_bounded_synthetic_evidence(tmp_path, capsys):
    marker = "encrypted-drill-parent-marker"
    workspace_parent = tmp_path / marker
    workspace_parent.mkdir(mode=0o700)

    exit_code = main([
        "drill",
        "--workspace-parent",
        str(workspace_parent),
        "--offline-confirmed",
        "--synthetic-data-only-confirmed",
        "--encrypted-workspace-confirmed",
    ])

    captured = capsys.readouterr()
    assert exit_code == 0
    payload = json.loads(captured.out)
    assert payload["operation"] == "drill"
    assert payload["status"] == "succeeded"
    assert payload["external_network_used"] is False
    assert payload["active_instance_modified"] is False
    assert payload["workspace_cleanup_verified"] is True
    assert payload["measurements_are_sla"] is False
    assert list(workspace_parent.iterdir()) == []
    serialized = json.dumps(payload, sort_keys=True)
    for forbidden in (
        marker,
        str(tmp_path),
        "synthetic-authorized-source.zip",
        "Synthetic recovery project",
        "synthetic-recovery-password",
        "synthetic-recovery-session",
        "synthetic-recovery-csrf",
        "synthetic-recovery-invitation-token",
    ):
        assert forbidden not in serialized
