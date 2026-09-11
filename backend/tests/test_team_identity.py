from datetime import datetime, timedelta, timezone
import sqlite3

import pytest
from pydantic import ValidationError

from app import team_identity as team_identity_module
from app.auth import hash_password
from app.models import StoredFile
from app.team_identity import (
    TEAM_DEPROVISIONED_PASSWORD_MARKER,
    TEAM_CAPABILITIES,
    TEAM_ROLE_CAPABILITIES,
    TeamIdentityError,
    TeamIdentityStore,
    hash_invitation_token,
    team_role_allows,
)


def test_team_role_capability_matrix_is_closed_monotonic_and_denies_unknown_values():
    assert TEAM_ROLE_CAPABILITIES == {
        "reader": frozenset({"workspace_read"}),
        "maintainer": frozenset({"workspace_read", "project_mutate"}),
        "administrator": frozenset(TEAM_CAPABILITIES),
    }
    assert all(team_role_allows("administrator", capability) for capability in TEAM_CAPABILITIES)
    assert team_role_allows("maintainer", "workspace_read")
    assert team_role_allows("maintainer", "project_mutate")
    assert not team_role_allows("maintainer", "workspace_admin")
    assert not team_role_allows("reader", "project_mutate")
    assert not team_role_allows("reader", "workspace_admin")
    assert not team_role_allows("owner", "workspace_read")
    assert not team_role_allows("administrator", "unknown")


def build_store(tmp_path, *, now=None, token_factory=None) -> TeamIdentityStore:
    current = now or datetime(2026, 9, 6, 12, 0, tzinfo=timezone.utc)
    return TeamIdentityStore(
        tmp_path / "runtime" / "auth_state.sqlite3",
        organization_name="Acme security",
        bootstrap_admin_password_hash=hash_password("bootstrap-password"),
        invitation_ttl_seconds=60,
        now_func=lambda: current,
        token_factory=token_factory,
    )


def test_team_identity_bootstrap_and_invitation_store_only_hashes(tmp_path):
    raw_token = "opaque-invitation-token-with-enough-entropy"
    store = build_store(tmp_path, token_factory=lambda: raw_token)

    admin = store.authenticate("ADMIN", "bootstrap-password")
    assert admin is not None
    assert admin.organization_id == "local-admin"
    assert admin.organization_name == "Acme security"
    assert admin.role == "administrator"

    invitation = store.create_invitation(principal=admin, username="Developer.One", role="maintainer")
    accepted = store.accept_invitation(token=invitation.token, password="developer-password")

    assert accepted.username == "developer.one"
    assert accepted.role == "maintainer"
    assert store.authenticate("developer.one", "developer-password") == accepted
    assert [member.role for member in store.list_members(admin.organization_id)] == ["administrator", "maintainer"]

    db_path = tmp_path / "runtime" / "auth_state.sqlite3"
    db_bytes = db_path.read_bytes()
    assert raw_token.encode() not in db_bytes
    assert b"bootstrap-password" not in db_bytes
    assert b"developer-password" not in db_bytes
    with sqlite3.connect(db_path) as connection:
        stored_token_hash = connection.execute("SELECT token_hash FROM team_invitations").fetchone()[0]
    assert stored_token_hash == hash_invitation_token(raw_token)


def test_invitation_is_single_use_and_expired_or_unknown_tokens_are_indistinguishable(tmp_path):
    current = datetime(2026, 9, 6, 12, 0, tzinfo=timezone.utc)
    store = build_store(tmp_path, now=current)
    admin = store.authenticate("admin", "bootstrap-password")
    assert admin is not None
    invitation = store.create_invitation(principal=admin, username="reader.one", role="reader")
    store.accept_invitation(token=invitation.token, password="reader-password")

    for token in (invitation.token, "unknown-token-with-enough-characters-1234"):
        with pytest.raises(TeamIdentityError, match="invalid_invitation"):
            store.accept_invitation(token=token, password="another-password")

    expired_store = TeamIdentityStore(
        tmp_path / "expired.sqlite3",
        organization_name="Acme security",
        bootstrap_admin_password_hash=hash_password("bootstrap-password"),
        invitation_ttl_seconds=60,
        now_func=lambda: current,
    )
    expired_admin = expired_store.authenticate("admin", "bootstrap-password")
    assert expired_admin is not None
    expired = expired_store.create_invitation(principal=expired_admin, username="old.reader", role="reader")
    expired_store._now_func = lambda: current + timedelta(seconds=61)
    with pytest.raises(TeamIdentityError, match="invalid_invitation"):
        expired_store.accept_invitation(token=expired.token, password="reader-password")


def test_role_change_and_revocation_are_organization_scoped_and_preserve_admin(tmp_path):
    store = build_store(tmp_path)
    admin = store.authenticate("admin", "bootstrap-password")
    assert admin is not None
    invitation = store.create_invitation(principal=admin, username="team.reader", role="reader")
    reader = store.accept_invitation(token=invitation.token, password="reader-password")

    changed = store.change_member_role(principal=admin, user_id=reader.user_id, role="maintainer")
    assert changed.role == "maintainer"
    assert store.get_principal(reader.user_id, reader.organization_id).role == "maintainer"

    store.revoke_member(principal=admin, user_id=reader.user_id)
    assert store.get_principal(reader.user_id, reader.organization_id) is None
    assert store.authenticate("team.reader", "reader-password") is None
    with sqlite3.connect(store.db_path) as connection:
        deprovisioned = connection.execute(
            "SELECT username, password_hash, active FROM team_users WHERE id = ?",
            (reader.user_id,),
        ).fetchone()
    assert deprovisioned == (
        f"deprovisioned.{reader.user_id}",
        TEAM_DEPROVISIONED_PASSWORD_MARKER,
        0,
    )

    with pytest.raises(TeamIdentityError, match="last_administrator"):
        store.revoke_member(principal=admin, user_id=admin.user_id)
    with pytest.raises(TeamIdentityError, match="last_administrator"):
        store.change_member_role(principal=admin, user_id=admin.user_id, role="reader")

    second_admin_invitation = store.create_invitation(
        principal=admin,
        username="second.admin",
        role="administrator",
    )
    second_admin = store.accept_invitation(
        token=second_admin_invitation.token,
        password="second-admin-password",
    )
    with pytest.raises(TeamIdentityError, match="last_administrator"):
        store.revoke_member(principal=second_admin, user_id=admin.user_id)


def test_multiple_organizations_require_explicit_membership_and_existing_password(tmp_path):
    store = build_store(tmp_path)
    bootstrap_admin = store.authenticate("admin", "bootstrap-password")
    assert bootstrap_admin is not None
    first_invitation = store.create_invitation(
        principal=bootstrap_admin,
        username="shared.member",
        role="reader",
    )
    first_membership = store.accept_invitation(
        token=first_invitation.token,
        password="shared-member-password",
    )

    second_workspace = store.create_organization(principal=bootstrap_admin, name="Second workspace")
    second_admin = store.get_principal(bootstrap_admin.user_id, second_workspace.organization_id)
    assert second_admin is not None
    assert store.get_principal(first_membership.user_id, second_workspace.organization_id) is None

    second_invitation = store.create_invitation(
        principal=second_admin,
        username="shared.member",
        role="maintainer",
    )
    with pytest.raises(TeamIdentityError, match="invalid_invitation"):
        store.accept_invitation(token=second_invitation.token, password="wrong-existing-password")

    replacement_invitation = store.create_invitation(
        principal=second_admin,
        username="shared.member",
        role="maintainer",
    )
    second_membership = store.accept_invitation(
        token=replacement_invitation.token,
        password="shared-member-password",
    )
    assert second_membership.user_id == first_membership.user_id
    assert second_membership.organization_id == second_workspace.organization_id
    assert second_membership.role == "maintainer"
    assert [workspace.name for workspace in store.list_organizations(first_membership.user_id)] == [
        "Acme security",
        "Second workspace",
    ]

    store.revoke_member(principal=bootstrap_admin, user_id=first_membership.user_id)
    assert store.get_principal(first_membership.user_id, bootstrap_admin.organization_id) is None
    assert store.get_principal(first_membership.user_id, second_workspace.organization_id) is not None
    assert store.authenticate("shared.member", "shared-member-password") is not None


def test_terminal_invitation_cleanup_is_bounded_and_organization_scoped(tmp_path):
    clock = [datetime(2026, 7, 1, 12, 0, tzinfo=timezone.utc)]
    store = TeamIdentityStore(
        tmp_path / "runtime" / "auth_state.sqlite3",
        organization_name="Acme security",
        bootstrap_admin_password_hash=hash_password("bootstrap-password"),
        invitation_ttl_seconds=60,
        now_func=lambda: clock[0],
    )
    admin = store.authenticate("admin", "bootstrap-password")
    assert admin is not None
    second = store.create_organization(principal=admin, name="Second workspace")
    second_admin = store.get_principal(admin.user_id, second.organization_id)
    assert second_admin is not None

    accepted = store.create_invitation(principal=admin, username="accepted.old", role="reader")
    store.accept_invitation(token=accepted.token, password="accepted-old-password")
    revoked = store.create_invitation(principal=admin, username="revoked.old", role="reader")
    store.create_invitation(principal=admin, username="revoked.old", role="maintainer")
    second_expired = store.create_invitation(principal=second_admin, username="other.old", role="reader")
    clock[0] = datetime(2026, 9, 10, 12, 0, tzinfo=timezone.utc)
    recent = store.create_invitation(principal=admin, username="recent.pending", role="reader")

    removed = store.purge_terminal_invitations(
        cutoff=clock[0] - timedelta(days=30),
        organization_id=admin.organization_id,
    )

    assert removed == 3
    with sqlite3.connect(store.db_path) as connection:
        rows = connection.execute(
            "SELECT organization_id, token_hash FROM team_invitations ORDER BY organization_id, id"
        ).fetchall()
    assert len(rows) == 2
    assert {row[0] for row in rows} == {admin.organization_id, second.organization_id}
    assert hash_invitation_token(recent.token) in {row[1] for row in rows}
    assert hash_invitation_token(second_expired.token) in {row[1] for row in rows}
    assert hash_invitation_token(accepted.token) not in {row[1] for row in rows}
    assert hash_invitation_token(revoked.token) not in {row[1] for row in rows}

    with pytest.raises(TeamIdentityError, match="invalid_retention_cutoff"):
        store.purge_terminal_invitations(cutoff=datetime(2026, 9, 10))


def test_non_bootstrap_last_administrator_is_protected_in_recovered_workspace(tmp_path):
    store = build_store(tmp_path)
    bootstrap = store.authenticate("admin", "bootstrap-password")
    assert bootstrap is not None
    workspace = store.create_organization(principal=bootstrap, name="Recovered workspace")
    workspace_admin = store.get_principal(bootstrap.user_id, workspace.organization_id)
    assert workspace_admin is not None
    invitation = store.create_invitation(
        principal=workspace_admin,
        username="sole.recovered.admin",
        role="administrator",
    )
    sole_admin = store.accept_invitation(token=invitation.token, password="sole-admin-password")
    with sqlite3.connect(store.db_path) as connection:
        connection.execute(
            "UPDATE team_memberships SET revoked_at = ? WHERE organization_id = ? AND user_id = ?",
            (datetime(2026, 9, 6, 13, tzinfo=timezone.utc).timestamp(), workspace.organization_id, bootstrap.user_id),
        )

    with pytest.raises(TeamIdentityError, match="last_administrator"):
        store.change_member_role(principal=sole_admin, user_id=sole_admin.user_id, role="reader")
    with pytest.raises(TeamIdentityError, match="last_administrator"):
        store.revoke_member(principal=sole_admin, user_id=sole_admin.user_id)


def test_public_identity_attestation_is_exact_scoped_expiring_and_revisable(tmp_path):
    current = datetime(2026, 9, 6, 12, 0, tzinfo=timezone.utc)
    store = build_store(tmp_path, now=current)
    admin = store.authenticate("admin", "bootstrap-password")
    assert admin is not None
    second_workspace = store.create_organization(principal=admin, name="Second workspace")

    proposed = store.propose_public_identity(
        principal=admin,
        ecosystem="pypi",
        package_name="Requests_Library",
        requested_ttl_days=30,
    )
    assert proposed.package_name == "requests-library"
    assert proposed.status == "pending"
    assert proposed.revision == 1
    assert store.is_public_identity_approved(admin.organization_id, "pypi", "requests-library") is False

    approved = store.approve_public_identity(principal=admin, attestation_id=proposed.attestation_id)
    assert approved.status == "approved"
    assert approved.revision == 2
    assert store.approved_public_identity_keys(admin.organization_id) == ("pypi:requests-library",)
    assert store.approved_public_identity_keys(second_workspace.organization_id) == ()
    assert store.is_public_identity_approved(admin.organization_id, "pypi", "requests-library") is True
    assert store.is_public_identity_approved(admin.organization_id, "pypi", "requests-library-extra") is False
    restarted = build_store(tmp_path, now=current)
    assert restarted.approved_public_identity_keys(admin.organization_id) == ("pypi:requests-library",)

    store._now_func = lambda: current + timedelta(days=31)
    assert store.list_public_identities(admin.organization_id)[0].status == "expired"
    assert store.is_public_identity_approved(admin.organization_id, "pypi", "requests-library") is False
    renewed = store.propose_public_identity(
        principal=admin,
        ecosystem="pypi",
        package_name="requests-library",
        requested_ttl_days=7,
    )
    assert renewed.revision == 3
    assert renewed.attestation_id != proposed.attestation_id


def test_public_identity_attestation_roles_races_and_revocation_fail_closed(tmp_path, monkeypatch):
    store = build_store(tmp_path)
    admin = store.authenticate("admin", "bootstrap-password")
    assert admin is not None
    invitation = store.create_invitation(principal=admin, username="team.maintainer", role="maintainer")
    maintainer = store.accept_invitation(token=invitation.token, password="maintainer-password")
    reader_invitation = store.create_invitation(principal=admin, username="team.reader", role="reader")
    reader = store.accept_invitation(token=reader_invitation.token, password="reader-password")

    with pytest.raises(TeamIdentityError, match="maintainer_required"):
        store.propose_public_identity(principal=reader, ecosystem="npm", package_name="react")
    proposed = store.propose_public_identity(principal=maintainer, ecosystem="npm", package_name="react")
    with pytest.raises(TeamIdentityError, match="administrator_required"):
        store.approve_public_identity(principal=maintainer, attestation_id=proposed.attestation_id)
    with pytest.raises(TeamIdentityError, match="attestation_exists"):
        store.propose_public_identity(principal=maintainer, ecosystem="npm", package_name="react")

    approved = store.approve_public_identity(principal=admin, attestation_id=proposed.attestation_id)
    with pytest.raises(TeamIdentityError, match="attestation_not_pending"):
        store.approve_public_identity(principal=admin, attestation_id=proposed.attestation_id)
    revoked = store.revoke_public_identity(principal=admin, attestation_id=approved.attestation_id)
    assert revoked.status == "revoked"
    assert revoked.revision == 3
    assert store.is_public_identity_approved(admin.organization_id, "npm", "react") is False
    with pytest.raises(TeamIdentityError, match="attestation_not_active"):
        store.revoke_public_identity(principal=admin, attestation_id=approved.attestation_id)
    monkeypatch.setattr(team_identity_module, "PUBLIC_IDENTITY_ATTESTATION_MAX_PER_ORGANIZATION", 1)
    with pytest.raises(TeamIdentityError, match="attestation_limit_reached"):
        store.propose_public_identity(principal=maintainer, ecosystem="npm", package_name="lodash")


def test_scoped_records_materialize_organization_and_reject_ambiguous_boundaries():
    payload = {
        "id": "a" * 32,
        "owner_id": "workspace-a",
        "kind": "archive",
        "original_filename": "source.zip",
        "stored_filename": "a.zip",
        "content_type": "application/zip",
        "size_bytes": 10,
        "sha256": "b" * 64,
        "created_at": "2026-09-06T10:00:00Z",
    }

    record = StoredFile.model_validate(payload)
    assert record.organization_id == "workspace-a"
    with pytest.raises(ValidationError, match="Organization boundary does not match"):
        StoredFile.model_validate({**payload, "organization_id": "workspace-b"})
