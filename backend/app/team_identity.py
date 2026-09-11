from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
from pathlib import Path
import re
import secrets
import sqlite3
from typing import Callable, Literal, TypeVar

from app.auth import hash_password, verify_admin_password


TeamRole = Literal["administrator", "maintainer", "reader"]
TEAM_ROLES: tuple[TeamRole, ...] = ("administrator", "maintainer", "reader")
TeamCapability = Literal["workspace_read", "project_mutate", "workspace_admin"]
TEAM_CAPABILITIES: tuple[TeamCapability, ...] = ("workspace_read", "project_mutate", "workspace_admin")
TEAM_ROLE_CAPABILITIES: dict[TeamRole, frozenset[TeamCapability]] = {
    "reader": frozenset({"workspace_read"}),
    "maintainer": frozenset({"workspace_read", "project_mutate"}),
    "administrator": frozenset(TEAM_CAPABILITIES),
}
PublicIdentityEcosystem = Literal["npm", "pypi", "go", "cargo", "composer", "maven", "nuget"]
PUBLIC_IDENTITY_ECOSYSTEMS: tuple[PublicIdentityEcosystem, ...] = (
    "npm",
    "pypi",
    "go",
    "cargo",
    "composer",
    "maven",
    "nuget",
)
PublicIdentityAttestationStatus = Literal["pending", "approved", "expired", "revoked"]
TEAM_IDENTITY_SCHEMA_VERSION = 3
TEAM_BOOTSTRAP_ORGANIZATION_ID = "local-admin"
TEAM_BOOTSTRAP_ADMIN_ID = "team-admin"
TEAM_BOOTSTRAP_ADMIN_USERNAME = "admin"
TEAM_INVITATION_TOKEN_BYTES = 32
TEAM_INVITATION_TOKEN_MAX_LENGTH = 128
TEAM_DEPROVISIONED_PASSWORD_MARKER = "account-deprovisioned"
TEAM_USERNAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{2,63}$")
PUBLIC_IDENTITY_ATTESTATION_CONTRACT_VERSION = "2026-09-09.1"
PUBLIC_IDENTITY_ATTESTATION_DEFAULT_TTL_DAYS = 30
PUBLIC_IDENTITY_ATTESTATION_MAX_TTL_DAYS = 90
PUBLIC_IDENTITY_ATTESTATION_MAX_PER_ORGANIZATION = 200
T = TypeVar("T")


class TeamIdentityError(RuntimeError):
    """Controlled identity failure whose code is safe to map at the API edge."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def team_role_allows(role: object, capability: object) -> bool:
    """Closed, deny-by-default role matrix shared by API authorization gates."""

    if role not in TEAM_ROLE_CAPABILITIES or capability not in TEAM_CAPABILITIES:
        return False
    return capability in TEAM_ROLE_CAPABILITIES[role]


def _subject_digest(value: object) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[a-f0-9]{64}", value) is None:
        raise TeamIdentityError("invalid_federated_subject")
    return value


@dataclass(frozen=True)
class TeamPrincipal:
    user_id: str
    username: str
    organization_id: str
    organization_name: str
    role: TeamRole


@dataclass(frozen=True)
class TeamMember:
    user_id: str
    username: str
    role: TeamRole
    joined_at: datetime


@dataclass(frozen=True)
class FederatedIdentityBinding:
    binding_id: str
    organization_id: str
    user_id: str
    username: str
    role: TeamRole
    created_at: datetime
    revoked_at: datetime | None


@dataclass(frozen=True)
class TeamOrganization:
    organization_id: str
    name: str
    role: TeamRole
    created_at: datetime


@dataclass(frozen=True)
class TeamInvitation:
    invitation_id: str
    token: str
    username: str
    role: TeamRole
    expires_at: datetime


@dataclass(frozen=True)
class PublicIdentityAttestation:
    attestation_id: str
    organization_id: str
    ecosystem: PublicIdentityEcosystem
    package_name: str
    status: PublicIdentityAttestationStatus
    revision: int
    requested_ttl_days: int
    proposed_by_user_id: str
    proposed_at: datetime
    approved_by_user_id: str | None
    approved_at: datetime | None
    expires_at: datetime | None
    revoked_by_user_id: str | None
    revoked_at: datetime | None


class TeamIdentityStore:
    """SQLite-backed identity for one private deployment workspace.

    The bootstrap organization deliberately reuses the legacy `local-admin`
    owner boundary. This makes existing trusted-local/single-admin resources
    visible to the explicitly configured team without granting a cross-owner
    administrator bypass.
    """

    def __init__(
        self,
        db_path: str | Path,
        *,
        organization_name: str,
        bootstrap_admin_password_hash: str,
        invitation_ttl_seconds: int,
        now_func=None,
        token_factory=None,
    ) -> None:
        self.db_path = Path(db_path)
        self.organization_name = normalize_organization_name(organization_name)
        self.bootstrap_admin_password_hash = bootstrap_admin_password_hash
        self.invitation_ttl_seconds = max(1, int(invitation_ttl_seconds))
        self._now_func = now_func or _utc_now
        self._token_factory = token_factory or _new_invitation_token
        self._initialize_schema()
        self._ensure_bootstrap_identity()

    def authenticate(self, username: str, password: str) -> TeamPrincipal | None:
        normalized_username = normalize_username(username)
        if normalized_username is None or not isinstance(password, str):
            return None
        row = self._fetchone(
            """
            SELECT u.id AS user_id, u.username, u.password_hash,
                   o.id AS organization_id, o.name AS organization_name,
                   m.role
            FROM team_users u
            JOIN team_memberships m ON m.user_id = u.id
            JOIN team_organizations o ON o.id = m.organization_id
            WHERE u.username = ? AND u.active = 1 AND m.revoked_at IS NULL
            ORDER BY CASE WHEN o.id = 'local-admin' THEN 0 ELSE 1 END, o.created_at ASC
            LIMIT 1
            """,
            (normalized_username,),
            many=True,
        )
        if not isinstance(row, list) or len(row) != 1:
            return None
        candidate = row[0]
        if not verify_admin_password(password, str(candidate["password_hash"])):
            return None
        return _principal_from_row(candidate)

    def list_organizations(self, user_id: str) -> list[TeamOrganization]:
        rows = self._fetchone(
            """
            SELECT o.id AS organization_id, o.name, o.created_at, m.role
            FROM team_memberships m
            JOIN team_organizations o ON o.id = m.organization_id
            JOIN team_users u ON u.id = m.user_id
            WHERE m.user_id = ? AND m.revoked_at IS NULL AND u.active = 1
            ORDER BY CASE WHEN o.id = 'local-admin' THEN 0 ELSE 1 END, o.created_at ASC
            """,
            (user_id,),
            many=True,
        )
        assert isinstance(rows, list)
        return [
            TeamOrganization(
                organization_id=str(row["organization_id"]),
                name=str(row["name"]),
                role=_team_role(str(row["role"])),
                created_at=_datetime_from_timestamp(row["created_at"]),
            )
            for row in rows
        ]

    def create_organization(self, *, principal: TeamPrincipal, name: str) -> TeamOrganization:
        if principal.role != "administrator":
            raise TeamIdentityError("administrator_required")
        normalized_name = normalize_organization_name(name)
        organization_id = secrets.token_hex(16)
        now = self._now()
        try:
            connection = self._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    "INSERT INTO team_organizations (id, name, created_at) VALUES (?, ?, ?)",
                    (organization_id, normalized_name, now.timestamp()),
                )
                connection.execute(
                    """
                    INSERT INTO team_memberships (organization_id, user_id, role, created_at, revoked_at)
                    VALUES (?, ?, 'administrator', ?, NULL)
                    """,
                    (organization_id, principal.user_id, now.timestamp()),
                )
                connection.commit()
            except Exception:
                connection.rollback()
                raise
            finally:
                connection.close()
        except sqlite3.Error as exc:
            raise TeamIdentityError("identity_store_unavailable") from exc
        return TeamOrganization(
            organization_id=organization_id,
            name=normalized_name,
            role="administrator",
            created_at=now,
        )

    def get_principal(self, user_id: str, organization_id: str) -> TeamPrincipal | None:
        row = self._fetchone(
            """
            SELECT u.id AS user_id, u.username,
                   o.id AS organization_id, o.name AS organization_name,
                   m.role
            FROM team_users u
            JOIN team_memberships m ON m.user_id = u.id
            JOIN team_organizations o ON o.id = m.organization_id
            WHERE u.id = ? AND o.id = ? AND u.active = 1 AND m.revoked_at IS NULL
            """,
            (user_id, organization_id),
        )
        return _principal_from_row(row) if row is not None else None

    def list_members(self, organization_id: str) -> list[TeamMember]:
        rows = self._fetchone(
            """
            SELECT u.id AS user_id, u.username, m.role, m.created_at
            FROM team_memberships m
            JOIN team_users u ON u.id = m.user_id
            WHERE m.organization_id = ? AND m.revoked_at IS NULL AND u.active = 1
            ORDER BY CASE m.role
                WHEN 'administrator' THEN 0
                WHEN 'maintainer' THEN 1
                ELSE 2 END, u.username ASC
            """,
            (organization_id,),
            many=True,
        )
        assert isinstance(rows, list)
        return [
            TeamMember(
                user_id=str(row["user_id"]),
                username=str(row["username"]),
                role=_team_role(str(row["role"])),
                joined_at=_datetime_from_timestamp(row["created_at"]),
            )
            for row in rows
        ]

    def provision_federated_identity(
        self,
        *,
        principal: TeamPrincipal,
        user_id: str,
        subject_digest: str,
    ) -> FederatedIdentityBinding:
        if principal.role != "administrator":
            raise TeamIdentityError("administrator_required")
        digest = _subject_digest(subject_digest)
        now = self._now()
        try:
            connection = self._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                member = connection.execute(
                    """
                    SELECT u.id AS user_id, u.username, m.role
                    FROM team_users u
                    JOIN team_memberships m ON m.user_id = u.id
                    WHERE u.id = ? AND m.organization_id = ?
                      AND u.active = 1 AND m.revoked_at IS NULL
                    """,
                    (user_id, principal.organization_id),
                ).fetchone()
                if member is None:
                    raise TeamIdentityError("member_not_found")
                role = _team_role(str(member["role"]))
                if role == "administrator":
                    raise TeamIdentityError("federated_administrator_forbidden")
                existing = connection.execute(
                    "SELECT * FROM team_federated_identities WHERE subject_digest = ?",
                    (digest,),
                ).fetchone()
                if existing is not None and (
                    existing["organization_id"] != principal.organization_id
                    or existing["user_id"] != user_id
                ):
                    raise TeamIdentityError("federated_identity_conflict")
                binding_id = str(existing["id"]) if existing is not None else secrets.token_hex(16)
                connection.execute(
                    """
                    INSERT INTO team_federated_identities (
                        id, subject_digest, organization_id, user_id,
                        created_by_user_id, created_at, revoked_at
                    ) VALUES (?, ?, ?, ?, ?, ?, NULL)
                    ON CONFLICT(subject_digest) DO UPDATE SET revoked_at = NULL
                    """,
                    (
                        binding_id,
                        digest,
                        principal.organization_id,
                        user_id,
                        principal.user_id,
                        now.timestamp(),
                    ),
                )
                connection.commit()
            except Exception:
                connection.rollback()
                raise
            finally:
                connection.close()
        except TeamIdentityError:
            raise
        except sqlite3.Error as exc:
            raise TeamIdentityError("identity_store_unavailable") from exc
        return FederatedIdentityBinding(
            binding_id=binding_id,
            organization_id=principal.organization_id,
            user_id=str(member["user_id"]),
            username=str(member["username"]),
            role=role,
            created_at=now,
            revoked_at=None,
        )

    def resolve_federated_principal(
        self,
        *,
        organization_id: str,
        subject_digest: str,
        asserted_role: str,
    ) -> TeamPrincipal | None:
        digest = _subject_digest(subject_digest)
        row = self._fetchone(
            """
            SELECT u.id AS user_id, u.username,
                   o.id AS organization_id, o.name AS organization_name, m.role
            FROM team_federated_identities f
            JOIN team_users u ON u.id = f.user_id
            JOIN team_memberships m
              ON m.user_id = f.user_id AND m.organization_id = f.organization_id
            JOIN team_organizations o ON o.id = f.organization_id
            WHERE f.subject_digest = ? AND f.organization_id = ?
              AND f.revoked_at IS NULL AND u.active = 1 AND m.revoked_at IS NULL
            """,
            (digest, organization_id),
        )
        if row is None or row["role"] != asserted_role or row["role"] == "administrator":
            return None
        return _principal_from_row(row)

    def list_federated_identities(self, organization_id: str) -> list[FederatedIdentityBinding]:
        rows = self._fetchone(
            """
            SELECT f.*, u.username, m.role
            FROM team_federated_identities f
            JOIN team_users u ON u.id = f.user_id
            JOIN team_memberships m
              ON m.user_id = f.user_id AND m.organization_id = f.organization_id
            WHERE f.organization_id = ? AND f.revoked_at IS NULL
            ORDER BY f.created_at DESC, f.id ASC
            """,
            (organization_id,),
            many=True,
        )
        assert isinstance(rows, list)
        return [
            FederatedIdentityBinding(
                binding_id=str(row["id"]),
                organization_id=organization_id,
                user_id=str(row["user_id"]),
                username=str(row["username"]),
                role=_team_role(str(row["role"])),
                created_at=_datetime_from_timestamp(row["created_at"]),
                revoked_at=None,
            )
            for row in rows
        ]

    def revoke_federated_identity(
        self,
        *,
        principal: TeamPrincipal,
        binding_id: str,
    ) -> FederatedIdentityBinding:
        if principal.role != "administrator":
            raise TeamIdentityError("administrator_required")
        normalized_id = _binding_identifier(binding_id)
        now = self._now()
        row = self._fetchone(
            """
            SELECT f.*, u.username, m.role
            FROM team_federated_identities f
            JOIN team_users u ON u.id = f.user_id
            JOIN team_memberships m
              ON m.user_id = f.user_id AND m.organization_id = f.organization_id
            WHERE f.id = ? AND f.organization_id = ?
            """,
            (normalized_id, principal.organization_id),
        )
        if row is None or row["revoked_at"] is not None:
            raise TeamIdentityError("federated_identity_not_found")
        self._execute(
            "UPDATE team_federated_identities SET revoked_at = ? WHERE id = ? AND organization_id = ?",
            (now.timestamp(), normalized_id, principal.organization_id),
        )
        return FederatedIdentityBinding(
            binding_id=normalized_id,
            organization_id=principal.organization_id,
            user_id=str(row["user_id"]),
            username=str(row["username"]),
            role=_team_role(str(row["role"])),
            created_at=_datetime_from_timestamp(row["created_at"]),
            revoked_at=now,
        )

    def create_invitation(
        self,
        *,
        principal: TeamPrincipal,
        username: str,
        role: TeamRole,
    ) -> TeamInvitation:
        if principal.role != "administrator":
            raise TeamIdentityError("administrator_required")
        normalized_username = normalize_username(username)
        if normalized_username is None:
            raise TeamIdentityError("invalid_username")
        normalized_role = _team_role(role)
        now = self._now()
        expires_at = now + timedelta(seconds=self.invitation_ttl_seconds)
        invitation_id = secrets.token_hex(16)
        token = self._token_factory()
        if not isinstance(token, str) or not token or len(token) > TEAM_INVITATION_TOKEN_MAX_LENGTH:
            raise TeamIdentityError("invitation_unavailable")

        try:
            connection = self._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                active = connection.execute(
                    """
                    SELECT 1
                    FROM team_users u
                    JOIN team_memberships m ON m.user_id = u.id
                    WHERE u.username = ? AND m.organization_id = ?
                      AND u.active = 1 AND m.revoked_at IS NULL
                    """,
                    (normalized_username, principal.organization_id),
                ).fetchone()
                if active is not None:
                    raise TeamIdentityError("member_exists")
                connection.execute(
                    """
                    UPDATE team_invitations
                    SET revoked_at = ?
                    WHERE organization_id = ? AND username = ?
                      AND accepted_at IS NULL AND revoked_at IS NULL
                    """,
                    (now.timestamp(), principal.organization_id, normalized_username),
                )
                connection.execute(
                    """
                    INSERT INTO team_invitations (
                        id, token_hash, organization_id, username, role,
                        created_by_user_id, created_at, expires_at,
                        accepted_at, revoked_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL)
                    """,
                    (
                        invitation_id,
                        hash_invitation_token(token),
                        principal.organization_id,
                        normalized_username,
                        normalized_role,
                        principal.user_id,
                        now.timestamp(),
                        expires_at.timestamp(),
                    ),
                )
                connection.commit()
            except Exception:
                connection.rollback()
                raise
            finally:
                connection.close()
        except TeamIdentityError:
            raise
        except sqlite3.Error as exc:
            raise TeamIdentityError("identity_store_unavailable") from exc

        return TeamInvitation(
            invitation_id=invitation_id,
            token=token,
            username=normalized_username,
            role=normalized_role,
            expires_at=expires_at,
        )

    def propose_public_identity(
        self,
        *,
        principal: TeamPrincipal,
        ecosystem: PublicIdentityEcosystem,
        package_name: str,
        requested_ttl_days: int = PUBLIC_IDENTITY_ATTESTATION_DEFAULT_TTL_DAYS,
    ) -> PublicIdentityAttestation:
        if principal.role not in {"administrator", "maintainer"}:
            raise TeamIdentityError("maintainer_required")
        normalized_ecosystem, normalized_name = normalize_public_identity(ecosystem, package_name)
        ttl_days = normalize_public_identity_ttl(requested_ttl_days)
        now = self._now()
        try:
            connection = self._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                existing = connection.execute(
                    """
                    SELECT * FROM team_public_identity_attestations
                    WHERE organization_id = ? AND ecosystem = ? AND package_name = ?
                    """,
                    (principal.organization_id, normalized_ecosystem, normalized_name),
                ).fetchone()
                if existing is not None and _public_identity_status(existing, now) in {"pending", "approved"}:
                    raise TeamIdentityError("attestation_exists")
                retained_count = connection.execute(
                    "SELECT COUNT(*) FROM team_public_identity_attestations WHERE organization_id = ?",
                    (principal.organization_id,),
                ).fetchone()[0]
                if existing is None and int(retained_count) >= PUBLIC_IDENTITY_ATTESTATION_MAX_PER_ORGANIZATION:
                    raise TeamIdentityError("attestation_limit_reached")
                attestation_id = secrets.token_hex(16)
                revision = int(existing["revision"]) + 1 if existing is not None else 1
                connection.execute(
                    """
                    INSERT INTO team_public_identity_attestations (
                        id, organization_id, ecosystem, package_name, state,
                        revision, requested_ttl_days, proposed_by_user_id,
                        proposed_at, approved_by_user_id, approved_at,
                        expires_at, revoked_by_user_id, revoked_at
                    ) VALUES (?, ?, ?, ?, 'pending', ?, ?, ?, ?, NULL, NULL, NULL, NULL, NULL)
                    ON CONFLICT(organization_id, ecosystem, package_name) DO UPDATE SET
                        id = excluded.id,
                        state = 'pending',
                        revision = excluded.revision,
                        requested_ttl_days = excluded.requested_ttl_days,
                        proposed_by_user_id = excluded.proposed_by_user_id,
                        proposed_at = excluded.proposed_at,
                        approved_by_user_id = NULL,
                        approved_at = NULL,
                        expires_at = NULL,
                        revoked_by_user_id = NULL,
                        revoked_at = NULL
                    """,
                    (
                        attestation_id,
                        principal.organization_id,
                        normalized_ecosystem,
                        normalized_name,
                        revision,
                        ttl_days,
                        principal.user_id,
                        now.timestamp(),
                    ),
                )
                row = connection.execute(
                    "SELECT * FROM team_public_identity_attestations WHERE id = ?",
                    (attestation_id,),
                ).fetchone()
                connection.commit()
            except Exception:
                connection.rollback()
                raise
            finally:
                connection.close()
        except TeamIdentityError:
            raise
        except sqlite3.Error as exc:
            raise TeamIdentityError("identity_store_unavailable") from exc
        assert row is not None
        return _public_identity_attestation_from_row(row, now)

    def approve_public_identity(
        self,
        *,
        principal: TeamPrincipal,
        attestation_id: str,
    ) -> PublicIdentityAttestation:
        if principal.role != "administrator":
            raise TeamIdentityError("administrator_required")
        normalized_id = _opaque_identifier(attestation_id)
        now = self._now()
        try:
            connection = self._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    """
                    SELECT * FROM team_public_identity_attestations
                    WHERE id = ? AND organization_id = ?
                    """,
                    (normalized_id, principal.organization_id),
                ).fetchone()
                if row is None:
                    raise TeamIdentityError("attestation_not_found")
                if _public_identity_status(row, now) != "pending":
                    raise TeamIdentityError("attestation_not_pending")
                expires_at = now + timedelta(days=int(row["requested_ttl_days"]))
                cursor = connection.execute(
                    """
                    UPDATE team_public_identity_attestations
                    SET state = 'approved', revision = revision + 1,
                        approved_by_user_id = ?, approved_at = ?, expires_at = ?,
                        revoked_by_user_id = NULL, revoked_at = NULL
                    WHERE id = ? AND organization_id = ? AND state = 'pending'
                    """,
                    (
                        principal.user_id,
                        now.timestamp(),
                        expires_at.timestamp(),
                        normalized_id,
                        principal.organization_id,
                    ),
                )
                if cursor.rowcount != 1:
                    raise TeamIdentityError("attestation_not_pending")
                approved = connection.execute(
                    "SELECT * FROM team_public_identity_attestations WHERE id = ?",
                    (normalized_id,),
                ).fetchone()
                connection.commit()
            except Exception:
                connection.rollback()
                raise
            finally:
                connection.close()
        except TeamIdentityError:
            raise
        except sqlite3.Error as exc:
            raise TeamIdentityError("identity_store_unavailable") from exc
        assert approved is not None
        return _public_identity_attestation_from_row(approved, now)

    def revoke_public_identity(
        self,
        *,
        principal: TeamPrincipal,
        attestation_id: str,
    ) -> PublicIdentityAttestation:
        if principal.role != "administrator":
            raise TeamIdentityError("administrator_required")
        normalized_id = _opaque_identifier(attestation_id)
        now = self._now()
        try:
            connection = self._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                cursor = connection.execute(
                    """
                    UPDATE team_public_identity_attestations
                    SET state = 'revoked', revision = revision + 1,
                        revoked_by_user_id = ?, revoked_at = ?
                    WHERE id = ? AND organization_id = ? AND state IN ('pending', 'approved')
                      AND (state != 'approved' OR expires_at > ?)
                    """,
                    (
                        principal.user_id,
                        now.timestamp(),
                        normalized_id,
                        principal.organization_id,
                        now.timestamp(),
                    ),
                )
                if cursor.rowcount != 1:
                    raise TeamIdentityError("attestation_not_active")
                row = connection.execute(
                    "SELECT * FROM team_public_identity_attestations WHERE id = ? AND organization_id = ?",
                    (normalized_id, principal.organization_id),
                ).fetchone()
                connection.commit()
            except Exception:
                connection.rollback()
                raise
            finally:
                connection.close()
        except TeamIdentityError:
            raise
        except sqlite3.Error as exc:
            raise TeamIdentityError("identity_store_unavailable") from exc
        if row is None:
            raise TeamIdentityError("attestation_not_found")
        return _public_identity_attestation_from_row(row, now)

    def list_public_identities(self, organization_id: str) -> list[PublicIdentityAttestation]:
        rows = self._fetchone(
            """
            SELECT * FROM team_public_identity_attestations
            WHERE organization_id = ?
            ORDER BY proposed_at DESC, id ASC
            """,
            (organization_id,),
            many=True,
        )
        assert isinstance(rows, list)
        now = self._now()
        return [_public_identity_attestation_from_row(row, now) for row in rows]

    def approved_public_identity_keys(self, organization_id: str) -> tuple[str, ...]:
        now = self._now().timestamp()
        rows = self._fetchone(
            """
            SELECT ecosystem, package_name FROM team_public_identity_attestations
            WHERE organization_id = ? AND state = 'approved' AND expires_at > ?
            ORDER BY ecosystem ASC, package_name ASC
            """,
            (organization_id, now),
            many=True,
        )
        assert isinstance(rows, list)
        return tuple(f"{row['ecosystem']}:{row['package_name']}" for row in rows)

    def is_public_identity_approved(self, organization_id: str, ecosystem: str, package_name: str) -> bool:
        try:
            normalized_ecosystem, normalized_name = normalize_public_identity(ecosystem, package_name)
        except TeamIdentityError:
            return False
        row = self._fetchone(
            """
            SELECT expires_at FROM team_public_identity_attestations
            WHERE organization_id = ? AND ecosystem = ? AND package_name = ? AND state = 'approved'
            """,
            (organization_id, normalized_ecosystem, normalized_name),
        )
        return (
            row is not None
            and not isinstance(row, list)
            and row["expires_at"] is not None
            and float(row["expires_at"]) > self._now().timestamp()
        )

    def accept_invitation(self, *, token: str, password: str) -> TeamPrincipal:
        if not isinstance(token, str) or not token or len(token) > TEAM_INVITATION_TOKEN_MAX_LENGTH:
            raise TeamIdentityError("invalid_invitation")
        password_hash = hash_password(password)
        now = self._now()
        token_hash = hash_invitation_token(token)

        try:
            connection = self._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                invitation = connection.execute(
                    """
                    SELECT i.*, o.name AS organization_name
                    FROM team_invitations i
                    JOIN team_organizations o ON o.id = i.organization_id
                    WHERE i.token_hash = ?
                    """,
                    (token_hash,),
                ).fetchone()
                if (
                    invitation is None
                    or invitation["accepted_at"] is not None
                    or invitation["revoked_at"] is not None
                    or float(invitation["expires_at"]) <= now.timestamp()
                    or not hmac.compare_digest(str(invitation["token_hash"]), token_hash)
                ):
                    raise TeamIdentityError("invalid_invitation")
                existing = connection.execute(
                    "SELECT id, password_hash, active FROM team_users WHERE username = ?",
                    (str(invitation["username"]),),
                ).fetchone()
                if existing is not None:
                    if int(existing["active"]) != 1 or not verify_admin_password(password, str(existing["password_hash"])):
                        raise TeamIdentityError("invalid_invitation")
                    user_id = str(existing["id"])
                else:
                    user_id = secrets.token_hex(16)
                    connection.execute(
                        """
                        INSERT INTO team_users (id, username, password_hash, active, created_at)
                        VALUES (?, ?, ?, 1, ?)
                        """,
                        (user_id, str(invitation["username"]), password_hash, now.timestamp()),
                    )
                connection.execute(
                    """
                    INSERT INTO team_memberships (
                        organization_id, user_id, role, created_at, revoked_at
                    ) VALUES (?, ?, ?, ?, NULL)
                    """,
                    (
                        str(invitation["organization_id"]),
                        user_id,
                        str(invitation["role"]),
                        now.timestamp(),
                    ),
                )
                connection.execute(
                    "UPDATE team_invitations SET accepted_at = ? WHERE id = ?",
                    (now.timestamp(), str(invitation["id"])),
                )
                connection.commit()
            except Exception:
                connection.rollback()
                raise
            finally:
                connection.close()
        except TeamIdentityError:
            raise
        except sqlite3.Error as exc:
            raise TeamIdentityError("identity_store_unavailable") from exc

        principal = self.get_principal(user_id, str(invitation["organization_id"]))
        if principal is None:
            raise TeamIdentityError("identity_store_unavailable")
        return principal

    def purge_terminal_invitations(
        self,
        *,
        cutoff: datetime,
        organization_id: str | None = None,
    ) -> int:
        """Remove terminal invitation metadata after its independent retention window.

        The selection is based only on server timestamps. The token hash, username,
        creator and role never leave the identity store as part of cleanup.
        """

        cutoff_ts = _aware_utc(cutoff).timestamp()
        query = """
            DELETE FROM team_invitations
            WHERE COALESCE(accepted_at, revoked_at, expires_at) <= ?
        """
        params: tuple[object, ...] = (cutoff_ts,)
        if organization_id is not None:
            normalized_organization_id = _organization_identifier(organization_id)
            query += " AND organization_id = ?"
            params = (cutoff_ts, normalized_organization_id)
        cursor = self._execute(query, params)
        return max(0, cursor.rowcount)

    def change_member_role(
        self,
        *,
        principal: TeamPrincipal,
        user_id: str,
        role: TeamRole,
    ) -> TeamMember:
        if principal.role != "administrator":
            raise TeamIdentityError("administrator_required")
        normalized_role = _team_role(role)
        if user_id == TEAM_BOOTSTRAP_ADMIN_ID and normalized_role != "administrator":
            raise TeamIdentityError("last_administrator")
        try:
            connection = self._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                current = connection.execute(
                    """
                    SELECT role FROM team_memberships
                    WHERE organization_id = ? AND user_id = ? AND revoked_at IS NULL
                    """,
                    (principal.organization_id, user_id),
                ).fetchone()
                if current is None:
                    raise TeamIdentityError("member_not_found")
                if str(current["role"]) == "administrator" and normalized_role != "administrator":
                    administrators = connection.execute(
                        """
                        SELECT COUNT(*) FROM team_memberships
                        WHERE organization_id = ? AND role = 'administrator' AND revoked_at IS NULL
                        """,
                        (principal.organization_id,),
                    ).fetchone()[0]
                    if int(administrators) <= 1:
                        raise TeamIdentityError("last_administrator")
                connection.execute(
                    """
                    UPDATE team_memberships SET role = ?
                    WHERE organization_id = ? AND user_id = ? AND revoked_at IS NULL
                    """,
                    (normalized_role, principal.organization_id, user_id),
                )
                connection.commit()
            except Exception:
                connection.rollback()
                raise
            finally:
                connection.close()
        except TeamIdentityError:
            raise
        except sqlite3.Error as exc:
            raise TeamIdentityError("identity_store_unavailable") from exc
        member = next((item for item in self.list_members(principal.organization_id) if item.user_id == user_id), None)
        if member is None:
            raise TeamIdentityError("member_not_found")
        return member

    def run_with_active_members(
        self,
        *,
        organization_id: str,
        user_ids: list[str],
        operation: Callable[[], T],
    ) -> T:
        """Serialize an external owner-scoped write with membership changes."""

        requested = set(user_ids)
        try:
            connection = self._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                if requested:
                    placeholders = ",".join("?" for _ in requested)
                    rows = connection.execute(
                        f"""
                        SELECT m.user_id
                        FROM team_memberships m
                        JOIN team_users u ON u.id = m.user_id
                        WHERE m.organization_id = ? AND m.user_id IN ({placeholders})
                          AND m.revoked_at IS NULL AND u.active = 1
                        """,
                        (organization_id, *sorted(requested)),
                    ).fetchall()
                    if {str(row["user_id"]) for row in rows} != requested:
                        raise TeamIdentityError("member_not_active")
                result = operation()
                connection.commit()
                return result
            except Exception:
                connection.rollback()
                raise
            finally:
                connection.close()
        except TeamIdentityError:
            raise
        except sqlite3.Error as exc:
            raise TeamIdentityError("identity_store_unavailable") from exc

    def revoke_member(
        self,
        *,
        principal: TeamPrincipal,
        user_id: str,
        on_membership_revoked: Callable[[], T] | None = None,
    ) -> T | None:
        if principal.role != "administrator":
            raise TeamIdentityError("administrator_required")
        if user_id == TEAM_BOOTSTRAP_ADMIN_ID:
            raise TeamIdentityError("last_administrator")
        now = self._now().timestamp()
        try:
            connection = self._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                membership = connection.execute(
                    """
                    SELECT role FROM team_memberships
                    WHERE organization_id = ? AND user_id = ? AND revoked_at IS NULL
                    """,
                    (principal.organization_id, user_id),
                ).fetchone()
                if membership is None:
                    raise TeamIdentityError("member_not_found")
                if str(membership["role"]) == "administrator":
                    administrators = connection.execute(
                        """
                        SELECT COUNT(*) FROM team_memberships
                        WHERE organization_id = ? AND role = 'administrator' AND revoked_at IS NULL
                        """,
                        (principal.organization_id,),
                    ).fetchone()[0]
                    if int(administrators) <= 1:
                        raise TeamIdentityError("last_administrator")
                cursor = connection.execute(
                    """
                    UPDATE team_memberships
                    SET revoked_at = ?
                    WHERE organization_id = ? AND user_id = ? AND revoked_at IS NULL
                    """,
                    (now, principal.organization_id, user_id),
                )
                if cursor.rowcount != 1:
                    raise TeamIdentityError("member_not_found")
                result = on_membership_revoked() if on_membership_revoked is not None else None
                remaining_memberships = connection.execute(
                    """
                    SELECT COUNT(*) FROM team_memberships
                    WHERE user_id = ? AND revoked_at IS NULL
                    """,
                    (user_id,),
                ).fetchone()[0]
                if int(remaining_memberships) == 0:
                    connection.execute(
                        """
                        UPDATE team_users
                        SET username = ?, password_hash = ?, active = 0
                        WHERE id = ?
                        """,
                        (f"deprovisioned.{user_id}", TEAM_DEPROVISIONED_PASSWORD_MARKER, user_id),
                    )
                connection.commit()
                return result
            except Exception:
                connection.rollback()
                raise
            finally:
                connection.close()
        except TeamIdentityError:
            raise
        except sqlite3.Error as exc:
            raise TeamIdentityError("identity_store_unavailable") from exc

    def _ensure_bootstrap_identity(self) -> None:
        now = self._now().timestamp()
        try:
            connection = self._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    """
                    INSERT INTO team_organizations (id, name, created_at)
                    VALUES (?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET name = excluded.name
                    """,
                    (TEAM_BOOTSTRAP_ORGANIZATION_ID, self.organization_name, now),
                )
                connection.execute(
                    """
                    INSERT INTO team_users (id, username, password_hash, active, created_at)
                    VALUES (?, ?, ?, 1, ?)
                    ON CONFLICT(id) DO UPDATE SET
                        username = excluded.username,
                        password_hash = excluded.password_hash,
                        active = 1
                    """,
                    (
                        TEAM_BOOTSTRAP_ADMIN_ID,
                        TEAM_BOOTSTRAP_ADMIN_USERNAME,
                        self.bootstrap_admin_password_hash,
                        now,
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO team_memberships (organization_id, user_id, role, created_at, revoked_at)
                    VALUES (?, ?, 'administrator', ?, NULL)
                    ON CONFLICT(organization_id, user_id) DO UPDATE SET
                        role = 'administrator', revoked_at = NULL
                    """,
                    (TEAM_BOOTSTRAP_ORGANIZATION_ID, TEAM_BOOTSTRAP_ADMIN_ID, now),
                )
                connection.commit()
            except Exception:
                connection.rollback()
                raise
            finally:
                connection.close()
        except sqlite3.Error as exc:
            raise TeamIdentityError("identity_store_unavailable") from exc

    def _initialize_schema(self) -> None:
        try:
            self.db_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            connection = self._connect()
            try:
                connection.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS team_organizations (
                        id TEXT PRIMARY KEY,
                        name TEXT NOT NULL,
                        created_at REAL NOT NULL
                    );
                    CREATE TABLE IF NOT EXISTS team_users (
                        id TEXT PRIMARY KEY,
                        username TEXT NOT NULL UNIQUE,
                        password_hash TEXT NOT NULL,
                        active INTEGER NOT NULL,
                        created_at REAL NOT NULL
                    );
                    CREATE TABLE IF NOT EXISTS team_memberships (
                        organization_id TEXT NOT NULL,
                        user_id TEXT NOT NULL,
                        role TEXT NOT NULL,
                        created_at REAL NOT NULL,
                        revoked_at REAL NULL,
                        PRIMARY KEY (organization_id, user_id),
                        FOREIGN KEY (organization_id) REFERENCES team_organizations(id),
                        FOREIGN KEY (user_id) REFERENCES team_users(id)
                    );
                    CREATE INDEX IF NOT EXISTS idx_team_memberships_user
                        ON team_memberships (user_id, revoked_at);
                    CREATE TABLE IF NOT EXISTS team_federated_identities (
                        id TEXT PRIMARY KEY,
                        subject_digest TEXT NOT NULL UNIQUE,
                        organization_id TEXT NOT NULL,
                        user_id TEXT NOT NULL,
                        created_by_user_id TEXT NOT NULL,
                        created_at REAL NOT NULL,
                        revoked_at REAL NULL,
                        FOREIGN KEY (organization_id) REFERENCES team_organizations(id),
                        FOREIGN KEY (user_id) REFERENCES team_users(id),
                        FOREIGN KEY (created_by_user_id) REFERENCES team_users(id)
                    );
                    CREATE INDEX IF NOT EXISTS idx_team_federated_identity_scope
                        ON team_federated_identities (organization_id, revoked_at);
                    CREATE TABLE IF NOT EXISTS team_invitations (
                        id TEXT PRIMARY KEY,
                        token_hash TEXT NOT NULL UNIQUE,
                        organization_id TEXT NOT NULL,
                        username TEXT NOT NULL,
                        role TEXT NOT NULL,
                        created_by_user_id TEXT NOT NULL,
                        created_at REAL NOT NULL,
                        expires_at REAL NOT NULL,
                        accepted_at REAL NULL,
                        revoked_at REAL NULL,
                        FOREIGN KEY (organization_id) REFERENCES team_organizations(id),
                        FOREIGN KEY (created_by_user_id) REFERENCES team_users(id)
                    );
                    CREATE INDEX IF NOT EXISTS idx_team_invitations_lookup
                        ON team_invitations (organization_id, username, expires_at);
                    CREATE TABLE IF NOT EXISTS team_public_identity_attestations (
                        id TEXT NOT NULL UNIQUE,
                        organization_id TEXT NOT NULL,
                        ecosystem TEXT NOT NULL,
                        package_name TEXT NOT NULL,
                        state TEXT NOT NULL,
                        revision INTEGER NOT NULL,
                        requested_ttl_days INTEGER NOT NULL,
                        proposed_by_user_id TEXT NOT NULL,
                        proposed_at REAL NOT NULL,
                        approved_by_user_id TEXT NULL,
                        approved_at REAL NULL,
                        expires_at REAL NULL,
                        revoked_by_user_id TEXT NULL,
                        revoked_at REAL NULL,
                        PRIMARY KEY (organization_id, ecosystem, package_name),
                        FOREIGN KEY (organization_id) REFERENCES team_organizations(id),
                        FOREIGN KEY (proposed_by_user_id) REFERENCES team_users(id),
                        FOREIGN KEY (approved_by_user_id) REFERENCES team_users(id),
                        FOREIGN KEY (revoked_by_user_id) REFERENCES team_users(id)
                    );
                    CREATE INDEX IF NOT EXISTS idx_team_public_identity_state
                        ON team_public_identity_attestations (organization_id, state, expires_at);
                    CREATE TABLE IF NOT EXISTS team_identity_metadata (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL,
                        updated_at REAL NOT NULL
                    );
                    """
                )
                connection.execute(
                    """
                    INSERT INTO team_identity_metadata (key, value, updated_at)
                    VALUES ('schema_version', ?, ?)
                    ON CONFLICT(key) DO UPDATE SET
                        value = excluded.value, updated_at = excluded.updated_at
                    """,
                    (str(TEAM_IDENTITY_SCHEMA_VERSION), self._now().timestamp()),
                )
                connection.commit()
            finally:
                connection.close()
        except (OSError, sqlite3.Error) as exc:
            raise TeamIdentityError("identity_store_unavailable") from exc

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def _execute(self, query: str, params: tuple[object, ...]) -> sqlite3.Cursor:
        try:
            connection = self._connect()
            try:
                cursor = connection.execute(query, params)
                connection.commit()
                return cursor
            finally:
                connection.close()
        except sqlite3.Error as exc:
            raise TeamIdentityError("identity_store_unavailable") from exc

    def _fetchone(
        self,
        query: str,
        params: tuple[object, ...],
        *,
        many: bool = False,
    ) -> sqlite3.Row | list[sqlite3.Row] | None:
        try:
            connection = self._connect()
            try:
                cursor = connection.execute(query, params)
                return cursor.fetchall() if many else cursor.fetchone()
            finally:
                connection.close()
        except sqlite3.Error as exc:
            raise TeamIdentityError("identity_store_unavailable") from exc

    def _now(self) -> datetime:
        current = self._now_func()
        if current.tzinfo is None:
            return current.replace(tzinfo=timezone.utc)
        return current.astimezone(timezone.utc)


def normalize_username(value: str) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip().lower()
    return normalized if TEAM_USERNAME_PATTERN.fullmatch(normalized) else None


def normalize_organization_name(value: str) -> str:
    if not isinstance(value, str):
        raise TeamIdentityError("invalid_organization_name")
    normalized = " ".join(value.strip().split())
    if not 3 <= len(normalized) <= 80:
        raise TeamIdentityError("invalid_organization_name")
    if any(ord(character) < 32 or character in {"/", "\\"} for character in normalized):
        raise TeamIdentityError("invalid_organization_name")
    return normalized


def normalize_public_identity(ecosystem: object, package_name: object) -> tuple[PublicIdentityEcosystem, str]:
    if ecosystem not in PUBLIC_IDENTITY_ECOSYSTEMS:
        raise TeamIdentityError("invalid_public_identity")
    from app.public_advisory_egress import normalize_public_component_name

    normalized_name = normalize_public_component_name(ecosystem, package_name)
    if normalized_name is None:
        raise TeamIdentityError("invalid_public_identity")
    return ecosystem, normalized_name  # type: ignore[return-value]


def normalize_public_identity_ttl(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TeamIdentityError("invalid_attestation_ttl")
    if not 1 <= value <= PUBLIC_IDENTITY_ATTESTATION_MAX_TTL_DAYS:
        raise TeamIdentityError("invalid_attestation_ttl")
    return value


def _opaque_identifier(value: object) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{32}", value):
        raise TeamIdentityError("attestation_not_found")
    return value


def _binding_identifier(value: object) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{32}", value):
        raise TeamIdentityError("federated_identity_not_found")
    return value


def _organization_identifier(value: object) -> str:
    if value == TEAM_BOOTSTRAP_ORGANIZATION_ID:
        return TEAM_BOOTSTRAP_ORGANIZATION_ID
    if not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{32}", value):
        raise TeamIdentityError("organization_not_found")
    return value


def _aware_utc(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise TeamIdentityError("invalid_retention_cutoff")
    return value.astimezone(timezone.utc)


def _public_identity_status(row: sqlite3.Row, now: datetime) -> PublicIdentityAttestationStatus:
    state = str(row["state"])
    if state == "approved" and row["expires_at"] is not None and float(row["expires_at"]) <= now.timestamp():
        return "expired"
    if state not in {"pending", "approved", "revoked"}:
        raise TeamIdentityError("identity_store_unavailable")
    return state  # type: ignore[return-value]


def _optional_datetime_from_timestamp(value: object) -> datetime | None:
    return None if value is None else _datetime_from_timestamp(float(value))


def _public_identity_attestation_from_row(row: sqlite3.Row, now: datetime) -> PublicIdentityAttestation:
    ecosystem = str(row["ecosystem"])
    if ecosystem not in PUBLIC_IDENTITY_ECOSYSTEMS:
        raise TeamIdentityError("identity_store_unavailable")
    return PublicIdentityAttestation(
        attestation_id=str(row["id"]),
        organization_id=str(row["organization_id"]),
        ecosystem=ecosystem,  # type: ignore[arg-type]
        package_name=str(row["package_name"]),
        status=_public_identity_status(row, now),
        revision=int(row["revision"]),
        requested_ttl_days=int(row["requested_ttl_days"]),
        proposed_by_user_id=str(row["proposed_by_user_id"]),
        proposed_at=_datetime_from_timestamp(row["proposed_at"]),
        approved_by_user_id=str(row["approved_by_user_id"]) if row["approved_by_user_id"] is not None else None,
        approved_at=_optional_datetime_from_timestamp(row["approved_at"]),
        expires_at=_optional_datetime_from_timestamp(row["expires_at"]),
        revoked_by_user_id=str(row["revoked_by_user_id"]) if row["revoked_by_user_id"] is not None else None,
        revoked_at=_optional_datetime_from_timestamp(row["revoked_at"]),
    )


def hash_invitation_token(token: str) -> str:
    payload = f"inspectra-team-invitation-v1\0{token}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _team_role(value: str) -> TeamRole:
    if value not in TEAM_ROLES:
        raise TeamIdentityError("invalid_role")
    return value  # type: ignore[return-value]


def _principal_from_row(row: sqlite3.Row) -> TeamPrincipal:
    return TeamPrincipal(
        user_id=str(row["user_id"]),
        username=str(row["username"]),
        organization_id=str(row["organization_id"]),
        organization_name=str(row["organization_name"]),
        role=_team_role(str(row["role"])),
    )


def _new_invitation_token() -> str:
    return secrets.token_urlsafe(TEAM_INVITATION_TOKEN_BYTES)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _datetime_from_timestamp(value: float | int) -> datetime:
    return datetime.fromtimestamp(float(value), tz=timezone.utc)
