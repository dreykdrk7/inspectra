from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
from io import BytesIO
import json
from pathlib import Path
import re
import sys
import tarfile
from typing import Any, Literal

from app.active_assets import ActiveAssetRecord, current_active_authorization_revision
from app.active_posture import build_active_evidence_snapshot, build_active_posture
from app.models import JobRecord


ACTIVE_EVIDENCE_BUNDLE_CONTRACT_VERSION = "2026-09-08.1"
ACTIVE_EVIDENCE_BUNDLE_MAX_EXECUTIONS = 100
ACTIVE_EVIDENCE_BUNDLE_MAX_ENTRIES = 6
ACTIVE_EVIDENCE_BUNDLE_MAX_ENTRY_BYTES = 512 * 1024
ACTIVE_EVIDENCE_BUNDLE_MAX_BYTES = 4 * 1024 * 1024
ACTIVE_EVIDENCE_BUNDLE_PERIODS = frozenset({"30d", "90d", "365d", "all"})
ActiveEvidencePeriod = Literal["30d", "90d", "365d", "all"]

_EVIDENCE_PATHS = (
    "active-asset.json",
    "executions.json",
    "posture.json",
    "report.md",
)
_ARCHIVE_PATHS = ("manifest.json", *_EVIDENCE_PATHS, "SHA256SUMS")
_PRIVACY_KEYS = frozenset(
    {
        "exact_target_included",
        "authorization_reference_included",
        "responsible_accounts_included",
        "notes_included",
        "raw_results_included",
        "challenge_material_included",
    }
)
_SHA256_LINE = re.compile(r"^([a-f0-9]{64})  ([A-Za-z0-9][A-Za-z0-9.-]{0,63})$")


class ActiveEvidenceBundleError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class ActiveEvidenceBundle:
    payload: bytes
    sha256: str
    manifest: dict[str, Any]


def build_active_asset_markdown_report(asset: ActiveAssetRecord, jobs: list[JobRecord]) -> str:
    posture = build_active_posture(jobs, baseline_execution_id=asset.baseline_execution_id)
    current_revision = current_active_authorization_revision(asset)
    lines = [
        "# Inspectra Active asset report",
        "",
        f"- Asset reference: `active-{asset.id[:12]}`",
        "- Exact target: withheld from export",
        f"- Type: `{asset.asset_type}`",
        f"- Authorization status: `{asset.status}`",
        f"- Authorization expires: `{asset.expires_at.isoformat()}`",
        (
            f"- Current authorization revision: `r{current_revision.sequence}` (`{current_revision.id[:12]}…`)"
            if current_revision is not None
            else "- Current authorization revision: `unknown` (legacy record; re-attestation required)"
        ),
        f"- Executions retained: {posture['execution_count']}",
        "",
        "## Authorization revision history",
        "",
    ]
    if asset.authorization_revisions:
        for revision in asset.authorization_revisions:
            ports = ", ".join(str(port) for port in revision.allowed_ports) or "none"
            lines.append(
                f"- `r{revision.sequence}` (`{revision.id[:12]}…`), `{revision.source}`: "
                f"scope `{'expanded' if revision.scope_expanded else 'unchanged-or-reduced'}`; "
                f"authorized `{revision.authorized_at.isoformat()}` through `{revision.expires_at.isoformat()}`; "
                f"method `{revision.authorization_method}`; capabilities `{', '.join(revision.capabilities)}`; "
                f"protocols `{', '.join(revision.allowed_protocols)}`; ports `{ports}`."
            )
    else:
        lines.append("- `unknown` — legacy record; re-attestation is required before execution.")
    lines.extend(
        [
            "",
            "## Interpretation boundary",
            "",
            "This report contains bounded observations. It does not assert exploitation or confirmed vulnerabilities.",
            "A port no longer observed is not a resolved-vulnerability claim, and discovered names are not authorized targets.",
            "",
            "## Capability history",
            "",
        ]
    )
    for entry in posture["capabilities"]:
        revision_label = (
            f"r{entry['latest_authorization_revision_sequence']} (`{entry['latest_authorization_revision_id'][:12]}…`)"
            if entry["latest_authorization_revision_sequence"] is not None
            and entry["latest_authorization_revision_id"] is not None
            else "unknown (legacy)"
        )
        lines.append(
            f"- `{entry['capability']}`: {entry['execution_count']} execution(s), "
            f"latest status `{entry['latest_status']}`, authorization revision {revision_label}"
        )
    comparison = posture.get("comparison")
    lines.extend(["", "## Latest comparable change", ""])
    if comparison is None:
        lines.append("No two compatible terminal executions are available for comparison.")
    else:
        lines.append(f"Comparison state: `{comparison['state']}`; capability: `{comparison['capability']}`.")
        lines.append(
            "Authorization revisions: "
            f"base `{comparison['authorization']['base']['label']}`, "
            f"target `{comparison['authorization']['target']['label']}`; "
            f"same revision: `{comparison['authorization']['same_revision']}`."
        )
        for change in comparison["changes"]:
            lines.append(f"- `{change['signal']}` — {change['interpretation']}")
    lines.extend(["", "## Limitations", ""])
    lines.extend(f"- {limitation}" for limitation in posture["limitations"])
    return "\n".join(lines) + "\n"


def build_active_evidence_bundle(
    asset: ActiveAssetRecord,
    jobs: list[JobRecord],
    *,
    period: ActiveEvidencePeriod = "90d",
    source_selection_incomplete: bool = False,
) -> ActiveEvidenceBundle:
    if period not in ACTIVE_EVIDENCE_BUNDLE_PERIODS:
        raise ActiveEvidenceBundleError("invalid_period")
    asset_jobs = [
        job
        for job in jobs
        if job.owner_id == asset.organization_id and job.active_asset_id == asset.id
    ]
    state_at = max([asset.updated_at, *(job.updated_at for job in asset_jobs)])
    period_start = _period_start(state_at, period)
    terminal = [
        job
        for job in asset_jobs
        if job.status in {"completed", "failed", "cancelled"}
        and (period_start is None or job.updated_at >= period_start)
        and job.updated_at <= state_at
    ]
    terminal.sort(key=lambda job: (job.created_at, job.id))
    selected = terminal[-ACTIVE_EVIDENCE_BUNDLE_MAX_EXECUTIONS:]

    asset_document = _asset_document(asset, state_at=state_at, period=period, period_start=period_start)
    executions_document = {
        "contract_version": ACTIVE_EVIDENCE_BUNDLE_CONTRACT_VERSION,
        "asset_reference": _asset_reference(asset.id),
        "items": [_execution_document(job) for job in selected],
        "total_in_period": len(terminal),
        "included": len(selected),
        "truncated": len(selected) < len(terminal),
        "source_selection_incomplete": source_selection_incomplete,
    }
    posture_document = _posture_document(asset, selected)
    report = build_active_asset_markdown_report(asset, selected).encode("utf-8")
    evidence_files = {
        "active-asset.json": _json_bytes(asset_document),
        "executions.json": _json_bytes(executions_document),
        "posture.json": _json_bytes(posture_document),
        "report.md": report,
    }
    for payload in evidence_files.values():
        if len(payload) > ACTIVE_EVIDENCE_BUNDLE_MAX_ENTRY_BYTES:
            raise ActiveEvidenceBundleError("entry_too_large")

    manifest = {
        "contract_version": ACTIVE_EVIDENCE_BUNDLE_CONTRACT_VERSION,
        "archive_format": "tar",
        "asset_reference": _asset_reference(asset.id),
        "state_at": _iso(state_at),
        "period": {
            "kind": period,
            "starts_at": _iso(period_start) if period_start is not None else None,
            "ends_at": _iso(state_at),
        },
        "scope": {
            "authorization_revisions": len(asset.authorization_revisions),
            "execution_records_in_period": len(terminal),
            "execution_records_included": len(selected),
            "execution_records_truncated": len(selected) < len(terminal),
            "source_selection_incomplete": source_selection_incomplete,
            "triage_records": len(asset.triage),
        },
        "privacy": {
            "exact_target_included": False,
            "authorization_reference_included": False,
            "responsible_accounts_included": False,
            "notes_included": False,
            "raw_results_included": False,
            "challenge_material_included": False,
        },
        "contents": [
            {
                "path": path,
                "media_type": "text/markdown" if path.endswith(".md") else "application/json",
                "size_bytes": len(evidence_files[path]),
                "sha256": _sha256(evidence_files[path]),
            }
            for path in _EVIDENCE_PATHS
        ],
    }
    manifest_bytes = _json_bytes(manifest)
    files_with_manifest = {"manifest.json": manifest_bytes, **evidence_files}
    checksums = "".join(
        f"{_sha256(files_with_manifest[path])}  {path}\n" for path in sorted(files_with_manifest)
    ).encode("ascii")
    archive = _tar_bytes({**files_with_manifest, "SHA256SUMS": checksums})
    if len(archive) > ACTIVE_EVIDENCE_BUNDLE_MAX_BYTES:
        raise ActiveEvidenceBundleError("bundle_too_large")
    validate_active_evidence_bundle(archive)
    return ActiveEvidenceBundle(payload=archive, sha256=_sha256(archive), manifest=manifest)


def validate_active_evidence_bundle(payload: bytes) -> dict[str, Any]:
    if not payload or len(payload) > ACTIVE_EVIDENCE_BUNDLE_MAX_BYTES:
        raise ActiveEvidenceBundleError("bundle_size_invalid")
    try:
        with tarfile.open(fileobj=BytesIO(payload), mode="r:") as archive:
            members = archive.getmembers()
            if len(members) != ACTIVE_EVIDENCE_BUNDLE_MAX_ENTRIES:
                raise ActiveEvidenceBundleError("entry_set_invalid")
            if tuple(member.name for member in members) != _ARCHIVE_PATHS:
                raise ActiveEvidenceBundleError("entry_set_invalid")
            if any(
                not member.isfile()
                or member.size < 0
                or member.size > ACTIVE_EVIDENCE_BUNDLE_MAX_ENTRY_BYTES
                or member.uid != 0
                or member.gid != 0
                or member.mtime != 0
                or member.mode != 0o644
                for member in members
            ):
                raise ActiveEvidenceBundleError("entry_metadata_invalid")
            extracted: dict[str, bytes] = {}
            for member in members:
                stream = archive.extractfile(member)
                if stream is None:
                    raise ActiveEvidenceBundleError("entry_unreadable")
                data = stream.read(ACTIVE_EVIDENCE_BUNDLE_MAX_ENTRY_BYTES + 1)
                if len(data) != member.size:
                    raise ActiveEvidenceBundleError("entry_size_invalid")
                extracted[member.name] = data
    except ActiveEvidenceBundleError:
        raise
    except (OSError, tarfile.TarError, EOFError) as exc:
        raise ActiveEvidenceBundleError("archive_invalid") from exc
    if _tar_bytes(extracted) != payload:
        raise ActiveEvidenceBundleError("archive_not_canonical")

    checksums = _parse_checksums(extracted["SHA256SUMS"])
    expected_checksum_paths = set(_ARCHIVE_PATHS) - {"SHA256SUMS"}
    if set(checksums) != expected_checksum_paths:
        raise ActiveEvidenceBundleError("checksum_set_invalid")
    if any(_sha256(extracted[path]) != digest for path, digest in checksums.items()):
        raise ActiveEvidenceBundleError("checksum_mismatch")

    manifest = _json_object(extracted["manifest.json"], "manifest_invalid")
    if set(manifest) != {
        "contract_version", "archive_format", "asset_reference", "state_at", "period", "scope", "privacy", "contents"
    } or (
        manifest.get("contract_version") != ACTIVE_EVIDENCE_BUNDLE_CONTRACT_VERSION
        or manifest.get("archive_format") != "tar"
        or not isinstance(manifest.get("asset_reference"), str)
    ):
        raise ActiveEvidenceBundleError("manifest_invalid")
    contents = manifest.get("contents")
    if not isinstance(contents, list) or [item.get("path") for item in contents if isinstance(item, dict)] != list(_EVIDENCE_PATHS):
        raise ActiveEvidenceBundleError("manifest_invalid")
    for item in contents:
        path = item.get("path")
        if (
            set(item) != {"path", "media_type", "size_bytes", "sha256"}
            or not isinstance(path, str)
            or path not in _EVIDENCE_PATHS
            or item.get("size_bytes") != len(extracted[path])
            or item.get("sha256") != _sha256(extracted[path])
        ):
            raise ActiveEvidenceBundleError("manifest_content_mismatch")
    privacy = manifest.get("privacy")
    if (
        not isinstance(privacy, dict)
        or set(privacy) != _PRIVACY_KEYS
        or any(value is not False for value in privacy.values())
    ):
        raise ActiveEvidenceBundleError("manifest_privacy_invalid")
    documents: dict[str, dict[str, Any]] = {}
    for path in ("active-asset.json", "executions.json", "posture.json"):
        document = _json_object(extracted[path], "document_invalid")
        if document.get("contract_version") != ACTIVE_EVIDENCE_BUNDLE_CONTRACT_VERSION:
            raise ActiveEvidenceBundleError("document_invalid")
        if document.get("asset_reference") != manifest["asset_reference"]:
            raise ActiveEvidenceBundleError("document_reference_mismatch")
        documents[path] = document
    if set(documents["active-asset.json"]) != {
        "contract_version", "asset_reference", "asset_type", "status", "authorized_at",
        "authorization_expires_at", "revoked_at", "state_at", "period", "scope",
        "current_authorization_revision", "authorization_revisions", "triage", "redactions",
    }:
        raise ActiveEvidenceBundleError("document_invalid")
    if set(documents["executions.json"]) != {
        "contract_version", "asset_reference", "items", "total_in_period", "included", "truncated",
        "source_selection_incomplete",
    }:
        raise ActiveEvidenceBundleError("document_invalid")
    if set(documents["posture.json"]) != {
        "contract_version", "source_contract_version", "asset_reference", "execution_count", "counts",
        "capabilities", "baseline_execution_reference", "comparison", "limitations",
    }:
        raise ActiveEvidenceBundleError("document_invalid")
    return {
        "valid": True,
        "contract_version": ACTIVE_EVIDENCE_BUNDLE_CONTRACT_VERSION,
        "bundle_sha256": _sha256(payload),
        "asset_reference": manifest["asset_reference"],
        "state_at": manifest.get("state_at"),
        "entries": len(extracted),
    }


def _asset_document(
    asset: ActiveAssetRecord,
    *,
    state_at: datetime,
    period: ActiveEvidencePeriod,
    period_start: datetime | None,
) -> dict[str, Any]:
    current = current_active_authorization_revision(asset)
    return {
        "contract_version": ACTIVE_EVIDENCE_BUNDLE_CONTRACT_VERSION,
        "asset_reference": _asset_reference(asset.id),
        "asset_type": asset.asset_type,
        "status": asset.status,
        "authorized_at": _iso(asset.authorized_at),
        "authorization_expires_at": _iso(asset.expires_at),
        "revoked_at": _iso(asset.revoked_at) if asset.revoked_at else None,
        "state_at": _iso(state_at),
        "period": {
            "kind": period,
            "starts_at": _iso(period_start) if period_start else None,
            "ends_at": _iso(state_at),
        },
        "scope": {
            "capabilities": sorted(asset.capabilities),
            "allowed_ports": sorted(asset.allowed_ports),
            "allowed_protocols": sorted(asset.allowed_protocols),
        },
        "current_authorization_revision": _revision_reference(current),
        "authorization_revisions": [_revision_document(revision) for revision in asset.authorization_revisions],
        "triage": [
            {
                "observation_key": entry.observation_key,
                "status": entry.status,
                "comment_code": entry.comment_code,
                "updated_at": _iso(entry.updated_at),
            }
            for entry in sorted(asset.triage, key=lambda item: (item.observation_key, item.updated_at))
        ],
        "redactions": [
            "exact_target",
            "authorization_reference",
            "responsible_accounts",
            "notes",
            "event_actor_identifiers",
        ],
    }


def _revision_document(revision: Any) -> dict[str, Any]:
    target_free = {
        "contract_version": revision.contract_version,
        "revision_id": revision.id,
        "sequence": revision.sequence,
        "source": revision.source,
        "scope_expanded": revision.scope_expanded,
        "created_at": _iso(revision.created_at),
        "authorized_at": _iso(revision.authorized_at),
        "expires_at": _iso(revision.expires_at),
        "authorization_method": revision.authorization_method,
        "capabilities": sorted(revision.capabilities),
        "allowed_ports": sorted(revision.allowed_ports),
        "allowed_protocols": sorted(revision.allowed_protocols),
    }
    target_free["exported_scope_sha256"] = _sha256(_json_bytes(target_free))
    return target_free


def _execution_document(job: JobRecord) -> dict[str, Any]:
    return {
        "execution_reference": _execution_reference(job.id),
        "capability": job.audit_type,
        "status": job.status,
        "created_at": _iso(job.created_at),
        "updated_at": _iso(job.updated_at),
        "started_at": _iso(job.started_at) if job.started_at else None,
        "finished_at": _iso(job.finished_at) if job.finished_at else None,
        "termination_reason": job.termination_reason,
        "authorization_revision": {
            "revision_id": job.active_authorization_revision_id,
            "sequence": job.active_authorization_revision_sequence,
        },
        "observation": build_active_evidence_snapshot(job),
        "raw_result_included": False,
    }


def _posture_document(asset: ActiveAssetRecord, jobs: list[JobRecord]) -> dict[str, Any]:
    posture = build_active_posture(jobs, baseline_execution_id=asset.baseline_execution_id)
    comparison = posture.get("comparison")
    safe_comparison = None
    if comparison is not None:
        safe_comparison = {
            "state": comparison["state"],
            "capability": comparison["capability"],
            "base_execution_reference": _execution_reference(comparison["base_execution_id"]),
            "target_execution_reference": _execution_reference(comparison["target_execution_id"]),
            "summary": comparison["summary"],
            "changes": comparison["changes"],
            "changes_truncated": comparison["changes_truncated"],
            "coverage": comparison["coverage"],
            "authorization": comparison["authorization"],
        }
    return {
        "contract_version": ACTIVE_EVIDENCE_BUNDLE_CONTRACT_VERSION,
        "source_contract_version": posture["contract_version"],
        "asset_reference": _asset_reference(asset.id),
        "execution_count": posture["execution_count"],
        "counts": posture["counts"],
        "capabilities": [
            {
                "capability": entry["capability"],
                "execution_count": entry["execution_count"],
                "latest_execution_reference": _execution_reference(entry["latest_execution_id"]),
                "latest_status": entry["latest_status"],
                "latest_at": _iso(entry["latest_at"]),
                "latest_authorization_revision": {
                    "revision_id": entry["latest_authorization_revision_id"],
                    "sequence": entry["latest_authorization_revision_sequence"],
                },
            }
            for entry in posture["capabilities"]
        ],
        "baseline_execution_reference": (
            _execution_reference(asset.baseline_execution_id)
            if asset.baseline_execution_id and any(job.id == asset.baseline_execution_id for job in jobs)
            else None
        ),
        "comparison": safe_comparison,
        "limitations": posture["limitations"],
    }


def _revision_reference(revision: Any | None) -> dict[str, Any] | None:
    if revision is None:
        return None
    return {"revision_id": revision.id, "sequence": revision.sequence}


def _period_start(state_at: datetime, period: ActiveEvidencePeriod) -> datetime | None:
    if period == "all":
        return None
    return state_at - timedelta(days=int(period[:-1]))


def _asset_reference(asset_id: str) -> str:
    return f"active-{asset_id[:12]}"


def _execution_reference(job_id: str) -> str:
    return f"execution-{job_id[:12]}"


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def _json_object(payload: bytes, code: str) -> dict[str, Any]:
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ActiveEvidenceBundleError(code) from exc
    if not isinstance(value, dict):
        raise ActiveEvidenceBundleError(code)
    return value


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _parse_checksums(payload: bytes) -> dict[str, str]:
    try:
        lines = payload.decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise ActiveEvidenceBundleError("checksum_file_invalid") from exc
    result: dict[str, str] = {}
    for line in lines:
        match = _SHA256_LINE.fullmatch(line)
        if match is None or match.group(2) in result:
            raise ActiveEvidenceBundleError("checksum_file_invalid")
        result[match.group(2)] = match.group(1)
    return result


def _tar_bytes(files: dict[str, bytes]) -> bytes:
    buffer = BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for path in _ARCHIVE_PATHS:
            payload = files[path]
            info = tarfile.TarInfo(path)
            info.size = len(payload)
            info.mtime = 0
            info.mode = 0o644
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            archive.addfile(info, BytesIO(payload))
    return buffer.getvalue()


def _main(argv: list[str]) -> int:
    if len(argv) != 1:
        print(json.dumps({"valid": False, "error": "usage"}, separators=(",", ":")))
        return 2
    try:
        path = Path(argv[0])
        if path.is_symlink() or not path.is_file() or path.stat().st_size > ACTIVE_EVIDENCE_BUNDLE_MAX_BYTES:
            raise ActiveEvidenceBundleError("bundle_size_invalid")
        result = validate_active_evidence_bundle(path.read_bytes())
    except (OSError, ActiveEvidenceBundleError) as exc:
        code = exc.code if isinstance(exc, ActiveEvidenceBundleError) else "bundle_unreadable"
        print(json.dumps({"valid": False, "error": code}, separators=(",", ":")))
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised through subprocess tests.
    raise SystemExit(_main(sys.argv[1:]))
