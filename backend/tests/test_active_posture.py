from datetime import datetime, timedelta, timezone

from app.active_posture import build_active_posture
from app.models import JobRecord


def _job(
    identifier: str,
    capability: str,
    result: dict,
    *,
    minute: int,
    status: str = "completed",
    revision_id: str | None = "e" * 32,
    revision_sequence: int | None = 1,
) -> JobRecord:
    at = datetime(2026, 9, 9, 10, minute, tzinfo=timezone.utc)
    return JobRecord(
        id=identifier * 32,
        owner_id="local-admin",
        active_asset_id="a" * 32,
        active_authorization_contract="2026-09-09.1",
        active_authorization_revision_id=revision_id,
        active_authorization_revision_digest_sha256="f" * 64 if revision_id is not None else None,
        active_authorization_revision_sequence=revision_sequence,
        audit_type=capability,
        status=status,
        created_at=at,
        updated_at=at,
        result=result,
    )


def test_active_posture_compares_tcp_ports_without_claiming_resolution():
    base = _job("b", "active_nmap_basic", {"status": "completed", "port_observations": [{"port": 80, "protocol": "tcp", "state": "open"}, {"port": 443, "protocol": "tcp", "state": "open"}], "limits": {}}, minute=1)
    target = _job("c", "active_nmap_basic", {"status": "completed", "port_observations": [{"port": 443, "protocol": "tcp", "state": "open"}, {"port": 8443, "protocol": "tcp", "state": "open"}], "limits": {}}, minute=2)
    posture = build_active_posture([base, target], capability="active_nmap_basic")
    comparison = posture["comparison"]
    assert comparison["state"] == "ready"
    assert comparison["authorization"]["same_revision"] is True
    assert comparison["summary"] == {"new": 1, "changed": 0, "disappeared": 1, "persistent": 1}
    disappeared = next(item for item in comparison["changes"] if item["signal"] == "tcp_port:80")
    assert "not a resolved-vulnerability claim" in disappeared["interpretation"]
    assert "example" not in str(comparison)


def test_active_posture_marks_truncated_or_failed_comparisons_inconclusive():
    base = _job("b", "active_dns_osint", {"status": "osint_best_effort", "observed_names": {"count": 2}, "limits": {}}, minute=1)
    target = _job("c", "active_dns_osint", {"status": "osint_best_effort", "observed_names": {"count": 3}, "limits": {"truncated": True}, "errors": [{"code": "source_unavailable"}]}, minute=2)
    comparison = build_active_posture([base, target], baseline_execution_id=base.id)["comparison"]
    assert comparison["state"] == "inconclusive"
    assert comparison["changes"][0]["signal"] == "dns_osint:observed_name_count"
    assert "not automatically authorized targets" in comparison["changes"][0]["interpretation"]


def test_active_posture_never_compares_different_capabilities():
    nmap = _job("b", "active_nmap_basic", {"port_observations": []}, minute=1)
    tls = _job("c", "active_tls_basic", {"handshake": {"protocol": "TLSv1.3"}}, minute=2)
    posture = build_active_posture([nmap, tls], baseline_execution_id=nmap.id)
    assert posture["comparison"] is None
    assert posture["execution_count"] == 2


def test_active_posture_labels_legacy_revision_as_unknown_without_inventing_evidence():
    base = _job("b", "active_dns_inventory", {"records": {}, "limits": {}}, minute=1, revision_id=None, revision_sequence=None)
    target = _job("c", "active_dns_inventory", {"records": {}, "limits": {}}, minute=2)

    comparison = build_active_posture([base, target], capability="active_dns_inventory")["comparison"]

    assert comparison["state"] == "inconclusive"
    assert comparison["authorization"]["base"] == {"id": None, "sequence": None, "label": "unknown (legacy)"}
    assert comparison["authorization"]["same_revision"] is None
