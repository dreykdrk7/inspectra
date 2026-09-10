"""Bounded exports for the shared risk-trend fact projection."""

from __future__ import annotations

import csv
import hashlib
import io
import json

from app.models import RiskTrendProfile, RiskTrendResponse


def render_risk_trend_report(
    trend: RiskTrendResponse,
    *,
    profile: RiskTrendProfile,
    report_format: str,
) -> tuple[bytes, str, str, str]:
    if report_format == "json":
        payload = {
            "report_contract_version": "2026-09-09.1",
            "profile": profile,
            "facts": trend.model_dump(mode="json"),
            "disclosures": [
                "Project names are included only after explicit export confirmation.",
                "Metrics are observations with declared denominators and exclusions; they are not service-level objectives.",
            ],
        }
        content = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        media_type = "application/json"
    elif report_format == "csv":
        output = io.StringIO(newline="")
        writer = csv.writer(output, lineterminator="\n")
        writer.writerow([
            "contract_version", "profile", "period_start", "period_end", "bucket_start", "bucket_end",
            "completed_analyses", "projects_analyzed", "comparable_local", "comparable_public",
            "excluded_transitions", "local_new", "local_resolved", "public_new", "public_resolved",
            "coverage_gained", "coverage_lost",
        ])
        for bucket in trend.buckets:
            writer.writerow([
                trend.contract_version, profile, trend.period_starts_at.isoformat(), trend.period_ends_at.isoformat(),
                bucket.starts_at.isoformat(), bucket.ends_at.isoformat(), bucket.completed_analyses,
                bucket.projects_analyzed, bucket.comparable_local_transitions,
                bucket.comparable_public_transitions, bucket.excluded_transitions,
                bucket.changes.local_new, bucket.changes.local_resolved,
                bucket.changes.public_new, bucket.changes.public_resolved,
                bucket.coverage_gained, bucket.coverage_lost,
            ])
        content = output.getvalue().encode("utf-8")
        media_type = "text/csv"
    else:
        raise ValueError("unsupported_report_format")
    digest = hashlib.sha256(content).hexdigest()
    return content, media_type, f"inspectra-risk-trends-{profile}.{report_format}", digest
