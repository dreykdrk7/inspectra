# Active DNS Inventory Authorized AXFR Frontend Review

Decision: `ACTIVE_DNS_INVENTORY_10_FRONTEND_AUTHORIZED_AXFR_REVIEW_PASSED`

This microphase reviews `fb01b7c feat(active): expose authorized axfr in dns
inventory ui`, covering the frontend and documentation changes that exposed the
already implemented authorized AXFR backend option in the Active DNS inventory
product flow.

No blockers were found. No runtime DNS, AXFR execution, provider API,
Certificate Transparency lookup, passive DNS lookup, subprocess, DNS CLI, Nmap,
Docker, HTTP crawling, archive/run-all, or `tools/runner/main.py` behavior is
added by this review.

## Reviewed Change

Reviewed commit:

- `fb01b7c feat(active): expose authorized axfr in dns inventory ui`

Reviewed changed files:

- `frontend/src/ActiveDnsInventoryPanel.tsx`;
- `frontend/src/ActiveDnsInventoryPanel.test.tsx`;
- `frontend/src/ActiveDnsInventoryJobReport.tsx`;
- `frontend/src/ActiveDnsInventoryJobReport.test.tsx`;
- `frontend/src/activeDnsInventoryReport.ts`;
- `frontend/src/types.ts`;
- `README.md`;
- `docs/architecture.md`;
- `docs/security-scope.md`;
- `docs/future/active-dns-inventory-frontend-authorized-axfr.md`.

## UI And Contract Review

The frontend keeps AXFR disabled by default:

- `attemptZoneTransfer` starts as `false`;
- the AXFR-specific confirmation starts as `false`;
- disabling AXFR clears the AXFR-specific confirmation;
- default submits send `attempt_zone_transfer: false`;
- default submits do not send `zone_transfer_authorized_confirmed: true`.

The frontend blocks submit when AXFR is selected but the specific AXFR
confirmation is missing. When AXFR is selected and confirmed, the request sends:

```json
{
  "attempt_zone_transfer": true,
  "zone_transfer_authorized_confirmed": true
}
```

The UI does not expose provider credential inputs, resolver overrides,
Certificate Transparency or passive DNS controls, target files, shell command
inputs, DNS CLI inputs, or archive/run-all actions.

## Wording Review

The report renders `zone_transfer_complete` conservatively as:

- `zone transfer accepted by authoritative server`;
- `high-risk configuration review indicator`;
- `Manual validation required`.

Controlled AXFR outcomes such as `refused`, `timed_out`,
`malformed_response`, `unavailable`, and `record_limit_exceeded` remain
controlled states and are not presented as complete coverage.

The reviewed frontend surfaces do not introduce:

- all-records-found claims;
- vulnerability claims;
- exploitability claims;
- target-safety claims;
- public-scanner claims;
- wording that presents `best_effort_inventory` or `partial_inventory` as
  complete-zone coverage.

## Redaction Review

Frontend report and Raw JSON rendering remain redaction-first:

- raw domains are redacted;
- raw nameserver values are redacted;
- raw zone material is redacted or omitted;
- raw DNS packets and resolver logs are redacted;
- raw DNS record values are redacted;
- provider tokens, account IDs, and zone IDs are redacted;
- credentials, headers, cookies, and tokens are redacted.

The frontend defensive redactor also normalizes unexpected or legacy payload
fields before report rendering, so malformed result payloads do not become raw
display surfaces.

## Boundary Review

The reviewed frontend change does not add:

- real AXFR execution;
- new DNS runtime;
- provider API usage;
- Certificate Transparency lookup;
- passive DNS lookup;
- subprocess execution;
- `dig`, `host`, or `nslookup`;
- Nmap;
- Docker or Compose runtime;
- HTTP crawling;
- archive/run-all;
- `tools/runner/main.py`.

The backend AXFR execution boundary remains the previously reviewed backend
module and is not changed by this microphase.

## Validation Results

Executed validations:

- `git status --short --branch`: clean at start, branch ahead of origin;
- `git show --stat --oneline fb01b7c`: 10 files changed, +603/-28;
- `git show --name-only --oneline fb01b7c`: reviewed changed-file list;
- `.venv/bin/python -m pytest backend/tests/test_backend.py -k active_dns_inventory`: 68 passed;
- `.venv/bin/python -m pytest backend/tests`: 642 passed;
- `npm test -- --run ActiveDnsInventoryPanel ActiveDnsInventoryJobReport App dashboardFilters`: 66 passed;
- `npm test -- --run`: 173 passed;
- `npm run build`: passed;
- `git diff --check`: passed;
- `git diff --cached --check`: passed.

Guardrail searches were reviewed for:

- AXFR real execution and new DNS runtime;
- provider/CT/passive DNS;
- subprocess and DNS CLI calls;
- Nmap, Docker, and HTTP behavior;
- archive-run-all and `tools/runner/main.py`;
- raw zone/domain/record/provider leakage;
- complete-coverage and vulnerability wording drift.

Matches were limited to existing backend runtime documentation/source outside
this frontend review scope, no-scope wording, defensive redaction code, or test
fixtures that assert prohibited wording and raw material do not render.

## Acceptance

The authorized AXFR frontend review is accepted:

- AXFR is off by default;
- AXFR requires specific confirmation;
- the frontend request contract is correct;
- AXFR statuses and counters render conservatively;
- `zone_transfer_complete` is high-risk manual-review wording only;
- reports and Raw JSON remain redaction-first;
- no frontend runtime DNS or AXFR execution was added;
- no public scanner, all-records-found, vulnerability, exploitability, or
  target-safety wording was introduced.

`ACTIVE_DNS_INVENTORY_10_FRONTEND_AUTHORIZED_AXFR_REVIEW_PASSED`
