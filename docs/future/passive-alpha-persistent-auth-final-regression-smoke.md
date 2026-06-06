# Passive Alpha Persistent Auth Final Regression Smoke

Status: `PASSIVE_ALPHA_PERSISTENT_AUTH_FINAL_REGRESSION_SMOKE_PASSED`

Base persistent auth closeout: `docs/future/passive-alpha-persistent-auth-closeout.md`

Base cleanup/rotation smoke: `docs/future/passive-alpha-auth-state-cleanup-rotation-smoke.md`

Commit scope: final regression smoke and documentation for the closed Pathing C persistent auth-state line. This block does not add backend features, frontend features, API/cookie/session/CSRF contract changes, admin recovery, trusted-proxy runtime behavior, secure-cookie runtime enforcement, public/community runtime, production approval, Nmap, Active expansion, push, tag, or release state.

## Status

```text
PASSIVE_ALPHA_PERSISTENT_AUTH_FINAL_REGRESSION_SMOKE_PASSED
```

Pathing C remains coherent after a final backend/frontend regression pass. The accepted persistent auth-state posture is ready to proceed to release-candidate checklist work.

## Scope

This is a smoke/regression validation block for the already closed persistent auth-state line.

It does not:

- add new runtime behavior;
- change backend features;
- change frontend features;
- change API, cookie, session, CSRF, `401`, `403`, `429`, or `Retry-After` contracts;
- add admin recovery;
- add trusted-proxy runtime behavior;
- add secure-cookie runtime enforcement;
- add public/community runtime or anti-abuse;
- add SaaS, billing, tenant billing, subscriptions, quotas, paid plans, or enterprise behavior;
- add OAuth/OIDC;
- add multi-user runtime;
- add Nmap behavior or Active expansion;
- approve production-ready use;
- push, tag, or publish a release.

## Validated Pathing C State

- `INSPECTRA_AUTH_STATE_STORE=memory` remains the default.
- `trusted_local_no_auth` remains local/dev/trusted and memory-backed.
- `self_hosted_single_admin` can opt in to SQLite auth state with `INSPECTRA_AUTH_STATE_STORE=sqlite`.
- SQLite mode persists single-admin sessions.
- SQLite mode persists CSRF hash/session binding.
- SQLite mode persists login attempts and soft lockouts.
- Cleanup, pruning, revocation, expiration, restart/store recreation, and DB-byte redaction were already smoke-tested by `PASSIVE_ALPHA_AUTH_STATE_CLEANUP_ROTATION_SMOKE_PASSED`.
- Raw session ids are not stored in SQLite auth state.
- Raw CSRF tokens are not stored in SQLite auth state.
- Raw login client keys are not stored in SQLite auth state.
- Password values and admin password hashes are not stored in SQLite auth state.
- Generic `401`, controlled `403`, controlled `429`, and safe `Retry-After` behavior are preserved.
- `X-Forwarded-For`, `X-Forwarded-Proto`, and `Forwarded` remain ignored until separate trusted-proxy policy exists.
- The frontend does not use browser `localStorage` or `sessionStorage` for auth state.
- Frontend login `401` and `429` copy remains controlled and does not expose internals.

## Validation Evidence

Commands executed for this final regression smoke:

```text
PYTHONPYCACHEPREFIX=/tmp/inspectra-pycache python3 -m compileall backend
.venv/bin/python -m pytest backend/tests/test_backend.py -k "auth_state or sqlite or session or csrf or login or logout or auth_status or rate or lockout or attempt or cleanup or rotation"
.venv/bin/python -m pytest backend/tests/test_backend.py
cd frontend && npm run test -- --run App
cd frontend && npm run test -- --run
cd frontend && npm run build
rg -n "localStorage|sessionStorage" frontend/src backend/app backend/tests
rg -n "Nmap|port scan|crawler|credential valid|vulnerability confirmed|exploitability confirmed|safe target|production ready|SaaS|billing|tenant billing|subscription|quota|paid plan" README.md docs/architecture.md docs/security-scope.md docs/future/passive-alpha-*.md frontend/src backend/app backend/tests
git diff --check
git diff --cached --check
git status --short
git status --branch --short
```

Results:

- Backend compile: passed.
- Backend focused persistent-auth smoke: `67 passed, 241 deselected in 8.84s`.
- Backend full suite: `308 passed in 13.04s`.
- Frontend App suite: `37 passed in 5.35s`.
- Frontend full suite: `127 passed in 8.93s`.
- Frontend build: passed; `tsc --noEmit` and `vite build` completed, with `1626 modules transformed`.
- Browser storage search: no `localStorage` or `sessionStorage` matches in `frontend/src`, `backend/app`, or `backend/tests`.
- Broad no-scope search: expected docs/test-copy hits only, where docs and tests explicitly reject Nmap, port scanning, production readiness, SaaS/billing, credential-validation, and confirmed-vulnerability claims.
- `git diff --check`: passed.
- `git diff --cached --check`: passed.

## Regression Notes

- No frontend runtime changed.
- No backend runtime changed.
- No API, cookie, session, CSRF, `401`, `403`, `429`, or `Retry-After` contract changed.
- No new tests were required because the existing backend and frontend regression suites covered the final Pathing C state.
- No admin recovery was added.
- No trusted-proxy runtime behavior was added.
- No secure-cookie runtime enforcement was added.
- No Docker execution was used.
- No Nmap, Active expansion, probes, DNS, or external traffic were used.
- No `.env`, `.env.*`, or `.envrc` files were read.

## Residual Gaps Before Release Candidate

- Admin recovery/setup guidance remains pending.
- Secure-cookie runtime enforcement remains pending.
- Trusted-proxy runtime enforcement remains pending.
- Public/community anti-abuse remains pending.
- Session/key rotation remains pending.
- Local/offline operator tooling remains pending.
- Release candidate checklist remains pending.
- Tag/release/push remains pending.
- Active/Nmap/CVE expansion remains pending under separate docs-first, opt-in, bounded design.

## Next Recommendation

```text
PASSIVE-ALPHA-RELEASE-CANDIDATE-CHECKLIST
```

## Final Decision

```text
PASSIVE_ALPHA_PERSISTENT_AUTH_FINAL_REGRESSION_SMOKE_PASSED
```

Pathing C has a final green regression record across backend compile, backend focused persistent-auth smoke, backend full suite, frontend App suite, frontend full suite, frontend build, browser-storage search, no-scope search, and diff checks.
