# node_package_config_basic Design

Status: implemented v1 / historical design reference. The runner analyzer, backend job, reporting/exports, frontend action, and report UI were implemented across commits `2a98d63`, `86f6203`, and `bfe29a9`; this document remains the design baseline and should not be read as the current runtime manual.

## 1. Module Objective

`node_package_config_basic` is a passive archive-based audit type for reviewing Node.js, JavaScript, and TypeScript package configuration supplied by the user. It should help Inspectra users identify package-management and build-configuration indicators that deserve manual review before installing dependencies, publishing a package, or deploying an application.

The module should detect review signals such as lifecycle scripts, shell/remote-code script patterns, broad dependency ranges, URL/Git/file/workspace dependency references, multiple lockfiles, package-manager config risks, publishing metadata, and basic framework/build-tool configuration hints.

The module should not prove malicious behavior, confirm vulnerabilities, install packages, run package managers, resolve transitive dependencies, query registries, call advisory services, or execute JavaScript/TypeScript. Findings must remain heuristic indicators for manual validation.

This module is useful for Inspectra because uploaded project archives commonly include `package.json`, lockfiles, package-manager config, bundler config, and CI workflows. A bounded local review can give useful supply-chain hygiene signals while preserving Inspectra's passive, no-execution, no-network MVP model.

## 2. Allowed Scope

The initial module should accept only uploaded archives already registered as `kind: "archive"`. It should reuse the same archive safety posture as existing archive-based modules:

- open ZIP/TAR/TAR.GZ/TGZ archives with Python standard library parsers;
- inspect archive metadata defensively;
- read only bounded candidate text files into memory;
- avoid broad extraction to the filesystem;
- skip path traversal entries, absolute paths, symlinks, hardlinks, non-regular files, oversized files, entry-heavy archives, and files beyond configured limits;
- detect real `.env`, `.env.*`, and `.envrc` files if encountered, but do not read their content;
- parse `package.json` and safe local config formats heuristically;
- never execute package managers, lifecycle scripts, JavaScript, TypeScript, shell scripts, or config files;
- never query npm, pnpm, Yarn, Bun, GitHub, OSV, Snyk, npm audit, CVE feeds, or any external service.

The analysis should be textual plus local structured parsing where safe:

- JSON parsing for `package.json`, `package-lock.json`, and JSON config files when bounded and valid;
- line-oriented text parsing for `.npmrc`, lockfiles, shell-like script strings, and JavaScript/TypeScript config files;
- YAML/TOML-style parsing only if a safe local parser is already available in the project; otherwise use conservative bounded text heuristics.

The module may reuse manifest parsing ideas from `manifest_basic` and `project_archive_basic`, but it should be a configuration review rather than a dependency inventory or SBOM generator.

## 3. Candidate Files

The module should classify candidate files conservatively and keep reads bounded.

Package manifests and lockfiles:

- `package.json`
- `package-lock.json`
- `npm-shrinkwrap.json`
- `pnpm-lock.yaml`
- `yarn.lock`
- `bun.lock`
- `bun.lockb` detected as a lockfile but likely skipped as binary/non-text

Package-manager and workspace config:

- `.npmrc`
- `.yarnrc`
- `.yarnrc.yml`
- `pnpm-workspace.yaml`
- `lerna.json`
- `turbo.json`
- `nx.json`
- `rush.json`

JavaScript and TypeScript config:

- `tsconfig.json`
- `tsconfig.*.json`
- `vite.config.*`
- `webpack.config.*`
- `rollup.config.*`
- `next.config.*`
- `nuxt.config.*`
- `eslint.config.*`
- `.eslintrc*`
- `jest.config.*`
- `vitest.config.*`

CI and package publishing hints:

- `.github/workflows/*.yml`
- `.github/workflows/*.yaml`
- `.gitlab-ci.yml`
- `package.json` `publishConfig`
- Changesets config paths such as `.changeset/config.json`
- Release config files if present, such as `.releaserc`, `.releaserc.json`, and `release.config.*`

Environment files:

- real `.env`, `.env.*`, and `.envrc` files should be detected as sensitive files and not read;
- environment templates such as `.env.example`, `.env.template`, `.env.sample`, `env.example`, `env.template`, and `sample.env` may be read only if needed for package config context, with redaction.

The exact first implementation can start with a smaller subset, but it should keep the same contract: explicit archive input, bounded reads, no execution, no registry access, and defensive redaction.

## 4. Out Of Scope

The first implementation must explicitly exclude:

- `npm audit`, `pnpm audit`, `yarn npm audit`, Bun audit equivalents, OSV, Snyk, GitHub advisories, CVEs, and all advisory lookups;
- transitive dependency resolution;
- package installation;
- `npm`, `pnpm`, `yarn`, `bun`, `npx`, or package-manager execution;
- lifecycle script execution;
- JavaScript, TypeScript, build-tool, or config execution;
- downloading packages, resolving dist-tags, verifying package integrity against a registry, or contacting registries;
- reputation or malware checks for package names;
- Git history scanning;
- deep source-code security review;
- SBOM generation beyond existing `manifest_basic` and `project_archive_basic` outputs unless a later design explicitly extends SBOM behavior;
- deep secret scanning beyond delegating to `secrets_review_basic` or applying defensive redaction to package-config evidence;
- binary lockfile parsing beyond safe detection and skip reporting;
- classifying a package, dependency, script, or configuration as malicious or vulnerable.

## 5. Initial Finding Model

Finding IDs should be stable, conservative, and framed as review indicators.

Scripts and lifecycle:

- `lifecycle_script_present`: package manifest defines install-time or publish-time lifecycle scripts that deserve review.
- `postinstall_script_present`: `postinstall` script is present.
- `prepare_script_present`: `prepare` script is present.
- `install_script_present`: `install` or `preinstall` script is present.
- `script_runs_remote_code`: script appears to fetch or execute remote code.
- `script_uses_shell_curl_pipe`: script includes a curl/wget pipe-to-shell pattern.
- `script_references_env_secret_name`: script references sensitive-looking environment variable names.

Dependency declarations:

- `unpinned_dependency_range`: dependency uses a non-exact semver range.
- `broad_dependency_range`: dependency uses a broad range such as `>=1`, `*`, `latest`, or empty values.
- `wildcard_dependency_version`: dependency is declared as `*` or equivalent.
- `git_dependency_reference`: dependency points to a Git reference.
- `url_dependency_reference`: dependency points to an HTTP(S), tarball, or other URL reference.
- `file_dependency_reference`: dependency points to a local `file:` or path reference.
- `workspace_dependency_reference`: dependency uses `workspace:` references.
- `alias_dependency_reference`: dependency uses npm alias syntax such as `npm:real-package@version`.
- `bundled_dependencies_present`: package declares bundled dependencies.
- `optional_dependencies_present`: package declares optional dependencies that may deserve review.

Package metadata:

- `package_private_false_or_missing`: package is not clearly private, or `private` is missing where publication risk may matter.
- `publish_config_registry_present`: `publishConfig.registry` is declared.
- `package_manager_missing`: no `packageManager` field is declared.
- `engines_missing`: no `engines` field is declared.
- `engines_broad_or_old`: `engines` appears broad or outdated.
- `license_missing`: no license field is declared.
- `repository_missing`: no repository field is declared.

Package-manager config:

- `npmrc_token_reference_detected`: `.npmrc` includes token/auth-like configuration; values must be redacted.
- `npmrc_registry_override`: `.npmrc` or package config overrides registry.
- `npmrc_strict_ssl_disabled`: `.npmrc` sets `strict-ssl=false`.
- `npmrc_ignore_scripts_configured`: `.npmrc` sets `ignore-scripts`, recorded as a security-relevant behavior signal rather than inherently good or bad.
- `npmrc_unsafe_perm_enabled`: `.npmrc` sets `unsafe-perm=true`.

Lockfile and config consistency:

- `package_lock_present`: package lockfile detected.
- `multiple_lockfiles_present`: more than one ecosystem lockfile is present.
- `lockfile_missing_for_package_manager`: package manager hints exist but expected lockfile is absent.
- `package_manager_mismatch`: `packageManager` appears inconsistent with lockfiles.
- `lockfile_large_or_truncated`: lockfile was skipped or truncated due to limits.

Framework and build config:

- `next_config_unsafe_headers_hint`: Next.js config hints at broad/unsafe headers or rewrites that deserve review.
- `vite_dev_host_exposed_hint`: Vite config appears to expose dev server host broadly.
- `webpack_dev_server_exposed_hint`: webpack dev server config appears exposed or permissive.
- `tsconfig_skip_lib_check_hint`: `skipLibCheck` is enabled; informational hygiene signal only.
- `source_maps_enabled_hint`: production-like config appears to enable source maps.

No finding should call itself malicious, exploited, or vulnerable by default. Recommendations should say "review", "confirm", "consider", or "validate manually".

## 6. Severity And Context

Severity should be conservative:

- `medium`: strong script or package-manager config indicators such as curl/wget pipe-to-shell, install/prepare/postinstall scripts with remote-code patterns, `strict-ssl=false`, `unsafe-perm=true`, or token-like `.npmrc` values.
- `low`: lifecycle scripts that need review, URL/Git/file/workspace dependencies, wildcard or broad ranges, multiple lockfiles, package-manager mismatches, and registry overrides.
- `info`: missing metadata, optional dependencies, package-manager hints, lockfile presence, engines missing, private missing, and framework/build hints without strong production context.

Context should be captured per file when possible:

- `production`: paths or filenames containing `prod`, `production`, `deploy/prod`, or release/publish-oriented config.
- `shared`: root-level `package.json`, common lockfiles, or root package-manager config without dev/test/example markers.
- `development`: `dev`, `development`, local dev server config, or override files.
- `test`: `test`, `tests`, `testing`, Jest/Vitest config, or CI test-only paths.
- `local`: `local` paths or config names.
- `example`: `example`, `examples`, `sample`, `samples`, `template`, or `docs`.
- `ambiguous`: recognized candidates without enough context.

Development, test, local, and example contexts should downgrade severity or confidence. Production and shared contexts should preserve the default severity. The report should avoid implying that dev/test findings are production issues.

## 7. Redaction And Safe Evidence

Evidence must never show complete tokens or credentials. The module should reuse or adapt defensive redaction rules from `secrets_review_basic` where practical.

Redact at least:

- `.npmrc` `_authToken`, `_auth`, `_password`, `password`, `token`, `key`, `secret`, and auth-like values;
- registry URLs with credentials;
- script fragments that include sensitive environment assignments;
- query parameters such as `token`, `api_key`, `key`, `secret`, `password`, `code`, and similar;
- webhook or deployment URLs with obvious embedded credentials.

Allowed evidence examples:

- script name and redacted script excerpt, such as `postinstall: curl ... | sh`;
- dependency name and version specifier when the specifier is not secret-like;
- `.npmrc` key name with `[REDACTED]`;
- registry hostname without credentials;
- package manager name and lockfile names;
- file path, context, line number, and finding category.

Do not add prefixes, suffixes, fingerprints, hashes, or token validation metadata in v1. Raw JSON, future exports, and future UI reports should display redacted payloads.

## 8. Comments And Non-Executable Lines

JSON does not allow comments, but JavaScript, TypeScript, YAML, shell-like config, and lockfile formats may include comments. The initial parser should:

- ignore full-line comments before applying strong text heuristics;
- support at least `#`, `//`, and block-comment-safe conservative handling where simple;
- avoid parsing commented examples as strong findings;
- keep lower-severity notes only when commented examples are important enough for manual review;
- avoid a full JavaScript parser in v1.

Inline comments should be treated conservatively. If executable-looking content appears before the comment marker, analyze that content. If the signal appears only after the comment marker, avoid a strong finding.

## 9. Proposed JSON Result

The result should follow Inspectra's existing analyzer shape:

```json
{
  "analyzer": "node_package_config_basic",
  "archive_type": "zip",
  "hashes": {
    "sha256": "..."
  },
  "summary": {
    "files_considered": 0,
    "files_reviewed": 0,
    "package_manifests_detected": 0,
    "lockfiles_detected": 0,
    "package_manager_configs_detected": 0,
    "packages_detected": 0,
    "scripts_detected": 0,
    "findings_count": 0,
    "redacted_values_count": 0,
    "truncated": false
  },
  "limits": {
    "max_files": 100,
    "max_file_bytes": 524288,
    "max_total_bytes": 2097152
  },
  "files_detected": [],
  "files_reviewed": [],
  "packages": [],
  "scripts": [],
  "dependency_groups": [],
  "package_manager_config_signals": [],
  "lockfile_signals": [],
  "findings": [],
  "redaction_notes": [],
  "errors": [],
  "truncated": false
}
```

Potential field details:

- `files_detected`: path, category, context, read status, skip reason, bytes read if available.
- `packages`: package name, version, private flag, package manager hint, workspace hint, manifest path.
- `scripts`: script name, redacted excerpt, lifecycle category, file path, context.
- `dependency_groups`: group name such as dependencies/devDependencies/peerDependencies/optionalDependencies plus dependency indicators.
- `package_manager_config_signals`: `.npmrc`, Yarn, pnpm, or workspace config signals with redacted values.
- `lockfile_signals`: lockfile type, size/truncation status, package manager consistency hints.
- `findings`: id, title, level, confidence, category, context, file_path, line, description, evidence, recommendation.

Payloads should tolerate sparse or legacy fields in future backend/reporting/UI layers.

## 10. Expected UX And Reporting

Future UI and exports should emphasize:

- top-level summary with files reviewed, package manifests, lockfiles, scripts, package-manager config files, findings, redactions, and truncation;
- package/workspace overview;
- scripts review with lifecycle scripts clearly separated from ordinary scripts;
- findings grouped by severity, category, and context;
- dependency declaration indicators with dependency name and non-secret specifier;
- package-manager config signals with redacted auth data;
- lockfile consistency and multiple-lockfile signals;
- files reviewed, skipped, and detected;
- redaction notes;
- limits, truncation, and controlled errors;
- raw JSON as a secondary debug view, redacted.

Reports should make it clear that findings are package-configuration review indicators, not vulnerability or malware verdicts.

## 11. Future Tests

Runner/parser tests:

- `package.json` with `postinstall` produces `postinstall_script_present`.
- Script with curl/wget pipe-to-shell produces `script_uses_shell_curl_pipe`.
- Dependency `"*"` produces `wildcard_dependency_version`.
- Dependency ranges such as `^1.2.3`, `>=1`, or `latest` produce range findings according to the final policy.
- Git, URL, file, workspace, and alias dependencies produce their corresponding finding IDs.
- Multiple lockfiles produce `multiple_lockfiles_present`.
- `.npmrc` with `//registry/:_authToken=fixture-token` produces `npmrc_token_reference_detected` and does not store the token.
- `.npmrc` with `strict-ssl=false` produces `npmrc_strict_ssl_disabled`.
- `package.json` with `private: false` or missing `private` produces a review/info finding according to context.
- Missing `packageManager` produces an informational finding.
- Commented script/config examples do not produce strong findings.
- Development, test, local, and example contexts downgrade severity.
- Path traversal entries, absolute paths, symlinks, hardlinks, non-regular TAR entries, binary files, and oversized files are not read.
- File count, per-file byte, total byte, and archive entry limits mark truncation predictably.
- Serialized JSON result does not contain fixture secrets from `.npmrc` or script/config evidence.

Backend/reporting tests when implemented:

- endpoint accepts only archive files and creates `node_package_config_basic` jobs;
- summaries tolerate sparse results and include package/script/finding counts;
- Markdown/HTML/XML/PDF exports render findings, scripts, lockfile signals, and limits without leaking secrets;
- queued/running/failed/sparse jobs export without tracebacks.

Frontend tests when implemented:

- archive action appears only for archive files;
- report renders summary, package overview, scripts, dependency indicators, package-manager config, lockfiles, findings, redaction notes, limits, and raw JSON;
- sparse/legacy/malformed payloads do not break the report;
- redaction hides fixture secrets in visible report and raw JSON.

## 12. Proposed Implementation Microphases

1. Runner/parser passive analyzer:
   - add candidate classification;
   - parse bounded `package.json` and selected config text;
   - implement comment-aware text heuristics;
   - implement redaction-first evidence;
   - add runner tests.

2. Backend job integration and exports:
   - add `node_package_config_basic` audit type and `POST /audits/node-package-config/{file_id}` or similar endpoint;
   - accept only `kind: "archive"`;
   - add service delegation, storage summary, Markdown/HTML/XML/PDF reporting, redaction tests, and sparse job tests.

3. Frontend report UX:
   - add archive action;
   - add report helper/component;
   - group findings by severity/category/context;
   - show package overview, scripts, dependency declarations, lockfile signals, package-manager config signals, limits, redaction notes, errors, and redacted raw JSON.

4. End-to-end contract and redaction review:
   - review runner/backend/frontend field names;
   - verify no raw `.npmrc` tokens or secret-like values leak in results, exports, UI, or errors;
   - tighten labels, empty states, and sparse/legacy compatibility.

5. Documentation and smoke validation:
   - update README, architecture, and security scope;
   - document variables and limitations;
   - manually test a small archive with package manifests, lockfiles, `.npmrc`, and config examples.

## 13. Documentation Changes When Implemented

When `node_package_config_basic` is implemented, update:

- `README.md`
  - endpoint usage;
  - UI action;
  - supported archive source;
  - limits and variables;
  - passive/no-install/no-registry/no-CVE scope;
  - redaction and local storage caveats.

- `docs/architecture.md`
  - archive-based flow;
  - runner parsing model;
  - result schema;
  - relationship to `manifest_basic`, `project_archive_basic`, `secrets_review_basic`, and archive safety helpers.

- `docs/security-scope.md`
  - add allowed scope for passive Node package config review;
  - explicitly keep package-manager execution, package installation, registry access, advisory/CVE lookups, dependency resolution, lifecycle-script execution, and malicious-package verdicts out of scope;
  - document best-effort redaction and uploaded archive storage sensitivity.

- `docs/future/passive-config-audits-v1-closeout.md`
  - optionally create a v2 closeout or add a new closeout document after the Node module is implemented and reviewed end-to-end.

Runtime docs now describe the implemented v1 module in `README.md`, `docs/architecture.md`, and `docs/security-scope.md`.
