# Inspectra Security Scope

## Intended Use

Inspectra is for defensive, educational, and authorized local security audits. The MVP is limited to files that the user intentionally uploads, starting with PDF/image metadata checks and dependency manifest review.

Use Inspectra only on files, domains, systems, or services that you own or are explicitly authorized to assess.

## Current MVP Scope

Allowed in this phase:

- Uploading local PDF files.
- Uploading local JPEG, PNG, and WebP images.
- Uploading local dependency manifests named `package.json`, `requirements.txt`, or `pyproject.toml`.
- Extracting PDF metadata.
- Extracting image metadata.
- Parsing dependency manifests as local text.
- Extracting declared dependencies, scripts, engines, and basic project metadata from supported manifests.
- Recording informational dependency indicators such as lifecycle scripts, unpinned requirements, broad ranges, and URL/VCS/local dependency references.
- Calculating cryptographic hashes.
- Running passive PDF validation.
- Listing and deleting locally uploaded PDFs, images, and manifests.
- Storing local JSON audit results.
- Exporting local reports from stored job JSON as Markdown, HTML, XML, and PDF.
- Using the local web UI to perform the same API actions.

Tools used in this phase:

- `pdfinfo`
- `exiftool`
- `qpdf --check`
- `file`

For images, Inspectra uses `file` and `exiftool` passively. It records informational privacy indicators when metadata suggests GPS data, author/creator values, serial numbers, device information, or software/toolchain information.

For manifests, Inspectra uses local Python parsing. It does not install dependencies, resolve transitive dependencies, run package managers, run project scripts, or call external vulnerability services. Findings are heuristic indicators for review, not confirmed vulnerabilities.

## Out of Scope

The MVP does not include:

- Exploit execution.
- Vulnerability exploitation.
- Network scanning.
- Internet-wide enumeration.
- Brute force checks.
- Credential attacks.
- Malware detonation.
- Fuzzing.
- Aggressive automation against external services.
- Image rendering, conversion, detonation, or embedded-content execution.
- Installing dependencies from uploaded manifests.
- Running npm, pip, Poetry, pnpm, yarn, or package lifecycle scripts against uploaded manifests.
- External CVE, advisory, package registry, or vulnerability database lookups.
- Claiming a heuristic dependency signal is a confirmed vulnerability.

These exclusions are intentional. Inspectra should evolve carefully and keep each new capability scoped, documented, and defensive.

## Data Handling

Uploaded files are stored locally under `data/uploads`. Results are stored under `data/results/jobs`. Do not upload confidential files unless you accept this local storage behavior.

Audit results may include document metadata such as author names, producer strings, timestamps, paths, or other embedded values. Treat results as potentially sensitive.

Deleting a file through `DELETE /files/{file_id}` removes the uploaded source file and its metadata. It does not delete historical job results; associated jobs are marked so it is clear that the source file is no longer present.

The backend limits uploads with `INSPECTRA_MAX_UPLOAD_BYTES`, defaulting to 20 MB. This is a usability and resource guardrail, not content sanitization.

The frontend does not add authentication or authorization. Run Inspectra only on trusted local development machines or behind controls you manage.

Image analysis does not render previews in this phase. Uploaded images are treated as local files for passive metadata and identification only.

Manifest analysis does not execute project code or package scripts. Uploaded manifests are treated as local text inputs for extraction and reporting only.

Report exports are generated locally from existing job results. The generated HTML is static, self-contained, and does not include JavaScript or external CSS. Inspectra escapes dynamic content before writing HTML and XML reports. Exporting a report does not execute uploaded files, manifest scripts, or result content.

## Container Boundary

External audit tools run in the `audit-tools` container, not on the host and not in the backend container. The MVP also avoids mounting the Docker socket into the backend.

The container boundary reduces host exposure, but it is not a perfect sandbox. Parser bugs in file tooling are still possible, so the tool container is constrained with:

- Internal-only Compose networking.
- Read-only root filesystem.
- Read-only access to `data/`.
- Dropped Linux capabilities.
- `no-new-privileges`.
- Temporary storage limited to `/tmp`.
- Per-tool command timeouts through `INSPECTRA_TOOL_TIMEOUT_SECONDS`, defaulting to 10 seconds.
- Explicit development CORS origins through `INSPECTRA_CORS_ORIGINS`.

## Operational Guidance

- Keep Docker and base images patched.
- Rebuild images after dependency updates.
- Review tool additions before enabling them.
- Prefer passive checks.
- Add timeouts to every external command.
- Do not add network scanners or exploit frameworks in this phase.
