# Inspectra Security Scope

## Intended Use

Inspectra is for defensive, educational, and authorized local security audits. The MVP is limited to files that the user intentionally uploads, starting with PDF metadata and validation checks.

Use Inspectra only on files, domains, systems, or services that you own or are explicitly authorized to assess.

## Current MVP Scope

Allowed in this phase:

- Uploading local PDF files.
- Extracting PDF metadata.
- Calculating cryptographic hashes.
- Running passive PDF validation.
- Listing and deleting locally uploaded PDFs.
- Storing local JSON audit results.

Tools used in this phase:

- `pdfinfo`
- `exiftool`
- `qpdf --check`
- `file`

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

These exclusions are intentional. Inspectra should evolve carefully and keep each new capability scoped, documented, and defensive.

## Data Handling

Uploaded files are stored locally under `data/uploads`. Results are stored under `data/results/jobs`. Do not upload confidential files unless you accept this local storage behavior.

Audit results may include document metadata such as author names, producer strings, timestamps, paths, or other embedded values. Treat results as potentially sensitive.

Deleting a file through `DELETE /files/{file_id}` removes the uploaded source PDF and its file metadata. It does not delete historical job results; associated jobs are marked so it is clear that the source file is no longer present.

The backend limits uploads with `INSPECTRA_MAX_UPLOAD_BYTES`, defaulting to 20 MB. This is a usability and resource guardrail, not content sanitization.

## Container Boundary

External audit tools run in the `audit-tools` container, not on the host and not in the backend container. The MVP also avoids mounting the Docker socket into the backend.

The container boundary reduces host exposure, but it is not a perfect sandbox. Parser bugs in PDF tooling are still possible, so the tool container is constrained with:

- Internal-only Compose networking.
- Read-only root filesystem.
- Read-only access to `data/`.
- Dropped Linux capabilities.
- `no-new-privileges`.
- Temporary storage limited to `/tmp`.
- Per-tool command timeouts through `INSPECTRA_TOOL_TIMEOUT_SECONDS`, defaulting to 10 seconds.

## Operational Guidance

- Keep Docker and base images patched.
- Rebuild images after dependency updates.
- Review tool additions before enabling them.
- Prefer passive checks.
- Add timeouts to every external command.
- Do not add network scanners or exploit frameworks in this phase.
