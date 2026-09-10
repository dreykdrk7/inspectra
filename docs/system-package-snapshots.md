# System package snapshots

The Python runtime image is pinned by digest and the two images that install
Debian packages (`tools` and `active-tools`) also use the immutable Debian
snapshot `20260824T000000Z`. This pins direct and transitive APT resolutions
without replacing Debian archive signature verification.

Archived Debian `Release` metadata expires by design, so the Dockerfiles disable
only APT's freshness check through `99inspectra-snapshot`. They continue to use
the Debian archive key already present in the pinned base image. Do not replace
the snapshot URLs with mutable mirrors or disable signature checks.

At this snapshot, controlled rebuilds on the pinned `python:3.12-slim` base are
expected to resolve these direct packages:

| Image | Package | Expected version |
| --- | --- | --- |
| `audit-tools` | `file` | `1:5.46-5` |
| `audit-tools` | `libimage-exiftool-perl` | `13.25+dfsg-1` |
| `audit-tools` | `poppler-utils` | `25.03.0-5+deb13u4` |
| `audit-tools` | `qpdf` | `12.2.0-1` |
| `active-tools` | `nmap` | `7.95+dfsg-3` |

## Updating the snapshot

Updating this timestamp is a security maintenance change, not a routine build
fix. First review relevant Debian security advisories and the release metadata
from [Debian Snapshot](https://snapshot.debian.org/). Choose one timestamp that
contains both `debian` and `debian-security` suites, then update the argument in
both Dockerfiles and this table in one change. Build with `--no-cache`, check
the installed versions with `dpkg-query -W`, run the project validations, and
record any package version change in the pull request.

For example, after a deliberate update:

```bash
docker build --no-cache -t inspectra-audit-tools:system-snapshot tools
docker run --rm --entrypoint dpkg-query inspectra-audit-tools:system-snapshot -W file libimage-exiftool-perl poppler-utils qpdf

docker build --no-cache -f docker/active-tools/Dockerfile -t inspectra-active-tools:system-snapshot .
docker run --rm --entrypoint dpkg-query inspectra-active-tools:system-snapshot -W nmap
```
