# syntax=docker/dockerfile:1@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32
#
# Inspectra active-tools scaffold.
# This image is intentionally not wired into runtime yet. It packages only the
# minimum future Active tooling boundary for active_nmap_basic and must not run
# Nmap at build time.

FROM python:3.12-slim@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

WORKDIR /app

ARG INSPECTRA_DEBIAN_SNAPSHOT=20260824T000000Z

# Future packaging path: install only Nmap and its package-managed runtime
# dependencies. Do not add broad scanners, brute-force tools, exploit tooling,
# credential tooling, crawlers, or custom NSE/script enablement here.
RUN printf '%s\n' 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/99inspectra-snapshot \
    && sed -i \
      -e "s|http://deb.debian.org/debian-security|https://snapshot.debian.org/archive/debian-security/${INSPECTRA_DEBIAN_SNAPSHOT}|" \
      -e "s|http://deb.debian.org/debian|https://snapshot.debian.org/archive/debian/${INSPECTRA_DEBIAN_SNAPSHOT}|" \
      /etc/apt/sources.list.d/debian.sources \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
      nmap \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 1000 appuser

# Install only the minimal ASGI runtime needed for an explicitly invoked
# no-live service smoke. The default scaffold command below remains no-run.
COPY docker/active-tools/requirements.lock /tmp/active-tools-requirements.lock
RUN pip install --no-cache-dir -r /tmp/active-tools-requirements.lock \
    && rm -f /tmp/active-tools-requirements.lock

# Keep Active code separate from the passive runner monolith.
# Copy only the isolated Active runner package into this image.
COPY tools/active_runner /app/active_runner
COPY backend/app/__init__.py /app/app/__init__.py
COPY backend/app/active_dns_inventory.py /app/app/active_dns_inventory.py
COPY backend/app/active_dns_osint.py /app/app/active_dns_osint.py
COPY backend/app/active_http_basic_header_review.py /app/app/active_http_basic_header_review.py
COPY backend/app/active_tls_basic.py /app/app/active_tls_basic.py

USER appuser

# No port, no HTTP endpoint, no target probe, and no Nmap execution in this
# scaffold. This command only reports scaffold readiness and binary presence if
# a later phase explicitly starts the container.
CMD ["python", "-c", "import json, shutil; print(json.dumps({'service':'active-tools','mode':'scaffold_no_run','nmap_present': shutil.which('nmap') is not None}))"]
