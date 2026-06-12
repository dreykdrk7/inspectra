# syntax=docker/dockerfile:1
#
# Inspectra active-tools scaffold.
# This image is intentionally not wired into runtime yet. It packages only the
# minimum future Active tooling boundary for active_nmap_basic and must not run
# Nmap at build time.

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

WORKDIR /app

# Future packaging path: install only Nmap and its package-managed runtime
# dependencies. Do not add broad scanners, brute-force tools, exploit tooling,
# credential tooling, crawlers, or custom NSE/script enablement here.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
      nmap \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 1000 appuser

# Keep Active code separate from the passive runner monolith.
# Copy only the isolated Active runner package into this image.
COPY tools/active_runner /app/active_runner

USER appuser

# No port, no HTTP endpoint, no target probe, and no Nmap execution in this
# scaffold. This command only reports scaffold readiness and binary presence if
# a later phase explicitly starts the container.
CMD ["python", "-c", "import json, shutil; print(json.dumps({'service':'active-tools','mode':'scaffold_no_run','nmap_present': shutil.which('nmap') is not None}))"]
