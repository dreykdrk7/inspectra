FROM python:3.12-slim@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

ARG INSPECTRA_DEBIAN_SNAPSHOT=20260824T000000Z

RUN printf '%s\n' 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/99inspectra-snapshot \
    && sed -i \
      -e "s|http://deb.debian.org/debian-security|https://snapshot.debian.org/archive/debian-security/${INSPECTRA_DEBIAN_SNAPSHOT}|" \
      -e "s|http://deb.debian.org/debian|https://snapshot.debian.org/archive/debian/${INSPECTRA_DEBIAN_SNAPSHOT}|" \
      /etc/apt/sources.list.d/debian.sources \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
      file \
      libimage-exiftool-perl \
      poppler-utils \
      qpdf \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 1000 appuser

COPY requirements.lock /tmp/requirements.lock
RUN pip install --no-cache-dir -r /tmp/requirements.lock

COPY runner /app/runner

USER appuser

EXPOSE 8081

CMD ["uvicorn", "runner.main:app", "--host", "0.0.0.0", "--port", "8081"]
