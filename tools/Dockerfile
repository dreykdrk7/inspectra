FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
      file \
      libimage-exiftool-perl \
      poppler-utils \
      qpdf \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 1000 appuser

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

COPY runner /app/runner

USER appuser

EXPOSE 8081

CMD ["uvicorn", "runner.main:app", "--host", "0.0.0.0", "--port", "8081"]
