FROM python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

RUN groupadd --gid 65532 app \
    && useradd --uid 65532 --gid 65532 --create-home --shell /usr/sbin/nologin app \
    && mkdir -p /app /var/lib/presidio-redaction-mcp/audit \
    && chown -R 65532:65532 /app /var/lib/presidio-redaction-mcp

WORKDIR /app
COPY pyproject.toml ./
COPY src ./src
COPY config ./config
RUN pip install --no-cache-dir .

USER 65532:65532
EXPOSE 8443 8444
CMD ["python", "-m", "presidio_redaction_mcp"]
