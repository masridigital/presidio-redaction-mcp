FROM python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PRM_ADMIN_BIND=127.0.0.1 \
    PRM_ADMIN_PORT=8080

RUN groupadd --gid 65532 app \
    && useradd --uid 65532 --gid 65532 --create-home --shell /usr/sbin/nologin app \
    && mkdir -p /app /data/store \
    && chown -R 65532:65532 /app /data/store

WORKDIR /app
COPY pyproject.toml ./
COPY src ./src
COPY admin/presidio_admin ./admin/presidio_admin
RUN pip install --no-cache-dir .

USER 65532:65532
EXPOSE 8080
CMD ["python", "-m", "presidio_admin"]
