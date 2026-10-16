# Custom analyzer for Azure Container Apps. The MCR presidio-analyzer image is not used.
# Base and dependencies are digest-pinned or hash-locked.

FROM python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PRESIDIO_BIND=127.0.0.1 \
    PRESIDIO_PORT=3000 \
    PRESIDIO_SCORE_THRESHOLD=0.4 \
    PRESIDIO_RECOGNIZERS=/app/recognizers.yaml \
    PRESIDIO_SPACY_MODEL=en_core_web_lg \
    HOME=/tmp

RUN groupadd --gid 65532 app \
    && useradd --uid 65532 --gid 65532 --create-home --shell /usr/sbin/nologin app

WORKDIR /app
COPY requirements.txt requirements-presidio.txt ./
COPY deploy/presidio /app/presidio
COPY config/recognizers.yaml /app/recognizers.yaml
RUN python -m pip install --require-hashes -r requirements.txt -r requirements-presidio.txt \
    && chown -R 65532:65532 /app

USER 65532:65532
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --start-period=120s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:3000/health', timeout=3)"]
CMD ["python", "-m", "presidio.serve"]
