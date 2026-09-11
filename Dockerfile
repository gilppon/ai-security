FROM python:3.12-slim@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN groupadd --system aisec \
    && useradd --system --gid aisec --home-dir /nonexistent --shell /usr/sbin/nologin aisec

COPY pyproject.toml README.md ./
COPY app ./app
COPY api ./api
COPY agent_security ./agent_security
COPY content_security ./content_security
COPY core ./core
COPY detection ./detection
COPY execution ./execution
COPY input_security ./input_security
COPY output_security ./output_security
COPY policy ./policy
COPY resource_security ./resource_security
COPY runtime ./runtime
COPY secret_detection ./secret_detection
COPY telemetry ./telemetry

RUN python -m pip install --no-cache-dir .

USER aisec

EXPOSE 8000

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/v1/health', timeout=2).read()"]

CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
