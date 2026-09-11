FROM python:3.13.15-slim-bookworm@sha256:ed86c82274b3c69b52fb5820f358f0bd7df0b603332063cb5c6e32bd220c3e6e

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
