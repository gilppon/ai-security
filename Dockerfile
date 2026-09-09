FROM python:3.12-slim

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

CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
