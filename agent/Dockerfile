FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

WORKDIR /app
COPY agent /app/agent
RUN useradd --uid 65533 --shell /usr/sbin/nologin --create-home agent \
    && mkdir -p /app/audit \
    && chown -R agent:agent /app/audit

USER 65533:65533
CMD ["python3", "-m", "agent.main", "--mode", "benign"]
