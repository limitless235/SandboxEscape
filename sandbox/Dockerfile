FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/opt/sandbox

RUN useradd --uid 65532 --home-dir /nonexistent --shell /usr/sbin/nologin --no-create-home sandbox \
    && mkdir -p /workspace /opt/sandbox \
    && chown sandbox:sandbox /workspace /opt/sandbox

COPY sandbox_server.py /opt/sandbox/sandbox_server.py
COPY entrypoint.sh /opt/sandbox/entrypoint.sh
COPY workspace/ /opt/sandbox/workspace-seed/

RUN chmod 755 /opt/sandbox/entrypoint.sh \
    && chmod 644 /opt/sandbox/sandbox_server.py \
    && chown -R sandbox:sandbox /opt/sandbox /workspace

USER 65532:65532
WORKDIR /workspace
EXPOSE 8080
ENTRYPOINT ["/opt/sandbox/entrypoint.sh"]
