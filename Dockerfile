FROM python:3.13-alpine

LABEL org.opencontainers.image.source="https://github.com/feocco/homelab-log-watcher"
LABEL org.opencontainers.image.description="Docker log stream watcher for homelab phone alerts"

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY homelab_log_watcher /app/homelab_log_watcher

ENV LOG_WATCHER_STATE_PATH=/app/state/log-watcher-state.json
ENV LOG_WATCHER_IGNORED_CONTAINERS=homelab-log-watcher
ENV SERVICE_HOST=0.0.0.0
ENV SERVICE_PORT=8093

EXPOSE 8093

CMD ["python", "-m", "homelab_log_watcher"]
