# infocon-auto: one small container that fetches the feeds every 30 minutes
# and serves the dashboard, JSON, badge and status.txt on port 8377.
FROM python:3.14-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    INFOCON_DATA_DIR=/data \
    INFOCON_SITE_DIR=/data/site \
    INFOCON_HOST=0.0.0.0 \
    INFOCON_PORT=8377 \
    INFOCON_INTERVAL=30 \
    INFOCON_BACKFILL_DAYS=75

WORKDIR /app
COPY infocon/ infocon/

# Standard library only, so there is nothing to install. Run unprivileged;
# everything the app writes (feed cache, history, the published site) is in /data.
RUN useradd --system --uid 10001 --no-create-home infocon \
    && mkdir /data && chown infocon:infocon /data
USER infocon
VOLUME /data
EXPOSE 8377

HEALTHCHECK --interval=1m --timeout=10s --start-period=15s --retries=3 \
    CMD ["python", "-c", "import os, urllib.request as u; u.urlopen('http://127.0.0.1:' + os.environ['INFOCON_PORT'] + '/', timeout=5)"]

CMD ["python", "-m", "infocon", "serve"]
