FROM python:3.11-slim

# openssl 是证书链核验的实际执行器；slim 镜像默认不带 CLI
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt gunicorn

COPY app ./app
COPY scripts ./scripts
COPY samples ./samples

RUN chmod +x /app/scripts/entrypoint.sh /app/scripts/prepare_samples.py

ENV PYTHONUNBUFFERED=1 \
    PORT=8000 \
    SAMPLES_DIR=/app/samples \
    PREPARE_STATUS_FILE=/tmp/tls-plan-prepare-status.json

EXPOSE 8000

# 入口先做“可沿用则不重签、缺件补齐、不可用才重建”的样例准备，
# 再启动 gunicorn；准备成败由 /api/health 结合状态标记反映。
CMD ["/app/scripts/entrypoint.sh"]
