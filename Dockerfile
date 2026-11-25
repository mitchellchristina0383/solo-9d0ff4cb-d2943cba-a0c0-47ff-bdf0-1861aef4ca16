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

ENV PYTHONUNBUFFERED=1 \
    PORT=8000

EXPOSE 8000

# 容器启动时确保样例存在（镜像已自带，这里保证挂载覆盖后仍可重建）
CMD ["sh", "-c", "python scripts/generate_samples.py samples || true; exec gunicorn --bind 0.0.0.0:${PORT} --workers 2 --timeout 60 app.app:app"]
