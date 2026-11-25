#!/bin/sh
# 容器入口：
#   1) 先做样例准备（可用 sample.json -> 沿用并对齐 PEM；缺失/排不出 -> 重签）；
#   2) 无论准备成败都启动 gunicorn —— 成败写入状态标记，由 /api/health
#      决定容器健康检查是否通过；准备失败时容器保持运行但 unhealthy，
#      排除故障后 `docker compose restart` 会重跑本脚本恢复。
set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
APP_DIR=$(dirname "$SCRIPT_DIR")
cd "$APP_DIR" || exit 1

SAMPLES_DIR="${SAMPLES_DIR:-$APP_DIR/samples}"
export SAMPLES_DIR
# 容器内固定把状态标记放在可写的 /tmp（即使 samples 挂载目录只读/故障，
# 健康探针仍能读到 error 标记）。
PREPARE_STATUS_FILE="${PREPARE_STATUS_FILE:-/tmp/tls-plan-prepare-status.json}"
export PREPARE_STATUS_FILE

python "$SCRIPT_DIR/prepare_samples.py" "$SAMPLES_DIR"
rc=$?

if [ "$rc" -ne 0 ]; then
    # 兜底：prepare_samples 理论上一定会写 error 标记；若它整体崩溃，
    # 这里补一个，避免健康检查因“无标记 + 镜像内 sample.json 结构可读”而误判通过。
    python - <<'PY' || true
from app.preparation import read_status, write_status
st = read_status()
if not st or st.get("status") != "error":
    write_status({
        "status": "error",
        "mode": "failed",
        "error": "prepare_samples.py 异常退出，详见容器日志；排除故障后请重启容器。",
    })
PY
fi

exec gunicorn --bind "0.0.0.0:${PORT:-8000}" --workers 2 --timeout 60 app.app:app
