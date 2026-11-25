#!/usr/bin/env python3
"""容器 / 本机启动前的样例准备入口。

用法::

    python scripts/prepare_samples.py [samples_dir]

目录可由第一个参数或 ``SAMPLES_DIR`` 环境变量给出，默认仓库根下的
``samples/``。准备结果以 JSON 打印并写入状态标记（见
:mod:`app.preparation`）：

* 退出码 0：样例可用（沿用并对齐了 PEM，或重新生成了可用样例）；
* 退出码 1：准备失败，``/api/health`` 会返回 503；已可用的 sample.json
  不会被破坏，排除故障后用原目录重启本脚本即可。
"""

from __future__ import annotations

import json
import pathlib
import sys

# 直接 `python scripts/prepare_samples.py` 时 sys.path[0] 是 scripts/，
# 这里把仓库根补进去，保证能 import app.*。
_ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from app.preparation import (  # noqa: E402
    marker_path_for,
    prepare_samples,
    samples_dir,
    write_status,
)


def main(argv: list[str]) -> int:
    target = argv[1] if len(argv) >= 2 and argv[1].strip() else None
    target_path = pathlib.Path(target) if target else samples_dir()
    try:
        result = prepare_samples(target)
    except BaseException as exc:  # noqa: BLE001 - CLI 最后防线，必须落失败标记
        result = {
            "status": "error",
            "mode": "failed",
            "error": f"prepare_samples 异常退出：{type(exc).__name__}: {exc}",
        }
        try:
            write_status(result, marker_path_for(target_path))
        except Exception:  # noqa: BLE001
            pass
    print(json.dumps(result, ensure_ascii=False, indent=2))
    if result.get("status") != "ok":
        print(
            "[prepare_samples] 准备失败：" + str(result.get("error")),
            file=sys.stderr,
        )
        return 1
    print(f"[prepare_samples] {result.get('message')}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
