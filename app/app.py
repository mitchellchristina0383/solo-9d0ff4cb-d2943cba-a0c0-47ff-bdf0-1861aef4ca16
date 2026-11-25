"""Flask 入口：录入证书材料、调用求解器、展示变更顺序与诊断。"""

from __future__ import annotations

import json
import os
import pathlib

from flask import Flask, jsonify, render_template, request

from .certutil import PemError, bundle_summary, leaf_summary
from .planner import (
    BUNDLE_MODE_LABEL,
    CHAIN_LABEL,
    STATE_LABEL,
    build_planner,
)

BASE_DIR = pathlib.Path(__file__).resolve().parent.parent
SAMPLE_PATH = BASE_DIR / "samples" / "sample.json"


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["JSON_AS_ASCII"] = False

    @app.get("/")
    def index():  # pragma: no cover - 纯渲染
        sample = None
        if SAMPLE_PATH.exists():
            sample = json.loads(SAMPLE_PATH.read_text(encoding="utf-8"))
        return render_template(
            "index.html",
            sample=sample,
            state_labels=STATE_LABEL,
            chain_labels=CHAIN_LABEL,
            bundle_mode_labels=BUNDLE_MODE_LABEL,
        )

    @app.get("/api/sample")
    def get_sample():
        if not SAMPLE_PATH.exists():
            return jsonify({"error": "样例尚未生成，请先运行 generate_samples.py"}), 404
        return jsonify(json.loads(SAMPLE_PATH.read_text(encoding="utf-8")))

    @app.post("/api/summaries")
    def summaries():
        """返回粘贴 PEM 的概要，供页面即时确认材料是否解析成功。"""
        payload = request.get_json(force=True, silent=True) or {}
        kind = payload.get("kind")
        pem = payload.get("pem", "")
        try:
            if kind == "chain":
                return jsonify({"ok": True, "summary": leaf_summary(pem)})
            if kind == "bundle":
                return jsonify({"ok": True, "summary": bundle_summary(pem)})
            return jsonify({"ok": False, "error": "kind 须为 chain 或 bundle"}), 400
        except PemError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 200

    @app.post("/api/plan")
    def plan():
        payload = request.get_json(force=True, silent=True) or {}
        try:
            max_transition = int(payload.get("max_transition", 0))
        except (TypeError, ValueError):
            return jsonify({"ok": False, "error": "同时过渡批次上限须为整数"}), 400

        try:
            replica_rows = _collect_rows(
                payload.get("replicas", []), ("old_chain", "new_chain")
            )
            batch_rows = _collect_rows(
                payload.get("batches", []), ("old_bundle", "new_bundle")
            )

            if not replica_rows:
                return jsonify(
                    {"ok": False, "error": "至少需要 1 个服务副本"}
                ), 400
            if not batch_rows:
                return jsonify(
                    {"ok": False, "error": "至少需要 1 批终端"}
                ), 400
            if len(replica_rows) > 4 or len(batch_rows) > 4:
                return jsonify(
                    {"ok": False, "error": "副本与终端批次均最多 4 个"}
                ), 400

            planner = build_planner(replica_rows, batch_rows, max_transition)
            result = planner.solve()
        except PemError as exc:
            return jsonify({"ok": False, "error": f"PEM 解析失败: {exc}"}), 400
        except ValueError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400
        return jsonify(
            {
                "ok": True,
                "status": result.status,
                "message": result.message,
                "steps_count": result.steps_count,
                "max_transition": result.max_transition,
                "min_required": result.min_required,
                "plan": result.plan,
                "matrix": result.matrix,
                "initial_violations": result.initial_violations,
                "target_violations": result.target_violations,
                "blocker_pairs": result.blocker_pairs,
                "replica_names": [r.name for r in planner.replicas],
                "batch_names": [b.name for b in planner.batches],
                "state_labels": STATE_LABEL,
                "chain_labels": CHAIN_LABEL,
                "bundle_mode_labels": BUNDLE_MODE_LABEL,
            }
        )

    return app


def _collect_rows(rows: list[dict], required_pem_fields: tuple[str, ...]) -> list[dict]:
    """丢弃完全空白的行，并校验保留行的必填 PEM 字段非空。"""
    cleaned: list[dict] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        has_text = any(
            str(row.get(field, "")).strip() for field in required_pem_fields
        )
        has_name_or_domain = bool(
            str(row.get("domain", "")).strip() or str(row.get("name", "")).strip()
        )
        if not has_text and not has_name_or_domain:
            continue
        for field in required_pem_fields:
            if not str(row.get(field, "")).strip():
                raise PemError(
                    f"行「{row.get('name') or row.get('domain') or '?'}」"
                    f"缺少字段 {field}"
                )
        cleaned.append({k: str(v) for k, v in row.items() if v is not None})
    return cleaned


app = create_app()


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    app.run(host="0.0.0.0", port=port)
