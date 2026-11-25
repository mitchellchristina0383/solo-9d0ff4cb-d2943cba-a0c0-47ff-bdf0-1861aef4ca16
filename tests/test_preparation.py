"""启动样例准备的行为测试：沿用 / 补齐 / 重建 / 失败保现场 / 健康探针。"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys

import pytest

from app import preparation
from app.app import create_app
from scripts.generate_samples import generate as generate_good_samples

ROOT = pathlib.Path(__file__).resolve().parent.parent
CLI = ROOT / "scripts" / "prepare_samples.py"


def _sha(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture(scope="session")
def good_baseline(tmp_path_factory) -> pathlib.Path:
    base = tmp_path_factory.mktemp("good_baseline") / "samples"
    generate_good_samples(base)
    return base


@pytest.fixture()
def samples(good_baseline, tmp_path, monkeypatch):
    """每个用例一份独立样例目录，并把环境变量 / 状态标记指向临时位置。"""
    dst = tmp_path / "samples"
    shutil.copytree(good_baseline, dst)
    status_file = tmp_path / "run" / "prepare-status.json"
    monkeypatch.setenv("SAMPLES_DIR", str(dst))
    monkeypatch.setenv("PREPARE_STATUS_FILE", str(status_file))
    monkeypatch.setattr(preparation, "FALLBACK_STATUS_PATH", tmp_path / "fallback.json")
    return dst


@pytest.fixture()
def status_file(tmp_path, monkeypatch):
    path = tmp_path / "run" / "prepare-status.json"
    monkeypatch.setenv("PREPARE_STATUS_FILE", str(path))
    monkeypatch.setattr(preparation, "FALLBACK_STATUS_PATH", tmp_path / "fallback.json")
    return path


def test_missing_dir_is_generated_and_planable(tmp_path, monkeypatch, status_file):
    target = tmp_path / "fresh" / "samples"
    monkeypatch.setenv("SAMPLES_DIR", str(target))
    result = preparation.prepare_samples(target)

    assert result["status"] == "ok", result
    assert result["mode"] == "generated"
    assert status_file.is_file()

    data = json.loads((target / "sample.json").read_text(encoding="utf-8"))
    ok, _, steps = preparation.evaluate_sample(data)
    assert ok and steps >= 1

    expected = [
        "sample.json",
        "bundles/old-bundle.pem",
        "bundles/new-bundle.pem",
        "bundles/union-bundle.pem",
        "roots/old-root.pem",
        "roots/new-root.pem",
        "intermediates/old-intermediate.pem",
        "intermediates/new-intermediate.pem",
        "replicas/svc-a/old-chain.pem",
        "replicas/svc-a/new-chain.pem",
        "replicas/svc-b/old-chain.pem",
        "replicas/svc-b/new-chain.pem",
        "replicas/svc-c/old-chain.pem",
        "replicas/svc-c/new-chain.pem",
    ]
    for rel in expected:
        assert (target / rel).is_file(), rel


def test_restart_keeps_certs_and_reports_all_unchanged(samples):
    first = preparation.prepare_samples(samples)
    assert first["status"] == "ok" and first["mode"] == "kept", first
    assert all(c["action"] == "unchanged" for c in first["changes"]), first["changes"]

    sample_hash = _sha(samples / "sample.json")
    pem_hashes = {
        str(p.relative_to(samples)): _sha(p)
        for p in samples.rglob("*.pem")
    }

    # 模拟 docker compose restart：再跑一次准备
    second = preparation.prepare_samples(samples)
    assert second["status"] == "ok" and second["mode"] == "kept"
    assert _sha(samples / "sample.json") == sample_hash
    for rel, digest in pem_hashes.items():
        assert _sha(samples / rel) == digest, f"重启后证书被改动: {rel}"


def test_missing_and_corrupt_pems_are_restored_from_sample_json(samples):
    data = json.loads((samples / "sample.json").read_text(encoding="utf-8"))

    # 值班员备份的旧根包；删掉目录里的旧根包
    backup_old_bundle = (samples / "bundles" / "old-bundle.pem").read_bytes()
    (samples / "bundles" / "old-bundle.pem").unlink()

    # 整个副本目录丢失
    shutil.rmtree(samples / "replicas" / "svc-a")

    # 另一个副本的新链与根证书被写坏
    (samples / "replicas" / "svc-b" / "new-chain.pem").write_text(
        "-----BEGIN CERTIFICATE-----\nGARBAGE\n-----END CERTIFICATE-----\n"
    )
    (samples / "roots" / "old-root.pem").write_text("corrupt")

    result = preparation.prepare_samples(samples)
    assert result["status"] == "ok", result
    assert result["mode"] == "kept"

    # 备份根包与补齐后的文件逐字节一致 —— “备下的根包仍验得过链”
    assert (samples / "bundles" / "old-bundle.pem").read_bytes() == backup_old_bundle
    assert (samples / "replicas" / "svc-a" / "old-chain.pem").read_text() == data[
        "replicas"
    ][0]["old_chain"]
    assert (samples / "replicas" / "svc-a" / "new-chain.pem").read_text() == data[
        "replicas"
    ][0]["new_chain"]
    assert (samples / "replicas" / "svc-b" / "new-chain.pem").read_text() == data[
        "replicas"
    ][1]["new_chain"]

    repaired = json.loads((samples / "sample.json").read_text(encoding="utf-8"))
    ok, _, steps = preparation.evaluate_sample(repaired)
    assert ok and steps == 9


def test_invalid_json_triggers_regeneration(samples):
    (samples / "sample.json").write_text("{ this is not json", encoding="utf-8")
    result = preparation.prepare_samples(samples)
    assert result["status"] == "ok", result
    assert result["mode"] == "regenerated"
    data = json.loads((samples / "sample.json").read_text(encoding="utf-8"))
    ok, _, _ = preparation.evaluate_sample(data)
    assert ok


def test_hard_infeasible_material_triggers_regeneration(samples):
    data = json.loads((samples / "sample.json").read_text(encoding="utf-8"))
    for batch in data["batches"]:
        batch["new_bundle"] = batch["old_bundle"]  # 目标态必坏
    (samples / "sample.json").write_text(
        json.dumps(data, ensure_ascii=False), encoding="utf-8"
    )

    result = preparation.prepare_samples(samples)
    assert result["status"] == "ok", result
    assert result["mode"] == "regenerated"
    fresh = json.loads((samples / "sample.json").read_text(encoding="utf-8"))
    ok, _, _ = preparation.evaluate_sample(fresh)
    assert ok
    # 重新签发后是新 PKI，新根包不应再等于旧根包
    assert fresh["batches"][0]["new_bundle"] != fresh["batches"][0]["old_bundle"]


def test_prepare_failure_keeps_usable_sample_and_health_503(samples, status_file):
    preparation.prepare_samples(samples)
    sample_bytes = (samples / "sample.json").read_bytes()

    # 用普通文件挡住 replicas 目录，纠正 PEM 必然失败（root 也绕不过 ENOTDIR 语义）
    shutil.rmtree(samples / "replicas")
    (samples / "replicas").write_text("blocker", encoding="utf-8")

    result = preparation.prepare_samples(samples)
    assert result["status"] == "error"
    assert result["error"]

    # 仍可用的 sample.json 原样保留
    assert (samples / "sample.json").read_bytes() == sample_bytes
    marker = json.loads(status_file.read_text(encoding="utf-8"))
    assert marker["status"] == "error"
    assert preparation.health_status()[0] == 503

    # Web 仍可读取 sample.json，但健康检查不放行
    app = create_app()
    client = app.test_client()
    assert client.get("/api/health").status_code == 503
    sample_resp = client.get("/api/sample")
    assert sample_resp.status_code == 200

    # 排除故障后用原目录再准备 -> 成功、沿用原证书、健康恢复
    (samples / "replicas").unlink()
    recovered = preparation.prepare_samples(samples)
    assert recovered["status"] == "ok" and recovered["mode"] == "kept", recovered
    assert (samples / "sample.json").read_bytes() == sample_bytes
    assert preparation.health_status()[0] == 200
    assert client.get("/api/health").status_code == 200


def test_health_without_marker_uses_structural_check(tmp_path, monkeypatch):
    target = tmp_path / "s"
    target.mkdir()
    monkeypatch.setenv("SAMPLES_DIR", str(target))
    marker = tmp_path / "no-marker.json"
    monkeypatch.setenv("PREPARE_STATUS_FILE", str(marker))
    monkeypatch.setattr(preparation, "FALLBACK_STATUS_PATH", tmp_path / "fb.json")

    app = create_app()
    client = app.test_client()
    assert client.get("/api/health").status_code == 503

    generate_good_samples(target)
    assert client.get("/api/health").status_code == 200
    assert client.get("/healthz").status_code == 200
    assert client.get("/health").status_code == 200


def test_cli_exit_codes(samples):
    env = dict(os.environ)
    # conftest / 手动运行时依赖都在 PYTHONPATH 上
    env["PYTHONPATH"] = str(ROOT) + os.pathsep + env.get("PYTHONPATH", "")

    ok = subprocess.run(
        [sys.executable, str(CLI), str(samples)],
        capture_output=True,
        text=True,
        env=env,
    )
    assert ok.returncode == 0, ok.stderr + ok.stdout

    shutil.rmtree(samples / "bundles")
    (samples / "bundles").write_text("blocker")
    bad = subprocess.run(
        [sys.executable, str(CLI), str(samples)],
        capture_output=True,
        text=True,
        env=env,
    )
    assert bad.returncode == 1, bad.stdout
    assert '"status": "error"' in bad.stdout


def test_prepared_sample_solves_via_http(samples, status_file):
    preparation.prepare_samples(samples)
    app = create_app()
    client = app.test_client()

    payload = client.get("/api/sample").get_json()
    payload["max_transition"] = 3
    resp = client.post("/api/plan", json=payload)
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "plan"
    assert data["steps_count"] == 9


def test_marker_defaults_next_to_explicit_target(tmp_path, monkeypatch, good_baseline):
    target = tmp_path / "explicit"
    shutil.copytree(good_baseline, target)
    elsewhere = tmp_path / "served-dir"
    elsewhere.mkdir()
    # SAMPLES_DIR 与显式 target 不同，且未设 PREPARE_STATUS_FILE
    monkeypatch.setenv("SAMPLES_DIR", str(elsewhere))
    monkeypatch.delenv("PREPARE_STATUS_FILE", raising=False)
    monkeypatch.setattr(preparation, "FALLBACK_STATUS_PATH", tmp_path / "fb.json")

    result = preparation.prepare_samples(target)
    assert result["status"] == "ok"
    assert (target / ".prepare-status.json").is_file()
    assert not (elsewhere / ".prepare-status.json").exists()

