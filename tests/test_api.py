"""Flask API 冒烟测试。"""

from __future__ import annotations

import json
import pathlib

import pytest

from app.app import create_app

SAMPLES = pathlib.Path(__file__).resolve().parent.parent / "samples_test"


@pytest.fixture(scope="module")
def client():
    app = create_app()
    app.testing = True
    return app.test_client()


@pytest.fixture()
def payload(sample_data):
    return json.loads(json.dumps(sample_data))  # 深拷贝，避免用例间污染


def test_index_renders(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert "根证书更换顺序规划".encode() in resp.data


def test_sample_api(client):
    resp = client.get("/api/sample")
    assert resp.status_code == 200
    data = resp.get_json()
    assert len(data["replicas"]) >= 1


def test_summaries_chain_and_bundle(client, payload):
    r = payload["replicas"][0]
    resp = client.post("/api/summaries", json={"kind": "chain", "pem": r["old_chain"]})
    data = resp.get_json()
    assert data["ok"] and data["summary"]["common_name"] == r["domain"]

    resp = client.post(
        "/api/summaries",
        json={"kind": "bundle", "pem": payload["batches"][0]["old_bundle"]},
    )
    assert resp.get_json()["ok"] and resp.get_json()["summary"]["count"] == 1

    resp = client.post("/api/summaries", json={"kind": "chain", "pem": "garbage"})
    assert resp.get_json()["ok"] is False


def test_plan_api_success(client, payload):
    resp = client.post("/api/plan", json=payload)
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["ok"] and data["status"] == "plan"
    assert data["steps_count"] >= 1
    assert data["plan"][0]["step_no"] == 1


def test_plan_api_quota_insufficient(client, payload):
    payload = dict(payload, max_transition=0)
    data = client.post("/api/plan", json=payload).get_json()
    assert data["ok"] and data["status"] == "insufficient_quota"
    assert data["min_required"] is not None


def test_plan_api_hard_infeasible(client, payload):
    for batch in payload["batches"]:
        batch["new_bundle"] = batch["old_bundle"]
    data = client.post("/api/plan", json=payload).get_json()
    assert data["ok"] and data["status"] == "hard_infeasible"
    assert data["target_violations"]


def test_plan_api_rejects_bad_input(client, payload):
    payload["replicas"][0]["new_chain"] = ""
    resp = client.post("/api/plan", json=payload)
    assert resp.status_code == 400

    resp = client.post("/api/plan", json={"replicas": [], "batches": []})
    assert resp.status_code == 400
