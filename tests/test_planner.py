"""求解器端到端测试：使用脚本生成的真实 PKI 材料 + 本机 openssl 核验。"""

from __future__ import annotations

import pathlib

import pytest

from app.certutil import extract_certs, merge_pem_bundles, verify_chain
from app.planner import (
    NEW,
    OLD,
    TRANSITION,
    Planner,
    build_planner,
)
from scripts.generate_samples import REPLICA_DOMAINS


def _planner(rows, limit: int) -> Planner:
    return build_planner(rows["replicas"], rows["batches"], limit)


def test_samples_generated_with_expected_structure(sample_data):
    assert 1 <= len(sample_data["replicas"]) <= 4
    assert 1 <= len(sample_data["batches"]) <= 4
    for replica in sample_data["replicas"]:
        # 链文件含叶子 + 中间两张证书
        assert len(extract_certs(replica["old_chain"])) == 2
        assert len(extract_certs(replica["new_chain"])) == 2
    for batch in sample_data["batches"]:
        assert len(extract_certs(batch["old_bundle"])) == 1
        assert len(extract_certs(batch["new_bundle"])) == 1


def test_verify_chain_trust_anchor_and_hostname(sample_data):
    replica = sample_data["replicas"][0]
    domain = replica["domain"]
    old_bundle = sample_data["batches"][0]["old_bundle"]
    new_bundle = sample_data["batches"][0]["new_bundle"]
    union = merge_pem_bundles(old_bundle, new_bundle)

    # 旧链只被旧根信任
    assert verify_chain(replica["old_chain"], old_bundle, domain).ok
    assert not verify_chain(replica["old_chain"], new_bundle, domain).ok
    # 新链只被新根信任
    assert verify_chain(replica["new_chain"], new_bundle, domain).ok
    assert not verify_chain(replica["new_chain"], old_bundle, domain).ok
    # 并集同时信任两套链
    assert verify_chain(replica["old_chain"], union, domain).ok
    assert verify_chain(replica["new_chain"], union, domain).ok
    # 域名不匹配必须失败
    bad = verify_chain(replica["old_chain"], old_bundle, "evil.example")
    assert not bad.ok
    assert "hostname" in bad.reason.lower() or "not match" in bad.reason.lower()


def test_plan_found_with_transition_limit(rows):
    # 标准双 PKI 下，首个副本换新链前所有批次都须持并集包，名额需等于批次数
    result = _planner(rows, limit=len(rows["batches"])).solve()
    assert result.status == "plan"
    assert result.steps_count > 0

    # 逐步回放：每步只动一个副本或一批终端
    chains = [OLD] * len(rows["replicas"])
    bundles = [OLD] * len(rows["batches"])
    for step in result.plan:
        kind = step["kind"]
        if kind == "replica":
            i = step["replica_index"]
            assert chains[i] == OLD
            chains[i] = NEW
            assert step["chains_after"] == chains
            assert step["bundles_after"] == bundles
        else:
            j = step["batch_index"]
            before = bundles[j]
            if kind == "batch_transition":
                assert before == OLD
                bundles[j] = TRANSITION
            elif kind == "batch_finish":
                assert before == TRANSITION
                bundles[j] = NEW
            elif kind == "batch_direct":
                assert before == OLD
                bundles[j] = NEW
            assert step["chains_after"] == chains
            assert step["bundles_after"] == bundles
        # 过渡名额约束
        assert bundles.count(TRANSITION) <= len(rows["batches"])
        # 每步核验计数全部通过
        assert step["checks_passed"] == step["checks_total"]

    assert chains == [NEW] * len(chains)
    assert bundles == [NEW] * len(bundles)


def test_limit_zero_is_insufficient_quota_for_multi_batch(rows):
    result = _planner(rows, limit=0).solve()
    assert result.status == "insufficient_quota"
    assert result.min_required >= 1
    # 放开到最小名额即可解
    ok = _planner(rows, limit=result.min_required).solve()
    assert ok.status == "plan"


def test_limit_one_single_batch_can_solve_directly(rows):
    rows["batches"] = rows["batches"][:1]
    result = _planner(rows, limit=0).solve()
    # 单批次可经并集过渡；limit=0 时若直跳不通则名额不足
    assert result.status in {"plan", "insufficient_quota"}
    relaxed = _planner(rows, limit=1).solve()
    assert relaxed.status == "plan"


def test_direct_switch_when_new_chain_trusted_by_old_bundle(rows):
    # 构造“旧包已含新根”的场景：新链被旧包直接信任，L=0 也应能直跳求解
    from app.certutil import merge_pem_bundles

    for batch in rows["batches"]:
        batch["old_bundle"] = merge_pem_bundles(
            batch["old_bundle"], batch["new_bundle"]
        )
    result = _planner(rows, limit=0).solve()
    assert result.status == "plan"
    # L=0 方案中不允许出现过渡动作
    assert all(step["kind"] != "batch_transition" for step in result.plan)
    assert all(
        TRANSITION not in step["bundles_after"] for step in result.plan
    )


def test_hard_infeasible_when_target_chain_untrusted(rows):
    # 所有批次的新根包都错放成旧根 → 新链永远无法被新包验证
    for batch in rows["batches"]:
        batch["new_bundle"] = batch["old_bundle"]
    result = _planner(rows, limit=len(rows["batches"])).solve()
    assert result.status == "hard_infeasible"
    assert result.target_violations
    assert result.blocker_pairs
    pair = result.blocker_pairs[0]
    # 明细中应包含 新链×新根包 的失败单元
    labels = [(c["chain_state"], c["bundle_mode"]) for c in pair["failed_cells"]]
    assert (NEW, NEW) in labels


def test_hard_infeasible_when_initial_state_broken(rows):
    # 旧根包错放成新根 → 现状（旧链×旧包）即失败
    for batch in rows["batches"]:
        batch["old_bundle"] = batch["new_bundle"]
    result = _planner(rows, limit=2).solve()
    assert result.status == "hard_infeasible"
    assert result.initial_violations


def test_hostname_mismatch_is_hard_infeasible(rows):
    # 新叶子域名与录入域名不一致：改域名制造 SAN 不匹配
    replica = rows["replicas"][0]
    replica["domain"] = "wrong-name.internal.example"
    result = _planner(rows, limit=len(rows["batches"])).solve()
    assert result.status == "hard_infeasible"
    hit = [
        v
        for v in result.initial_violations + result.target_violations
        if v["replica_name"] == replica["name"]
    ]
    assert hit
    assert "hostname" in hit[0]["reason"].lower() or "not match" in hit[0]["reason"].lower()


def test_invalid_pem_raises(rows):
    rows["replicas"][0]["old_chain"] = "not a pem"
    with pytest.raises(Exception):
        build_planner(rows["replicas"], rows["batches"], 2)


def test_bad_limit_rejected(rows):
    with pytest.raises(ValueError):
        build_planner(rows["replicas"], rows["batches"], len(rows["batches"]) + 1)
    with pytest.raises(ValueError):
        build_planner(rows["replicas"], rows["batches"], -1)


def test_matrix_covers_six_combinations(rows):
    result = _planner(rows, limit=len(rows["batches"])).solve()
    n, m = len(rows["replicas"]), len(rows["batches"])
    assert len(result.matrix) == n
    assert all(len(row) == m for row in result.matrix)
    for row in result.matrix:
        for cells in row:
            assert set(cells) == {
                f"{cs}-{bm}" for cs in (OLD, NEW) for bm in (OLD, TRANSITION, NEW)
            }


def test_domains_match_sample():
    assert [d for _, d in REPLICA_DOMAINS][:1] == ["svc-a.internal.example"]
