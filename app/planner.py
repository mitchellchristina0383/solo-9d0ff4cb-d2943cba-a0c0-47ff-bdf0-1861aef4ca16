"""根证书更换顺序求解器。

状态建模
========
* 每个服务副本有两种链状态: OLD(旧链) / NEW(新链)，一次只更换一个副本；
* 每批终端有三种根包状态: OLD(旧包) / TRANSITION(新旧并集) / NEW(新包)。
  OLD→NEW 可直跳，也可经 TRANSITION 过渡；处于 TRANSITION 的批次数不得超过
  页面设定的“同时过渡批次上限”。

核验约束
========
任何核验时刻（初始态、每一步动作之后），每批终端都必须能用“当前持有的根
证书包”按域名验证每个副本“当前出示的证书链”。核验委托给
:mod:`app.certutil` 中的 openssl verify。

搜索
====
状态空间至多 2^4 × 3^4 = 1296，直接 BFS 求步数最少的可行顺序；无解时区分
“材料本身无法通过验证（硬无解）”与“过渡名额不足（调大上限即可）”。
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

from .certutil import PemError, merge_pem_bundles, verify_chain

OLD = 0
NEW = 1
TRANSITION = 2

STATE_LABEL = {OLD: "旧", TRANSITION: "过渡(并集)", NEW: "新"}
BUNDLE_MODE_LABEL = {OLD: "旧根包", NEW: "新根包", TRANSITION: "并集根包"}
CHAIN_LABEL = {OLD: "旧证书链", NEW: "新证书链"}


@dataclass
class Replica:
    name: str
    domain: str
    chains: dict[int, str]  # OLD / NEW 两份 PEM 链


@dataclass
class Batch:
    name: str
    bundles: dict[int, str]  # OLD / NEW / TRANSITION(并集) 三份 PEM 包


@dataclass
class CellResult:
    ok: bool
    reason: str = ""


@dataclass
class SolveResult:
    status: str  # "plan" | "hard_infeasible" | "insufficient_quota"
    plan: list[dict] = field(default_factory=list)
    steps_count: int = 0
    matrix: list[list[dict]] = field(default_factory=list)
    initial_violations: list[dict] = field(default_factory=list)
    target_violations: list[dict] = field(default_factory=list)
    blocker_pairs: list[dict] = field(default_factory=list)
    max_transition: int = 0
    min_required: int | None = None
    message: str = ""


class Planner:
    def __init__(
        self,
        replicas: list[Replica],
        batches: list[Batch],
        max_transition: int,
    ):
        self.replicas = replicas
        self.batches = batches
        self.n = len(replicas)
        self.m = len(batches)
        self.max_transition = max_transition
        # verify_cache[(replica_idx, chain_state, bundle_mode, batch_idx)]
        self._cache: dict[tuple[int, int, int, int], CellResult] = {}

    # ------------------------------------------------------------------ #
    # 核验矩阵
    # ------------------------------------------------------------------ #
    def _cell(self, i: int, chain_state: int, j: int, bundle_mode: int) -> CellResult:
        key = (i, chain_state, bundle_mode, j)
        cached = self._cache.get(key)
        if cached is not None:
            return cached
        replica = self.replicas[i]
        bundle = self.batches[j].bundles[bundle_mode]
        result = verify_chain(replica.chains[chain_state], bundle, replica.domain)
        cell = CellResult(result.ok, result.reason)
        self._cache[key] = cell
        return cell

    def _state_valid(self, chains: tuple[int, ...], bundles: tuple[int, ...]) -> bool:
        for i, chain_state in enumerate(chains):
            for j, bundle_mode in enumerate(bundles):
                if not self._cell(i, chain_state, j, bundle_mode).ok:
                    return False
        return True

    # ------------------------------------------------------------------ #
    # BFS
    # ------------------------------------------------------------------ #
    def _neighbors(
        self,
        chains: tuple[int, ...],
        bundles: tuple[int, ...],
        limit: int,
    ) -> list[tuple[tuple[int, ...], tuple[int, ...], dict]]:
        neighbors: list[tuple[tuple[int, ...], tuple[int, ...], dict]] = []
        transitioning = sum(1 for b in bundles if b == TRANSITION)

        # 顺序固定，保证方案可复现：先开过渡 → 再换副本链 → 最后收过渡/直跳
        for j in range(self.m):
            if bundles[j] == OLD and transitioning < limit:
                new_bundles = list(bundles)
                new_bundles[j] = TRANSITION
                move = {
                    "kind": "batch_transition",
                    "batch_index": j,
                    "text": (
                        f"终端批次「{self.batches[j].name}」: 旧根包 → 过渡根包"
                        f"（新旧并集）"
                    ),
                }
                neighbors.append((chains, tuple(new_bundles), move))

        for i in range(self.n):
            if chains[i] == OLD:
                new_chains = list(chains)
                new_chains[i] = NEW
                move = {
                    "kind": "replica",
                    "replica_index": i,
                    "text": (
                        f"服务副本「{self.replicas[i].name}」"
                        f"({self.replicas[i].domain}): 旧证书链 → 新证书链"
                    ),
                }
                neighbors.append((tuple(new_chains), bundles, move))

        for j in range(self.m):
            if bundles[j] == TRANSITION:
                new_bundles = list(bundles)
                new_bundles[j] = NEW
                move = {
                    "kind": "batch_finish",
                    "batch_index": j,
                    "text": (
                        f"终端批次「{self.batches[j].name}」: 过渡根包 → 新根包"
                    ),
                }
                neighbors.append((chains, tuple(new_bundles), move))
            elif bundles[j] == OLD:
                # 直跳: OLD → NEW（仅当目标态核验通过才可能被走到）
                new_bundles = list(bundles)
                new_bundles[j] = NEW
                move = {
                    "kind": "batch_direct",
                    "batch_index": j,
                    "text": (
                        f"终端批次「{self.batches[j].name}」: 旧根包 → 新根包"
                        f"（直接更换）"
                    ),
                }
                neighbors.append((chains, tuple(new_bundles), move))
        return neighbors

    def _bfs(
        self, limit: int
    ) -> list[dict] | None:
        start_chains = tuple([OLD] * self.n)
        start_bundles = tuple([OLD] * self.m)
        target_chains = tuple([NEW] * self.n)
        target_bundles = tuple([NEW] * self.m)

        if not self._state_valid(start_chains, start_bundles):
            return []  # 空列表表示初始态即不合法，由上层诊断
        goal = (target_chains, target_bundles)
        queue: deque[
            tuple[tuple[int, ...], tuple[int, ...]]
        ] = deque([(start_chains, start_bundles)])
        prev: dict[
            tuple[tuple[int, ...], tuple[int, ...]],
            tuple[tuple[int, ...], tuple[int, ...], dict] | None,
        ] = {(start_chains, start_bundles): None}

        while queue:
            chains, bundles = queue.popleft()
            if (chains, bundles) == goal:
                # 回溯动作序列
                path: list[dict] = []
                node = goal
                while prev[node] is not None:
                    prev_chains, prev_bundles, move = prev[node]
                    move = dict(move)
                    move["chains_after"] = list(node[0])
                    move["bundles_after"] = list(node[1])
                    path.append(move)
                    node = (prev_chains, prev_bundles)
                path.reverse()
                return path
            for next_chains, next_bundles, move in self._neighbors(
                chains, bundles, limit
            ):
                if (next_chains, next_bundles) in prev:
                    continue
                if not self._state_valid(next_chains, next_bundles):
                    continue
                prev[(next_chains, next_bundles)] = (chains, bundles, move)
                queue.append((next_chains, next_bundles))
        return None

    # ------------------------------------------------------------------ #
    # 诊断
    # ------------------------------------------------------------------ #
    def _build_matrix(self) -> list[list[dict]]:
        """每个 (副本, 批次) 在三种根包 × 两种链下的核验结果。"""
        matrix: list[list[dict]] = []
        for i in range(self.n):
            row: list[dict] = []
            for j in range(self.m):
                cells = {}
                for chain_state in (OLD, NEW):
                    for bundle_mode in (OLD, TRANSITION, NEW):
                        cell = self._cell(i, chain_state, j, bundle_mode)
                        cells[f"{chain_state}-{bundle_mode}"] = {
                            "ok": cell.ok,
                            "reason": cell.reason,
                        }
                row.append(cells)
            matrix.append(row)
        return matrix

    def _violations(self, chain_state: int, bundle_mode: int) -> list[dict]:
        out: list[dict] = []
        for i in range(self.n):
            for j in range(self.m):
                cell = self._cell(i, chain_state, j, bundle_mode)
                if not cell.ok:
                    out.append(
                        {
                            "replica_index": i,
                            "replica_name": self.replicas[i].name,
                            "domain": self.replicas[i].domain,
                            "batch_index": j,
                            "batch_name": self.batches[j].name,
                            "reason": cell.reason,
                            "chain_state": chain_state,
                            "bundle_mode": bundle_mode,
                        }
                    )
        return out

    def solve(self) -> SolveResult:
        # 1) 现状核验：旧链 + 旧包必须全部通过，否则变更无从谈起
        initial_violations = self._violations(OLD, OLD)
        target_violations = self._violations(NEW, NEW)
        matrix = self._build_matrix()

        result = SolveResult(
            status="plan",
            matrix=matrix,
            initial_violations=initial_violations,
            target_violations=target_violations,
            max_transition=self.max_transition,
        )

        if initial_violations or target_violations:
            result.status = "hard_infeasible"
            result.blocker_pairs = self._blocker_pairs()
            if initial_violations and target_violations:
                result.message = (
                    "现状与目标态均存在无法通过的核验，证书材料本身不成立。"
                )
            elif initial_violations:
                result.message = "现状（旧链 + 旧根包）已无法通过核验，无法开始变更。"
            else:
                result.message = (
                    "目标态（新链 + 新根包）无法通过核验，再怎么安排顺序也无解。"
                )
            return result

        # 2) 按页面上限搜索
        path = self._bfs(self.max_transition)
        if path is not None:
            result.plan = self._decorate(path)
            result.steps_count = len(path)
            result.message = f"找到可行变更顺序，共 {len(path)} 步。"
            return result

        # 3) 放开上限到全部批次，判断是硬无解还是名额不足
        relaxed = self._bfs(self.m)
        if relaxed is None:
            result.status = "hard_infeasible"
            result.blocker_pairs = self._blocker_pairs()
            result.message = (
                "即使所有批次同时过渡也无解：存在副本链与任何可用根包都无法"
                "完成的核验组合，见下方阻塞明细。"
            )
            return result

        # 4) 名额不足：二分/线性求最小同时过渡名额
        min_required = self._min_limit()
        result.status = "insufficient_quota"
        result.min_required = min_required
        result.message = (
            f"过渡名额不足：当前上限为 {self.max_transition}，"
            f"至少需要 {min_required} 个批次同时处于过渡态才能排通。"
        )
        return result

    def _min_limit(self) -> int:
        lo, hi = 1, self.m
        while lo < hi:
            mid = (lo + hi) // 2
            if self._bfs(mid) is not None:
                hi = mid
            else:
                lo = mid + 1
        return lo

    def _blocker_pairs(self) -> list[dict]:
        """列出存在失败核验组合的 (副本, 批次) 对及全部失败原因。"""
        blockers: list[dict] = []
        for i in range(self.n):
            for j in range(self.m):
                failed_cells: list[dict] = []
                any_ok = False
                for chain_state in (OLD, NEW):
                    for bundle_mode in (OLD, TRANSITION, NEW):
                        cell = self._cell(i, chain_state, j, bundle_mode)
                        if cell.ok:
                            any_ok = True
                        else:
                            failed_cells.append(
                                {
                                    "chain_state": chain_state,
                                    "bundle_mode": bundle_mode,
                                    "chain_label": CHAIN_LABEL[chain_state],
                                    "bundle_label": BUNDLE_MODE_LABEL[bundle_mode],
                                    "reason": cell.reason,
                                }
                            )
                if failed_cells:
                    blockers.append(
                        {
                            "replica_index": i,
                            "replica_name": self.replicas[i].name,
                            "domain": self.replicas[i].domain,
                            "batch_index": j,
                            "batch_name": self.batches[j].name,
                            "any_ok": any_ok,
                            "failed_cells": failed_cells,
                        }
                    )
        return blockers

    def _decorate(self, path: list[dict]) -> list[dict]:
        """补充分步的状态快照与本步核验摘要，便于页面展示。"""
        decorated: list[dict] = []
        for step_no, move in enumerate(path, start=1):
            info = dict(move)
            info["step_no"] = step_no
            info["chains_label"] = [STATE_LABEL[s] for s in move["chains_after"]]
            info["bundles_label"] = [STATE_LABEL[s] for s in move["bundles_after"]]
            # 本步动作后仍逐对核验通过，附上核验计数作为证据
            checks: list[dict] = []
            for i, chain_state in enumerate(move["chains_after"]):
                for j, bundle_mode in enumerate(move["bundles_after"]):
                    cell = self._cell(i, chain_state, j, bundle_mode)
                    checks.append({"ok": cell.ok, "reason": cell.reason})
            info["checks_total"] = len(checks)
            info["checks_passed"] = sum(1 for c in checks if c["ok"])
            decorated.append(info)
        return decorated


def build_planner(
    replica_rows: list[dict],
    batch_rows: list[dict],
    max_transition: int,
) -> Planner:
    """从页面表单数据构造 :class:`Planner`，并计算并集根包。

    每个 replica_rows 元素: {name, domain, old_chain, new_chain}
    每个 batch_rows 元素:   {name, old_bundle, new_bundle}
    """
    if not (1 <= len(replica_rows) <= 4):
        raise ValueError("服务副本数量须在 1~4 之间")
    if not (1 <= len(batch_rows) <= 4):
        raise ValueError("终端批次数量须在 1~4 之间")
    if not (0 <= max_transition <= len(batch_rows)):
        raise ValueError("同时过渡批次上限须在 0 与批次数之间")

    replicas: list[Replica] = []
    for idx, row in enumerate(replica_rows, start=1):
        domain = (row.get("domain") or "").strip()
        if not domain:
            raise ValueError(f"第 {idx} 个副本缺少域名")
        try:
            old_chain = row["old_chain"]
            new_chain = row["new_chain"]
            merge_pem_bundles(old_chain, new_chain)  # 仅用于校验两份 PEM 均可解析
        except PemError as exc:
            raise PemError(f"第 {idx} 个副本证书链解析失败: {exc}") from exc
        replicas.append(
            Replica(
                name=(row.get("name") or f"副本{idx}").strip() or f"副本{idx}",
                domain=domain,
                chains={
                    OLD: old_chain,
                    NEW: new_chain,
                },
            )
        )

    batches: list[Batch] = []
    for idx, row in enumerate(batch_rows, start=1):
        name = (row.get("name") or f"批次{idx}").strip() or f"批次{idx}"
        old_b = row["old_bundle"]
        new_b = row["new_bundle"]
        try:
            union_b = merge_pem_bundles(old_b, new_b)
        except PemError as exc:
            raise PemError(f"批次「{name}」根证书包解析失败: {exc}") from exc
        batches.append(
            Batch(
                name=name,
                bundles={OLD: old_b, NEW: new_b, TRANSITION: union_b},
            )
        )
    return Planner(replicas, batches, max_transition)
