"""启动时样例目录准备（修复“每次启动重新签发，备下的根包失效”问题）。

决策顺序
========
1. ``samples/sample.json`` 存在，且其中的证书材料在放开过渡名额后**能排出
   迁移方案**（求解状态为 ``plan``）：沿用其中的证书作为唯一事实来源，把目录
   里的副本链、根证书包（以及可由它们推导的根 / 中间证书）补齐或纠正到与
   ``sample.json`` 一致；**不重新签发、不改写 sample.json**。
2. ``sample.json`` 缺失，或其中材料解析 / 核验 / 求解排不出方案：调用
   :mod:`scripts.generate_samples` 重新生成一套确定可用的样例。
3. 上述准备过程本身失败（目录被占位文件挡住、权限 / 磁盘 / openssl 缺失等）：
   写入 ``error`` 状态标记并返回非零结论；已经可用的 ``sample.json`` 在第 1
   步的纠正过程中绝不会被改写或删除，排除故障后用原目录重启即可继续。

状态标记文件供 ``/api/health`` 读取：准备失败时健康检查必须返回 503。
标记路径取环境变量 ``PREPARE_STATUS_FILE``，默认 ``<samples>/.prepare-status.json``；
若该位置不可写则退到系统临时目录的固定文件，保证容器内总能留下失败标记。
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import pathlib
import re
import shutil
import sys
import tempfile
from typing import Any

from .certutil import PemError, extract_certs, merge_pem_bundles
from .planner import build_planner
from cryptography.hazmat.primitives import serialization as _serialization

BASE_DIR = pathlib.Path(__file__).resolve().parent.parent
DEFAULT_SAMPLES_DIR = BASE_DIR / "samples"
STATUS_FILENAME = ".prepare-status.json"
FALLBACK_STATUS_PATH = (
    pathlib.Path(tempfile.gettempdir()) / "tls_rotation_prepare_status.json"
)

# 这些异常来自“sample.json 材料本身不合法 / 排不出方案”，此时应重新生成；
# 其余异常（OSError、子进程环境错误等）属于“准备过程失败”，必须保留现场。
_MATERIAL_ERRORS = (
    PemError,
    ValueError,
    KeyError,
    TypeError,
    IndexError,
    AttributeError,
)


class PreparationError(RuntimeError):
    """样例准备因环境 / 文件系统问题无法完成（区别于材料不可用）。"""


# --------------------------------------------------------------------------- #
# 路径与状态标记
# --------------------------------------------------------------------------- #
def samples_dir() -> pathlib.Path:
    env = os.environ.get("SAMPLES_DIR", "").strip()
    return pathlib.Path(env) if env else DEFAULT_SAMPLES_DIR


def sample_json_path() -> pathlib.Path:
    return samples_dir() / "sample.json"


def status_file_path() -> pathlib.Path:
    return marker_path_for(samples_dir())


def marker_path_for(root: str | os.PathLike[str]) -> pathlib.Path:
    """状态标记位置：显式 ``PREPARE_STATUS_FILE`` 优先，否则放到被准备目录内。"""
    env = os.environ.get("PREPARE_STATUS_FILE", "").strip()
    if env:
        return pathlib.Path(env)
    return pathlib.Path(root) / STATUS_FILENAME


def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _atomic_write(path: pathlib.Path, content: str) -> None:
    """同目录临时文件 + os.replace，避免写出半截 PEM / JSON。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        prefix=path.name + ".", suffix=".tmp", dir=str(path.parent)
    )
    try:
        # 证书 / PEM 均为公开材料，统一 0644，避免 mkstemp 默认 0600
        # 给非 root 挂载读取或值班员备份脚本造成麻烦。
        try:
            os.fchmod(fd, 0o644)
        except OSError:
            pass
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_name, path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def write_status(
    status: dict[str, Any], path: str | os.PathLike[str] | None = None
) -> pathlib.Path | None:
    """写出准备状态；主位置不可写时退到临时目录。返回实际写入路径。"""
    payload = dict(status)
    payload.setdefault("checked_at", _now_iso())
    payload.setdefault("samples_dir", str(samples_dir()))
    primary = pathlib.Path(path) if path is not None else status_file_path()
    try:
        _atomic_write(
            primary, json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
        )
        return primary
    except OSError:
        try:
            _atomic_write(
                FALLBACK_STATUS_PATH,
                json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
            )
            return FALLBACK_STATUS_PATH
        except OSError:
            return None


def read_status() -> dict[str, Any] | None:
    """读取最近一次准备状态（环境指定位置 → 样例目录 → 临时目录兜底）。"""
    candidates = [status_file_path()]
    if FALLBACK_STATUS_PATH not in candidates:
        candidates.append(FALLBACK_STATUS_PATH)
    for path in candidates:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(data, dict):
            data.setdefault("status_file", str(path))
            return data
    return None


def health_status(
    sample_path_override: pathlib.Path | str | None = None,
) -> tuple[int, dict[str, Any]]:
    """供 ``/api/health`` 使用：有 error 标记必 503，ok 标记必 200。

    没有任何标记（例如开发 / 测试直接起 Flask、没走过入口脚本）时，退化为
    轻量结构检查：sample.json 存在且含非空 replicas/batches 才视为就绪，
    绝不在健康检查里跑 openssl 求解。
    """
    marker = read_status()
    if marker is not None:
        if marker.get("status") == "ok":
            return 200, {"health": "ok", "preparation": marker}
        return 503, {"health": "not_ready", "preparation": marker}

    path = (
        pathlib.Path(sample_path_override)
        if sample_path_override is not None
        else sample_json_path()
    )
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        replicas = data["replicas"]
        batches = data["batches"]
        if not isinstance(replicas, list) or not replicas:
            raise ValueError("replicas 为空")
        if not isinstance(batches, list) or not batches:
            raise ValueError("batches 为空")
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return 503, {
            "health": "not_ready",
            "error": f"样例尚未准备好：{exc}",
            "sample_json": str(path),
        }
    return 200, {
        "health": "ok",
        "preparation": None,
        "note": "未发现准备状态标记，但 sample.json 结构可读",
    }


# --------------------------------------------------------------------------- #
# 材料可用性判定
# --------------------------------------------------------------------------- #
def openssl_available() -> bool:
    return bool(shutil.which("openssl"))


def evaluate_sample(sample: Any) -> tuple[bool, str, int]:
    """用满过渡名额求解，判断“证书材料本身”能否排出迁移顺序。

    返回 ``(是否可排通, 说明, 步数)``。材料格式错误抛
    :class:`ValueError`/:class:`KeyError` 等；openssl/系统级错误以
    :class:`OSError` 等形式向上传播，由调用方按“准备失败”处理。
    """
    if not isinstance(sample, dict):
        return False, "sample.json 顶层不是 JSON 对象", 0
    replicas = sample.get("replicas")
    batches = sample.get("batches")
    if not isinstance(replicas, list) or not replicas:
        return False, "sample.json 缺少非空 replicas 列表", 0
    if not isinstance(batches, list) or not batches:
        return False, "sample.json 缺少非空 batches 列表", 0
    if len(replicas) > 4 or len(batches) > 4:
        return False, "副本与终端批次均最多 4 个", 0

    # 名额给到批次数上限：区分“材料硬无解”与“只是配额设置不足”。
    planner = build_planner(replicas, batches, len(batches))
    result = planner.solve()
    if result.status == "plan":
        return True, result.message, result.steps_count
    return False, result.message or result.status, 0


# --------------------------------------------------------------------------- #
# 按 sample.json 对齐目录中的 PEM 文件
# --------------------------------------------------------------------------- #
def _slugify(name: Any, index: int, kind: str = "svc") -> str:
    text = re.sub(r"[^\w.-]+", "-", str(name or ""), flags=re.UNICODE)
    text = text.strip(".-_")
    return text or f"{kind}-{index}"


def _install_file(path: pathlib.Path, content: str) -> str:
    """内容不同才原子替换；返回 created / updated / unchanged。"""
    if path.exists() or path.is_symlink():
        if not path.is_file():
            raise PreparationError(f"{path} 已存在但不是普通文件，无法纠正")
        try:
            old = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            old = None
        if old == content:
            return "unchanged"
        action = "updated"
    else:
        action = "created"
    _atomic_write(path, content)
    return action


def _pem_text(certs: list) -> str:
    return "".join(
        cert.public_bytes(_serialization.Encoding.PEM).decode("ascii")
        for cert in certs
    )


def _self_signed_pem(bundle_text: str) -> str | None:
    roots = [c for c in extract_certs(bundle_text) if c.subject == c.issuer]
    return _pem_text(roots) if roots else None


def _chain_intermediates_pem(chain_text: str) -> str | None:
    certs = extract_certs(chain_text)
    if len(certs) <= 1:
        return None
    return _pem_text(certs[1:])


def _first_cert_der(pem_text: Any) -> bytes | None:
    if not isinstance(pem_text, str):
        return None
    try:
        certs = extract_certs(pem_text)
    except PemError:
        return None
    if not certs:
        return None
    return certs[0].public_bytes(_serialization.Encoding.DER)


def _choose_replica_dir(
    replicas_dir: pathlib.Path, slug: str, row: dict, index: int
) -> pathlib.Path:
    direct = replicas_dir / slug
    if direct.exists() or direct.is_symlink():
        if not direct.is_dir():
            raise PreparationError(
                f"{direct} 已存在但不是目录，无法补齐该副本的证书链"
            )
        return direct

    # 目录名对不上时，用叶子证书 DER 在已有目录里精确匹配，尽量纠正而不是
    # 另建一套（例如目录被改名、sample.json 里 name 被改动）。
    wanted = {
        _first_cert_der(row.get("old_chain")),
        _first_cert_der(row.get("new_chain")),
    }
    wanted.discard(None)
    if replicas_dir.is_dir() and wanted:
        for child in sorted(replicas_dir.iterdir()):
            if not child.is_dir():
                continue
            for fname in ("old-chain.pem", "new-chain.pem"):
                der = _first_cert_der_from_file(child / fname)
                if der is not None and der in wanted:
                    return child
    return direct


def _first_cert_der_from_file(path: pathlib.Path) -> bytes | None:
    try:
        return _first_cert_der(path.read_text(encoding="utf-8"))
    except OSError:
        return None


def reconcile_files(root: pathlib.Path, sample: dict[str, Any]) -> list[dict]:
    """把目录内 PEM 对齐到 sample.json；返回每个文件的处置记录。"""
    changes: list[dict] = []

    def record(rel: pathlib.Path, action: str) -> None:
        changes.append({"path": str(rel), "action": action})

    replicas_dir = root / "replicas"
    if replicas_dir.exists() and not replicas_dir.is_dir():
        raise PreparationError(f"{replicas_dir} 已存在但不是目录，无法补齐副本链")

    for idx, row in enumerate(sample["replicas"], start=1):
        if not isinstance(row, dict):
            raise ValueError(f"第 {idx} 个副本不是对象")
        slug = _slugify(row.get("name") or f"svc-{idx}", idx)
        replica_dir = _choose_replica_dir(replicas_dir, slug, row, idx)
        for fname, field in (
            ("old-chain.pem", "old_chain"),
            ("new-chain.pem", "new_chain"),
        ):
            content = row[field]
            if not isinstance(content, str):
                raise ValueError(f"副本 {slug} 的 {field} 不是 PEM 文本")
            target = replica_dir / fname
            action = _install_file(target, content)
            record(target.relative_to(root), action)

    batches_dir = root / "bundles"
    if batches_dir.exists() and not batches_dir.is_dir():
        raise PreparationError(f"{batches_dir} 已存在但不是目录，无法补齐根包")

    batches = sample["batches"]
    first = batches[0]
    for fname, field in (
        ("old-bundle.pem", "old_bundle"),
        ("new-bundle.pem", "new_bundle"),
    ):
        content = first[field]
        action = _install_file(batches_dir / fname, content)
        record(batches_dir.relative_to(root) / fname, action)

    union_content = merge_pem_bundles(
        first["old_bundle"], first["new_bundle"]
    ) + "\n"
    action = _install_file(batches_dir / "union-bundle.pem", union_content)
    record(batches_dir.relative_to(root) / "union-bundle.pem", action)

    # 各批根包不一致时，单一的 old/new/union-bundle.pem 无法完整表示，
    # 额外按批落盘，保证“按这套材料补齐目录里的根包”无遗漏。
    def _der_tuple(text: Any) -> tuple[bytes, ...]:
        return tuple(
            c.public_bytes(_serialization.Encoding.DER)
            for c in extract_certs(text if isinstance(text, str) else "")
        )

    old_materials = {_der_tuple(b.get("old_bundle")) for b in batches}
    new_materials = {_der_tuple(b.get("new_bundle")) for b in batches}
    if len(old_materials) > 1 or len(new_materials) > 1:
        for j, batch in enumerate(batches, start=1):
            bslug = _slugify(batch.get("name") or f"batch-{j}", j, "batch")
            specs = (
                (f"batch-{j:02d}-{bslug}-old.pem", batch["old_bundle"]),
                (f"batch-{j:02d}-{bslug}-new.pem", batch["new_bundle"]),
                (
                    f"batch-{j:02d}-{bslug}-union.pem",
                    merge_pem_bundles(batch["old_bundle"], batch["new_bundle"])
                    + "\n",
                ),
            )
            for fname, content in specs:
                action = _install_file(batches_dir / fname, content)
                record(batches_dir.relative_to(root) / fname, action)

    # 根证书可从根包中的自签名证书推导；中间证书可从副本链（叶子之后）推导。
    roots_dir = root / "roots"
    for fname, field in (("old-root.pem", "old_bundle"), ("new-root.pem", "new_bundle")):
        pem = _self_signed_pem(first[field])
        if pem is not None:
            target = roots_dir / fname
            action = _install_file(target, pem)
            record(target.relative_to(root), action)

    intermediates_dir = root / "intermediates"
    first_replica = sample["replicas"][0]
    for fname, field in (
        ("old-intermediate.pem", "old_chain"),
        ("new-intermediate.pem", "new_chain"),
    ):
        pem = _chain_intermediates_pem(first_replica[field])
        if pem is not None:
            target = intermediates_dir / fname
            action = _install_file(target, pem)
            record(target.relative_to(root), action)

    return changes


# --------------------------------------------------------------------------- #
# 重新生成
# --------------------------------------------------------------------------- #
def _regenerate(root: pathlib.Path) -> None:
    if str(BASE_DIR) not in sys.path:
        sys.path.insert(0, str(BASE_DIR))
    from scripts.generate_samples import generate as _generate

    root.mkdir(parents=True, exist_ok=True)
    _generate(root)


# --------------------------------------------------------------------------- #
# 主入口
# --------------------------------------------------------------------------- #
def prepare_samples(target: str | os.PathLike[str] | None = None) -> dict[str, Any]:
    """执行启动样例准备，返回并落盘状态；任何失败都体现在 ``status=error``。"""
    root = pathlib.Path(target) if target else samples_dir()
    root = root.expanduser()
    sample_path = root / "sample.json"
    marker_path = marker_path_for(root)

    try:
        if not openssl_available():
            raise PreparationError(
                "PATH 中找不到 openssl 可执行文件，证书链核验无法进行；"
                "请在镜像 / 环境中安装 openssl 后用原目录重启。"
            )

        mode: str
        message: str
        regenerate_reason = ""
        regenerate_mode = "regenerated"
        sample: dict[str, Any] | None = None

        if sample_path.exists() or sample_path.is_symlink():
            if not sample_path.is_file():
                raise PreparationError(
                    f"{sample_path} 存在但不是普通文件（可能是目录 / 异常挂载点），"
                    "无法沿用也无法原地重建；请排除该故障后用原目录重启。"
                )
            try:
                raw = sample_path.read_text(encoding="utf-8")
            except OSError as exc:
                raise PreparationError(f"无法读取 {sample_path}: {exc}") from exc

            try:
                sample = json.loads(raw)
            except ValueError as exc:
                sample = None
                regenerate_reason = f"sample.json 不是合法 JSON：{exc}"

            if sample is not None:
                try:
                    planable, why, steps = evaluate_sample(sample)
                except _MATERIAL_ERRORS as exc:
                    planable = False
                    why = f"{type(exc).__name__}: {exc}"
                except OSError as exc:
                    # openssl 子进程 / 文件系统等环境问题：不得误判为材料坏，
                    # 更不能重新生成覆盖仍可用的 sample.json。
                    raise PreparationError(
                        f"核验 sample.json 材料时发生系统 / 环境错误：{exc}"
                    ) from exc

                if planable:
                    # 关键：这一步只读 sample.json、只写周边 PEM，绝不改写它。
                    changes = reconcile_files(root, sample)
                    created = sum(c["action"] == "created" for c in changes)
                    updated = sum(c["action"] == "updated" for c in changes)
                    mode = "kept"
                    message = (
                        f"沿用现有 sample.json（{steps} 步迁移方案可排通）；"
                        f"PEM 文件核对完成：新建 {created}、纠正 {updated}、"
                        f"其余一致。"
                    )
                    payload: dict[str, Any] = {
                        "status": "ok",
                        "mode": mode,
                        "message": message,
                        "steps_count": steps,
                        "changes": changes,
                        "samples_dir": str(root.resolve()),
                    }
                    marker = write_status(payload, marker_path)
                    payload["status_file"] = str(marker) if marker else None
                    return payload

                regenerate_reason = f"现有 sample.json 材料排不出方案：{why}"
        else:
            regenerate_reason = "sample.json 缺失"
            regenerate_mode = "generated"

        # 走到这里：缺失 / 非法 / 材料硬无解 → 重新生成一套可用样例。
        try:
            _regenerate(root)
        except OSError as exc:
            raise PreparationError(
                f"{regenerate_reason}；尝试重新生成样例但写目录失败：{exc}"
            ) from exc

        try:
            new_sample = json.loads(sample_path.read_text(encoding="utf-8"))
            planable, why, steps = evaluate_sample(new_sample)
        except (OSError, ValueError) as exc:
            raise PreparationError(f"重新生成后仍无法读取 / 解析样例：{exc}") from exc
        except _MATERIAL_ERRORS as exc:
            raise PreparationError(f"重新生成的样例结构异常：{exc}") from exc
        if not planable:
            raise PreparationError(f"重新生成的样例仍排不出方案：{why}")

        mode = regenerate_mode
        if mode == "generated":
            message = "sample.json 缺失；已生成一套可排 " f"{steps} 步方案的可用样例。"
        else:
            message = (
                f"{regenerate_reason}；已重新签发并生成可排 {steps} 步方案的样例。"
            )
        payload = {
            "status": "ok",
            "mode": mode,
            "message": message,
            "steps_count": steps,
            "regenerate_reason": regenerate_reason,
            "samples_dir": str(root.resolve()),
        }
        marker = write_status(payload, marker_path)
        payload["status_file"] = str(marker) if marker else None
        return payload

    except Exception as exc:  # noqa: BLE001 - 启动准备必须兜底并点亮健康检查
        error_payload = {
            "status": "error",
            "mode": "failed",
            "error": str(exc) or exc.__class__.__name__,
            "samples_dir": str(root),
        }
        marker = write_status(error_payload, marker_path)
        error_payload["status_file"] = str(marker) if marker else None
        return error_payload


# 语义化别名：部分调用方 / 脚本可能以 ensure_samples 命名这一“确保样例就绪”入口。
ensure_samples = prepare_samples
