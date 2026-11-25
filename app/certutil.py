"""证书链 / 根证书包解析与核验工具。

核验基于系统 openssl 命令（``openssl verify``），同时完成：
  1. 证书链签名与有效期核验；
  2. 以终端根证书包作为唯一信任锚（``-no-CAfile``，不加载系统默认 CA）；
  3. 按域名做 SAN/CN 主机名校验（``-verify_hostname``）。

所有 PEM 数据均视为不可信外部输入，只通过临时文件传给 openssl 子进程。
"""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID

_PEM_RE = re.compile(
    rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
    re.DOTALL,
)


class PemError(ValueError):
    """PEM 内容无法解析为证书时抛出。"""


def extract_certs(pem_text: str) -> list[x509.Certificate]:
    """从一段 PEM 文本中提取全部证书，按文件中的顺序返回。"""
    if not pem_text or not pem_text.strip():
        raise PemError("PEM 内容为空")
    blobs = _PEM_RE.findall(pem_text.encode("utf-8", errors="replace"))
    certs: list[x509.Certificate] = []
    for blob in blobs:
        try:
            certs.append(x509.load_pem_x509_certificate(blob))
        except Exception as exc:  # pragma: no cover - 正则已限定 PEM 结构
            raise PemError(f"无法解析证书: {exc}") from exc
    if not certs:
        raise PemError("未找到 PEM 证书（需要 -----BEGIN CERTIFICATE----- 块）")
    return certs


def cert_subject(cert: x509.Certificate) -> str:
    try:
        return cert.subject.rfc4514_string()
    except Exception:  # pragma: no cover
        return "<未知主题>"


def cert_issuer(cert: x509.Certificate) -> str:
    try:
        return cert.issuer.rfc4514_string()
    except Exception:  # pragma: no cover
        return "<未知颁发者>"


def cert_serials(certs: list[x509.Certificate]) -> list[str]:
    """用序列号指纹标识证书，用于界面区分新旧材料。"""
    return [f"{c.serial_number:X}"[:16] for c in certs]


def leaf_summary(pem_text: str) -> dict:
    """提取证书链中叶子证书的概要信息供页面展示。"""
    certs = extract_certs(pem_text)
    leaf = certs[0]
    cn = ""
    try:
        attrs = leaf.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if attrs:
            cn = attrs[0].value
    except x509.ExtensionNotFound:
        pass
    sans: list[str] = []
    try:
        ext = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans = ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        pass
    return {
        "subject": cert_subject(leaf),
        "common_name": cn,
        "sans": sans,
        "issuer": cert_issuer(leaf),
        "serial": f"{leaf.serial_number:X}",
        "not_valid_before": leaf.not_valid_before_utc.strftime("%Y-%m-%d %H:%M UTC"),
        "not_valid_after": leaf.not_valid_after_utc.strftime("%Y-%m-%d %H:%M UTC"),
        "chain_length": len(certs),
        "all_serials": cert_serials(certs),
    }


def bundle_summary(pem_text: str) -> dict:
    """提取根证书包概要（包内每个证书的主题/序列号）。"""
    certs = extract_certs(pem_text)
    return {
        "count": len(certs),
        "subjects": [cert_subject(c) for c in certs],
        "serials": cert_serials(certs),
    }


def pem_normalized(pem_text: str) -> str:
    """规范化 PEM 文本，便于做并集与去重（按证书 DER 去重）。"""
    certs = extract_certs(pem_text)
    seen: set[bytes] = set()
    out: list[str] = []
    for cert in certs:
        der = cert.public_bytes(serialization.Encoding.DER)
        if der in seen:
            continue
        seen.add(der)
        out.append(
            cert.public_bytes(serialization.Encoding.PEM).decode("ascii").strip()
        )
    return "\n".join(out)


def merge_pem_bundles(pem_a: str, pem_b: str) -> str:
    """两个根证书包取并集（按证书 DER 去重，保持 a 在前 b 在后）。"""
    merged: list[x509.Certificate] = []
    seen: set[bytes] = set()
    for text in (pem_a, pem_b):
        for cert in extract_certs(text):
            der = cert.public_bytes(serialization.Encoding.DER)
            if der not in seen:
                seen.add(der)
                merged.append(cert)
    return "\n".join(
        c.public_bytes(serialization.Encoding.PEM).decode("ascii").strip()
        for c in merged
    )


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    reason: str = ""

    def __bool__(self) -> bool:  # 方便直接 if result:
        return self.ok


def _write_pem_tmp(directory: str, name: str, pem_text: str) -> str:
    path = os.path.join(directory, name)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(pem_text)
    return path


def verify_chain(chain_pem: str, bundle_pem: str, hostname: str) -> VerifyResult:
    """用终端根证书包按域名核验服务证书链。

    返回 :class:`VerifyResult`；失败时 ``reason`` 为 openssl 给出的原因摘要。
    信任锚仅来自 ``bundle_pem``（-no-CAfile），系统默认 CA 不参与。
    """
    # 先在进程内解析，材料非法时给出明确错误而不是 openssl 的模糊报错
    chain_certs = extract_certs(chain_pem)
    bundle_certs = extract_certs(bundle_pem)
    leaf_der = chain_certs[0].public_bytes(serialization.Encoding.DER)
    if len(chain_certs) < 1 or len(bundle_certs) < 1:
        return VerifyResult(False, "证书链或根证书包为空")

    with tempfile.TemporaryDirectory(prefix="tlsplan_") as tmp:
        leaf_path = _write_pem_tmp(tmp, "leaf.pem", chain_pem)
        bundle_path = _write_pem_tmp(tmp, "bundle.pem", bundle_pem)
        untrusted_path = None
        if len(chain_certs) > 1:
            # openssl 要求叶子单独传入，其余链上证书走 -untrusted
            leaf_only = chain_certs[0].public_bytes(
                serialization.Encoding.PEM
            ).decode("ascii")
            intermediates = "\n".join(
                c.public_bytes(serialization.Encoding.PEM).decode("ascii")
                for c in chain_certs[1:]
            )
            leaf_path = _write_pem_tmp(tmp, "leaf_only.pem", leaf_only)
            untrusted_path = _write_pem_tmp(tmp, "untrusted.pem", intermediates)

        cmd = [
            "openssl",
            "verify",
            "-no-CAfile",
            "-CAfile",
            bundle_path,
            "-verify_hostname",
            hostname,
        ]
        if untrusted_path:
            cmd += ["-untrusted", untrusted_path]
        cmd.append(leaf_path)

        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    if proc.returncode == 0:
        return VerifyResult(True)
    # openssl 的具体原因在 "error N at X depth lookup: ..." 行，
    # 最后一行只有 "verification failed"，需扫描全部输出。
    detail_lines = (proc.stderr or proc.stdout or "").strip().splitlines()
    reason = ""
    for line in detail_lines:
        match = re.search(r"error \d+ at \d+ depth lookup:\s*(.+)$", line)
        if match:
            reason = match.group(1).strip()
            break
    if not reason:
        reason = (
            detail_lines[-1].strip()
            if detail_lines
            else f"openssl 返回码 {proc.returncode}"
        )
    reason = re.sub(r"^[^\s:]+: ", "", reason)
    if "hostname" in reason.lower() or "not match" in reason.lower():
        # 附带叶子实际 SAN，方便值班员定位域名问题
        sans: list[str] = []
        try:
            ext = chain_certs[0].extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            )
            sans = ext.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            pass
        if sans:
            reason = f"{reason}（叶子证书 SAN: {', '.join(sans)}）"
    return VerifyResult(False, reason)
