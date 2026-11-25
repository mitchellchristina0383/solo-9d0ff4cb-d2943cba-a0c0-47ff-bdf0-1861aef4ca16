"""生成可在网页直接试跑的一套 HTTPS 根证书更换样例。

层级（新旧两套完全独立的 PKI）::

    old-root CA ── old-intermediate CA ── 各副本旧叶子证书
    new-root CA ── new-intermediate CA ── 各副本新叶子证书（相同 SAN）

产物（默认写入 samples/）：
  roots/        旧/新根 CA 自签名证书
  intermediates/旧/新中间 CA 证书
  replicas/     每个副本的旧链、新链（叶子 + 中间，PEM 拼接）
  bundles/      终端旧根包、新根包、并集过渡包
  sample.json   页面表单预填数据

样例只用于本地演示：私钥仅在内存中生成与使用，不会落盘；请勿把样例证书
用于任何真实环境。
"""

from __future__ import annotations

import datetime
import json
import os
import pathlib

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

REPLICA_DOMAINS = [
    ("svc-a", "svc-a.internal.example"),
    ("svc-b", "svc-b.internal.example"),
    ("svc-c", "svc-c.internal.example"),
]


def _key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _name(cn: str, ou: str) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "TLS Rotation Demo"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ou),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ]
    )


def _pem_cert(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


def _save(path: pathlib.Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="ascii")


def make_root(cn: str) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
    key = _key()
    now = datetime.datetime.now(datetime.timezone.utc)
    subject = _name(cn, "Root CA")
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_encipherment=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
        )
        .sign(key, hashes.SHA256())
    )
    return cert, key


def make_intermediate(
    cn: str,
    root_cert: x509.Certificate,
    root_key: rsa.RSAPrivateKey,
) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
    key = _key()
    now = datetime.datetime.now(datetime.timezone.utc)
    subject = _name(cn, "Intermediate CA")
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(root_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1825))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_encipherment=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()),
            critical=False,
        )
        .sign(root_key, hashes.SHA256())
    )
    return cert, key


def make_leaf(
    cn: str,
    dns_names: list[str],
    issuer_cert: x509.Certificate,
    issuer_key: rsa.RSAPrivateKey,
) -> x509.Certificate:
    key = _key()
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name(cn, "Service"))
        .issuer_name(issuer_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=398))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName(name) for name in dns_names]
            ),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                issuer_key.public_key()
            ),
            critical=False,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .sign(issuer_key, hashes.SHA256())
    )
    return cert


def generate(out_dir: str | os.PathLike = "samples") -> pathlib.Path:
    out = pathlib.Path(out_dir)

    old_root, old_root_key = make_root("Demo Old Root CA")
    new_root, new_root_key = make_root("Demo New Root CA")
    old_int, old_int_key = make_intermediate(
        "Demo Old Intermediate CA", old_root, old_root_key
    )
    new_int, new_int_key = make_intermediate(
        "Demo New Intermediate CA", new_root, new_root_key
    )

    _save(out / "roots" / "old-root.pem", _pem_cert(old_root))
    _save(out / "roots" / "new-root.pem", _pem_cert(new_root))
    _save(out / "intermediates" / "old-intermediate.pem", _pem_cert(old_int))
    _save(out / "intermediates" / "new-intermediate.pem", _pem_cert(new_int))

    old_bundle = _pem_cert(old_root)
    new_bundle = _pem_cert(new_root)
    union_bundle = old_bundle + new_bundle
    _save(out / "bundles" / "old-bundle.pem", old_bundle)
    _save(out / "bundles" / "new-bundle.pem", new_bundle)
    _save(out / "bundles" / "union-bundle.pem", union_bundle)

    sample = {"replicas": [], "batches": [], "max_transition": 3}
    for idx, (label, domain) in enumerate(REPLICA_DOMAINS, start=1):
        old_leaf = make_leaf(domain, [domain], old_int, old_int_key)
        new_leaf = make_leaf(domain, [domain], new_int, new_int_key)
        old_chain = _pem_cert(old_leaf) + _pem_cert(old_int)
        new_chain = _pem_cert(new_leaf) + _pem_cert(new_int)
        _save(out / "replicas" / label / "old-chain.pem", old_chain)
        _save(out / "replicas" / label / "new-chain.pem", new_chain)
        sample["replicas"].append(
            {
                "name": label,
                "domain": domain,
                "old_chain": old_chain,
                "new_chain": new_chain,
            }
        )

    # 3 批终端共享同样的旧包/新包，但页面允许各批粘贴不同内容
    for idx in range(1, 4):
        sample["batches"].append(
            {
                "name": f"终端批次{idx}",
                "old_bundle": old_bundle,
                "new_bundle": new_bundle,
            }
        )

    meta_path = out / "sample.json"
    # 原子替换，避免生成中途失败/被杀后留下截断的 sample.json。
    meta_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_meta = meta_path.with_name(meta_path.name + ".tmp")
    tmp_meta.write_text(
        json.dumps(sample, ensure_ascii=False, indent=2), "utf-8"
    )
    os.replace(tmp_meta, meta_path)
    return meta_path


if __name__ == "__main__":
    import sys

    args = [a for a in sys.argv[1:] if a != "--ensure"]
    target = args[0] if args else "samples"

    if "--ensure" in sys.argv[1:]:
        # 启动语义：可用 sample.json 则沿用并对齐 PEM，缺失 / 排不出才重签。
        # 这里延迟导入，避免“强制重新生成”的常规用法依赖 Flask 之外的模块顺序。
        sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
        from app.preparation import prepare_samples

        result = prepare_samples(target)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        sys.exit(0 if result.get("status") == "ok" else 1)

    path = generate(target)
    print(f"样例证书已生成: {path.resolve()}")
