"""OID 名称数据库。

数据来源分两层：
1. `_PKI_SUPPLEMENT`：内置 PKI 补充表（DN 属性、扩展、算法、CMS 内容类型），
   同 dotted 冲突时优先级最高；
2. `data/oid_dumpasn1.json`：由 `tools/build_oids.py` 从 dumpasn1.cfg（MIT）
   构建的紧凑全量库，随包发布；文件缺失时自动退化为仅补充表（不崩溃）。

查询：先精确匹配，未命中时沿点分前缀做最长前缀匹配——子条目有具体名时用
具体名，仅父条目（如 2.5.29 → id-ce）收录时给出父名提示；完全未知仍返回
None（调用方显示 dotted 原文，不崩溃）。
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from importlib.resources import files as _res_files

# 数据文件（由 tools/build_oids.py 生成；随包发布，PyInstaller 需一并收集）
_DATA_REL = ("data", "oid_dumpasn1.json")

# OID 值区解码上限：超过视为异常输入，不构造 dotted 文本。
# 256 B 的最坏单弧约 540 位十进制，远低于 Python 4300 位 int→str 上限。
MAX_OID_BYTES = 256

# dotted OID → (名称, 说明)。说明留空的仅显示名称。
# ---- X.500 DN 属性（RDN） ----
_PKI_SUPPLEMENT: dict[str, tuple[str, str]] = {
    "2.5.4.3": ("commonName", "DN 属性：CN"),
    "2.5.4.4": ("surname", "DN 属性：SN"),
    "2.5.4.5": ("serialNumber", "DN 属性：serialNumber"),
    "2.5.4.6": ("countryName", "DN 属性：C"),
    "2.5.4.7": ("localityName", "DN 属性：L"),
    "2.5.4.8": ("stateOrProvinceName", "DN 属性：ST"),
    "2.5.4.9": ("streetAddress", "DN 属性"),
    "2.5.4.10": ("organizationName", "DN 属性：O"),
    "2.5.4.11": ("organizationalUnitName", "DN 属性：OU"),
    "2.5.4.12": ("title", "DN 属性"),
    "2.5.4.42": ("givenName", "DN 属性"),
    "2.5.4.43": ("initials", "DN 属性"),
    "2.5.4.46": ("dnQualifier", "DN 属性"),
    "2.5.4.65": ("pseudonym", "DN 属性"),
    # ---- X.509 v3 标准扩展（id-ce） ----
    "2.5.29.9": ("subjectDirectoryAttributes", "标准扩展"),
    "2.5.29.14": ("subjectKeyIdentifier", "标准扩展"),
    "2.5.29.15": ("keyUsage", "标准扩展"),
    "2.5.29.17": ("subjectAltName", "标准扩展：SAN"),
    "2.5.29.18": ("issuerAltName", "标准扩展"),
    "2.5.29.19": ("basicConstraints", "标准扩展"),
    "2.5.29.20": ("cRLNumber", "CRL 扩展"),
    "2.5.29.21": ("cRLReason", "CRL 扩展"),
    "2.5.29.24": ("invalidityDate", "CRL 扩展"),
    "2.5.29.27": ("privilegeWithdrawn", "CRL 扩展"),
    "2.5.29.28": ("issuingDistributionPoint", "CRL 扩展"),
    "2.5.29.29": ("certificateIssuer", "CRL 扩展"),
    "2.5.29.30": ("nameConstraints", "标准扩展"),
    "2.5.29.31": ("cRLDistributionPoints", "标准扩展"),
    "2.5.29.32": ("certificatePolicies", "标准扩展"),
    "2.5.29.33": ("policyMappings", "标准扩展"),
    "2.5.29.35": ("authorityKeyIdentifier", "标准扩展"),
    "2.5.29.36": ("policyConstraints", "标准扩展"),
    "2.5.29.37": ("extendedKeyUsage", "标准扩展"),
    "2.5.29.54": ("inhibitAnyPolicy", "标准扩展"),
    # ---- PKIX（id-pkix） ----
    "1.3.6.1.5.5.7.1.1": ("authorityInfoAccess", "扩展：AIA"),
    "1.3.6.1.5.5.7.48.1": ("id-pkix-OCSP", "AIA 访问方法"),
    "1.3.6.1.5.5.7.48.2": ("caIssuers", "AIA 访问方法"),
    "1.3.6.1.5.5.7.3.1": ("serverAuth", "扩展用途"),
    "1.3.6.1.5.5.7.3.2": ("clientAuth", "扩展用途"),
    "1.3.6.1.5.5.7.3.3": ("codeSigning", "扩展用途"),
    "1.3.6.1.5.5.7.3.4": ("emailProtection", "扩展用途"),
    "1.3.6.1.5.5.7.3.8": ("timeStamping", "扩展用途"),
    # ---- RSA / PKCS（id-rsa，Dodge-Ferry 弧） ----
    "1.2.840.113549.1.1.1": ("rsaEncryption", "签名/密钥算法"),
    "1.2.840.113549.1.1.2": ("md2WithRSAEncryption", "签名算法"),
    "1.2.840.113549.1.1.4": ("md5WithRSAEncryption", "签名算法"),
    "1.2.840.113549.1.1.5": ("sha1WithRSAEncryption", "签名算法"),
    "1.2.840.113549.1.1.10": ("rsassaPss", "签名算法"),
    "1.2.840.113549.1.1.11": ("sha256WithRSAEncryption", "签名算法"),
    "1.2.840.113549.1.1.12": ("sha384WithRSAEncryption", "签名算法"),
    "1.2.840.113549.1.1.13": ("sha512WithRSAEncryption", "签名算法"),
    "1.2.840.113549.1.1.14": ("sha224WithRSAEncryption", "签名算法"),
    "1.2.840.113549.1.7.1": ("data", "PKCS#7 contentInfo 类型"),
    "1.2.840.113549.1.7.2": ("signedData", "PKCS#7 contentInfo 类型（.p7b）"),
    "1.2.840.113549.1.7.3": ("envelopedData", "PKCS#7 contentInfo 类型"),
    "1.2.840.113549.1.7.4": ("signedAndEnvelopedData", "PKCS#7 contentInfo 类型"),
    "1.2.840.113549.1.7.5": ("digestedData", "PKCS#7 contentInfo 类型"),
    "1.2.840.113549.1.7.6": ("encryptedData", "PKCS#7 contentInfo 类型"),
    "1.2.840.113549.1.9.1": ("emailAddress", "PKCS#9 属性"),
    "1.2.840.113549.1.9.2": ("unstructuredName", "PKCS#9 属性"),
    "1.2.840.113549.1.9.3": ("contentType", "CMS 属性"),
    "1.2.840.113549.1.9.4": ("messageDigest", "CMS 属性"),
    "1.2.840.113549.1.9.5": ("signingTime", "CMS 属性"),
    "1.2.840.113549.1.9.7": ("challengePassword", "PKCS#10 属性"),
    "1.2.840.113549.1.9.15": ("extensionRequest", "PKCS#10 属性"),
    # ---- 摘要算法 ----
    "1.2.840.113549.2.5": ("md5", "摘要算法"),
    "1.3.14.3.2.26": ("sha1", "摘要算法"),
    "2.16.840.1.101.3.4.2.1": ("sha256", "摘要算法"),
    "2.16.840.1.101.3.4.2.2": ("sha384", "摘要算法"),
    "2.16.840.1.101.3.4.2.3": ("sha512", "摘要算法"),
    "2.16.840.1.101.3.4.2.4": ("sha224", "摘要算法"),
    # ---- 椭圆曲线 / ECDSA ----
    "1.2.840.10045.2.1": ("id-ecPublicKey", "签名/密钥算法"),
    "1.2.840.10045.3.1.7": ("prime256v1 (secp256r1)", "命名曲线"),
    "1.3.132.0.34": ("secp384r1", "命名曲线"),
    "1.3.132.0.35": ("secp521r1", "命名曲线"),
    "1.2.840.10045.4.1": ("ecdsa-with-SHA1", "签名算法"),
    "1.2.840.10045.4.3.2": ("ecdsa-with-SHA256", "签名算法"),
    "1.2.840.10045.4.3.3": ("ecdsa-with-SHA384", "签名算法"),
    "1.2.840.10045.4.3.4": ("ecdsa-with-SHA512", "签名算法"),
    # ---- Edwards 曲线 ----
    "1.3.101.110": ("X25519", "命名曲线"),
    "1.3.101.111": ("X448", "命名曲线"),
    "1.3.101.112": ("Ed25519", "签名/密钥算法"),
    "1.3.101.113": ("Ed448", "签名/密钥算法"),
    # ---- 对称算法（CMS 常见） ----
    "2.16.840.1.101.3.4.1.2": ("aes128-CBC", "对称算法"),
    "2.16.840.1.101.3.4.1.6": ("aes192-CBC", "对称算法"),
    "2.16.840.1.101.3.4.1.22": ("aes256-CBC", "对称算法"),
    "1.2.840.113549.3.7": ("des-EDE3-CBC (3DES)", "对称算法"),
    # ---- 常见父级弧（最长前缀匹配的回退锚点） ----
    "1.2": ("member-body", "ISO 成员体"),
    "1.2.840": ("us", "美国国家机构（member-body US）"),
    "1.2.840.113549": ("rsadsi", "RSA Data Security, Inc."),
    "1.2.840.113549.1": ("pkcs", "PKCS（RSA 实验室）"),
    "1.2.840.10045": ("ansi-X9-62", "EC 曲线与算法（ANSI X9.62）"),
    "1.3.132": ("certicom", "Certicom 公司弧"),
    "1.3.132.0": ("ellipticCurve", "命名曲线"),
    "1.3.6.1.5.5.7": ("id-pkix", "PKIX（IETF）"),
    "2.5": ("ds", "X.500 目录服务（joint-iso-itu-t/ds）"),
    "2.5.4": ("id-at", "X.500 属性类型"),
    "2.5.29": ("id-ce", "X.509 证书扩展"),
    "2.16.840.1.101.3.4": ("nistAlgorithms", "NIST CSOR 算法"),
}


@dataclass(frozen=True)
class OidInfo:
    dotted: str
    name: str
    description: str = ""
    exact: bool = True  # False：仅最长前缀命中，name 是祖先名而非该 OID 的名称


# --------------------------------------------------------------------------
# OID 值区解码（decode / export 共用，避免私有函数穿透）
# --------------------------------------------------------------------------


def decode_arcs(
    raw: bytes,
    *,
    first_arc_1_3: bool = True,
    max_bytes: int = MAX_OID_BYTES,
) -> list[int] | None:
    """按 X.690 8.19 解码 OID 子标识符。

    ``first_arc_1_3=True`` 用于 universal OBJECT IDENTIFIER：首个组合值
    按 40*a1+a2 拆成两个弧；RELATIVE-OID 传 False。
    超过 ``max_bytes``、截断或为空时返回 ``None``。
    """
    if not raw or len(raw) > max_bytes:
        return None
    arcs: list[int] = []
    value = 0
    pending = 0  # 尚未收尾的高位基数
    first = True
    for byte in raw:
        value = (value << 7) | (byte & 0x7F)
        pending += 1
        if not byte & 0x80:
            if first and first_arc_1_3:
                if value < 40:
                    arcs.extend((0, value))
                elif value < 80:
                    arcs.extend((1, value - 40))
                else:
                    arcs.extend((2, value - 80))
            else:
                arcs.append(value)
            first = False
            value = 0
            pending = 0
    if pending:
        return None  # 以续位字节结尾（截断）
    return arcs


def dotted(raw: bytes, *, relative: bool = False) -> str | None:
    """OID 值区字节 → 点分文本；空/超长/非法/截断返回 None。"""
    arcs = decode_arcs(raw, first_arc_1_3=not relative)
    if not arcs:
        return None
    try:
        return ".".join(str(x) for x in arcs)
    except ValueError:
        # 防御 Python 3.11+ 的 int→str 十进制位数上限；正常应被 max_bytes 挡住。
        return None


# 合并后的全量库（补充表 ∪ dumpasn1 库），首次查询时加载
_DB: dict[str, tuple[str, str]] | None = None


def _load_db() -> dict[str, tuple[str, str]]:
    """加载 JSON 库并与补充表合并（补充表优先）。文件缺失则仅用补充表。"""
    global _DB
    if _DB is not None:
        return _DB
    merged: dict[str, tuple[str, str]] = dict(_PKI_SUPPLEMENT)
    try:
        resource = _res_files("asn1peek.core").joinpath(*_DATA_REL)
        payload = json.loads(resource.read_text(encoding="utf-8"))
        for dotted, (name, desc) in payload.items():
            merged.setdefault(dotted, (name, desc))  # 补充表优先（去重）
    except (OSError, ValueError, TypeError):
        pass  # 数据缺失/损坏：退化为内置表，不崩溃
    _DB = merged
    return _DB


def _iter_prefixes(dotted: str):
    """点分 OID 的祖先前缀，从最长到最短（不含自身）。"""
    parts = dotted.split(".")
    for i in range(len(parts) - 1, 0, -1):
        yield ".".join(parts[:i])


def _prefix_info(dotted: str, db: dict[str, tuple[str, str]]) -> OidInfo | None:
    """最长前缀匹配：返回最近的已收录祖先条目。"""
    for prefix in _iter_prefixes(dotted):
        entry = db.get(prefix)
        if entry is not None:
            return OidInfo(prefix, entry[0], entry[1])
    return None


def lookup(dotted: str) -> OidInfo | None:
    """精确 → 最长前缀两级查询；未知返回 None（显示 dotted 不崩溃）。"""
    db = _load_db()
    leaf = db.get(dotted)
    parent = _prefix_info(dotted, db)
    if leaf is None:
        if parent is None:
            return None
        # 未收录的子 OID：显示父名 + 归属提示（如 2.5.29 → id-ce）
        return OidInfo(
            dotted,
            parent.name,
            f"{dotted} 未收录，归入 {parent.dotted}（{parent.name}）",
            exact=False,
        )
    name, desc = leaf
    if not desc and parent is not None and parent.dotted != dotted:
        desc = f"{parent.name} 子项"
    return OidInfo(dotted, name, desc)


def known_names() -> int:
    return len(_load_db())


def pki_supplement() -> dict[str, tuple[str, str]]:
    """返回内置 PKI 补充表的副本（供 build_oids 等外部工具使用）。"""
    return dict(_PKI_SUPPLEMENT)


def pki_supplement_size() -> int:
    return len(_PKI_SUPPLEMENT)
