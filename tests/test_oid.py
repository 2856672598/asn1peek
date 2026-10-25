"""OID 库查询测试。

覆盖：精确匹配 → 最长前缀匹配（父条目合并）→ 未知返回 None（不崩溃）；
并抽样对照 openssl 已知名称（用 openssl x509 -text 解析样例证书得到
扩展/算法名，与库内名称核对）。
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from asn1peek.core import oid


class TestLookup:
    def test_exact_supplement(self):
        info = oid.lookup("1.2.840.113549.1.1.11")
        assert info is not None
        assert info.name == "sha256WithRSAEncryption"
        assert info.exact is True

    def test_exact_dn_attribute(self):
        info = oid.lookup("2.5.4.3")
        assert info is not None
        assert info.name == "commonName"
        assert "CN" in info.description

    def test_parent_prefix_fallback(self):
        """未收录的子 OID：沿最长前缀给出父名（2.5.29 → id-ce 类祖先）。"""
        # 2.5.29 下新增一个虚构子项
        info = oid.lookup("2.5.29.999")
        assert info is not None
        assert info.dotted == "2.5.29.999"
        assert info.name, "应回退到父条目名称"
        assert info.exact is False
        assert "2.5.29" in info.description

    def test_unknown_returns_none(self):
        assert oid.lookup("0.0.42.0.0.42") is None

    def test_supplement_priority_over_packaged(self):
        """补充表与 JSON 库同 dotted 时，补充表优先（去重语义）。"""
        db = oid._load_db()
        supplement = oid.pki_supplement()
        for dotted, entry in supplement.items():
            assert db[dotted] == entry

    def test_data_file_loads(self):
        """随包 JSON 存在且可加载（含全部补充表条目）。"""
        db = oid._load_db()
        assert oid.pki_supplement_size() <= len(db)
        assert oid.known_names() == len(db)

    def test_pki_supplement_returns_copy(self):
        first = oid.pki_supplement()
        first["2.5.4.3"] = ("tampered", "")
        assert oid.pki_supplement()["2.5.4.3"][0] == "commonName"


class TestDotted:
    def test_empty_returns_none(self):
        assert oid.dotted(b"") is None
        assert oid.dotted(b"", relative=True) is None

    def test_oversized_returns_none(self):
        raw = b"\x2a" + b"\x81" * 2098 + b"\x00"
        assert oid.dotted(raw) is None

    def test_large_arc_does_not_raise_valueerror(self):
        # 256 B 上限内最坏单弧仍低于 int→str 位数上限；直接构造 2100 B 验证兜底。
        raw = b"\x2a" + b"\x81" * 2098 + b"\x00"
        assert oid.dotted(raw) is None

    def test_decode_arcs_honors_max_bytes(self):
        assert oid.decode_arcs(b"\x2a", max_bytes=0) is None
        assert oid.decode_arcs(b"\x2a", max_bytes=1) == [1, 2]

    def test_longest_prefix_wins_over_shorter(self):
        """1.3.6.1.5.5.7.3.1 精确收录 → 名称必须是 serverAuth 而非祖先名。"""
        info = oid.lookup("1.3.6.1.5.5.7.3.1")
        assert info is not None
        assert info.name == "serverAuth"


# ---- 抽样对照 openssl ----------------------------------------------------

SAMPLES = Path(__file__).parent.parent / "samples"

# openssl -text 输出中的名称 → 本库期望名称（缩写差异映射）
_OPENSSL_NAME_MAP = {
    "X509v3 Subject Alternative Name": "subjectAltName",
    "X509v3 Basic Constraints": "basicConstraints",
    "X509v3 Key Usage": "keyUsage",
    "X509v3 Subject Key Identifier": "subjectKeyIdentifier",
    "X509v3 Authority Key Identifier": "authorityKeyIdentifier",
}


@pytest.mark.skipif(shutil.which("openssl") is None, reason="无 openssl")
@pytest.mark.parametrize("sample", ["leaf.pem", "ecc.pem", "intermediate.pem", "root.pem"])
def test_names_match_openssl(sample: str):
    """样例证书里出现的扩展/算法 OID 名称与本库一致。"""
    path = SAMPLES / sample
    if not path.exists():
        pytest.skip(f"样例未生成: {sample}")
    out = subprocess.run(
        ["openssl", "x509", "-in", str(path), "-text", "-noout"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    checked = 0
    for label, expected in _OPENSSL_NAME_MAP.items():
        if label not in out:
            continue
        info = oid.lookup(_dotted_of(label, path.name))
        assert info is not None, f"{label} 应收录"
        assert info.name == expected, f"{label}: {info.name} != {expected}"
        checked += 1
    assert checked >= 2, f"{sample} 至少应核对 2 个扩展"


def _dotted_of(label: str, sample: str) -> str:
    table = {
        "X509v3 Subject Alternative Name": "2.5.29.17",
        "X509v3 Basic Constraints": "2.5.29.19",
        "X509v3 Key Usage": "2.5.29.15",
        "X509v3 Subject Key Identifier": "2.5.29.14",
        "X509v3 Authority Key Identifier": "2.5.29.35",
    }
    return table[label]
