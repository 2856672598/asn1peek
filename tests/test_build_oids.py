"""tools/build_oids.py 解析测试。

真实 dumpasn1.cfg 格式（cryptlib/dumpasn1，CRLF 行尾）：
    OID = 2 5 4 3
    Comment = X.520 DN component
    Description = commonName

覆盖：真实格式、值内含 '#'、无 Comment 条目、Warning 标记行、旧式单行回退、
与补充表合并时的优先级。
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).parent.parent


def _load_build_oids():
    spec = importlib.util.spec_from_file_location("build_oids", ROOT / "tools" / "build_oids.py")
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def test_parse_real_format_crlf():
    mod = _load_build_oids()
    text = (
        "# dumpasn1 OID configuration (简化片段)\r\n"
        "\r\n"
        "OID = 2 5 4 3\r\n"
        "Comment = X.520 DN component\r\n"
        "Description = commonName\r\n"
        "\r\n"
        "OID = 1 2 840 113549 1 1 11\r\n"
        "Comment = PKCS #1\r\n"  # 值内 # 不得被当作行内注释
        "Description = sha256WithRSAEncryption\r\n"
        "\r\n"
        "OID = 1 2 840 113549 1 3\r\n"  # 无 Comment 的条目
        "Description = pkcs-3\r\n"
        "\r\n"
        "Warning\r\n"  # 独立标记行忽略
    )
    entries = mod.parse_dumpasn1_cfg(text)
    assert entries["2.5.4.3"] == ("commonName", "X.520 DN component")
    assert entries["1.2.840.113549.1.1.11"] == ("sha256WithRSAEncryption", "PKCS #1")
    assert entries["1.2.840.113549.1.3"] == ("pkcs-3", "")


def test_parse_legacy_single_line():
    mod = _load_build_oids()
    entries = mod.parse_dumpasn1_cfg("2.5.4.3\tcommonName\n")
    assert entries == {"2.5.4.3": ("commonName", "")}


def test_build_merges_supplement_priority(tmp_path: Path):
    """同 dotted 时补充表优先（去重语义）。"""
    mod = _load_build_oids()
    cfg = tmp_path / "mini.cfg"
    cfg.write_text(
        "OID = 1 2 840 113549 1 1 11\r\nDescription = shadowed\r\n",
        encoding="utf-8",
    )
    merged, cfg_count = mod.build(cfg)
    assert cfg_count == 1
    assert merged["1.2.840.113549.1.1.11"] == ("sha256WithRSAEncryption", "签名算法")
