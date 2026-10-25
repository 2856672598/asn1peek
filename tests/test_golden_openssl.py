"""黄金对照：解析结果与 `openssl asn1parse` 逐节点一致。

对 samples/ 下真实文件核对每个节点 offset / depth / value_len；
universal 类型节点额外核对类型名（context 类 asn1parse 记 cont，不比对）。
内嵌 DER 探测节点不属于 asn1parse 可见层级，跳过。
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from asn1peek.core.parser import parse_document
from asn1peek.core.sniff import sniff

SAMPLES = Path(__file__).parent.parent / "samples"

ASN1PARSE_TAG_NUMBER = {
    "INTEGER": 2,
    "BOOLEAN": 1,
    "BIT STRING": 3,
    "OCTET STRING": 4,
    "NULL": 5,
    "OBJECT": 6,
    "ENUMERATED": 10,
    "SEQUENCE": 16,
    "SET": 17,
    "UTF8String": 12,
    "NumericString": 18,
    "PrintableString": 19,
    "T61String": 20,
    "IA5String": 22,
    "UTCTIME": 23,
    "UTCTime": 23,
    "GENERALIZEDTIME": 24,
    "GeneralizedTime": 24,
    "BMPString": 30,
    "VisibleString": 26,
}

ROW_RE = re.compile(r"^\s*(\d+):d=\s*(\d+)\s+hl=\s*(\d+)\s+l=\s*(\d+)\s+(prim|cons):\s*(\S.*)?$")


def asn1parse_rows_of_blob(blob: bytes, tmpdir: Path) -> dict[int, tuple[int, int, str]]:
    path = tmpdir / "blob.der"
    path.write_bytes(blob)
    out = subprocess.run(
        ["openssl", "asn1parse", "-inform", "der", "-in", str(path)],
        capture_output=True,
        text=True,
        check=True,
    )
    rows: dict[int, tuple[int, int, str]] = {}
    for line in out.stdout.splitlines():
        m = ROW_RE.match(line)
        if not m:
            continue
        offset, depth, l_len = int(m.group(1)), int(m.group(2)), int(m.group(4))
        name = (m.group(6) or "").split(":")[0].strip()
        rows[offset] = (depth, l_len, name)
    return rows


def _is_inside_embedded(node) -> bool:
    n = node
    while n is not None:
        if n.is_embedded:
            return True
        n = n.parent
    return False


def check_blob(blob: bytes, tmpdir: Path, min_checked: int = 20) -> None:
    rows = asn1parse_rows_of_blob(blob, tmpdir)
    doc = parse_document(blob)
    assert doc.roots, "无顶层节点"

    checked = 0
    for node in doc.iter_roots_deep():
        if node.is_embedded or _is_inside_embedded(node):
            continue
        assert node.error is None, f"意外错误节点 @0x{node.offset:X}: {node.error}"
        expected = rows.get(node.offset)
        assert expected is not None, f"asn1parse 没有 offset {node.offset} 的行"
        depth, value_len, name = expected
        assert node.depth == depth, f"depth 不一致 @{node.offset}: {node.depth} vs {depth}"
        assert node.value_len == value_len, (
            f"长度不一致 @{node.offset}: {node.value_len} vs {value_len}"
        )
        if node.tag_class == 0 and name in ASN1PARSE_TAG_NUMBER:
            assert node.tag_number == ASN1PARSE_TAG_NUMBER[name], (
                f"类型不一致 @{node.offset}: ours={node.tag_number} vs {name}"
            )
        checked += 1
    assert checked >= min_checked, f"对照节点过少（{checked}）"


def fetch_blobs(path: Path) -> list[bytes]:
    result = sniff(path.read_bytes())
    assert result.blobs, "sniff 没有得到 blob"
    return result.blobs


@pytest.mark.skipif(shutil.which("openssl") is None, reason="无 openssl")
@pytest.mark.parametrize(
    "name",
    [
        "leaf.der",
        "root.der",
        "leaf.pem",
        "root.pem",
        "ecc.der",
        "ecc.pem",
        "intermediate.pem",
        "chain.pem",
        "certs.p7b",
    ],
)
def test_golden_against_asn1parse(name: str):
    path = SAMPLES / name
    if not path.exists():
        pytest.skip(f"样例未生成: {name}")
    blobs = fetch_blobs(path)
    with tempfile.TemporaryDirectory() as td:
        tmpdir = Path(td)
        for blob in blobs:
            check_blob(blob, tmpdir)
