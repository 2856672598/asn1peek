"""export.py 纯函数单测。

覆盖：
- node_bytes：完整 TLV（含 tag+length+value）；不定长节点含 EOC；错误节点为垃圾区；
- der_hex / der_base64：与 xxd/base64 -d 可互证；
- subtree_text：行数/缩进/偏移与树结构一致（含内嵌 DER）；
- wrap_pem。
"""

from __future__ import annotations

import base64
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from asn1peek.core import export
from asn1peek.core.export import (
    ValueVariant,
    copy_value_variants,
    der_base64,
    der_hex,
    node_bytes,
    subtree_text,
    value_dump_lines,
    wrap_pem,
)
from asn1peek.core.parser import parse_document
from asn1peek.core.sniff import sniff

SAMPLES = Path(__file__).parent.parent / "samples"


def _tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag, len(value)]) + value


def _nested() -> bytes:
    inner = _tlv(0x02, b"\x05") + _tlv(0x0C, b"hello")
    return _tlv(0x30, inner) + _tlv(0x02, b"\x01")


# ---- node_bytes ---------------------------------------------------------


class TestNodeBytes:
    def test_full_tlv_leaf(self):
        doc = parse_document(b"\x02\x01\x05")
        node = doc.roots[0]
        assert node_bytes(node) == b"\x02\x01\x05"  # tag+len+value 全包含

    def test_nested_tlv(self):
        data = _nested()
        doc = parse_document(data)
        root = doc.roots[0]
        assert node_bytes(root) == data[: root.total_len]
        child = root.child_items[0]
        assert node_bytes(child) == data[child.offset : child.end]

    def test_indefinite_includes_eoc(self):
        # 31 80 02 01 05 00 00 —— SET 不定长 + EOC
        data = b"\x31\x80\x02\x01\x05\x00\x00"
        doc = parse_document(data)
        root = doc.roots[0]
        assert root.length_form == "indefinite"
        assert node_bytes(root) == data  # 原始 TLV 保持不变

    def test_nested_indefinite_exports_both_eocs(self):
        data = bytes.fromhex("3180308002010500000201060000")
        doc = parse_document(data)
        root = doc.roots[0]
        inner = root.child_items[0]
        assert node_bytes(root) == data
        assert node_bytes(inner) == data[2:9]

    def test_error_node_garbage_span(self):
        doc = parse_document(b"\xff\x99\x99\x99")  # 垃圾
        root = doc.roots[0]
        assert root.error is not None
        assert node_bytes(root) == b"\xff\x99\x99\x99"


# ---- Hex / Base64 互证 ---------------------------------------------------


class TestEncodings:
    def test_hex_matches_stdlib(self):
        doc = parse_document(_nested())
        node = doc.roots[0]
        raw = node_bytes(node)
        assert der_hex(raw) == raw.hex().upper()
        assert bytes.fromhex(der_hex(raw)) == raw

    def test_base64_matches_stdlib(self):
        raw = bytes(range(256))
        text = der_base64(raw)
        assert base64.b64decode(text, validate=True) == raw


# ---- 子树文本 ------------------------------------------------------------


class TestSubtreeText:
    def test_structure_matches_tree(self):
        data = _nested()
        doc = parse_document(data)
        text = subtree_text(doc.roots[0])
        lines = text.splitlines()
        nodes = list(doc.roots[0].iter_nodes())
        assert len(lines) == len(nodes)  # 不含内嵌/EOC 时行数与节点数一致
        # 行首缩进 = 2×深度，其后是固定宽度偏移/长度列
        for line, node in zip(lines, nodes, strict=False):
            assert line.startswith("  " * node.depth)
            assert f"{node.offset:d}" in line
            assert node.type_name in line

    def test_indentation_increases(self):
        doc = parse_document(_nested())
        lines = subtree_text(doc.roots[0]).splitlines()
        # 类型名列的起始位置随深度递增（固定宽度偏移/长度列在缩进之后）
        col0 = lines[0].index("SEQUENCE")
        col1 = lines[1].index("INTEGER")
        assert col1 > col0

    def test_embedded_marker(self):
        """内嵌 DER 子树带有 --> 标记。"""
        data = sniff((SAMPLES / "leaf.der").read_bytes()).blobs[0]
        doc = parse_document(data)
        embedded = next((n for n in doc.iter_roots_deep() if n.is_embedded), None)
        if embedded is None:
            pytest.skip("样例无内嵌 DER")
        text = subtree_text(embedded.parent)
        assert "-->" in text

    def test_eoc_line_comes_after_children(self):
        """不定长节点的 EOC 行必须排在全部子节点之后。"""
        data = bytes.fromhex("3180308002010500000201060000")
        text = subtree_text(parse_document(data).roots[0])
        lines = text.splitlines()
        integer_index = next(i for i, line in enumerate(lines) if "INTEGER" in line)
        eoc_indexes = [i for i, line in enumerate(lines) if line.endswith(": EOC")]
        assert len(eoc_indexes) == 2
        assert all(index > integer_index for index in eoc_indexes)


class TestValueDump:
    """详情面板「Value」区转储：小写、16 字节/行、与 ID/Length 值列对齐。"""

    def test_lines_and_indent(self):
        doc = parse_document(b"\x04\x20" + bytes(range(32)))
        lines, skipped = value_dump_lines(doc.roots[0])
        assert skipped == 0
        assert lines == [
            "         00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f",
            "         10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f",
        ]

    def test_max_lines_and_skipped(self):
        doc = parse_document(b"\x04\x81\xc8" + bytes(200))  # 200 字节 → 13 行
        lines, skipped = value_dump_lines(doc.roots[0])
        assert len(lines) == 12
        assert skipped == 1

    def test_error_node_dumps_garbage_area(self):
        doc = parse_document(b"\x30\x82\x99\x99\x01")
        node = doc.roots[0]
        assert node.error is not None
        lines, skipped = value_dump_lines(node)
        assert lines == ["         30 82 99 99 01"]
        assert skipped == 0

    def test_bit_string_prefix_leads_first_row(self):
        # BIT STRING：未用位字节 + 15 个数据字节 = 首行 16 字节，后续每行 16 字节
        der = b"\x03\x21\x00" + bytes(range(32))
        node = parse_document(der).roots[0]
        lines, skipped = value_dump_lines(node)
        assert skipped == 0
        assert lines == [
            "         00 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e",
            "         0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e",
            "         1f",
        ]

    def test_bit_string_skip_count_flat(self):
        # 257 字节值共 17 行，最多显示 12 行，其余计入 skipped。
        der = b"\x03\x82\x01\x01\x00" + bytes(256)
        node = parse_document(der).roots[0]
        lines, skipped = value_dump_lines(node)
        assert len(lines) == 12
        assert skipped == 5
        assert len(lines[0].split()) == 16  # 未用位 + 15 数据字节
        assert len(lines[1].split()) == 16

    def test_last_row_is_clamped_to_value_end(self):
        """最后一行不得读入后续 TLV；17 字节值只显示末尾 1 字节。"""
        der = b"\x04\x11" + bytes(range(17)) + b"\x02\x01\xaa"
        node = parse_document(der).roots[0]
        lines, skipped = value_dump_lines(node, max_lines=99)
        assert skipped == 0
        assert lines == [
            "         00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f",
            "         10",
        ]
        assert "02 01 aa" not in "\n".join(lines)

    def test_last_row_bit_string_is_clamped(self):
        der = b"\x03\x11\x00" + bytes(range(16)) + b"\x05\x00"
        node = parse_document(der).roots[0]
        lines, _ = value_dump_lines(node, max_lines=99)
        assert lines[-1] == "         0f"
        assert "05 00" not in "\n".join(lines)

    @pytest.mark.parametrize("raw_len", [15, 16, 17, 31, 32, 33])
    def test_bit_string_rows_cover_exact_value_bytes(self, raw_len):
        """BIT STRING 任意长度下列数/偏移一致，且不越过值区。"""
        value = b"\x00" + bytes(i % 256 for i in range(raw_len - 1))
        der = bytes([0x03, raw_len]) + value + b"\xde\xad\xbe\xef"
        node = parse_document(der).roots[0]
        lines, skipped = value_dump_lines(node, max_lines=99)
        assert skipped == 0
        assert len(lines) == (raw_len + 15) // 16
        shown = b"".join(bytes.fromhex(line.replace(" ", "")) for line in lines)
        assert shown == value
        assert "de ad be ef" not in "\n".join(lines)

    def test_large_value_materializes_only_visible_lines(self, monkeypatch):
        """4 MiB 值也只构造 12 行，不先把整个值区拆成数万行字符串。"""
        size = 4 * 1024 * 1024
        der = b"\x04\x84" + size.to_bytes(4, "big") + bytes(size)
        node = parse_document(der).roots[0]
        calls = []
        original = export._dump_line

        def counting(raw):
            calls.append(len(raw))
            return original(raw)

        monkeypatch.setattr(export, "_dump_line", counting)
        lines, skipped = value_dump_lines(node)
        assert len(lines) == 12
        assert len(calls) == 12
        assert skipped == size // 16 - 12


class TestCopyValueVariants:
    """复制值：稳定 key，不依赖 details 中文标签。"""

    @staticmethod
    def _node(der: bytes):
        return parse_document(der).roots[0]

    @staticmethod
    def _pairs(node) -> list[tuple[str, str]]:
        return [(v.key, v.text) for v in copy_value_variants(node)]

    def test_valuevariant_is_frozen_dataclass(self):
        variant = ValueVariant("text", "x")
        assert variant.key == "text" and variant.text == "x"
        with pytest.raises(FrozenInstanceError):
            variant.key = "y"  # type: ignore[misc]

    def test_oid_dotted_then_name(self):
        node = self._node(bytes.fromhex("06092A864886F70D01010B"))
        assert self._pairs(node) == [
            ("oid-dotted", "1.2.840.113549.1.1.11"),
            ("oid-name", "sha256WithRSAEncryption"),
        ]

    def test_oid_without_exact_name_has_only_dotted(self):
        node = self._node(bytes.fromhex("0605002A00002A"))
        assert self._pairs(node) == [("oid-dotted", "0.0.42.0.0.42")]

    def test_empty_and_oversized_oid_have_no_variants(self):
        assert copy_value_variants(self._node(bytes.fromhex("0600"))) == []
        raw = b"\x2a" + b"\x81" * 300 + b"\x00"
        der = b"\x06\x82" + len(raw).to_bytes(2, "big") + raw
        assert copy_value_variants(self._node(der)) == []

    def test_relative_oid(self):
        node = self._node(bytes.fromhex("0D02852A"))
        assert self._pairs(node) == [("relative-oid", "682")]

    def test_empty_relative_oid_has_no_variants(self):
        assert copy_value_variants(self._node(bytes.fromhex("0D00"))) == []

    def test_integer_decimal_and_hex(self):
        node = self._node(bytes.fromhex("020105"))
        assert self._pairs(node) == [("int-decimal", "5"), ("int-hex", "05")]

    def test_large_integer_keeps_hex_only(self):
        raw = b"\x7f" + b"\xff" * 1999
        der = b"\x02\x82" + len(raw).to_bytes(2, "big") + raw
        pairs = self._pairs(self._node(der))
        assert [key for key, _ in pairs] == ["int-hex"]
        assert len(pairs[0][1]) == 4000

    def test_octet_and_bit_variants(self):
        octet = self._node(bytes.fromhex("0403414243"))
        assert self._pairs(octet) == [
            ("octet-hex", "414243"),
            ("octet-base64", "QUJD"),
        ]
        bit = self._node(bytes.fromhex("030400DEADBE"))
        assert self._pairs(bit) == [
            ("bit-hex", "DEADBE"),
            ("bit-base64", "3q2+"),
        ]

    def test_time_text_boolean_null(self):
        assert self._pairs(self._node(bytes.fromhex("170D3234303430353132333435365A"))) == [
            ("time-iso", "2024-04-05T12:34:56Z"),
            ("time-raw", "240405123456Z"),
        ]
        assert self._pairs(self._node(b"\x0c\x02hi")) == [("text", "hi")]
        assert self._pairs(self._node(b"\x01\x01\xff")) == [("boolean", "TRUE")]
        assert self._pairs(self._node(b"\x05\x00")) == [("null", "NULL")]

    def test_oversized_time_does_not_copy_whole_value(self):
        raw = b"2" * 200
        node = self._node(b"\x17\x81\xc8" + raw)
        assert self._pairs(node) == []

    def test_container_error_and_oversized_value_are_empty(self):
        assert copy_value_variants(self._node(bytes.fromhex("3003020105"))) == []
        assert copy_value_variants(self._node(b"\x30\x82\x99\x99\x01")) == []
        size = (1 << 20) + 1
        der = b"\x04\x83" + size.to_bytes(3, "big") + b"\x00" * size
        assert copy_value_variants(self._node(der)) == []

    def test_unknown_primitive_has_hex_and_base64(self):
        node = self._node(bytes.fromhex("8101FF"))
        assert self._pairs(node) == [("hex", "FF"), ("base64", "/w==")]


# ---- PEM -----------------------------------------------------------------


class TestPem:
    def test_wrap_pem_roundtrip(self):
        raw = (SAMPLES / "leaf.der").read_bytes()
        pem = wrap_pem(raw, "CERTIFICATE")
        assert pem.startswith("-----BEGIN CERTIFICATE-----\n")
        body = pem.split("\n", 1)[1].split("-----END")[0]
        assert base64.b64decode(body) == raw
