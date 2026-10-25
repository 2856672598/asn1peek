"""详情面板（TLV 检视）回归：ID / Length / Value 块。

显示规则：
- 任何节点统一三行：ID（tag 十六进制 + 类型，右端标签类别）、
  Length（值长：十六进制 + 十进制）、Value；
- Value 有可读语义时显示解析值（OID：dotted + 名称；时间：ISO 8601；
  字符串/BOOLEAN/NULL 同理），不再重复十六进制；
- 无可读语义时显示值区转储：每行 16 字节、最多 12 行，超出提示
  `another N lines skipped.....`；「视图→显示解码信息」关闭时回退到转储；
- 路径/偏移不再常驻面板（偏移走树节点 tooltip，路径走右键「复制路径」）；
- 错误节点在块尾红字给出 `offset 0x…: 消息`。
"""

from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest

from asn1peek.core.parser import parse_document
from asn1peek.ui.detail_panel import DetailPanel


@pytest.fixture()
def panel(qapp):
    widget = DetailPanel()
    widget.resize(600, 400)
    yield widget
    widget.close()


def _show(panel: DetailPanel, der: bytes) -> str:
    doc = parse_document(der)
    panel.show_node(doc.roots[0])
    return panel.toPlainText()


def test_container_block(panel):
    """容器节点：ID/Length/Value 三行 + 值区转储（不是子树预览）。"""
    text = _show(panel, bytes.fromhex("3006020105020106"))
    assert "ID     : [0X30] SEQUENCE" in text
    assert "Universal" in text
    assert "Length : [0X00000006] 6" in text
    assert "Value  :" in text
    assert "         02 01 05 02 01 06" in text
    assert "路径" not in text
    assert "位置" not in text


def test_oid_block_shows_dotted_then_name(panel):
    """OID：Value 下先 dotted，再名称；不再显示原始十六进制。"""
    text = _show(panel, bytes.fromhex("06092A864886F70D01010B"))
    assert "ID     : [0X06] OBJECT IDENTIFIER" in text
    assert "Length : [0X00000009] 9" in text
    assert ("\n         1.2.840.113549.1.1.11\n         sha256WithRSAEncryption") in text
    assert "2a 86 48 86 f7 0d 01 01 0b" not in text
    assert "解码" not in text
    assert "名称" not in text
    assert "说明" not in text


def test_context_tag_class(panel):
    text = _show(panel, bytes.fromhex("a003020102"))
    assert "ID     : [0XA0] Context[0]" in text
    assert "Context-specific" in text


def test_dump_truncation_note(panel):
    der = b"\x04\x81\xc8" + bytes(200)  # 200 字节 → 13 行，显示 12 行
    text = _show(panel, der)
    assert "another 1 lines skipped....." in text


def test_dump_without_truncation_note(panel):
    text = _show(panel, bytes.fromhex("030400DEADBE"))
    assert "skipped" not in text
    assert "de ad be" in text  # BIT STRING 未用位计数 + 内容


def test_bit_string_unused_byte_leads_first_row(panel):
    """BIT STRING：未用位字节 + 15 数据字节凑满首行 16 字节。"""
    der = b"\x03\x21\x00" + bytes(range(32))
    text = _show(panel, der)
    assert "         00 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e" in text
    assert "         0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e" in text
    assert "         1f" in text


def test_error_node_block(panel):
    text = _show(panel, b"\x30\x82\x99\x99\x01")
    assert "ID     : ERROR" in text
    assert "30 82 99 99 01" in text  # 垃圾区转储
    assert "offset 0x0:" in text


def test_placeholder_shows_document_summary(panel):
    doc = parse_document(bytes.fromhex("020105"))
    panel.set_document(doc)
    text = panel.toPlainText()
    assert "文档概要" in text
    assert "顶层对象" in text


def test_empty_oid_shows_summary(panel):
    text = _show(panel, bytes.fromhex("0600"))
    assert "空 OID" in text
    assert text.split("Value")[-1].strip()


def test_oversized_oid_shows_summary(panel):
    der = b"\x06\x82\x01\x01" + b"\x2a" * 257
    text = _show(panel, der)
    assert "OID 过大（257 字节，不展开）" in text


def test_long_text_is_truncated_with_note(panel):
    raw = b"A" * 5000
    der = b"\x0c\x82\x13\x88" + raw
    text = _show(panel, der)
    assert "A" * 4096 in text
    assert "A" * 4097 not in text
    assert "文本超过 4096 字符，已截断" in text


# %------------------------------------------------------------------------
# Value 可读解析值（OID / 时间 / 字符串；默认开，视图菜单可关）
# -------------------------------------------------------------------------


def test_oid_unknown_has_no_name_line(panel):
    """完全未知的 OID：Value 下只有 dotted，不补任何名称行。"""
    text = _show(panel, bytes.fromhex("0605002A00002A"))  # 0.0.42.0.0.42
    lines = text.splitlines()
    value_index = next(i for i, line in enumerate(lines) if line.startswith("Value"))
    assert [line.strip() for line in lines[value_index + 1 :] if line.strip()] == ["0.0.42.0.0.42"]


def test_oid_prefix_only_does_not_show_parent_name(panel):
    """仅命中父前缀（1.2.3.4 → member-body）不是该 OID 的名称 → 不显示。"""
    text = _show(panel, bytes.fromhex("06032A0304"))
    assert "\n         1.2.3.4" in text
    assert "member-body" not in text


def test_time_value_is_iso8601(panel):
    text = _show(panel, bytes.fromhex("170D3236313031373036333330385A"))
    assert "\n         2026-10-17T06:33:08Z" in text
    assert "261017063308Z" not in text
    assert "ISO 8601" not in text
    assert "解码" not in text


def test_string_value_is_decoded_text(panel):
    text = _show(panel, b"\x0c\x08asn1peek")
    assert "\n         asn1peek" in text
    assert "61 73 6e 31 70 65 65 6b" not in text


def test_boolean_and_null_values(panel):
    assert "\n         TRUE" in _show(panel, b"\x01\x01\xff")
    assert "\n         FALSE" in _show(panel, b"\x01\x01\x00")
    assert "\n         NULL" in _show(panel, b"\x05\x00")


def test_no_semantic_value_falls_back_to_dump(panel):
    """INTEGER / OCTET STRING / BIT STRING / 容器：继续显示十六进制转储。"""
    text = _show(panel, bytes.fromhex("020102"))
    assert "\n         02" in text
    assert "\n         2" not in text
    assert "41 42 43" in _show(panel, bytes.fromhex("0403414243"))
    assert "de ad be" in _show(panel, bytes.fromhex("030400DEADBE"))
    assert "02 01 05 02 01 06" in _show(panel, bytes.fromhex("3006020105020106"))


def test_big_integer_falls_back_to_dump(panel):
    der = bytes.fromhex("02140617d7fd7214c11d559f33056d9c8cd443e065dc")
    text = _show(panel, der)
    assert "06 17 d7 fd" in text


def test_decoded_toggle_off_and_on(panel):
    der = bytes.fromhex("06092A864886F70D01010B")
    assert "sha256WithRSAEncryption" in _show(panel, der)
    panel.set_decoded_visible(False)
    text = panel.toPlainText()
    assert "sha256WithRSAEncryption" not in text  # 立即按当前节点重绘
    assert "2a 86 48 86 f7 0d 01 01 0b" in text
    panel.set_decoded_visible(True)
    assert "sha256WithRSAEncryption" in panel.toPlainText()
