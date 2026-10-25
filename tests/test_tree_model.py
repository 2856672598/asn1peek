"""结构树显示回归：第一列只显示结构，不展示解码值。

非 universal 标签显示为 ``Context[n]`` / ``Application[n]`` /
``Private[n]``；内嵌节点加 ``⤷`` 前缀。
"""

from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtCore import Qt

from asn1peek.core.parser import parse_document
from asn1peek.ui.tree_model import Asn1TreeModel


def _display(model: Asn1TreeModel, index) -> str:
    return model.data(index, Qt.DisplayRole)


def test_oid_shows_type_only(qapp):
    """OID 节点：只显示 OBJECT IDENTIFIER，dotted 与名称都不出现。"""
    doc = parse_document(bytes.fromhex("06092A864886F70D01010B"))  # 1.2.840.113549.1.1.11
    assert "sha256WithRSAEncryption" in doc.roots[0].summary  # 前置：解码结果确有名称
    model = Asn1TreeModel(doc)
    text = _display(model, model.index(0, 0))
    assert text == "OBJECT IDENTIFIER"
    assert "1.2.840" not in text


@pytest.mark.parametrize(
    "der,expected",
    [
        (bytes.fromhex("020105"), "INTEGER"),
        (bytes.fromhex("030400DEADBE"), "BIT STRING"),
        (b"\x0c\x08asn1peek", "UTF8String"),
        (bytes.fromhex("04020102"), "OCTET STRING"),
        (bytes.fromhex("0500"), "NULL"),
    ],
)
def test_scalar_nodes_show_type_only(qapp, der, expected):
    """标量节点：不再附带数值/字节预览/字符串内容。"""
    model = Asn1TreeModel(parse_document(der))
    assert _display(model, model.index(0, 0)) == expected


@pytest.mark.parametrize(
    "der,expected",
    [
        (bytes.fromhex("A003020102"), "Context[0]"),  # [0] EXPLICIT
        (bytes.fromhex("800101"), "Context[0]"),  # [0] IMPLICIT（原始）
        (bytes.fromhex("6100"), "Application[1]"),
        (bytes.fromhex("E20100"), "Private[2]"),
    ],
)
def test_non_universal_tags_show_class_name(qapp, der, expected):
    """非 universal 标签：Context[n]/Application[n]/Private[n]。"""
    model = Asn1TreeModel(parse_document(der))
    assert _display(model, model.index(0, 0)) == expected


def test_warning_and_error_markers_kept(qapp):
    """⚠（非最小编码）与 ✗（解析错误）标记保留——它们是结构信号，非解码值。"""
    warned = parse_document(b"\x02\x81\x05\x00\x00\x00\x00\x00")  # 长形式编码小长度
    assert warned.roots[0].warnings
    model = Asn1TreeModel(warned)
    assert _display(model, model.index(0, 0)) == "⚠ INTEGER"

    broken = parse_document(b"\x30\x82\x99\x99\x01")  # 长度越界
    assert broken.roots[0].error is not None
    model = Asn1TreeModel(broken)
    idx = model.index(0, 0)
    assert _display(model, idx) == "✗ ERROR"
    assert "无效（错误节点）" in model.data(idx, Qt.ToolTipRole)


def test_embedded_root_shows_arrow(qapp):
    """内嵌 DER 根节点保留 ⤷ 前缀。"""
    # BIT STRING（未用位 0）内嵌 SEQUENCE { INTEGER 5, INTEGER 6 }
    der = bytes.fromhex("0309003006020105020106")
    doc = parse_document(der)
    model = Asn1TreeModel(doc)
    parent_idx = model.index(0, 0)
    assert model.hasChildren(parent_idx) is True  # 可展开 → 显示展开箭头
    assert model.rowCount(parent_idx) == 1  # 触发内嵌探测
    child = model.index(0, 0, parent_idx)
    assert _display(model, child) == "⤷ SEQUENCE"


# %------------------------------------------------------------------------
# 展开箭头：没有可展开内容的不画箭头（hasChildren == rowCount > 0）
# %------------------------------------------------------------------------


def test_empty_constructed_node_is_leaf(qapp):
    """空值区的构造节点（如空 Context[n]）：没有可展开行，不显示展开箭头。"""
    model = Asn1TreeModel(parse_document(bytes.fromhex("3002A000")))  # SEQUENCE{ Context[0] 空 }
    root = model.index(0, 0)
    assert model.hasChildren(root) is True  # 前置：外层容器本身可展开
    ctx = model.index(0, 0, root)
    assert _display(model, ctx) == "Context[0]"
    assert model.hasChildren(ctx) is False
    assert model.rowCount(ctx) == 0


def test_empty_indefinite_context_is_leaf(qapp):
    """不定长但立即 EOC 的空构造节点同样视为叶子。"""
    model = Asn1TreeModel(parse_document(bytes.fromhex("A0800000")))
    idx = model.index(0, 0)
    assert model.hasChildren(idx) is False
    assert model.rowCount(idx) == 0


def test_garbage_constructed_keeps_expander(qapp):
    """内容解析失败的构造节点仍可展开——展开后是 ✗ 错误行，不是空箭头。"""
    doc = parse_document(b"\x30\x02\x02\x05")  # SEQUENCE 内声明 5 字节的 INTEGER（越界）
    model = Asn1TreeModel(doc)
    root = model.index(0, 0)
    assert model.hasChildren(root) is True
    assert model.rowCount(root) == 1
    assert _display(model, model.index(0, 0, root)) == "✗ ERROR"


def test_error_child_has_valid_parent_index(qapp):
    """错误子节点的 parent/_row 正确，树模型能反查并定位其父级。"""
    doc = parse_document(b"\x30\x02\x02\x05")
    root = doc.roots[0]
    err = root.children[0]
    assert err.parent is root
    assert err._row == 0
    assert err.depth == 1
    assert err.path == "SEQUENCE/ERROR"

    model = Asn1TreeModel(doc)
    err_idx = model.index_for_node(err)
    assert err_idx.isValid()
    parent_idx = model.parent(err_idx)
    assert parent_idx.isValid()
    assert parent_idx.internalPointer() is root


def test_truncated_indefinite_shows_error_child(qapp):
    """缺少 EOC 但已有子节点时，根保留，并显示零长度错误行。"""
    doc = parse_document(bytes.fromhex("3180020105"))
    model = Asn1TreeModel(doc)
    root_idx = model.index(0, 0)
    assert model.hasChildren(root_idx) is True
    assert model.rowCount(root_idx) == 2
    assert _display(model, model.index(1, 0, root_idx)) == "✗ ERROR"


def test_missing_eoc_tooltip_does_not_claim_terminated(qapp):
    """缺 EOC 的不定长节点，tooltip 不能仍写“EOC 终止”。"""
    doc = parse_document(bytes.fromhex("3180020105"))
    model = Asn1TreeModel(doc)
    tip = model.data(model.index(0, 0), Qt.ToolTipRole)
    assert "缺少 EOC 终止" in tip
    assert "BER，EOC 终止" not in tip


def test_failed_embedded_probe_is_leaf(qapp):
    """原生串内嵌探测失败：没有 ⤷ 行，不显示展开箭头。"""
    # OCTET STRING 内是完整覆盖的单子节点 SEQUENCE（不满足“≥2 子节点”约束）
    doc = parse_document(bytes.fromhex("040730050203010203"))
    assert doc.roots[0].possible_embedded  # 前置：形似内嵌
    model = Asn1TreeModel(doc)
    idx = model.index(0, 0)
    assert model.hasChildren(idx) is False
    assert model.rowCount(idx) == 0
