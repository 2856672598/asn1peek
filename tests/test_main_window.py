"""MainWindow 无头 UI 集成测试。

覆盖打开、展开、选择、复制、粘贴和错误提示等真实窗口路径。
"""

from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import base64
from pathlib import Path

import pytest
from PySide6.QtCore import Qt
from PySide6.QtGui import QKeySequence, QTextCursor
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QMessageBox

import asn1peek.core.parser as parser_module
from asn1peek.core.export import (
    LARGE_COPY_LIMIT,
    copy_value_variants,
    node_bytes,
)
from asn1peek.core.parser import locate_node, parse_document
from asn1peek.ui.actions import CopyController
from asn1peek.ui.main_window import MainWindow

SAMPLES = Path(__file__).parent.parent / "samples"


@pytest.fixture()
def window(qapp):
    win = MainWindow()
    win.show()
    yield win
    win.close()


def _leaf_der() -> bytes:
    path = SAMPLES / "leaf.der"
    if not path.exists():
        pytest.skip("samples/leaf.der 未生成")
    return path.read_bytes()


def _select(qapp, win, node):
    idx = win.tree_model.index_for_node(node)
    for anc in _ancestors(idx):
        win.tree_view.expand(anc)
    win.tree_view.scrollTo(idx)
    win.tree_navigator.select_index(idx)
    qapp.processEvents()
    return idx


def _ancestors(idx):
    chain, cur = [], idx.parent()
    while cur.isValid():
        chain.append(cur)
        cur = cur.parent()
    return list(reversed(chain))


def _tree_menu(qapp, win, monkeypatch, index):
    """捕获树右键菜单，避免 QMenu.exec 模态阻塞。"""
    captured = []
    monkeypatch.setattr(
        win,
        "_exec_context_menu",
        lambda menu, pos: captured.append(menu),
    )
    qapp.processEvents()
    rect = win.tree_view.visualRect(index)
    win._on_tree_context_menu(rect.center())
    assert captured, "未构建右键菜单"
    return captured[0]


class TestOpen:
    def test_open_pem_three_roots(self, qapp, window):
        path = SAMPLES / "chain.pem"
        if not path.exists():
            pytest.skip("samples/chain.pem 未生成")
        window.open_file(str(path))
        assert len(window.tree_model.document.roots) == 3
        assert window.tree_model.document.source_kind == "PEM"
        assert window._current_path == str(path)
        qapp.processEvents()

    def test_open_missing_file_no_crash(self, qapp, window, monkeypatch):
        # 无法读取文件走模态错误框：无头环境下替换为空操作避免阻塞
        monkeypatch.setattr("asn1peek.ui.main_window.QMessageBox.critical", lambda *a, **k: None)
        window.open_file("/nonexistent/xx.der")  # 不应抛出
        assert len(window.tree_model.document.roots) == 0


class TestCopy:
    def test_copy_path(self, qapp, window):
        window.open_data(_leaf_der(), "测试")
        doc = window.tree_model.document
        node = doc.roots[0].child_items[0]
        _select(qapp, window, node)
        window._copy_path()
        assert qapp.clipboard().text() == node.path

    def test_copy_raw_hex_b64(self, qapp, window):
        data = _leaf_der()
        window.open_data(data, "测试")
        node = window.tree_model.document.roots[0]
        _select(qapp, window, node)

        window._copy_raw("hex")
        hexed = qapp.clipboard().text()
        assert hexed == data[: node.total_len].hex().upper()

        window._copy_raw("base64")
        assert base64.b64decode(qapp.clipboard().text(), validate=True) == data[: node.total_len]


class TestCopyValue:
    OID_DER = bytes.fromhex("06092A864886F70D01010B")

    def _oid(self, qapp, window):
        window.open_data(self.OID_DER, "测试")
        node = window.tree_model.document.roots[0]
        _select(qapp, window, node)
        return node

    def test_act_copy_value_is_ctrl_c(self, window):
        assert hasattr(window, "act_copy_value")
        expected = QKeySequence(QKeySequence.StandardKey.Copy).toString()
        assert window.act_copy_value.shortcut().toString() == expected

    def test_ctrl_c_copies_first_value_variant(self, qapp, window):
        node = self._oid(qapp, window)
        variants = copy_value_variants(node)
        assert variants
        window.tree_view.setFocus()
        QTest.keyClick(
            window.tree_view,
            Qt.Key.Key_C,
            Qt.KeyboardModifier.ControlModifier,
        )
        qapp.processEvents()
        assert qapp.clipboard().text() == variants[0].text

    def test_context_menu_value_submenu_matches_variants(self, qapp, window, monkeypatch):
        node = self._oid(qapp, window)
        variants = copy_value_variants(node)
        menu = _tree_menu(
            qapp,
            window,
            monkeypatch,
            window.tree_model.index_for_node(node),
        )
        value_action = next(a for a in menu.actions() if a.text() == "复制值")
        submenu = value_action.menu()
        assert submenu is not None
        assert [a.text() for a in submenu.actions()] == ["OID（点分）", "OID 名称"]
        submenu.actions()[0].trigger()
        assert qapp.clipboard().text() == variants[0].text

    @pytest.mark.parametrize(
        "der",
        [
            bytes.fromhex("3006020105020106"),  # 容器
            b"\x30\x82\x99\x99\x01",  # 错误
        ],
        ids=["container", "error"],
    )
    def test_no_variants_fall_back_to_raw_hex(self, qapp, window, der):
        window.open_data(der, "测试")
        node = window.tree_model.document.roots[0]
        _select(qapp, window, node)
        assert copy_value_variants(node) == []
        window.tree_view.setFocus()
        QTest.keyClick(
            window.tree_view,
            Qt.Key.Key_C,
            Qt.KeyboardModifier.ControlModifier,
        )
        qapp.processEvents()
        assert qapp.clipboard().text() == node_bytes(node).hex().upper()

    def test_hex_selection_ctrl_c_uses_native_copy(self, qapp, window):
        window.open_data(_leaf_der(), "测试")
        window.hex_view.setFocus()
        cursor = window.hex_view.textCursor()
        cursor.setPosition(0)
        cursor.setPosition(5, QTextCursor.MoveMode.KeepAnchor)
        window.hex_view.setTextCursor(cursor)
        QTest.keyClick(
            window.hex_view,
            Qt.Key.Key_C,
            Qt.KeyboardModifier.ControlModifier,
        )
        qapp.processEvents()
        assert qapp.clipboard().text() == cursor.selectedText()

    def test_detail_selection_ctrl_c_uses_native_copy(self, qapp, window):
        self._oid(qapp, window)
        browser = window.detail_panel.browser
        browser.setFocus()
        cursor = browser.textCursor()
        cursor.setPosition(0)
        cursor.setPosition(12, QTextCursor.MoveMode.KeepAnchor)
        browser.setTextCursor(cursor)
        QTest.keyClick(
            browser,
            Qt.Key.Key_C,
            Qt.KeyboardModifier.ControlModifier,
        )
        qapp.processEvents()
        copied = qapp.clipboard().text()
        assert "OBJECT IDENTIFIER" in copied
        assert copied != copy_value_variants(window.tree_model.document.roots[0])[0].text

    def test_detail_no_selection_ctrl_c_copies_value(self, qapp, window):
        node = self._oid(qapp, window)
        browser = window.detail_panel.browser
        browser.setFocus()
        cursor = browser.textCursor()
        cursor.clearSelection()
        browser.setTextCursor(cursor)
        QTest.keyClick(
            browser,
            Qt.Key.Key_C,
            Qt.KeyboardModifier.ControlModifier,
        )
        qapp.processEvents()
        assert qapp.clipboard().text() == copy_value_variants(node)[0].text


class TestContextSelectionSync:
    def test_right_click_updates_detail_and_hex(self, qapp, window, monkeypatch):
        window.open_data(_leaf_der(), "测试")
        doc = window.tree_model.document
        deep = doc.roots[0].child_items[1]
        _select(qapp, window, deep)
        root = doc.roots[0]
        _tree_menu(
            qapp,
            window,
            monkeypatch,
            window.tree_model.index_for_node(root),
        )
        qapp.processEvents()
        current = window.tree_view.selectionModel().currentIndex()
        assert current.internalPointer() is root
        assert window.detail_panel._node is root
        assert window.hex_view._hl_node is root
        window._copy_path()
        assert qapp.clipboard().text() == root.path


class TestCopyRawGuard:
    def test_size_check_precedes_node_bytes(self, qapp, window, monkeypatch):
        class _BigNode:
            total_len = LARGE_COPY_LIMIT + 1
            type_name = "SEQUENCE"
            offset = 0

        node = _BigNode()
        calls = []
        asked = []

        def fake_node_bytes(value):
            calls.append(value)
            return b""

        def fake_question(*args, **kwargs):
            asked.append(args)
            return QMessageBox.StandardButton.No

        monkeypatch.setattr("asn1peek.ui.actions.exp.node_bytes", fake_node_bytes)
        monkeypatch.setattr(QMessageBox, "question", fake_question)
        controller = CopyController(window, lambda: node, lambda *args: None)
        controller.copy_raw("hex")
        assert calls == []
        assert asked
        assert f"{LARGE_COPY_LIMIT + 1:,} B" in asked[0][2]


class TestHexContextMenu:
    def test_copies_selected_node_raw_bytes(self, qapp, window):
        """选中树节点 → Hex 区右键 → 复制该节点完整 TLV（Hex / Base64）。"""
        assert (
            window.hex_view.contextMenuPolicy() == Qt.ContextMenuPolicy.CustomContextMenu
        )  # 右键菜单已接线
        data = _leaf_der()
        window.open_data(data, "测试")
        root = window.tree_model.document.roots[0]
        _select(qapp, window, root)

        menu = window._hex_context_menu(root)
        header = menu.actions()[0]
        assert not header.isEnabled()
        assert header.text() == (f"{root.type_name} @0x{root.offset:X} · {root.total_len} B")

        next(a for a in menu.actions() if a.text() == "复制原始字节（Hex）").trigger()
        assert (
            qapp.clipboard().text().replace(" ", "").upper() == data[: root.total_len].hex().upper()
        )

        next(a for a in menu.actions() if a.text() == "复制原始字节（Base64）").trigger()
        assert base64.b64decode(qapp.clipboard().text(), validate=True) == data[: root.total_len]

    def test_no_selection_falls_back_to_standard_menu(self, qapp, window):
        """未选中节点：Hex 区右键保留 Qt 原生文本菜单，不出现节点复制项。"""
        menu = window._hex_context_menu(None)
        labels = [a.text() for a in menu.actions()]
        assert not any("复制原始字节" in text for text in labels)


class TestPaste:
    def test_pem_text_paste_equals_file_open(self, qapp, window):
        """粘贴 PEM 原文结果与打开文件一致。"""
        pem_path = SAMPLES / "leaf.pem"
        if not pem_path.exists():
            pytest.skip("samples/leaf.pem 未生成")
        pem_text = pem_path.read_text()
        window.open_file(str(pem_path))
        ref = window.tree_model.document
        sig0 = (ref.roots[0].total_len, ref.roots[0].type_name, ref.node_count)

        window.open_data(pem_text.encode(), "剪贴板内容")
        pasted = window.tree_model.document
        sig1 = (pasted.roots[0].total_len, pasted.roots[0].type_name, pasted.node_count)
        assert sig0 == sig1
        assert pasted.source_kind == "PEM"
        assert window._current_path is None

    def test_base64_and_hex_paste(self, qapp, window):
        raw = _leaf_der()
        window.open_data(raw, "参考")
        ref = window.tree_model.document
        ref_root = ref.roots[0]

        b64_text = base64.encodebytes(raw).decode()
        window.open_data(b64_text.encode(), "剪贴板 Base64")
        assert window.tree_model.document.roots[0].total_len == ref_root.total_len

        hex_text = " ".join(f"{b:02X}" for b in raw)
        window.open_data(hex_text.encode(), "剪贴板 Hex")
        assert window.tree_model.document.roots[0].total_len == ref_root.total_len

    def test_plain_text_no_crash(self, qapp, window):
        """粘贴普通文本：不崩溃，给出无效结构提示（错误节点可见）。"""
        window.open_data("hello world 不是 ASN.1".encode(), "剪贴板内容")
        doc = window.tree_model.document
        assert doc.roots and all(r.error is not None for r in doc.roots)

    def test_empty_paste_no_crash(self, qapp, window):
        window.open_data(b"", "空输入")
        assert len(window.tree_model.document.roots) == 0

    def test_empty_input_clears_previous_document(self, qapp, window):
        window.open_data(_leaf_der(), "参考")
        assert window.tree_model.document.roots
        window.open_data(b"", "空输入")
        assert window.tree_model.document.roots == []
        assert window.tree_model.document.data == b""
        assert window.hex_view.toPlainText() == ""
        assert window._current_path is None

    def test_empty_file_clears_previous_path(self, qapp, window, tmp_path):
        window.open_data(_leaf_der(), "参考")
        empty = tmp_path / "empty.der"
        empty.write_bytes(b"")
        window.open_file(str(empty))
        assert window.tree_model.document.roots == []
        assert window._current_path is None

    def test_collapse_all_does_not_parse_unexpanded_children(self, qapp, window, monkeypatch):
        """折叠全部不能递归遍历未展开节点（否则会触发整棵懒解析）。"""
        monkeypatch.setattr(parser_module, "EAGER_SCAN_LIMIT", 0)
        inner = b"\x02\x01\x05" * 1000
        data = (
            b"\x30\x82"
            + len(inner).to_bytes(2, "big")
            + (b"\x30\x82" + len(inner).to_bytes(2, "big") + inner)
        )
        window.open_data(data, "测试")
        root = window.tree_model.document.roots[0]
        assert root.child_items  # 根已展开
        calls = []
        original = parser_module.parse_children

        def counting(node):
            calls.append(node.offset)
            return original(node)

        monkeypatch.setattr(parser_module, "parse_children", counting)
        window._collapse_all()
        assert calls == []


class TestErrorMessage:
    def test_error_text_has_offset_prefix(self):
        """错误消息格式 `offset 0x…: 消息`，与节点 offset 一致。"""
        doc = parse_document(b"\x30\x82\x99\x99\x01")  # 长度越界
        node = doc.roots[0]
        assert node.error is not None
        assert node.error_text == f"offset 0x{node.offset:X}: {node.error}"

    def test_detail_panel_shows_offset(self, qapp, window):
        window.open_data(b"\x30\x82\x99\x99\x01", "测试")
        node = window.tree_model.document.roots[0]
        window.detail_panel.show_node(node)
        plain = window.detail_panel.toPlainText()
        assert f"offset 0x{node.offset:X}" in plain


class TestStatusBar:
    def test_load_leaves_no_persistent_meta(self, qapp, window):
        """状态栏不常驻文件元信息。"""
        window.open_data(_leaf_der(), "测试")
        _select(qapp, window, window.tree_model.document.roots[0])
        assert window.statusBar().currentMessage() == ""

    def test_transient_feedback_still_shown(self, qapp, window):
        """复制操作反馈显示在状态栏。"""
        window.open_data(_leaf_der(), "测试")
        _select(qapp, window, window.tree_model.document.roots[0])
        window._copy_path()
        assert "已复制" in window.statusBar().currentMessage()


class TestTreeHeader:
    def test_hidden_for_structure_only_and_restored_for_extra_columns(self, qapp, window):
        """仅结构列时隐藏空表头；开启长度/偏移列时恢复。"""
        assert window.tree_view.isHeaderHidden()

        window.act_show_length.setChecked(True)
        assert not window.tree_view.isColumnHidden(1)
        assert not window.tree_view.isHeaderHidden()

        window.act_show_length.setChecked(False)
        assert window.tree_view.isHeaderHidden()

        window.act_show_offset.setChecked(True)
        assert not window.tree_view.isColumnHidden(2)
        assert not window.tree_view.isHeaderHidden()

        window.act_show_length.setChecked(True)
        window.act_show_offset.setChecked(False)
        assert not window.tree_view.isHeaderHidden()

        window.act_show_length.setChecked(False)
        assert window.tree_view.isHeaderHidden()


class TestDecodedToggle:
    def test_view_menu_toggle_hides_decoded(self, qapp, window):
        """「视图→显示解码信息」总开关：关掉解析值回退为转储，再开恢复。"""
        window.open_data(bytes.fromhex("06092A864886F70D01010B"), "测试")
        node = window.tree_model.document.roots[0]
        window.detail_panel.show_node(node)
        assert "sha256WithRSAEncryption" in window.detail_panel.toPlainText()
        window.act_show_decoded.setChecked(False)
        assert "sha256WithRSAEncryption" not in window.detail_panel.toPlainText()
        window.act_show_decoded.setChecked(True)
        assert "sha256WithRSAEncryption" in window.detail_panel.toPlainText()


class TestHexClick:
    def test_click_selects_innermost_node(self, qapp, window):
        """Hex 点击反向定位：树选中点击字节的最内层节点。

        旧实现先 select() 后 setCurrentIndex()：selectionChanged 触发时
        currentIndex() 尚未指向目标节点，高亮/详情按旧节点计算，
        还会把 Hex 视口拉走；此用例同时防该回归。
        """
        data = _leaf_der()
        window.open_data(data, "测试")
        doc = window.tree_model.document
        # 先选中一个与目标不同的节点
        deep = doc.roots[0].child_items[1]
        _select(qapp, window, deep)

        for target in (0, len(data) - 1):
            expected = locate_node(doc, target)
            window._on_hex_click(target)
            qapp.processEvents()
            cur = window.tree_view.selectionModel().currentIndex()
            assert cur.internalPointer() is expected, target


class TestContextMenuHelpers:
    def test_expand_here_and_collapse_all(self, qapp, window):
        window.open_data(_leaf_der(), "测试")
        doc = window.tree_model.document
        deep = doc.roots[0].child_items[1]  # tbsCertificate 下的兄弟
        _select(qapp, window, deep)
        window._collapse_all()
        assert not any(
            window.tree_view.isExpanded(window.tree_model.index(r, 0))
            for r in range(window.tree_model.rowCount())
        )
        window._expand_here()
        assert window.tree_view.isExpanded(window.tree_model.index_for_node(doc.roots[0]))
