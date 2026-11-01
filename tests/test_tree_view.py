"""连接线几何与开关测试（offscreen 无头运行）。

覆盖：
- connector_segments/last_flags 的纯几何（最后子节点 └、非最后子节点 ├、
  上层总线是否穿过本行、父级列/自身按钮格中心）；
- Asn1TreeView 开关：默认开、关闭后重绘、绘制结果确实随开关变化；
- 主窗口接线：视图菜单「显示连接线」动作可切换。
"""

from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from pathlib import Path

import pytest
from PySide6.QtCore import QRect
from PySide6.QtGui import QColor, QPalette, QStandardItem, QStandardItemModel

from asn1peek.core.parser import parse_document
from asn1peek.ui.tree_model import Asn1TreeModel
from asn1peek.ui.tree_view import Asn1TreeView, connector_segments, last_flags, line_color

SAMPLES = Path(__file__).parent.parent / "samples"


# ---- 几何：connector_segments -------------------------------------------


class TestSegments:
    def test_root_row_has_no_lines(self):
        assert connector_segments(QRect(0, 0, 20, 18), 20, [False]) == []

    def test_last_child_is_elbow(self):
        # 深度 1 的最后子节点：竖线只到行中 + 横线到本行按钮格中心
        segs = connector_segments(QRect(0, 0, 40, 18), 20, [False, True])
        assert segs == [(9, 0, 9, 8), (9, 8, 29, 8)]

    def test_not_last_child_has_full_bus(self):
        segs = connector_segments(QRect(0, 0, 40, 18), 20, [False, False])
        assert segs == [(9, 0, 9, 17), (9, 8, 29, 8)]

    def test_ancestor_bus_and_hidden_column(self):
        # A/A1/A1x 链：A 非最后（总线穿过）、A1 是最后（本行不出线）、
        # A1x 是最后子节点（└）
        segs = connector_segments(QRect(0, 0, 80, 18), 20, [False, False, True, True])
        assert segs == [(9, 0, 9, 17), (49, 0, 49, 8), (49, 8, 69, 8)]

    def test_deep_ancestor_continues(self):
        # A 非最后、A1 非最后：两列总线都穿过本行
        segs = connector_segments(QRect(0, 0, 80, 18), 20, [False, False, False, True])
        assert segs == [
            (9, 0, 9, 17),
            (29, 0, 29, 17),
            (49, 0, 49, 8),
            (49, 8, 69, 8),
        ]

    def test_odd_indent_and_rect_offset(self):
        segs = connector_segments(QRect(3, 100, 30, 16), 15, [False, True])
        assert segs == [(10, 100, 10, 107), (10, 107, 25, 107)]

    def test_indent_guard(self):
        assert connector_segments(QRect(0, 0, 40, 18), 0, [False, True]) == []


# ---- 几何：last_flags ----------------------------------------------------


class TestLastFlags:
    @pytest.fixture()
    def model(self):
        model = Asn1TreeModel()
        model.set_document(parse_document(b"\x30\x06\x02\x01\x05\x02\x01\x06"))
        return model

    def test_root_flag(self, model):
        assert last_flags(model.index(0, 0)) == [False]

    def test_children_flags(self, model):
        parent = model.index(0, 0)
        first = model.index(0, 0, parent)
        second = model.index(1, 0, parent)
        assert last_flags(first) == [False, False]
        assert last_flags(second) == [False, True]


# ---- 视图开关与绘制 ------------------------------------------------------


def _build_view(qapp) -> Asn1TreeView:
    model = QStandardItemModel()
    root = model.invisibleRootItem()
    for name in ("A", "B"):
        item = QStandardItem(name)
        root.appendRow(item)
        if name == "A":
            for sub in ("A1", "A2"):
                s = QStandardItem(sub)
                item.appendRow(s)
                if sub == "A1":
                    s.appendRow(QStandardItem("A1x"))
        else:
            item.appendRow(QStandardItem("B1"))
    view = Asn1TreeView()
    view.setHeaderHidden(True)
    view.setModel(model)
    view.resize(320, 200)
    view.show()
    view.expandAll()
    qapp.processEvents()
    return view


# ---- 线色（不能依赖调色板 Mid） -----------------------------------------


def _palette(
    base: str, text: str, mid: str, window: str = "#000000", window_text: str = "#ffffff"
) -> QPalette:
    pal = QPalette()
    pal.setColor(QPalette.ColorRole.Base, QColor(base))
    pal.setColor(QPalette.ColorRole.Text, QColor(text))
    pal.setColor(QPalette.ColorRole.Mid, QColor(mid))
    pal.setColor(QPalette.ColorRole.Window, QColor(window))
    pal.setColor(QPalette.ColorRole.WindowText, QColor(window_text))
    return pal


class TestLineColor:
    def test_yaru_like_palette_visible(self):
        # 某些主题可能将 Mid 设为白色，而行背景接近白色。
        pal = _palette(base="#fcfcfc", text="#000000", mid="#ffffff")
        color = line_color(pal)
        assert color.alpha() == 90
        # 与背景保持足够的亮度差。
        assert abs(color.lightness() - QColor("#fcfcfc").lightness()) > 40

    def test_dark_palette_visible(self):
        pal = _palette(
            base="#232323", text="#ffffff", mid="#a0a0a0", window="#353535", window_text="#ffffff"
        )
        color = line_color(pal)
        assert abs(color.lightness() - QColor("#232323").lightness()) > 40

    def test_windowtext_preferred_when_text_blends_in(self):
        # Text 与背景同色（病态主题）时退回 WindowText
        pal = _palette(
            base="#fcfcfc", text="#fcfcfc", mid="#ffffff", window="#ffffff", window_text="#000000"
        )
        assert line_color(pal).lightness() < 150

    def test_transparent_foreground_falls_back(self):
        pal = _palette(base="#fcfcfc", text="#000000", mid="#ffffff")
        pal.setColor(QPalette.ColorRole.Text, QColor(0, 0, 0, 0))
        assert line_color(pal).alpha() == 90


class TestViewToggle:
    def test_default_on(self, qapp):
        view = _build_view(qapp)
        assert view.connection_lines() is True
        view.close()

    def test_toggle_changes_rendering(self, qapp):
        view = _build_view(qapp)
        with_lines = view.grab().toImage()
        view.set_connection_lines(False)
        qapp.processEvents()
        without = view.grab().toImage()
        assert view.connection_lines() is False
        assert with_lines != without, "关闭连接线后画面应发生变化"
        view.set_connection_lines(True)
        qapp.processEvents()
        assert view.grab().toImage() == with_lines, "重新开启应恢复原画面"
        view.close()

    def test_empty_model_paints(self, qapp):
        view = Asn1TreeView()
        view.resize(100, 60)
        view.show()
        qapp.processEvents()
        view.grab()  # 空模型下不应抛异常
        view.close()

    def test_lines_visible_on_yaru_palette(self, qapp):
        """线下沉到像素级：浅色主题下仍然可见。"""
        view = _build_view(qapp)
        view.setPalette(_palette(base="#fcfcfc", text="#000000", mid="#ffffff"))
        qapp.processEvents()
        img = view.grab().toImage()

        child = view.model().index(0, 0, view.model().index(0, 0))  # A1
        rect = view.visualRect(child)  # 视口坐标
        indent = view.indentation()
        vp = view.viewport()  # grab() 含 1px 外框，需加视口原点
        mid_y = rect.top() + rect.height() // 2
        line_px = img.pixelColor(vp.x() + (indent - 1) // 2, vp.y() + mid_y)
        bg_px = img.pixelColor(vp.x() + indent - 4, vp.y() + rect.top() + 2)
        assert line_px.lightness() < bg_px.lightness() - 40, (
            f"连接线不可见: line={line_px.name()} bg={bg_px.name()}"
        )
        view.close()


# ---- 主窗口接线 ----------------------------------------------------------


class TestMainWindowWiring:
    @pytest.fixture()
    def window(self, qapp):
        from asn1peek.ui.main_window import MainWindow

        win = MainWindow()
        win.show()
        yield win
        win.close()

    def test_uses_lined_tree_view(self, window):
        assert isinstance(window.tree_view, Asn1TreeView)
        assert window.tree_view.connection_lines() is True

    def test_menu_action_toggles(self, qapp, window):
        leaf = SAMPLES / "leaf.der"
        if not leaf.exists():
            pytest.skip("samples/leaf.der 未生成")
        window.open_file(str(leaf))
        qapp.processEvents()

        # PySide6 6.8/6.9 下 QAction.menu() 返回的 QMenu 包装器依赖 QAction 存活。
        # 生成器表达式会让临时 QAction 包装器被回收，进而把 QMenu 一起删掉
        # （RuntimeError: Internal C++ object (QMenu) already deleted）。
        # 先持有菜单栏 action 列表，再取 menu()。
        menu_actions = window.menuBar().actions()
        view_action = next(a for a in menu_actions if a.text().startswith("视图"))
        view_menu = view_action.menu()
        assert view_menu is not None
        action = next(a for a in view_menu.actions() if "连接线" in a.text())
        assert action.isChecked()
        action.trigger()
        assert window.tree_view.connection_lines() is False
        action.trigger()
        assert window.tree_view.connection_lines() is True
