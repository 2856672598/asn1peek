"""Hex 视图回归测试：大节点高亮「可视区域化」+ 文档替换清理旧选区。

背景（已修复的两个性能缺陷）：
1. 旧实现为选中节点的整个区间逐行生成 ExtraSelection：10MB 文件的根节点
   会生成约 26 万条选区，打开耗时 ~15s；
2. 替换文档时不清理旧选区，Qt 在 setPlainText 期间逐条同步光标，
   连续打开「10MB → 50MB」时长时间无响应。

本文件用 offscreen 平台无头运行，断言选区数量只与视口有关、滚动后重建、
以及 set_data() 会先清空选区，防止两个问题回归。
"""

from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QEvent, QPointF, Qt
from PySide6.QtGui import QMouseEvent, QPalette, QTextCursor

from asn1peek.core.parser import parse_document
from asn1peek.ui.hex_view import (
    ASCII_START,
    BYTES_PER_LINE,
    HEX_START,
    MAX_DISPLAY_BYTES,
    OFFSET_COL_END,
    HexView,
    byte_col,
    offset_column_format,
)


def _enc_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _huge_der() -> bytes:
    """根 SEQUENCE 的值区超过 Hex 显示上限：选中根节点会覆盖整个可视区。"""
    payload = b"\xaa" * (MAX_DISPLAY_BYTES + BYTES_PER_LINE)
    inner = b"\x04" + _enc_len(len(payload)) + payload
    return b"\x30" + _enc_len(len(inner)) + inner


def _long_root(size: int = 800) -> bytes:
    """一个可滚动的普通根节点，用于把后续错误标记放到文档后部。"""
    payload = b"\xaa" * size
    inner = b"\x04" + _enc_len(size) + payload
    return b"\x30" + _enc_len(len(inner)) + inner


def _make_view(qapp) -> HexView:
    view = HexView()
    view.resize(800, 400)
    view.show()
    qapp.processEvents()
    return view


def _selected_lines(view: HexView) -> set[int]:
    return {
        view.document().findBlock(s.cursor.selectionStart()).blockNumber()
        for s in view.extraSelections()
    }


def _selection_cols(view: HexView, sel) -> tuple[int, int]:
    """选区在该行内的列区间 [start, end)。"""
    start = sel.cursor.selectionStart()
    block = view.document().findBlock(start)
    return start - block.position(), sel.cursor.selectionEnd() - block.position()


def _offset_selections(view: HexView) -> list:
    """只取常驻的偏移列选区（[0, OFFSET_COL_END)）。"""
    return [s for s in view.extraSelections() if _selection_cols(view, s) == (0, OFFSET_COL_END)]


def _node_selections(view: HexView) -> list:
    """只取节点三色高亮选区（排除常驻的偏移列选区）。"""
    return [s for s in view.extraSelections() if _selection_cols(view, s)[0] >= HEX_START]


def test_huge_node_selections_bounded(qapp):
    """整份可视区（2 MiB ≈ 13 万行）的节点：选区只覆盖视口行，数量为百级。"""
    view = _make_view(qapp)
    doc = parse_document(_huge_der())
    view.set_data(doc.data)
    view.highlight_node(doc.roots[0])

    selections = view.extraSelections()
    assert selections, "根节点应产生高亮"
    assert len(selections) < 1000, f"选区数量未按视口收敛：{len(selections)}"

    first, last = view._visible_line_range()
    lines = _selected_lines(view)
    assert lines and min(lines) >= first and max(lines) <= last
    assert max(lines) < 1000, "不应为整个文档逐行生成选区"
    view.close()


def test_selections_rebuild_on_scroll(qapp):
    """滚动后按新的可视行区间重建选区，而不是保留首屏的旧选区。"""
    view = _make_view(qapp)
    doc = parse_document(_huge_der())
    view.set_data(doc.data)
    view.highlight_node(doc.roots[0])

    vbar = view.verticalScrollBar()
    vbar.setValue(vbar.maximum() // 2)
    qapp.processEvents()

    selections = view.extraSelections()
    assert selections, "滚动后节点仍覆盖视口，应有高亮"
    assert len(selections) < 1000

    lines = _selected_lines(view)
    first, last = view._visible_line_range()
    assert min(lines) > 0, "已滚离首屏"
    assert min(lines) >= first and max(lines) <= last
    view.close()


def test_set_data_clears_stale_selections(qapp):
    """替换文档前必须清空旧选区（否则二次打开大文件会卡死）。"""
    view = _make_view(qapp)
    doc = parse_document(_huge_der())
    view.set_data(doc.data)
    view.highlight_node(doc.roots[0])
    assert _node_selections(view)

    small = parse_document(b"\x02\x01\x05")
    view.set_data(small.data)
    assert _node_selections(view) == [], "旧节点高亮必须随文档替换清空"
    view.close()


def test_small_node_span_colors(qapp):
    """小节点的三色区间：tag/len/value 各在 hex 列与 ascii 列各一条。"""
    view = _make_view(qapp)
    doc = parse_document(b"\x02\x01\x05")  # INTEGER 5：tag 1B + len 1B + value 1B
    view.set_data(doc.data)
    view.highlight_node(doc.roots[0])

    selections = _node_selections(view)
    assert len(selections) == 6  # 3 段 × (hex 列段 + ascii 列段)
    assert _selected_lines(view) == {0}
    colors = {s.format.background().color().name() for s in selections}
    assert len(colors) == 3, "应能看到三种颜色（tag/长度/值）"
    view.close()


def test_offset_column_selections(qapp):
    """偏移列常驻选区：只铺可视数据行、只覆盖 [0, OFFSET_COL_END)。"""
    view = _make_view(qapp)
    view.set_data(bytes(i & 0xFF for i in range(16 * 40)))  # 40 行，一屏放不下
    view.highlight_node(None)  # 无节点高亮时偏移列仍在

    selections = _offset_selections(view)
    first, last = view._visible_line_range()
    assert selections, "偏移列应常驻"
    assert _selected_lines(view) == set(range(first, min(last, 39) + 1))
    assert len(_node_selections(view)) == 0
    # 浅/深主题下底色都不是窗口底色本身（可见但不刺眼）
    fmt = selections[0].format
    assert fmt.background().color() != view.palette().color(QPalette.ColorRole.Base)
    assert fmt.foreground().color() != view.palette().color(QPalette.ColorRole.Text)
    view.close()


def test_offset_column_scrolls_with_view(qapp):
    """滚动后偏移列跟随可视行重建，不会残留首屏选区。"""
    view = _make_view(qapp)
    view.set_data(bytes(i & 0xFF for i in range(16 * 200)))
    vbar = view.verticalScrollBar()
    vbar.setValue(vbar.maximum() // 2)
    qapp.processEvents()

    lines = {
        view.document().findBlock(s.cursor.selectionStart()).blockNumber()
        for s in _offset_selections(view)
    }
    first, last = view._visible_line_range()
    assert min(lines) > 0, "已滚离首屏"
    assert min(lines) >= first and max(lines) <= last
    view.close()


def test_offset_column_painted(qapp):
    """像素级：底色只铺 8 位地址；其后 2 格分隔空格与数据列留白。"""
    view = _make_view(qapp)
    view.set_data(bytes(range(16 * 8)))
    qapp.processEvents()

    fm = view.fontMetrics()
    cell = fm.horizontalAdvance("0")
    cursor = QTextCursor(view.document())  # 第 0 行数据列起点（视口坐标）
    cursor.setPosition(view._char_pos(0, HEX_START))
    data_rect = view.cursorRect(cursor)
    data_x = data_rect.left()
    y = data_rect.center().y()

    img = view.viewport().grab().toImage()
    dpr = img.devicePixelRatio()
    base = view.palette().color(QPalette.ColorRole.Base)
    expected = offset_column_format(view.palette()).background().color()
    assert expected != base, "底色应与窗口底色可区分"

    # 地址区的空白处（字符上方 2px，避开数字笔画）应可见淡底色
    addr_px = img.pixelColor(
        int((data_x - 6 * cell + cell // 2) * dpr),
        int((data_rect.top() + 2) * dpr),
    )
    assert addr_px == expected, f"地址列底色未生效：{addr_px.name()}"

    # 地址与 hex 之间的 2 格分隔空格：留白，保持窗口底色（空格无字形，
    # 取 col 9 中心采样，不会采到文字抗锯齿）
    gutter_px = img.pixelColor(int((data_x - cell // 2) * dpr), int(y * dpr))
    data_px = img.pixelColor(int((data_x + 2 * cell + cell // 2) * dpr), int(y * dpr))
    assert gutter_px == base, f"分隔空格应留白：{gutter_px.name()}"
    assert data_px == base, f"数据列不应有底色：{data_px.name()}"
    view.close()


def test_left_click_emits_right_click_does_not(qapp):
    """左键反向定位；右键只出菜单，不改变树选中（Hex 右键复制选中节点）。"""
    view = _make_view(qapp)
    view.set_data(bytes(range(64)))
    seen: list[int] = []
    view.byte_clicked.connect(seen.append)

    # 像素坐标按字体度量换算到「第 0 字节」的 hex 列（列 ≠ 像素 x；
    # 直接写死像素会在字体/布局变化后失准）。
    fm = view.fontMetrics()
    pos = QPointF(
        view.document().documentMargin() + byte_col(0) * fm.horizontalAdvance("0") + 1,
        fm.height() / 2,
    )

    right = QMouseEvent(
        QEvent.Type.MouseButtonPress,
        pos,
        pos,
        Qt.MouseButton.RightButton,
        Qt.MouseButton.RightButton,
        Qt.KeyboardModifier.NoModifier,
    )
    view.mousePressEvent(right)
    assert seen == []

    left = QMouseEvent(
        QEvent.Type.MouseButtonPress,
        pos,
        pos,
        Qt.MouseButton.LeftButton,
        Qt.MouseButton.LeftButton,
        Qt.KeyboardModifier.NoModifier,
    )
    view.mousePressEvent(left)
    assert seen == [0]

    # 覆盖字节数字位、字节间隔空白等边界位置。
    # 逐像素扫描，以点击后命中的列为准（cursorForPosition 与
    # mousePressEvent 使用同一列换算路径），断言
    # 发射的字节 == _col_to_byte(命中列)，且 hex 数据区不许可哑区。
    from PySide6.QtGui import QTextCursor

    def site_x(col: int) -> int:
        cur = QTextCursor(view.document())
        cur.setPosition(view.document().findBlockByNumber(0).position() + col)
        # cursorRect 为 viewport 坐标，换回 widget 坐标
        return int(view.cursorRect(cur).left() + view.viewport().x())

    def hit_col(x: int) -> tuple[int, int]:
        cur = view.cursorForPosition(QPointF(x, y).toPoint())
        block = view.document().findBlock(cur.position())
        return block.blockNumber(), cur.position() - block.position()

    y = int(fm.height() / 2)
    cw = fm.horizontalAdvance("0")
    x0 = site_x(10) + 2  # 避开 col 9|10 边界的舍入歧义
    x1 = site_x(10) + (ASCII_START + BYTES_PER_LINE - 10) * cw + 8

    bytes_seen = set()
    for x in range(x0, x1):
        seen.clear()
        ev = QMouseEvent(
            QEvent.Type.MouseButtonPress,
            QPointF(x, y),
            QPointF(x, y),
            Qt.MouseButton.LeftButton,
            Qt.MouseButton.LeftButton,
            Qt.KeyboardModifier.NoModifier,
        )
        view.mousePressEvent(ev)
        line, col = hit_col(x)
        expected = view._col_to_byte(line, col)
        if expected is None:
            assert len(seen) == 0, f"x={x} 列={col} 不应触发，却发了 {seen}"
        else:
            assert len(seen) == 1, f"x={x} 列={col} 成为哑区（未触发）"
            assert seen[0] == expected, f"x={x} 列={col} 发射 {seen[0]} != {expected}"
        if line == 0 and HEX_START <= col < ASCII_START:
            bytes_seen.add(seen[0])
    assert bytes_seen == set(range(BYTES_PER_LINE)), "0–15 字节都应可点中"
    view.close()


def test_zero_length_eoc_error_does_not_highlight_following_root(qapp):
    """零长度 EOC 错误标记与后续顶层节点同 offset，不能高亮后者。"""
    doc = parse_document(bytes.fromhex("30053180020105020106"))
    inner = doc.roots[0].child_items[0]
    err = inner.child_items[1]
    assert err.error is not None
    assert err.offset == 7 and err.next_offset == 7

    view = _make_view(qapp)
    view.set_data(doc.data)
    view.highlight_node(err)
    assert _node_selections(view) == []
    view.close()


def test_zero_length_eoc_error_does_not_scroll_to_following_root(qapp):
    """零长度错误标记不可见，不能把视口滚到同 offset 的后续 root。"""
    doc = parse_document(_long_root() + bytes.fromhex("30053180020105020106"))
    err = doc.roots[1].child_items[0].child_items[1]
    assert err.error is not None
    assert err.offset == err.next_offset == doc.roots[2].offset

    view = _make_view(qapp)
    view.set_data(doc.data)
    vbar = view.verticalScrollBar()
    vbar.setValue(0)
    qapp.processEvents()
    assert vbar.maximum() > 0, "测试文档应足以滚动"
    before = vbar.value()

    view.highlight_node(err)
    qapp.processEvents()
    assert vbar.value() == before
    assert _node_selections(view) == []
    view.close()


def test_nonzero_error_still_scrolls_and_highlights(qapp):
    """有可见 span 的错误节点保持原有滚动与红色高亮行为。"""
    doc = parse_document(_long_root() + b"\x30\x82")
    err = doc.roots[1]
    assert err.error is not None
    assert err.end > err.offset

    view = _make_view(qapp)
    view.set_data(doc.data)
    vbar = view.verticalScrollBar()
    vbar.setValue(0)
    qapp.processEvents()
    assert vbar.maximum() > 0, "测试文档应足以滚动"
    before = vbar.value()

    view.highlight_node(err)
    qapp.processEvents()
    assert vbar.value() > before
    assert _node_selections(view)
    view.close()


def test_col_to_byte_matrix(qapp):
    """hex 区任意字符列都能命中字节：数字列/尾空格 → 本字节，间隔列 → 就近。"""
    view = _make_view(qapp)
    view.set_data(bytes(range(64)))  # 恰好 4 行整数行
    # 统一网格：每字节占 3 列（两位数字 + 尾空格），全部命中本字节
    for i in range(BYTES_PER_LINE):
        for d in (0, 1, 2):
            col = byte_col(i) + d
            assert view._col_to_byte(0, col) == i, (i, d)
    # hex 与 ascii 之间的分隔空格列（byte_col(15)+3）钳到字节 15
    assert view._col_to_byte(0, byte_col(15) + 3) == 15
    # ascii 列逐列命中
    for i in range(BYTES_PER_LINE):
        assert view._col_to_byte(0, ASCII_START + i) == i
    # 偏移字段与文本区外不留尾巴
    for col in (0, 5, 9, ASCII_START + BYTES_PER_LINE):
        assert view._col_to_byte(0, col) is None
    view.close()


def test_col_to_byte_short_line_pads(qapp):
    """最后一行不足 16 字节：补位/留白列钳到行内最后一个真实字节。"""
    view = _make_view(qapp)
    view.set_data(b"\x30\x05\x02\x01\x05")  # 5 字节 → 仅 1 行
    assert view._col_to_byte(0, byte_col(4)) == 4
    # hex 补位区与 ascii 补位区都钳到最后一个真实字节
    assert view._col_to_byte(0, byte_col(5)) == 4
    assert view._col_to_byte(0, byte_col(15) + 1) == 4
    assert view._col_to_byte(0, ASCII_START + 10) == 4
    assert view._col_to_byte(0, ASCII_START + 15) == 4
    # 偏移列外/下一行为空数据
    assert view._col_to_byte(0, 5) is None
    assert view._col_to_byte(1, byte_col(0)) is None
    view.close()


def test_highlight_anchor_keeps_viewport(qapp):
    """Hex 点击锚点：高亮同一大节点时视口围绕点击字节，不被拉回节点起始。"""
    node = parse_document(_huge_der()).roots[0]
    view = _make_view(qapp)
    view.set_data(_huge_der())
    view.highlight_node(node)
    vbar = view.verticalScrollBar()
    vbar.setValue(vbar.maximum())  # 滚到底：可视区为数据末尾几行
    qapp.processEvents()
    before = vbar.value()
    anchor = (view._line_count() - 2) * BYTES_PER_LINE  # 可视区内某字节的行首
    view.highlight_node(node, anchor_byte=anchor)
    qapp.processEvents()
    assert vbar.value() == before
    assert _selected_lines(view), "锚点高亮后选区仍在"
    view.close()
