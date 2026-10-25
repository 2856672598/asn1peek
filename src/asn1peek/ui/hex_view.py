"""Hex 视图：字节转储 + 三色区间高亮（tag/length/value 分别着色）。

- 树选中节点 → highlight_node()：按节点坐标计算区间，用 QPlainTextEdit 的
  extraSelections 做背景色叠加（只铺 hex 字符与 ASCII 列）；
- 高亮选区只按可视区域生成（滚动/缩放时重建），大节点不会产生 O(文件) 级
  选区，保证 10MB/50MB 文件打开与滚动性能；
- 偏移列（地址栏）常驻视觉：[0, 8) 铺极淡底 + 地址文字弱化，把「地址」与
  「数据」分成两栏（对照 Hex 编辑器惯例）；地址与 hex 之间的 2 格分隔空格
  不铺底色（留白），避免色块贴到数据列；颜色全部由调色板派生（前景 8%
  混入底色，见 offset_column_format），深浅主题各自适配，强度比三色高亮
  （45–51%）低一个量级，不会与「有底色 = 选中区间」的语义混淆；
- 左键点击任意字节 → byte_clicked(offset) 信号 → 反向定位最内层节点。

行布局（每行 16 字节，行宽 75 字符，无 8 字节分组空隙）：
  00000000  30 82 03 C1 30 82 02 A9 A0 03 02 01 06 07 2A 86  |0....'
  [off 8][2空格][hex 47字符][2空格][ascii 16]
  hex 列起点 = 10；ascii 列起点 = 59。
"""

from __future__ import annotations

from PySide6.QtCore import QEvent, Qt, Signal
from PySide6.QtGui import QColor, QFontDatabase, QPalette, QTextCharFormat, QTextCursor
from PySide6.QtWidgets import QPlainTextEdit, QTextEdit

from ..core.model import Asn1Node
from .theme import blend

BYTES_PER_LINE = 16
HEX_START = 10
ASCII_START = 59
OFFSET_COL_END = 8  # 底色只铺 8 位地址；其后 2 格分隔空格留白到 hex 列

MAX_DISPLAY_BYTES = 1 << 21  # Hex 视图最多展示（2 MiB），超出行数再截断

# 可视区上下各多生成的行数：滚动时留一点余量，减少重建频率与边缘闪烁
_VISIBLE_MARGIN_LINES = 2

_COLOR_TAG = QColor(245, 158, 11, 130)  # tag 区：琥珀
_COLOR_LEN = QColor(56, 189, 248, 130)  # length 区：青
_COLOR_VALUE = QColor(74, 222, 128, 115)  # 值区：绿
_COLOR_ERROR = QColor(239, 68, 68, 130)  # 错误节点整体：红

# 偏移列（地址栏）：底色强度 / 文字弱化比例——两者都从调色板派生，不写死颜色
_OFFSET_TINT_RATIO = 0.08
_OFFSET_TEXT_RATIO = 0.55


def byte_col(i: int) -> int:
    """第 i 个字节 (0..15) 的 hex 列起点。"""
    return HEX_START + i * 3


def offset_column_format(palette: QPalette) -> QTextCharFormat:
    """偏移列格式：极淡底色 + 弱化地址文字。

    底色 = 前景色 8% 混入窗口底色（浅色主题下约 #EBEBEB）——比三色高亮
    （45–51% 叠加）低一个量级，只作「栏」的分组提示；文字弱化到 55% 让数据
    列成为视觉主体。底色只覆盖 8 位地址，地址与 hex 之间的 2 格分隔空格
    保持窗口底色（留白），不形成贴住数据列的色块。深浅主题各自从调色板
    派生，不改写死颜色。
    """
    base = palette.color(QPalette.ColorRole.Base)
    text = palette.color(QPalette.ColorRole.Text)
    fmt = QTextCharFormat()
    fmt.setBackground(blend(text, base, _OFFSET_TINT_RATIO))
    fmt.setForeground(blend(text, base, _OFFSET_TEXT_RATIO))
    return fmt


class HexView(QPlainTextEdit):
    byte_clicked = Signal(int)  # 点击的绝对字节 offset

    def __init__(self, parent=None) -> None:
        # 属性先于 Qt 初始化置好：构造期到达的 resize/changeEvent 也会走
        # _rebuild_highlight()，不会因缺属性而报错
        self._data = b""
        self._displayed = 0  # 实际显示的长度（可能被截断）
        self._hl_node: Asn1Node | None = None  # 当前高亮节点（滚动时按需重建选区）
        super().__init__(parent)
        self.setReadOnly(True)
        self.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        font = QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont)
        font.setPointSize(10)
        self.setFont(font)
        self.setPlaceholderText("（打开文件后此处显示原始字节）")

    # ---- 布局维护 ------------------------------------------------------

    def resizeEvent(self, e) -> None:  # noqa: N802
        super().resizeEvent(e)
        self._rebuild_highlight()  # 可视行数变化 → 重建选区

    def changeEvent(self, e) -> None:  # noqa: N802
        super().changeEvent(e)
        if e.type() == QEvent.Type.PaletteChange:
            self._rebuild_highlight()  # 主题切换 → 偏移列底色/文字按新调色板重派生

    def scrollContentsBy(self, dx, dy) -> None:  # noqa: N802
        super().scrollContentsBy(dx, dy)
        if dy:
            self._rebuild_highlight()  # 可视行区间变化 → 重建选区

    # ---- 数据生成 ------------------------------------------------------

    def set_data(self, data: bytes) -> None:
        # 替换文档前必须清空旧选区：大文件遗留的批量 ExtraSelection
        # 会让 Qt 在 setPlainText 期间逐条同步光标，替换文档时长时间无响应。
        self._clear_highlight()
        self._data = data
        shown = data[:MAX_DISPLAY_BYTES]
        self._displayed = len(shown)
        lines = [
            self._format_line(off, shown[off : off + BYTES_PER_LINE])
            for off in range(0, len(shown), BYTES_PER_LINE)
        ]
        if len(shown) < len(data):
            lines.append(
                f"…（Hex 视图仅显示前 {MAX_DISPLAY_BYTES >> 20} MiB，共 {len(data)} 字节）"
            )
        self.setPlainText("\n".join(lines))
        cursor = self.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.Start)
        self.setTextCursor(cursor)
        self.ensureCursorVisible()
        self._rebuild_highlight()  # 新文档：只铺偏移列底色（节点高亮已随旧文档清空）

    @staticmethod
    def _format_line(off: int, chunk: bytes) -> str:
        tokens = [f"{b:02X}" for b in chunk]
        tokens += ["  "] * (BYTES_PER_LINE - len(tokens))
        hex_part = " ".join(tokens)
        ascii_part = "".join(chr(c) if 0x20 <= c < 0x7F else "·" for c in chunk).ljust(
            BYTES_PER_LINE
        )
        return f"{off:08X}  {hex_part}  {ascii_part}"

    # ---- 高亮 ----------------------------------------------------------

    def highlight_node(self, node: Asn1Node | None, anchor_byte: int | None = None) -> None:
        """树选中节点 → 三色高亮；错误节点整体红色。

        anchor_byte：Hex 点击反向定位时传入被点击的字节，视口围绕它保持
        稳定（不跳回节点起始）；缺省时滚到节点起始（树点击路径）。
        零长度错误标记没有可见 span，保持当前视口，不滚到同 offset 的后继节点。
        选区仅覆盖当前可视行区间，滚动/缩放时由 _rebuild_highlight() 重建，
        因此高亮开销与节点跨度无关，只与视口行数成正比。
        """
        self._hl_node = node
        if node is not None and node.end > node.offset:
            byte = node.offset
            if anchor_byte is not None:
                byte = max(node.offset, min(anchor_byte, node.end - 1))
            self._scroll_to_byte(byte)
        self._rebuild_highlight()

    def _clear_highlight(self) -> None:
        """完全清空选区（含常驻的偏移列选区）：仅替换文档前调用，见 set_data()。"""
        self._hl_node = None
        if self.extraSelections():
            self.setExtraSelections([])

    @staticmethod
    def _node_spans(node: Asn1Node) -> list[tuple[int, int, QColor]]:
        """节点的三色区间（错误节点为整段红色）。"""
        if node.error is not None:
            # 不定长缺 EOC 且正好停在 end 时会产生零长度错误标记；不要把它
            # 扩成 1 字节，否则会错误高亮同偏移的兄弟/后继节点。
            if node.end <= node.offset:
                return []
            return [(node.offset, node.end, _COLOR_ERROR)]
        tag_end = node.offset + node.tag_len
        return [
            (node.offset, tag_end, _COLOR_TAG),
            (tag_end, node.value_offset, _COLOR_LEN),
            (node.value_offset, node.end, _COLOR_VALUE),
        ]

    def _rebuild_highlight(self) -> None:
        """按当前可视行区间重建选区（滚动、缩放、文档/主题切换后调用）。

        选区 = 常驻的偏移列（淡底色 + 弱化地址文字）+ 当前节点的三色高亮；
        两者都只覆盖可视行，开销与文件大小无关。
        """
        if self._displayed <= 0:
            if self.extraSelections():
                self.setExtraSelections([])
            return
        first, last = self._visible_line_range()
        selections = self._offset_selections(first, last)
        node = self._hl_node
        if node is not None:
            selections += self._build_selections(self._node_spans(node), first, last)
        self.setExtraSelections(selections)

    def _offset_selections(self, first_line: int, last_line: int) -> list:
        """偏移列 [0, OFFSET_COL_END) 的常驻选区（只铺可视行）。

        截断提示行（「…（Hex 视图仅显示前 N MiB…）」）不是数据行，不铺底色。
        """
        last_line = min(last_line, self._line_count() - 1)
        if last_line < first_line:
            return []
        fmt = offset_column_format(self.palette())
        selections = []
        for line in range(first_line, last_line + 1):
            sel = self._make_selection(line, 0, OFFSET_COL_END, fmt)
            if sel is not None:
                selections.append(sel)
        return selections

    def _visible_line_range(self) -> tuple[int, int]:
        """当前视口覆盖的行号闭区间（含上下余量）；空文档返回 (0, -1)。"""
        line_count = self._line_count()
        if line_count <= 0:
            return 0, -1
        block = self.firstVisibleBlock()
        if not block.isValid():
            return 0, -1
        first = last = block.blockNumber()
        viewport_bottom = self.viewport().rect().bottom()
        offset = self.contentOffset()
        while block.isValid():
            top = self.blockBoundingGeometry(block).translated(offset).top()
            if top > viewport_bottom:
                break
            last = block.blockNumber()
            block = block.next()
        first = max(0, first - _VISIBLE_MARGIN_LINES)
        last = min(last + _VISIBLE_MARGIN_LINES, line_count - 1)
        return first, last

    def _build_selections(
        self, spans: list[tuple[int, int, QColor]], first_line: int, last_line: int
    ) -> list:
        """在 [first_line, last_line] 可视行范围内生成选区：
        每行最多 2 个选区（hex 列段 + ascii 列段），大节点不再逐行铺满全文。"""
        if last_line < first_line:
            return []
        selections = []
        for start, end, color in spans:
            if end <= start or start >= self._displayed:
                continue
            end = min(end, self._displayed)
            fmt = QTextCharFormat()
            fmt.setBackground(color)  # 同一段共用格式对象（ExtraSelection 按值持有）
            span_first = start // BYTES_PER_LINE
            span_last = (end - 1) // BYTES_PER_LINE
            line_lo = max(span_first, first_line)
            line_hi = min(span_last, last_line)
            for line in range(line_lo, line_hi + 1):
                lo = max(start, line * BYTES_PER_LINE)
                hi = min(end, (line + 1) * BYTES_PER_LINE)
                lo_i, hi_i = lo % BYTES_PER_LINE, (hi - lo) + lo % BYTES_PER_LINE - 1
                hexa = self._make_selection(line, byte_col(lo_i), byte_col(hi_i) + 2, fmt)
                asciia = self._make_selection(line, ASCII_START + lo_i, ASCII_START + hi_i + 1, fmt)
                selections += [s for s in (hexa, asciia) if s is not None]
        return selections

    def _make_selection(
        self, line: int, col_start: int, col_end: int, fmt: QTextCharFormat
    ) -> QTextEdit.ExtraSelection | None:
        if col_end <= col_start or line >= self.document().blockCount():
            return None
        cursor = QTextCursor(self.document())
        cursor.setPosition(self._char_pos(line, col_start))
        cursor.setPosition(self._char_pos(line, col_end), QTextCursor.KeepAnchor)
        extra = QTextEdit.ExtraSelection()
        extra.cursor = cursor
        extra.format = fmt
        return extra

    # ---- 坐标换算 ------------------------------------------------------

    def _line_count(self) -> int:
        return (self._displayed + BYTES_PER_LINE - 1) // BYTES_PER_LINE

    def _char_pos(self, line: int, col: int) -> int:
        block = self.document().findBlockByNumber(line)
        return block.position() + col

    def _scroll_to_byte(self, byte: int) -> None:
        if byte < 0 or byte >= self._displayed:
            return
        line = byte // BYTES_PER_LINE
        col = byte_col(byte % BYTES_PER_LINE)
        cursor = QTextCursor(self.document())
        cursor.setPosition(self._char_pos(line, col))
        self.setTextCursor(cursor)
        self.ensureCursorVisible()

    # ---- 反向点击定位 ---------------------------------------------------

    def mousePressEvent(self, event) -> None:
        super().mousePressEvent(event)
        if event.button() != Qt.MouseButton.LeftButton:
            return  # 右键等只出菜单，不反向定位（保持树选中不变）
        cursor = self.cursorForPosition(event.position().toPoint())
        pos = cursor.position()
        block = self.document().findBlock(pos)
        line = block.blockNumber()
        if line < 0 or line >= self._line_count():
            return
        col = pos - block.position()
        byte = self._col_to_byte(line, col)
        if byte is not None:
            self.byte_clicked.emit(byte)

    def _col_to_byte(self, line: int, col: int) -> int | None:
        """列号 → 行内字节 offset。

        每字节占 3 列（两位数字 + 1 空格）。间隔空格与行尾补位列就近钳到
        相邻的真实字节，点击 hex 任何字符不再出现无响应的「哑列」。
        """
        first = line * BYTES_PER_LINE
        if first >= self._displayed:
            return None
        line_bytes = min(BYTES_PER_LINE, self._displayed - first)
        if ASCII_START <= col < ASCII_START + BYTES_PER_LINE:
            i = col - ASCII_START
        elif HEX_START <= col < ASCII_START:
            rel = col - HEX_START
            i = min(rel // 3, 15)
        else:
            return None
        # 行尾补位（最后一行不足 16 字节）钳到行内最后一个真实字节
        return first + min(i, line_bytes - 1)
