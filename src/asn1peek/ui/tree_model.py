"""结构树模型：把 Asn1Document 映射为 QAbstractItemModel。

懒解析的关键路径：展开容器时 Qt 调 rowCount()/data()，进而触发
node.child_items()——首次展开才解析直接子节点。

第一列只显示结构信息（类型名——非 universal 标签写作
`Context[n]`/`Application[n]`/`Private[n]`；内嵌与警告/错误标记），不展示
OID 名称、值摘要等解码结果。
"""

from __future__ import annotations

from functools import cache

from PySide6.QtCore import QAbstractItemModel, QModelIndex, Qt
from PySide6.QtGui import QColor, QFont

from ..core.model import LEN_INDEFINITE, LEN_LONG, Asn1Document, Asn1Node

_COL_COUNT = 3
_HEADERS = ("", "长度 (B)", "偏移")

_COLOR_ERROR = QColor("#c62828")
_COLOR_WARNING = QColor("#b26a00")
_COLOR_EMBEDDED = QColor("#00695c")

# QModelIndex 为不可变值类型；复用无效索引作为 Qt 覆写方法的默认参数，
# 避免在函数签名里每次调用构造对象（B008）。
_INVALID_INDEX = QModelIndex()


@cache
def _font(bold: bool, italic: bool) -> QFont:
    font = QFont()
    font.setBold(bold)
    font.setItalic(italic)
    return font


class Asn1TreeModel(QAbstractItemModel):
    def __init__(self, document: Asn1Document | None = None, parent=None) -> None:
        super().__init__(parent)
        self.document = document or Asn1Document(data=b"", roots=[])

    # ---- 结构 ----------------------------------------------------------

    def set_document(self, document: Asn1Document) -> None:
        self.beginResetModel()
        self.document = document
        self.endResetModel()

    def columnCount(self, parent=_INVALID_INDEX) -> int:
        return _COL_COUNT

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role != Qt.DisplayRole or orientation != Qt.Horizontal:
            return None
        return _HEADERS[section] if 0 <= section < _COL_COUNT else None

    def rowCount(self, parent=_INVALID_INDEX) -> int:
        if parent.column() > 0:  # Qt 约定：非 0 列不产生子行
            return 0
        if not parent.isValid():
            return len(self.document.roots)
        node: Asn1Node = parent.internalPointer()
        if node.error is not None:
            return 0
        if node.constructed or node.possible_embedded:
            return len(node.child_items)  # 此处触发懒解析
        return 0

    def hasChildren(self, parent=_INVALID_INDEX) -> bool:
        if not parent.isValid():
            return bool(self.document.roots)
        node: Asn1Node = parent.internalPointer()
        if node.error is not None:
            return False
        if node.constructed:
            # 与可展开行保持一致：空值区的构造节点（如空 Context[n]）展开后
            # 没有任何行，就不画展开箭头。非空内容展开后至少有 1 行（子节点
            # 或 ✗ 错误节点），故无需在此触发懒解析即可判定。
            return node.value_len_ > 0
        if node.possible_embedded:
            # 原生串能否展开取决于内嵌 DER 探测结果（严格、有界、缓存）；
            # 探测失败则没有 ⤷ 行，不显示展开箭头。
            return self.rowCount(parent) > 0
        return False

    def flags(self, index):
        if not index.isValid():
            return Qt.NoItemFlags
        return Qt.ItemIsEnabled | Qt.ItemIsSelectable

    def index(self, row, column, parent=_INVALID_INDEX) -> QModelIndex:
        if not self.hasIndex(row, column, parent):
            return QModelIndex()
        if not parent.isValid():
            if 0 <= row < len(self.document.roots):
                return self.createIndex(row, column, self.document.roots[row])
            return QModelIndex()
        node: Asn1Node = parent.internalPointer()
        items = node.child_items
        if 0 <= row < len(items):
            return self.createIndex(row, column, items[row])
        return QModelIndex()

    def parent(self, index: QModelIndex) -> QModelIndex:
        if not index.isValid():
            return QModelIndex()
        node: Asn1Node = index.internalPointer()
        p = node.parent
        if p is None:
            return QModelIndex()
        gp = p.parent
        if gp is None:
            siblings = self.document.roots
        else:
            siblings = gp.child_items
        row = p._row
        if not (0 <= row < len(siblings)) or siblings[row] is not p:
            try:
                row = siblings.index(p)
            except ValueError:
                return QModelIndex()
        return self.createIndex(row, 0, p)

    # ---- 视觉数据 ------------------------------------------------------

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        node: Asn1Node = index.internalPointer()
        col = index.column()

        if role == Qt.DisplayRole:
            if col == 0:
                # 纯结构显示：类型名（Context[n]/Application[n]/Private[n]，
                # 内嵌节点加 ⤷ 前缀），不带 OID 名称/值摘要
                label = "⤷ " + node.type_name if node.is_embedded else node.type_name
                if node.error is not None:
                    return f"✗ {label}"
                if node.warnings:
                    return f"⚠ {label}"
                return label
            if col == 1:
                return str(node.value_len) if node.error is None else str(node.value_len_)
            if col == 2:
                return f"0x{node.offset:X}"
            return None

        if role == Qt.ForegroundRole:
            if node.error is not None:
                return _COLOR_ERROR
            if node.warnings:
                return _COLOR_WARNING
            if node.is_embedded:
                return _COLOR_EMBEDDED
            return None

        if role == Qt.FontRole:
            if node.warnings or node.is_embedded:
                return _font(False, True)
            if node.error is not None:
                return _font(True, False)
            return None

        if role == Qt.ToolTipRole:
            if node.error is not None:
                total = f"错误区 {node.value_len_} B"
            else:
                total = f"总长 {node.total_len} B = 头 {node.header_len} B + 值 {node.value_len} B"
                if node.eoc_len:
                    total += f" + EOC {node.eoc_len} B"
            lines = [
                f"{node.type_name}    offset 0x{node.offset:X}",
                total,
            ]
            if node.error is not None:
                lines.append("长度编码：无效（错误节点）")
            elif node.length_form == LEN_INDEFINITE:
                if node.eoc_len:
                    lines.append("长度编码：不定长（BER，EOC 终止）")
                else:
                    lines.append("长度编码：不定长（BER，缺少 EOC 终止）")
            elif node.length_form == LEN_LONG:
                lines.append(f"长度编码：长形式（{node.length_len} B）")
            else:
                lines.append("长度编码：短形式")
            lines += [f"⚠ {w}" for w in node.warnings]
            if node.error:
                lines.append(f"✗ {node.error_text}")
            return "\n".join(lines)
        return None

    # ---- 辅助查询 -------------------------------------------------------

    def index_for_node(self, node: Asn1Node) -> QModelIndex:
        """从节点反查 QModelIndex（O(depth)，用于 Hex → 树反向定位）。"""
        rows: list[int] = []
        n: Asn1Node = node
        while True:
            p = n.parent
            siblings = self.document.roots if p is None else p.child_items
            row = n._row
            if not (0 <= row < len(siblings)) or siblings[row] is not n:
                try:
                    row = siblings.index(n)
                except ValueError:
                    return QModelIndex()
            rows.append(row)
            if p is None:
                break
            n = p
        idx = QModelIndex()
        for r in reversed(rows):
            idx = self.index(r, 0, idx)
            if not idx.isValid():
                return QModelIndex()
        if idx.internalPointer() is not node:
            return QModelIndex()
        return idx
