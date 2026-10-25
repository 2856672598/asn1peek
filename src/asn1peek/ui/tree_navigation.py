"""树视图导航：展开祖先链、选中与滚动定位。"""

from __future__ import annotations

from PySide6.QtCore import QModelIndex
from PySide6.QtWidgets import QTreeView

from ..core.model import Asn1Node
from .tree_model import Asn1TreeModel


class TreeNavigator:
    """封装 QTreeView 的常用定位操作，避免主窗口散落索引遍历代码。"""

    def __init__(self, view: QTreeView, model: Asn1TreeModel) -> None:
        self.view = view
        self.model = model

    def selected_node(self) -> Asn1Node | None:
        index = self.view.selectionModel().currentIndex()
        if not index.isValid():
            return None
        node: Asn1Node | None = index.internalPointer()
        return node

    def expand_ancestors(self, index: QModelIndex) -> None:
        """展开 index 的祖先链（Qt 的 expand 只影响节点自身）。"""
        ancestors: list[QModelIndex] = []
        parent = index.parent()
        while parent.isValid():
            ancestors.append(parent)
            parent = parent.parent()
        for ancestor in reversed(ancestors):
            self.view.expand(ancestor)

    def expand_here(self, node: Asn1Node) -> None:
        """展开节点的祖先链与自身，使其子树可见。"""
        index = self.model.index_for_node(node)
        self.expand_ancestors(index)
        self.view.expand(index)

    def collapse_all(self) -> None:
        """折叠树中所有已展开的节点。

        不能用递归 rowCount/index 遍历：那会为每个尚未展开的容器触发懒解析，
        巨大文档上一次「折叠全部」等于把整棵树全部解析。QTreeView.collapseAll
        只处理当前可见（已展开）项。
        """
        self.view.collapseAll()

    def select_index(self, index: QModelIndex) -> None:
        """先设当前索引、后改选，保证 selectionChanged 时 currentIndex 已就绪。"""
        selection = self.view.selectionModel()
        self.view.setCurrentIndex(index)
        selection.select(
            index,
            selection.SelectionFlag.ClearAndSelect | selection.SelectionFlag.Rows,
        )
