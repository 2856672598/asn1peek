"""树 / Hex 右键菜单构建：接收动作与复制回调，不反向依赖 MainWindow。"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from PySide6.QtGui import QAction
from PySide6.QtWidgets import QMenu, QWidget

from ..core.export import ValueVariant
from ..core.model import Asn1Node
from .actions import value_variant_label

CopyRaw = Callable[[str], None]


@dataclass(frozen=True)
class TreeMenuActions:
    """树右键菜单使用的动作集合（由 MainWindow 持有并复用）。"""

    copy_raw: CopyRaw
    copy_path: QAction
    copy_subtree: QAction
    expand_here: QAction
    collapse_all: QAction
    value_variants: Callable[[], list[ValueVariant]]
    copy_value_text: Callable[[ValueVariant], None]


def _add_value_menu(menu: QMenu, actions: TreeMenuActions) -> None:
    """添加「复制值」子菜单；无变体时给原始字节回落入库。"""
    variants = actions.value_variants()
    if not variants:
        fallback = menu.addAction("复制值（原始字节 Hex）")
        fallback.triggered.connect(lambda: actions.copy_raw("hex"))
        return
    value_menu = menu.addMenu("复制值")
    for variant in variants:
        action = value_menu.addAction(value_variant_label(variant.key))
        action.triggered.connect(lambda _checked=False, v=variant: actions.copy_value_text(v))


def build_tree_context_menu(parent: QWidget, actions: TreeMenuActions) -> QMenu:
    """构建树节点右键菜单。"""
    menu = QMenu(parent)
    _add_value_menu(menu, actions)
    raw_menu = menu.addMenu("复制原始字节")
    raw_menu.addAction("Hex（完整 TLV）").triggered.connect(lambda: actions.copy_raw("hex"))
    raw_menu.addAction("Base64（完整 TLV）").triggered.connect(lambda: actions.copy_raw("base64"))
    menu.addAction(actions.copy_path)
    menu.addAction(actions.copy_subtree)
    menu.addSeparator()
    menu.addAction(actions.expand_here)
    menu.addAction(actions.collapse_all)
    return menu


def build_hex_context_menu(
    parent: QWidget,
    node: Asn1Node,
    copy_raw: CopyRaw,
) -> QMenu:
    """构建有选中节点时的 Hex 区右键菜单。"""
    menu = QMenu(parent)
    header = menu.addAction(f"{node.type_name} @0x{node.offset:X} · {node.total_len} B")
    header.setEnabled(False)
    menu.addSeparator()
    menu.addAction("复制原始字节（Hex）").triggered.connect(lambda: copy_raw("hex"))
    menu.addAction("复制原始字节（Base64）").triggered.connect(lambda: copy_raw("base64"))
    return menu
