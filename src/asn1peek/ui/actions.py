"""复制动作：与窗口装配解耦，通过回调读取选中节点和写状态栏。

MainWindow 保留 ``_copy_raw`` 等兼容方法并委托到本控制器；右键菜单与全局
快捷键共用同一套实现。
"""

from __future__ import annotations

from collections.abc import Callable

from PySide6.QtCore import QEvent, QObject
from PySide6.QtGui import QKeySequence
from PySide6.QtWidgets import QApplication, QMessageBox, QWidget

from ..core import export as exp
from ..core.export import ValueVariant
from ..core.model import Asn1Node

StatusMessage = Callable[[str, int], None]

# core 只提供稳定 ASCII key；中文文案由 UI 决定。
VALUE_KEY_LABELS = {
    "int-decimal": "整数（十进制）",
    "int-hex": "整数（十六进制）",
    "bit-hex": "BIT STRING（Hex）",
    "bit-base64": "BIT STRING（Base64）",
    "octet-hex": "OCTET STRING（Hex）",
    "octet-base64": "OCTET STRING（Base64）",
    "oid-dotted": "OID（点分）",
    "oid-name": "OID 名称",
    "relative-oid": "RELATIVE-OID（点分）",
    "time-iso": "时间（ISO 8601）",
    "time-raw": "时间（原文）",
    "text": "文本",
    "boolean": "BOOLEAN",
    "null": "NULL",
    "hex": "Hex",
    "base64": "Base64",
}


def value_variant_label(key: str) -> str:
    """把 core 的稳定 key 映射为菜单/状态栏中文文案。"""
    return VALUE_KEY_LABELS.get(key, key)


class CopyShortcutFilter(QObject):
    """让文本控件的选区复制优先于窗口级 Ctrl+C QAction。"""

    def eventFilter(self, obj, event) -> bool:  # noqa: N802
        if event.type() == QEvent.Type.ShortcutOverride and event.matches(
            QKeySequence.StandardKey.Copy
        ):
            cursor = getattr(obj, "textCursor", None)
            if cursor is not None and cursor().hasSelection():
                event.accept()
                return True
        return False


class CopyController:
    """复制路径 / 子树文本 / 原始字节 / 节点值。"""

    def __init__(
        self,
        parent: QWidget,
        selected_node: Callable[[], Asn1Node | None],
        status: StatusMessage,
    ) -> None:
        self._parent = parent
        self._selected_node = selected_node
        self._status = status

    def _require_node(self) -> Asn1Node | None:
        node = self._selected_node()
        if node is None:
            self._status("未选中节点", 4000)
        return node

    def _copy_text(self, text: str, note: str) -> None:
        QApplication.clipboard().setText(text)
        self._status(f"已复制{note}（{len(text)} 字符）", 4000)

    def value_variants(self) -> list[ValueVariant]:
        """当前选中节点的可复制值变体；无选中时返回空列表。"""
        node = self._selected_node()
        if node is None:
            return []
        return exp.copy_value_variants(node)

    def copy_value(self) -> None:
        """复制第一个值变体；无变体（容器/错误/无值）回落完整 TLV Hex。"""
        node = self._require_node()
        if node is None:
            return
        variants = exp.copy_value_variants(node)
        if variants:
            self.copy_value_text(variants[0])
            return
        self._copy_raw_node(node, "hex")

    def copy_value_text(self, variant: ValueVariant) -> None:
        """复制指定值变体，并在状态栏显示 UI 侧文案。"""
        if not variant.text:
            self._status("该节点没有可复制的值", 4000)
            return
        self._copy_text(
            variant.text,
            f"节点值（{value_variant_label(variant.key)}）",
        )

    def copy_raw(self, fmt: str) -> None:
        """复制完整 TLV 原始字节（Hex/Base64）；超大节点先确认。"""
        node = self._require_node()
        if node is not None:
            self._copy_raw_node(node, fmt)

    def _copy_raw_node(self, node: Asn1Node, fmt: str) -> None:
        """先按 span 判断大小，确认后才切片，避免大节点先分配。"""
        size = max(0, node.total_len)
        if size > exp.LARGE_COPY_LIMIT:
            answer = QMessageBox.question(
                self._parent,
                "复制超大节点",
                f"该节点原始字节为 {size:,} B（超过 16 MiB），确定复制到剪贴板吗？",
            )
            if answer != QMessageBox.StandardButton.Yes:
                return
        raw = exp.node_bytes(node)
        if fmt == "hex":
            self._copy_text(exp.der_hex(raw), "原始字节 Hex")
        else:
            self._copy_text(exp.der_base64(raw), "原始字节 Base64")

    def copy_path(self) -> None:
        node = self._require_node()
        if node is not None:
            self._copy_text(node.path, "节点路径")

    def copy_subtree(self) -> None:
        node = self._require_node()
        if node is not None:
            self._copy_text(exp.subtree_text(node), "子树缩进文本")
