"""主窗口：窗口装配与槽函数编排（树 + Hex + 详情三区联动）。

职责拆分：
- document_session：sniff/parse/空输入等纯逻辑；
- tree_navigation：展开祖先链与选中定位；
- actions：复制路径/子树/原始字节；
- context_menus：树与 Hex 右键菜单构建。

联动链路：
- 树 selectionChanged → Highlighter(hex_view.highlight_node) + DetailPanel；
- HexView.byte_clicked → locate_node（最内层包含）→ 树选中并滚动到位；
- 树右键菜单 → 复制原始字节 / 复制路径 / 复制子树文本
  / 展开到此处 / 折叠全部；
- Hex 区右键菜单 → 复制树中选中节点的原始字节（Hex / Base64）；
- Ctrl+V 粘贴解析：读剪贴板文本 → sniff → open_data。
"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QApplication,
    QFileDialog,
    QFrame,
    QHeaderView,
    QMainWindow,
    QMenu,
    QMessageBox,
    QTreeView,
)

from .. import __version__
from ..core.model import Asn1Node
from ..core.parser import locate_node
from .actions import CopyController, CopyShortcutFilter
from .context_menus import TreeMenuActions, build_hex_context_menu, build_tree_context_menu
from .detail_panel import DetailPanel
from .document_session import empty_document, load_document
from .hex_view import HexView
from .splitter import LineSplitter
from .tree_model import Asn1TreeModel
from .tree_navigation import TreeNavigator
from .tree_view import Asn1TreeView
from .window_menus import MenuHandlers, build_window_actions

_WINDOW_TITLE = f"asn1peek {__version__}"

_ABOUT_TEXT = f"""<h3>asn1peek {__version__}</h3>
<p>Linux 桌面端 ASN.1 数据查看器（树状结构 + Hex 联动）。</p>
<p>许可：<b>MIT License</b></p>
<p>第三方组件：</p>
<ul>
<li><b>PySide6</b>（Qt for Python）— LGPLv3</li>
<li><b>dumpasn1.cfg</b> OID 名称库 — MIT 授权（cryptlib / Peter Gutmann）</li>
</ul>"""


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(_WINDOW_TITLE)
        self.resize(1200, 800)
        self.setAcceptDrops(True)

        self._current_path: str | None = None
        self._hex_click_anchor: int | None = None  # Hex 点击反定位：视口锚点字节

        self.tree_model = Asn1TreeModel()
        self.tree_view = Asn1TreeView()
        self.tree_view.setModel(self.tree_model)
        self.tree_view.setUniformRowHeights(True)
        self.tree_view.setSelectionBehavior(QTreeView.SelectionBehavior.SelectRows)
        self.tree_view.setSelectionMode(QTreeView.SelectionMode.SingleSelection)
        self.tree_view.setExpandsOnDoubleClick(True)
        header = self.tree_view.header()
        header.setStretchLastSection(False)
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)
        header.resizeSection(1, 70)
        header.resizeSection(2, 80)
        # 默认仅显示「结构」列；长度/偏移列由「视图」菜单按需开启。
        self.tree_view.setColumnHidden(1, True)
        self.tree_view.setColumnHidden(2, True)
        # 结构列的表头文本为空，仅显示该列时隐藏表头；开启长度/偏移列后恢复
        self._update_tree_header()
        self.tree_view.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tree_view.customContextMenuRequested.connect(self._on_tree_context_menu)

        self.hex_view = HexView()
        self.hex_view.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.hex_view.customContextMenuRequested.connect(self._on_hex_context_menu)
        self.detail_panel = DetailPanel()

        # 文本控件的选区复制优先于窗口级 Ctrl+C（树/无选区时才复制节点值）
        self._copy_shortcut_filter = CopyShortcutFilter(self)
        self.hex_view.installEventFilter(self._copy_shortcut_filter)
        self.detail_panel.browser.installEventFilter(self._copy_shortcut_filter)

        self.tree_navigator = TreeNavigator(self.tree_view, self.tree_model)
        self._copy = CopyController(self, self._selected_node, self._show_status)
        # 分栏之间只显示一条 1px 分隔线：视图自身不画外框，由 LineSplitter
        # 统一绘制（否则相邻视图两道边框 + 手柄缝隙会形成「双线」）。
        for view in (self.tree_view, self.hex_view, self.detail_panel.browser):
            view.setFrameShape(QFrame.Shape.NoFrame)

        right_split = LineSplitter(Qt.Orientation.Vertical)
        right_split.addWidget(self.hex_view)
        right_split.addWidget(self.detail_panel)
        right_split.setStretchFactor(0, 3)
        right_split.setStretchFactor(1, 1)

        split = LineSplitter(Qt.Orientation.Horizontal)
        split.addWidget(self.tree_view)
        split.addWidget(right_split)
        split.setStretchFactor(0, 1)
        split.setStretchFactor(1, 2)
        self.setCentralWidget(split)

        self._build_menus()

        # 联动信号
        self.tree_view.selectionModel().selectionChanged.connect(self._on_tree_selection)
        self.hex_view.byte_clicked.connect(self._on_hex_click)

        self.statusBar().showMessage("拖入、打开或粘贴（Ctrl+V）一个 DER/PEM/Base64/Hex 文件开始")

    # ---- 菜单与动作 ------------------------------------------------------

    def _build_menus(self) -> None:
        """构建菜单与复制动作（右键菜单与全局快捷键共用）。"""
        actions = build_window_actions(
            self,
            self.tree_view,
            self.detail_panel,
            MenuHandlers(
                open=self._on_open,
                reload=self._on_reload,
                quit=self.close,
                toggle_column=self._on_toggle_tree_column,
                set_connection_lines=self.tree_view.set_connection_lines,
                set_decoded_visible=self.detail_panel.set_decoded_visible,
                about=self._on_about,
                copy_path=self._copy_path,
                copy_subtree=self._copy_subtree,
                expand_here=self._expand_here,
                collapse_all=self._collapse_all,
                paste=self._on_paste,
                copy_value=self._copy.copy_value,
            ),
        )
        self.act_show_length = actions.show_length
        self.act_show_offset = actions.show_offset
        self.act_show_decoded = actions.show_decoded
        self.act_copy_value = actions.copy_value
        self.act_copy_path = actions.copy_path
        self.act_copy_subtree = actions.copy_subtree
        self.act_expand_here = actions.expand_here
        self.act_collapse_all = actions.collapse_all

    def _update_tree_header(self) -> None:
        """仅显示结构列时隐藏表头。

        结构列的表头文本为空，默认只显示该列时表头纯占一行高度；
        开启长度/偏移列后恢复表头，保证这两列有可见列名。
        """
        self.tree_view.setHeaderHidden(
            self.tree_view.isColumnHidden(1) and self.tree_view.isColumnHidden(2)
        )

    def _on_toggle_tree_column(self, column: int, checked: bool) -> None:
        self.tree_view.setColumnHidden(column, not checked)
        self._update_tree_header()

    def _selected_node(self) -> Asn1Node | None:
        return self.tree_navigator.selected_node()

    def _show_status(self, message: str, timeout: int = 4000) -> None:
        self.statusBar().showMessage(message, timeout)

    # ---- 复制 ------------------------------------------------------------

    def _copy_raw(self, fmt: str) -> None:
        self._copy.copy_raw(fmt)

    def _copy_path(self) -> None:
        self._copy.copy_path()

    def _copy_subtree(self) -> None:
        self._copy.copy_subtree()

    # ---- 视图操作 --------------------------------------------------------

    def _expand_here(self) -> None:
        node = self._selected_node()
        if node is not None:
            self.tree_navigator.expand_here(node)

    def _collapse_all(self) -> None:
        self.tree_navigator.collapse_all()
        self.statusBar().showMessage("已折叠全部", 4000)

    # ---- 关于 ------------------------------------------------------------

    def _on_about(self) -> None:
        QMessageBox.about(self, "关于 asn1peek", _ABOUT_TEXT)

    # ---- 文件装配 -------------------------------------------------------

    def open_file(self, path: str) -> None:
        try:
            data = Path(path).read_bytes()
        except (OSError, PermissionError) as exc:
            QMessageBox.critical(self, "打开失败", f"无法读取文件：\n{exc}")
            return
        self._current_path = None
        if self._load(data, path):
            self._current_path = path

    def open_data(self, data: bytes, desc: str) -> None:
        """直接解析一段数据（例如剪贴板内容），不关联文件路径。"""
        self._current_path = None
        self._load(data, desc)

    def _clear_view(self, source: str) -> None:
        """空输入必须清掉旧树/Hex/详情，避免界面继续展示上一份文件。"""
        self._hex_click_anchor = None
        empty = empty_document()
        self.tree_model.set_document(empty)
        self.hex_view.set_data(b"")
        self.detail_panel.set_document(empty)
        self.statusBar().showMessage(f"{source}：内容为空", 8000)

    def _load(self, data: bytes, source: str) -> bool:
        """sniff → parse → 三区装配的公共路径。source 为路径或来源描述。

        返回是否装载了有效输入；空输入返回 False 并清空旧视图。
        """
        loaded = load_document(data, source)
        if loaded.is_empty:
            self._clear_view(source)
            return False

        doc = loaded.document
        self.tree_model.set_document(doc)
        self.hex_view.set_data(doc.data)
        self.detail_panel.set_document(doc)
        self.statusBar().clearMessage()  # 状态栏只显示操作反馈。
        for root in doc.roots:
            idx = self.tree_model.index_for_node(root)
            if idx.isValid():
                self.tree_view.expand(idx)
        if doc.roots:
            first = self.tree_model.index_for_node(doc.roots[0])
            if first.isValid():
                self.tree_navigator.select_index(first)
        if loaded.message:
            self.statusBar().showMessage(loaded.message, loaded.message_timeout)
        return True

    # ---- 剪贴板粘贴 ------------------------------------------------------

    def _on_paste(self) -> None:
        """Ctrl+V：读剪贴板文本 → sniff → open_data。"""
        text = QApplication.clipboard().text()
        if not text:
            self.statusBar().showMessage("剪贴板为空", 4000)
            return
        self.open_data(text.encode("utf-8", "surrogatepass"), "剪贴板内容")
        # 识别失败/无效结构由 _load 统一给出状态栏提示

    # ---- 拖拽-------------------------------------------------------------

    def dragEnterEvent(self, event) -> None:  # noqa: N802
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event) -> None:  # noqa: N802
        urls = event.mimeData().urls()
        event.acceptProposedAction()
        if not urls:
            return
        path = urls[0].toLocalFile()
        if path:
            self.open_file(path)

    # ---- 事件槽 ---------------------------------------------------------

    def _on_open(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "打开 ASN.1 数据文件",
            "",
            "PKI 文件 (*.der *.cer *.crt *.pem *.csr *.p10 *.p7b *.p7s *.key *.pub *.crl);;"
            "所有文件 (*)",
        )
        if path:
            self.open_file(path)

    def _on_reload(self) -> None:
        if self._current_path:
            self.open_file(self._current_path)

    def _on_tree_selection(self, selected, deselected) -> None:
        index = self.tree_view.selectionModel().currentIndex()
        if not index.isValid():
            self.hex_view.highlight_node(None)
            self.detail_panel.show_node(None)
            return
        node = index.internalPointer()
        anchor, self._hex_click_anchor = self._hex_click_anchor, None
        if anchor is None:
            self.hex_view.highlight_node(node)
        else:  # Hex 点击发起：视口围绕点击字节，不跳回节点起始
            self.hex_view.highlight_node(node, anchor_byte=anchor)
        self.detail_panel.show_node(node)

    def _on_hex_click(self, byte_offset: int) -> None:
        doc = self.tree_model.document
        node = locate_node(doc, byte_offset)
        if node is None:
            return
        idx = self.tree_model.index_for_node(node)
        if not idx.isValid():
            return
        # 展开祖先链，保证目标行可见
        self.tree_navigator.expand_ancestors(idx)
        # 先设当前索引、后改选：select() 触发 selectionChanged 时
        # currentIndex() 已指向目标节点，否则高亮/详情仍按旧节点计算，
        # 还会把 Hex 视口拉走（点击后视图跳动的根源）。
        self._hex_click_anchor = byte_offset
        try:
            self.tree_navigator.select_index(idx)
        finally:
            self._hex_click_anchor = None
        self.tree_view.scrollTo(idx)

    # ---- 右键菜单 --------------------------------------------------------

    def _on_tree_context_menu(self, pos) -> None:
        index = self.tree_view.indexAt(pos)
        if not index.isValid():
            return
        # 右键先选中该行，保证复制操作与所见一致；select_index 先设 current
        # 再触发 selectionChanged，详情/Hex 不会停留在旧节点。
        self.tree_navigator.select_index(index)

        menu = build_tree_context_menu(
            self,
            TreeMenuActions(
                copy_raw=self._copy_raw,
                copy_path=self.act_copy_path,
                copy_subtree=self.act_copy_subtree,
                expand_here=self.act_expand_here,
                collapse_all=self.act_collapse_all,
                value_variants=self._copy.value_variants,
                copy_value_text=self._copy.copy_value_text,
            ),
        )
        self._exec_context_menu(menu, self.tree_view.viewport().mapToGlobal(pos))

    def _exec_context_menu(self, menu: QMenu, global_pos) -> None:
        """执行右键菜单并释放；独立方法便于无头测试替换 exec。"""
        menu.exec(global_pos)
        menu.deleteLater()

    # ---- Hex 区右键：复制选中节点数据 -----------------------------------

    def _on_hex_context_menu(self, pos) -> None:
        """Hex 区右键：对树中选中节点提供原始字节复制（与树右键「复制原始字节」同源）。

        无选中节点时回落到 Qt 原生文本菜单（复制/全选），不改变既有行为；
        右键不反向定位，树中的选中节点保持不变。
        """
        menu = self._hex_context_menu(self._selected_node())
        self._exec_context_menu(menu, self.hex_view.viewport().mapToGlobal(pos))

    def _hex_context_menu(self, node: Asn1Node | None) -> QMenu:
        """构建 Hex 区右键菜单。"""
        if node is None:
            return self.hex_view.createStandardContextMenu()
        return build_hex_context_menu(self, node, self._copy_raw)
