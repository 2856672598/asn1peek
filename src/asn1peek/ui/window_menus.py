"""主窗口菜单与全局 QAction 构建：只创建控件并接线，不持有窗口状态。"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from PySide6.QtGui import QAction, QKeySequence
from PySide6.QtWidgets import QMainWindow

from .detail_panel import DetailPanel
from .tree_view import Asn1TreeView


@dataclass(frozen=True)
class MenuHandlers:
    """菜单/动作触发的槽函数集合（由 MainWindow 提供）。"""

    open: Callable[[], None]
    reload: Callable[[], None]
    quit: Callable[[], None]
    toggle_column: Callable[[int, bool], None]
    set_connection_lines: Callable[[bool], None]
    set_decoded_visible: Callable[[bool], None]
    about: Callable[[], None]
    copy_path: Callable[[], None]
    copy_subtree: Callable[[], None]
    expand_here: Callable[[], None]
    collapse_all: Callable[[], None]
    paste: Callable[[], None]
    copy_value: Callable[[], None]


@dataclass(frozen=True)
class WindowActions:
    """由 MainWindow 持有并复用的动作。"""

    show_length: QAction
    show_offset: QAction
    show_decoded: QAction
    copy_path: QAction
    copy_subtree: QAction
    expand_here: QAction
    collapse_all: QAction
    copy_value: QAction


def build_window_actions(
    window: QMainWindow,
    tree_view: Asn1TreeView,
    detail_panel: DetailPanel,
    handlers: MenuHandlers,
) -> WindowActions:
    """构建「文件/视图/帮助」菜单与复制/粘贴动作。"""
    open_action = QAction("打开(&O)…", window)
    open_action.setShortcut(QKeySequence.StandardKey.Open)
    open_action.triggered.connect(handlers.open)
    quit_action = QAction("退出(&Q)", window)
    quit_action.setShortcut(QKeySequence("Ctrl+Q"))
    quit_action.triggered.connect(handlers.quit)
    reload_action = QAction("重新解析(&R)", window)
    reload_action.setShortcut(QKeySequence("F5"))
    reload_action.triggered.connect(handlers.reload)

    file_menu = window.menuBar().addMenu("文件(&F)")
    file_menu.addAction(open_action)
    file_menu.addAction(reload_action)
    file_menu.addAction(quit_action)

    # 编码细节按需查看。
    view_menu = window.menuBar().addMenu("视图(&V)")
    show_length = QAction("显示长度列", window)
    show_offset = QAction("显示偏移列", window)
    for column, action in ((1, show_length), (2, show_offset)):
        action.setCheckable(True)
        action.toggled.connect(lambda checked, col=column: handlers.toggle_column(col, checked))
        view_menu.addAction(action)
    # 层级连接线（默认开；深树里比纯缩进更易读）
    lines_action = QAction("显示连接线(&L)", window)
    lines_action.setCheckable(True)
    lines_action.setChecked(tree_view.connection_lines())
    lines_action.toggled.connect(handlers.set_connection_lines)
    view_menu.addAction(lines_action)
    # 详情面板 Value 解析值（默认开）：OID 名称、时间 ISO 8601 等
    show_decoded = QAction("显示解码信息(&D)", window)
    show_decoded.setCheckable(True)
    show_decoded.setChecked(detail_panel.decoded_visible())
    show_decoded.toggled.connect(handlers.set_decoded_visible)
    view_menu.addAction(show_decoded)

    help_menu = window.menuBar().addMenu("帮助(&H)")
    about_action = QAction("关于(&A)", window)
    about_action.triggered.connect(handlers.about)
    help_menu.addAction(about_action)

    copy_path = QAction("复制路径(&P)", window)
    copy_path.setShortcut(QKeySequence("Ctrl+Shift+C"))
    copy_path.triggered.connect(handlers.copy_path)

    copy_value = QAction("复制值(&V)", window)
    copy_value.setShortcut(QKeySequence.StandardKey.Copy)
    copy_value.triggered.connect(handlers.copy_value)

    copy_subtree = QAction("复制子树文本(&T)", window)
    copy_subtree.triggered.connect(handlers.copy_subtree)

    expand_here = QAction("展开到此处", window)
    expand_here.triggered.connect(handlers.expand_here)

    collapse_all = QAction("折叠全部", window)
    collapse_all.triggered.connect(handlers.collapse_all)

    paste_action = QAction("粘贴解析(&P)", window)
    paste_action.setShortcut(QKeySequence("Ctrl+V"))
    paste_action.triggered.connect(handlers.paste)

    for act in (copy_value, copy_path, copy_subtree, paste_action):
        window.addAction(act)  # 窗口级快捷键

    return WindowActions(
        show_length=show_length,
        show_offset=show_offset,
        show_decoded=show_decoded,
        copy_path=copy_path,
        copy_subtree=copy_subtree,
        expand_here=expand_here,
        collapse_all=collapse_all,
        copy_value=copy_value,
    )
