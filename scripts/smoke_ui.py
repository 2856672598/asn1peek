"""冒烟脚本（offscreen 无头环境）：打开样例证书 → 自动展开 → 选中目标节点
→ 断言 Hex 高亮已生成 → 截图保留。

用法：
  uv run python scripts/smoke_ui.py samples/leaf.der [--target summary] [输出.png]
"""

from __future__ import annotations

import os
import sys

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from asn1peek.ui.hex_view import HEX_START
from asn1peek.ui.main_window import MainWindow


def expand_all_shallow(win, indices, depth=2):
    for idx in list(indices):
        if depth <= 0 or not idx.isValid():
            continue
        win.tree_view.expand(idx)
        child_idx = [win.tree_model.index(r, 0, idx) for r in range(win.tree_model.rowCount(idx))]
        expand_all_shallow(win, child_idx, depth - 1)


def find_by_marker(win, wanted: str):
    for node in win.tree_model.document.iter_roots_deep():
        if wanted.lower() in node.summary.lower() or wanted.lower() in node.type_name.lower():
            return node
    return None


def _node_selections(view):
    """只统计节点三色高亮选区：偏移列的常驻选区（[0, HEX_START)）不算。"""
    doc = view.document()
    picked = []
    for sel in view.extraSelections():
        start = sel.cursor.selectionStart()
        if start - doc.findBlock(start).position() >= HEX_START:
            picked.append(sel)
    return picked


def main() -> int:
    argv = sys.argv[1:]
    path = argv[0] if argv else "samples/leaf.der"
    wanted = argv[1] if len(argv) > 1 else "subjectAltName"
    out_png = argv[2] if len(argv) > 2 else "/tmp/asn1peek-smoke.png"

    app = QApplication([])
    win = MainWindow()
    win.resize(1280, 860)
    win.show()
    win.open_file(path)
    app.processEvents()

    # 展开根节点两层，制造可见的懒解析 / 高亮目标
    roots = [win.tree_model.index(r, 0) for r in range(win.tree_model.rowCount())]
    if roots:
        expand_all_shallow(win, roots, depth=2)
    app.processEvents()

    node = find_by_marker(win, wanted)
    if node is None:
        print(f"[!] 未找到目标节点（wanted={wanted}），改选第一个深层节点")
        root = win.tree_model.document.roots[0]
        node = [n for n in root.iter_nodes()][-1]

    for anc in _ancestor_chain(win, node):
        win.tree_view.expand(anc)
    idx = win.tree_model.index_for_node(node)
    assert idx.isValid(), "index_for_node 失败"
    win.tree_view.scrollTo(idx)
    win.tree_view.selectionModel().select(
        idx, win.tree_view.selectionModel().SelectionFlag.ClearAndSelect
    )
    win.tree_view.setCurrentIndex(idx)
    app.processEvents()
    app.processEvents()

    hexsel = win.hex_view
    hexsel.highlight_node(node)
    app.processEvents()

    count = len(_node_selections(hexsel))
    assert count > 0, "Hex 高亮未生成"

    # ---- 反向联动端到端验证：点 Hex 值区中部字节 → 树选中该节点 ----
    mid = (node.offset + node.end) // 2
    win.hex_view.byte_clicked.emit(mid)
    app.processEvents()
    sel_idx = win.tree_view.selectionModel().currentIndex()
    assert sel_idx.isValid(), "反向点击后树无选中"
    assert sel_idx.internalPointer() is node, (
        f"反向定位到别的节点了: {sel_idx.internalPointer()!r} != {node!r}"
    )
    app.processEvents()

    grabbed = win.grab()
    grabbed.save(out_png)

    print(f"[ok] 已高亮 {node.type_name} @0x{node.offset:X}–0x{node.end:X}: {node.summary}")
    print(f"[ok] extraSelections 数量: {count}（节点高亮，不含偏移列选区），截图: {out_png}")
    return 0


def _ancestor_chain(win, node):
    """返回 node 的父链对应的 QModelIndex 列表（用于预先展开）。"""
    chain = []
    n = node
    while n is not None:
        idx = win.tree_model.index_for_node(n)
        if idx.isValid():
            chain.append(idx)
        n = n.parent
    return list(reversed(chain))


if __name__ == "__main__":
    raise SystemExit(main())
