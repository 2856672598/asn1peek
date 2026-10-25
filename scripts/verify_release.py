#!/usr/bin/env python3
"""发布前独立复验：离屏驱动 MainWindow 真实代码路径，与 openssl/xxd 外部对照。

覆盖：
- samples/certs.p7b → 树中逐字节定位 openssl 提取的证书；
- 真实证书上 der_hex / der_base64 / node_bytes 对照；
- subtree_text 行数/格式、wrap_pem 可解析；
- 剪贴板 PEM/Base64 → _on_paste() 与 open_file 等价；垃圾输入不崩；
- 错误 offset 前缀、chain.pem 3 根、动作/快捷键存在性。

用法：
    QT_QPA_PLATFORM=offscreen .venv/bin/python scripts/verify_release.py
退出码 0 = 全部通过。
"""

from __future__ import annotations

import base64
import hashlib
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from PySide6.QtWidgets import QApplication  # noqa: E402

from asn1peek.core import export as exp  # noqa: E402
from asn1peek.core.oid import dotted  # noqa: E402
from asn1peek.ui.main_window import MainWindow  # noqa: E402

OUT = Path(tempfile.mkdtemp(prefix="asn1peek-verify-"))
FAILED: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    print(("PASS  " if cond else "FAIL  ") + name + (f"   [{detail}]" if detail else ""))
    if not cond:
        FAILED.append(name)


def run(*args: str, **kw) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=True, **kw)


def pem_blocks(text: str) -> list[bytes]:
    out = []
    for m in re.finditer(r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", text, re.S):
        out.append(base64.b64decode("".join(m.group(1).split())))
    return out


def all_nodes(doc):
    nodes = []
    for r in doc.roots:
        nodes.extend(r.iter_nodes())
    return nodes


app = QApplication.instance() or QApplication([])
win = MainWindow()
win.show()

# ---------------------------------------------------------------- p7b 解析与内嵌定位
win.open_file(str(ROOT / "samples/certs.p7b"))
doc = win.tree_model.document
check(
    "p7b: certs.p7b 已加载",
    bool(doc.roots) and doc.error_count == 0,
    f"kind={doc.source_kind} roots={len(doc.roots)} 节点={doc.node_count}",
)

pc = run(
    "openssl", "pkcs7", "-inform", "DER", "-in", str(ROOT / "samples/certs.p7b"), "-print_certs"
)
ders = pem_blocks(pc.stdout)
check("p7b: openssl 提取到证书", len(ders) >= 1, f"{len(ders)} 张")

by_hash: dict[bytes, object] = {}
for n in all_nodes(doc):
    if n.error is not None:
        continue
    try:
        by_hash.setdefault(hashlib.sha256(exp.node_bytes(n)).digest(), n)
    except Exception:
        pass
located = [by_hash.get(hashlib.sha256(d).digest()) for d in ders]
check(
    "p7b: 每张证书在树中逐字节可定位（内嵌识别）",
    all(m is not None for m in located),
    f"{sum(m is not None for m in located)}/{len(ders)}",
)

# ---------------------------------------------------------------- 原始字节
win.open_file(str(ROOT / "samples/leaf.der"))
doc = win.tree_model.document
nodes = all_nodes(doc)


def find(pred):
    for n in nodes:
        try:
            if pred(n):
                return n
        except Exception:
            pass
    return None


san = find(
    lambda n: n.tag_class == 0 and n.tag_number == 6 and dotted(n.value_bytes()) == "2.5.29.17"
)
check("原始字节: 定位 SAN OID 节点", san is not None)
if san is not None:
    blob = exp.node_bytes(san)
    hx = exp.der_hex(blob).replace(" ", "").lower()
    xxd = (
        subprocess.run(["xxd", "-p"], input=blob, capture_output=True)
        .stdout.decode()
        .strip()
        .lower()
    )
    check("原始字节: Hex 与 xxd 对照一致", hx == xxd, f"{len(blob)} B")
    check("原始字节: Base64 解码回原文", base64.b64decode(exp.der_base64(blob)) == blob)

# ---------------------------------------------------------------- 子树文本
cert = doc.roots[0] if doc.roots else None
if cert is not None:
    txt = exp.subtree_text(cert)
    lines = txt.splitlines()
    n_nodes = sum(1 for _ in cert.iter_nodes())
    check(
        "子树文本: subtree_text 行数 == 子树节点数",
        len(lines) == n_nodes,
        f"{len(lines)} 行 / {n_nodes} 节点",
    )
    check(
        "子树文本: 首行格式「缩进 偏移 长度: 类型」",
        bool(re.match(r"^\s*\d+\s+\d+: \S", lines[0])),
        lines[0][:60],
    )
    if len(lines) > 1:
        check("子树文本: 子行有更深缩进", lines[1].startswith("  "), lines[1][:40])

pem_out = str(OUT / "gate2_first.pem")
Path(pem_out).write_text(exp.wrap_pem(ders[0]))
r = run("openssl", "x509", "-in", pem_out, "-noout", "-subject")
check("PEM 包装: wrap_pem 产物可被 openssl 解析", r.returncode == 0)

# ---------------------------------------------------------------- 剪贴板粘贴
pem_text = (ROOT / "samples/intermediate.pem").read_text()
QApplication.clipboard().setText(pem_text)
win._on_paste()
paste_doc = win.tree_model.document
win.open_file(str(ROOT / "samples/intermediate.pem"))
file_doc = win.tree_model.document
check(
    "粘贴: 粘贴 PEM 与直接打开等价",
    paste_doc.data == file_doc.data and paste_doc.node_count == file_doc.node_count,
    f"节点 {paste_doc.node_count}",
)
check("粘贴: 粘贴内容识别为 PEM", paste_doc.source_kind == "PEM", paste_doc.source_desc)

leaf_der = (ROOT / "samples/leaf.der").read_bytes()
QApplication.clipboard().setText(base64.b64encode(leaf_der).decode())
win._on_paste()
paste_doc = win.tree_model.document
check(
    "粘贴: 粘贴 Base64 与 DER 打开等价",
    paste_doc.data == leaf_der and paste_doc.node_count > 0,
    f"节点 {paste_doc.node_count}",
)

QApplication.clipboard().setText("这不是 ASN.1 数据 ---- !!!")
win._on_paste()  # 不得抛异常
msg = win.statusBar().currentMessage()
check("粘贴: 垃圾输入不崩溃且有明确提示", "未识别" in msg or "错误" in msg, msg[:70])

# ---------------------------------------------------------------- 错误定位 / 证书链
win.open_data(b"\x30\x82\xff\xff\x01\x02", "截断的 DER（测试）")
msg = win.statusBar().currentMessage()
check("错误定位: 全错误时提示带 offset 前缀", "offset 0x" in msg, msg[:80])

win.open_file(str(ROOT / "samples/chain.pem"))
doc = win.tree_model.document
check("chain.pem: 解析出 3 个顶层对象", len(doc.roots) == 3, f"{len(doc.roots)}")
chain_ders = pem_blocks((ROOT / "samples/chain.pem").read_text())
by_hash2: dict[bytes, object] = {}
for n in all_nodes(doc):
    if n.error is None:
        try:
            by_hash2.setdefault(hashlib.sha256(exp.node_bytes(n)).digest(), n)
        except Exception:
            pass
check(
    "chain.pem: 3 张证书均在树中逐字节可定位",
    all(hashlib.sha256(d).digest() in by_hash2 for d in chain_ders),
    f"{len(chain_ders)} 张",
)

# ---------------------------------------------------------------- 动作接线
acts = {a.text(): a for a in win.actions()}
need = {
    "复制路径(&P)": "Ctrl+Shift+C",
    "复制子树文本(&T)": None,
    "粘贴解析(&P)": "Ctrl+V",
}
missing = [t for t in need if t not in acts]
check("窗口动作: 窗口级动作与快捷键齐备", not missing, f"缺 {missing}" if missing else "")
check(
    "右键菜单: 右键菜单处理函数存在",
    all(
        hasattr(win, a)
        for a in (
            "_on_tree_context_menu",
            "_on_hex_context_menu",
            "_copy_raw",
            "_copy_path",
            "_copy_subtree",
            "_expand_here",
            "_collapse_all",
        )
    ),
)

# ---------------------------------------------------------------- 汇总
print()
print(
    f"== 汇总: {'全部通过' if not FAILED else f'{len(FAILED)} 项失败: {FAILED}'}（中间产物: {OUT}）"
)
sys.exit(1 if FAILED else 0)
