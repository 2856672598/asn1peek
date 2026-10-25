"""详情面板（TLV 检视）：ID / Length / Value 三行。

- ID     : [0X30] SEQUENCE            类型行：tag 字节 + 类型名，
                                      右端右对齐标签类别（Universal 等）
- Length : [0X00000409] 1033          值区长度：十六进制 + 十进制
- Value  :                            有可解析语义值时，在 Value 下一行显示
    2.5.4.10                          解析值（OID：dotted + 名称，名称缺失则
    organizationName                  只显示 dotted；时间：ISO 8601；字符串/
                                      BOOLEAN/NULL 同理），不再重复十六进制；
                                      无可解析值时显示值区十六进制转储（每行
                                      16 字节、最多 12 行，超出提示省略行数）。
- 错误节点：块尾红字 `✗ offset 0x…: 消息`；
- 路径/偏移不占面板（偏移走树 tooltip，路径走右键「复制路径」）。

「视图→显示解码信息」关闭时 Value 回退为十六进制转储。不再有独立「解码」区，
也不显示「名称」「值」「说明」标签。

配色随系统浅/深主题、不用任何填充底色（保持各主题原生观感）：tag 字节琥珀
呼应 Hex 视图高亮，行标签用前景/背景混色（对比 ≥4.5:1）。
"""

from __future__ import annotations

from html import escape

from PySide6.QtGui import QFontDatabase, QPalette
from PySide6.QtWidgets import QTextBrowser, QVBoxLayout, QWidget

from ..core import export as exp
from ..core.model import TAG_CLASS_NAMES, Asn1Document, Asn1Node, ValueKind
from .theme import blend

# 显式等宽字体栈：转储列对齐不依赖系统 monospace 解析（个别环境会落到比例字体）
_MONO_FAMILIES = (
    "DejaVu Sans Mono",
    "Liberation Mono",
    "Noto Sans Mono",
    "Noto Sans Mono CJK SC",
    "Ubuntu Mono",
    "Consolas",
    "Courier New",
    "monospace",
)
_MONO_STACK = ",".join(f"'{name}'" for name in _MONO_FAMILIES)

# Value 区文本预览上限：避免超长字符串把详情面板撑爆/卡住。
TEXT_PREVIEW_LIMIT = 4096


def _panel_colors(palette: QPalette) -> dict[str, str]:
    """按主题取 tag 色（呼应 Hex 视图琥珀高亮）与标签灰（对比 ≥4.5:1）。"""
    base = palette.color(QPalette.ColorRole.Base)
    text = palette.color(QPalette.ColorRole.Text)
    tag = "#953800" if base.lightness() > 128 else "#D29922"
    return {"tag": tag, "muted": blend(text, base, 0.58).name()}


class DetailPanel(QWidget):
    """TLV 检视面板：ID / Length / Value（可读解析值优先，原转储兜底）。"""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._doc_info: Asn1Document | None = None
        self._node: Asn1Node | None = None
        self._decoded_visible = True  # Value 可读解析值默认开（视图菜单可关）

        self.browser = QTextBrowser(self)
        self.browser.setOpenExternalLinks(True)
        self.browser.setPlaceholderText("（选择一个树节点查看 TLV）")
        self.browser.document().setDocumentMargin(10)  # 内容留白，不贴面板边缘
        # TLV 块按参考界面用等宽字体（ID/Length/Value 与转储列对齐）
        self.browser.setFont(QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont))

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(self.browser, 1)

    # ---- 兼容/转发 API ---------------------------------------------------

    def toPlainText(self) -> str:  # noqa: N802
        return self.browser.toPlainText()

    # ---- 文档 / 节点 -----------------------------------------------------

    def set_document(self, document: Asn1Document | None) -> None:
        self._doc_info = document
        self.show_node(None)

    def show_node(self, node: Asn1Node | None) -> None:
        self._node = node
        if node is None:
            self._render_placeholder()
        else:
            self._render_node(node)

    # ---- Value 解析值开关（视图菜单） ------------------------------------

    def decoded_visible(self) -> bool:
        return self._decoded_visible

    def set_decoded_visible(self, visible: bool) -> None:
        """切换 Value 解析值显示并重绘当前节点（菜单勾选状态保持同步）。"""
        visible = bool(visible)
        if visible == self._decoded_visible:
            return
        self._decoded_visible = visible
        self.show_node(self._node)

    # ---- 渲染 ------------------------------------------------------------

    def _set_html(self, body: str) -> None:
        self.browser.setHtml("<div style='font-size:10pt'>" + body + "</div>")

    def _render_node(self, node: Asn1Node) -> None:
        """ID / Length / Value 三行块；Value 优先显示可读解析值。"""
        tag_bytes = node.blob[node.offset : node.offset + node.tag_len] if node.tag_len else b""
        tag_cell = f"[0X{tag_bytes.hex().upper()}]" if tag_bytes else ""
        name = escape(node.type_name)
        if node.is_embedded:
            name += "（内嵌 DER）"
        class_label = ""
        if node.error is None:
            class_label = escape(TAG_CLASS_NAMES[node.tag_class].capitalize())

        colors = _panel_colors(self.palette())
        muted = f"color:{colors['muted']}"

        # 错误节点的 value_len_ 为“垃圾区”长度，其余节点为值区长度
        length = node.value_len_
        parsed_lines = self._semantic_lines(node) if self._decoded_visible else []
        body_lines = [
            f"<span style='{muted}'>{'Length':<7}:</span> [0X{length:08X}] {length}",
            f"<span style='{muted}'>{'Value':<7}:</span>",
        ]
        if parsed_lines:
            body_lines += [escape(exp.DUMP_INDENT + line) for line in parsed_lines]
        else:
            dump_lines, skipped = exp.value_dump_lines(node)
            body_lines += [escape(line) for line in dump_lines]
            if skipped:
                body_lines.append(escape(f"{exp.DUMP_INDENT}another {skipped} lines skipped....."))

        id_rest = name
        if tag_cell:
            id_rest = f"<span style='color:{colors['tag']}'>{tag_cell}</span> {name}"
        html = [
            f"<div style='font-family:{_MONO_STACK}'>",
            "<table width='100%' cellspacing='0' cellpadding='0'><tr>",
            "<td valign='top'><pre style='margin:0'>"
            f"<span style='{muted}'>{'ID':<7}:</span> {id_rest}</pre></td>",
            f"<td align='right' valign='top'><span style='{muted}'>{class_label}</span></td>",
            "</tr></table>",
            "<pre style='margin:0'>" + "\n".join(body_lines) + "</pre>",
        ]
        if node.error is not None:
            html.append(
                "<div style='color:#c62828;margin-top:4px'>✗ " + escape(node.error_text) + "</div>"
            )
        html.append("</div>")
        self._set_html("".join(html))

    @staticmethod
    def _semantic_lines(node: Asn1Node) -> list[str]:
        """Value 区要显示的解析值行；没有可读语义时返回空列表。

        只取真正增加阅读价值的结果：OID dotted + 名称（名称缺失则只给
        dotted）、时间 ISO 8601、字符串内容、BOOLEAN、NULL。INTEGER /
        BIT STRING / OCTET STRING / 容器等继续显示十六进制转储。
        """
        info = node.decoded
        if info is None:
            return []
        if info.kind is ValueKind.OID:
            primary = info.semantic or info.summary
            lines = [primary] if primary else []
            if info.name:
                lines.append(info.name)
            return lines
        if info.kind in (ValueKind.RELATIVE_OID, ValueKind.TIME):
            value = info.semantic or info.summary
            return [value] if value else []
        if info.kind is ValueKind.TEXT:
            if not info.semantic:
                return [info.summary] if info.summary else []
            text = info.semantic
            if len(text) > TEXT_PREVIEW_LIMIT:
                return [
                    text[:TEXT_PREVIEW_LIMIT],
                    f"…（文本超过 {TEXT_PREVIEW_LIMIT} 字符，已截断）",
                ]
            return [text]
        if info.kind is ValueKind.BOOLEAN:
            return [info.summary] if info.summary else []
        if info.kind is ValueKind.NULL:
            # 合法 NULL 的 summary 为空，显示类型值；非法 NULL 显示错误摘要。
            return [info.summary] if info.summary else ["NULL"]
        return []

    def _render_placeholder(self) -> None:
        doc = self._doc_info
        if doc is None:
            self._set_html("<p style='color:#888'>（打开文件查看详情）</p>")
            return
        rows = [
            ("识别", doc.source_desc or doc.source_kind),
            ("编码判断", doc.encoding_label),
            ("顶层对象", str(len(doc.roots))),
        ]
        if doc.error_count:
            rows.append(("错误", str(doc.error_count)))
        if doc.warning_count:
            rows.append(("警告", str(doc.warning_count)))
        body = self._rows_html(rows)
        self._set_html("<h3 style='margin:2px 0 2px 0'>文档概要</h3>" + body)

    def _rows_html(self, rows: list[tuple[str, str]]) -> str:
        cells: list[str] = []
        for label, value in rows:
            cells.append(
                "<tr>"
                "<td valign='top' style='color:#666;padding:0 12px 4px 0;"
                f"white-space:nowrap'><b>{escape(label)}</b></td>"
                f"<td valign='top' style='padding-bottom:4px'>{escape(value)}</td>"
                "</tr>"
            )
        return "<table cellspacing='0' cellpadding='0'>" + "".join(cells) + "</table>"
