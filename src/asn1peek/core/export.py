"""节点复制与文本导出纯函数。

core 层零 GUI 依赖，UI 只做菜单接线：
- node_bytes()            节点完整 TLV 编码（复制原始字节）；
- der_hex()/der_base64()  原始字节的 Hex / Base64 文本；
- subtree_text()          dumpasn1 风格缩进文本；
- value_dump_lines()      详情面板「Value」区十六进制转储（每行 16 字节、12 行上限）；
- copy_value_variants()   复制节点值（结构化 key + 文本变体）；
- wrap_pem()              DER → PEM 文本（core 预留）；
"""

from __future__ import annotations

import base64
from dataclasses import dataclass

from .model import CLASS_UNIVERSAL, Asn1Node, ValueKind

# 超大节点确认阈值（>16MB 弹确认）
LARGE_COPY_LIMIT = 16 * 1024 * 1024

# 子树文本展开的最大节点数（防护懒解析失控；受 parser 全局上限约束）
MAX_SUBTREE_NODES = 100_000


# --------------------------------------------------------------------------
# 完整 TLV 原始字节
# --------------------------------------------------------------------------


def node_bytes(node: Asn1Node) -> bytes:
    """节点的完整 TLV 编码：data[offset:next_offset]，含 tag + length + value。

    不定长节点（BER）的 next_offset 已包含 EOC 两个字节。错误节点返回
    其覆盖的垃圾区字节。
    """
    return node.blob[node.offset : node.next_offset]


def der_hex(raw: bytes) -> str:
    """原始字节的十六进制文本（大写、无分隔，可直接 bytes.fromhex 还原）。"""
    return raw.hex().upper()


def der_base64(raw: bytes) -> str:
    """原始字节的 Base64 文本（单行，无换行，便于直接粘贴使用）。"""
    return base64.b64encode(raw).decode("ascii")


# --------------------------------------------------------------------------
# 子树缩进文本（dumpasn1 风格）
# --------------------------------------------------------------------------


def _eoc_line(n: Asn1Node) -> str:
    """不定长节点的 EOC 行（缩进比节点多两级，偏移为值区结束）。"""
    return f"{'  ' * (n.depth + 2)}{n.content_end:5d} {n.eoc_len:>5d}: EOC"


def _dump_lines(n: Asn1Node, *, include_eoc: bool = True) -> list[str]:
    """单个节点在 dumpasn1 风格文本中的行（内嵌根 1 行；不定长可带 EOC）。"""
    if n.is_embedded:
        # 内嵌 DER 根：比所在值缩进多一级，前置标记
        indent = "  " * (n.depth + 1)
        return [f"{indent}    --> {n.type_name}" + (f"  {n.summary}" if n.summary else "")]
    indent = "  " * n.depth
    # 行长度列表示 TLV 内容长度；不定长的 EOC 单独成行，避免重复计数。
    length = n.total_len if n.error is not None else n.header_len + n.value_len
    lines = [
        f"{indent}{n.offset:5d} {length:>5d}: {n.type_name}"
        + (f"  {n.summary}" if n.summary else "")
    ]
    if include_eoc and n.eoc_len > 0:
        lines.append(_eoc_line(n))
    return lines


def subtree_text(node: Asn1Node) -> str:
    """节点的子树缩进文本：每行「偏移 长度 类型 值摘要」，按深度缩进。

    用显式栈做 DFS（不依赖 Python 递归深度）；不定长节点的 EOC 行排在
    其全部子节点之后。遍历会触发懒解析；含内嵌 DER 节点。
    """
    lines: list[str] = []
    count = 0
    truncated = False
    # (节点, 是否为该节点的 EOC 收尾标记)
    stack: list[tuple[Asn1Node, bool]] = [(node, False)]
    while stack:
        current, is_eoc = stack.pop()
        if is_eoc:
            lines.append(_eoc_line(current))
            continue
        count += 1
        if count > MAX_SUBTREE_NODES:
            truncated = True
            break
        lines.extend(_dump_lines(current, include_eoc=False))
        # 先压 EOC，再压子节点（逆序），保证子节点全部出栈后才输出 EOC。
        if current.eoc_len > 0:
            stack.append((current, True))
        for child in reversed(current.child_items):
            stack.append((child, False))
    if truncated:
        lines.append("…（节点数超过上限，子树文本截断）")
    return "\n".join(lines)


# --------------------------------------------------------------------------
# 详情面板「Value」区十六进制转储（ID/Length/Value 布局）
# --------------------------------------------------------------------------

# 每行字节数与最大显示行数（超出由 UI 提示 `another N lines skipped.....`）
DUMP_BYTES_PER_LINE = 16
DUMP_MAX_LINES = 12

# 转储缩进：与 ID/Length 行的值列对齐（`Length : ` 之后，共 9 字符）
DUMP_INDENT = " " * 9


def _dump_line(chunk: bytes) -> str:
    """转储单行：缩进 + 小写双位十六进制，空格分隔。"""
    return DUMP_INDENT + " ".join(f"{byte:02x}" for byte in chunk)


def value_dump_lines(node: Asn1Node, max_lines: int = DUMP_MAX_LINES) -> tuple[list[str], int]:
    """值区十六进制转储（小写、每行 16 字节、与 ID/Length 值列对齐）。

    BIT STRING 特殊处理：首字节是"未用位数"，与首行前 15 个数据字节
    合计 16 字节；其余数据仍按 16 字节/行，保证所有行列宽一致。
    返回 (行列表, 省略行数)；错误节点转储其"垃圾区"字节。

    只构造前 max_lines 行，不复制整个值区——大值选中时不会生成数万行
    临时字符串（省略行数由总行数直接算出）。
    """
    raw_len = node.value_len_
    if raw_len <= 0:
        return [], 0

    start = node.value_offset
    value_end = min(start + raw_len, len(node.blob))
    # BIT STRING 的特殊性只在“首字节是未用位计数”，行数/偏移仍按原始值区
    # 16 字节一行计算：首行含未用位 + 15 数据字节，后续行不额外 +1 偏移。
    total = (raw_len + DUMP_BYTES_PER_LINE - 1) // DUMP_BYTES_PER_LINE
    shown = min(total, max(0, max_lines))

    lines: list[str] = []
    for i in range(shown):
        off = start + i * DUMP_BYTES_PER_LINE
        end = min(off + DUMP_BYTES_PER_LINE, value_end)
        lines.append(_dump_line(node.blob[off:end]))
    return lines, total - shown


# --------------------------------------------------------------------------
# 复制节点值（按 ValueInfo 的结构化字段生成稳定变体）
# --------------------------------------------------------------------------

# 复制值总上限：超过 1 MiB 的节点只允许“复制原始字节”，不构造文本变体。
MAX_COPY_VALUE_BYTES = 1 << 20
# 时间原文变体上限：与 decode.MAX_TIME_BYTES 对齐，避免非法超长时间被整段复制。
MAX_TIME_COPY_BYTES = 64


@dataclass(frozen=True, slots=True)
class ValueVariant:
    """一种可复制的值表示；key 为稳定 ASCII，UI 负责映射显示文案。"""

    key: str
    text: str


def copy_value_variants(node: Asn1Node) -> list[ValueVariant]:
    """返回节点的可复制值变体；容器/错误/无值/超大值返回空列表。

    数据源优先使用 ``node.decoded`` 的 kind/semantic/name，不读取 details
    的中文标签。INTEGER/OCTET STRING/BIT STRING 等按标签补充 hex/Base64
    表示，空 OID/超限 OID 不返回变体。
    """
    if node.error is not None or node.constructed:
        return []

    info = node.decoded
    if info is None:
        return []
    if info.kind is ValueKind.NULL:
        return [ValueVariant("null", "NULL")]
    if node.value_len_ <= 0 or node.value_len_ > MAX_COPY_VALUE_BYTES:
        return []

    if node.tag_class == CLASS_UNIVERSAL:
        tag = node.tag_number
        if tag in (2, 10):  # INTEGER / ENUMERATED
            raw = node.value_bytes()
            variants: list[ValueVariant] = []
            if info.semantic:
                variants.append(ValueVariant("int-decimal", info.semantic))
            variants.append(ValueVariant("int-hex", raw.hex().upper()))
            return variants
        if tag == 3:  # BIT STRING：复制内容字节（不含未用位计数）
            content = node.value_bytes()[1:]
            if not content:
                return []
            return [
                ValueVariant("bit-hex", content.hex().upper()),
                ValueVariant("bit-base64", base64.b64encode(content).decode("ascii")),
            ]
        if tag == 4:  # OCTET STRING
            raw = node.value_bytes()
            return [
                ValueVariant("octet-hex", raw.hex().upper()),
                ValueVariant("octet-base64", base64.b64encode(raw).decode("ascii")),
            ]
        if tag == 6:  # OBJECT IDENTIFIER
            if info.kind is not ValueKind.OID or not info.semantic:
                return []
            variants = [ValueVariant("oid-dotted", info.semantic)]
            if info.name:
                variants.append(ValueVariant("oid-name", info.name))
            return variants
        if tag == 13:  # RELATIVE-OID
            if info.kind is not ValueKind.RELATIVE_OID or not info.semantic:
                return []
            return [ValueVariant("relative-oid", info.semantic)]
        if tag in (23, 24):  # UTCTime / GeneralizedTime
            variants = []
            if info.semantic:
                variants.append(ValueVariant("time-iso", info.semantic))
            # 超长时间值只让“复制原始字节”兜底，避免把异常输入整段文本化。
            if node.value_len_ <= MAX_TIME_COPY_BYTES:
                try:
                    raw_text = node.value_bytes().decode("ascii")
                except UnicodeDecodeError:
                    raw_text = ""
                if raw_text:
                    variants.append(ValueVariant("time-raw", raw_text))
            return variants

    if info.kind is ValueKind.TEXT:
        return [ValueVariant("text", info.semantic)] if info.semantic else []
    if info.kind is ValueKind.BOOLEAN:
        return [ValueVariant("boolean", info.semantic)] if info.semantic else []

    # 未知 primitive / 非法已知类型：保留原始 hex/Base64 兜底。
    raw = node.value_bytes()
    return [
        ValueVariant("hex", raw.hex().upper()),
        ValueVariant("base64", base64.b64encode(raw).decode("ascii")),
    ]


# --------------------------------------------------------------------------
# DER → PEM（core 预留，UI 不单独设计入口）
# --------------------------------------------------------------------------


def wrap_pem(der: bytes, label: str = "CERTIFICATE") -> str:
    """DER 字节 → PEM 文本（64 列 Base64 + BEGIN/END 标记）。"""
    body = base64.encodebytes(der).decode("ascii")
    return f"-----BEGIN {label}-----\n{body}-----END {label}-----\n"
