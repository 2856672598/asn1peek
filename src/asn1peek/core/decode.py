"""通用 ASN.1 值解码。

输出两种表示：
- summary：值的单行短摘要（复制子树文本等使用；结构树只显示类型，不展示摘要）；
- details：详情面板 (标签, 值文本) 列表。

details 只给"有阅读价值"的解码：内容与值区十六进制转储重复或无意义的
类型不提供详情（BIT STRING 内容、INTEGER/ENUMERATED 的十进制、
OCTET STRING 的 HEX/ASCII 等）。
"""

from __future__ import annotations

import re
from datetime import date

from . import oid as oid_db
from .model import (
    Asn1Node,
    ValueInfo,
    ValueKind,
)

# 摘要与详情的显示长度上限
MAX_SUMMARY = 60
MAX_DETAIL_HEX = 512

# 解码/物化上限：超过上限时只给尺寸和前缀，避免 UI 被巨型值拖死。
MAX_TEXT_DECODE_BYTES = 64 * 1024
MAX_INT_DECIMAL_BYTES = 1024
MAX_TIME_BYTES = 64

# 字符串类型的解码字典：universal tag number → codec
_STRING_CODECS = {
    12: "utf-8",  # UTF8String
    18: "ascii",  # NumericString
    19: "ascii",  # PrintableString
    20: "latin-1",  # T61String
    21: "latin-1",  # VideotexString
    22: "ascii",  # IA5String
    25: "latin-1",  # GraphicString
    26: "latin-1",  # VisibleString
    27: "latin-1",  # GeneralString
    28: "utf-32-be",  # UniversalString
    30: "utf-16-be",  # BMPString
}

_TIME_TAGS = (23, 24)  # UTCTime, GeneralizedTime

_TIMEZONE_TAIL_RE = re.compile(r"(Z|[+-]\d{2}(?::?\d{2})?)$")


# --------------------------------------------------------------------------
# 主入口
# --------------------------------------------------------------------------


def value_of(node: Asn1Node) -> ValueInfo | None:
    """按标签类别/类型/构造性分派解码。未知类型退化为通用十六进制视图。"""
    if node.error is not None:
        return None
    if node.constructed:
        return ValueInfo("")  # 容器：值即子树，不给摘要
    if node.tag_class == 0:
        handler = _HANDLERS.get(node.tag_number)
        if handler is not None:
            return handler(node)
    return _decode_generic(node)


# --------------------------------------------------------------------------
# 各类型解码
# --------------------------------------------------------------------------


def _decode_octet_string(node: Asn1Node) -> ValueInfo:
    """OCTET STRING：不给解码详情。

    HEX 行与值区转储完全重复、ASCII 行对二进制数据多为点号（无类型无法
    判断编码）→ 详情不重复展示；内嵌 DER 由树中 ⤷ 子节点展开。
    """
    length = node.value_len_
    summary = f"{length} 字节"
    if length:
        # 多取 1 字节，保证 _hex_preview 能判断“后面还有数据”。
        summary += " · " + _hex_preview(_value_prefix(node, 9), 8)
    return ValueInfo(summary)


def _decode_bit_string(node: Asn1Node) -> ValueInfo:
    length = node.value_len_
    if length == 0:
        return ValueInfo("空（无未用位计数）", [("提示", "空 BIT STRING（缺少未用位计数字节）")])
    first = _value_prefix(node, 1)
    if not first:
        return ValueInfo("空（无未用位计数）", [("提示", "空 BIT STRING（缺少未用位计数字节）")])
    unused = first[0]
    content_len = length - 1
    if unused > 7:
        raw = _value_prefix(node, MAX_DETAIL_HEX)
        return ValueInfo(
            f"非法未用位数 {unused}",
            [("提示", f"非法未用位数 {unused}"), ("原始", _hex_full(raw, length))],
        )
    summary = f"{content_len} 字节 · 未用位 {unused}"
    if content_len:
        # 前缀包含未用位字节；再取 9 个内容字节供预览判断是否截断。
        content_head = _value_prefix(node, 10)[1:]
        summary += " · " + _hex_preview(content_head, 8)
    # 不给详情：未用位计数在值区转储首字节已可见，HEX 与转储重复；
    # 内嵌 DER（若可解析）由树中 ⤷ 子节点展开，不在面板重复
    return ValueInfo(summary)


def _decode_integer(node: Asn1Node) -> ValueInfo:
    """INTEGER / ENUMERATED：不给解码详情。

    十进制只是值区转储的另一种写法（小整数在转储里直接可读、大整数如
    证书序列号无阅读价值）→ 详情不重复展示；summary 仍给十进制，
    供复制子树文本等使用。超过 MAX_INT_DECIMAL_BYTES 时不做大整数转换。
    """
    length = node.value_len_
    if length == 0:
        return ValueInfo(
            "0（空编码，DER 违例）", [("提示", "空编码（DER 违例）")], ValueKind.GENERIC, "0"
        )
    if length > MAX_INT_DECIMAL_BYTES:
        head = _value_prefix(node, 8)
        summary = f"{length} 字节 · 0x{head.hex().upper()}…（超出十进制显示上限）"
        return ValueInfo(summary)
    raw = node.value_bytes()
    value = int.from_bytes(raw, "big", signed=True)
    try:
        decimal = str(value)
    except ValueError:
        # 防御 Python 3.11+ 的 int→str 位数上限；正常应被长度上限挡住。
        decimal = None
    if decimal is None:
        summary = f"0x{raw.hex().upper()}"
        semantic = ""
    else:
        summary = decimal if len(decimal) <= MAX_SUMMARY else f"0x{raw.hex().upper()}"
        semantic = decimal
    return ValueInfo(summary, [], ValueKind.GENERIC, semantic)


def _decode_boolean(node: Asn1Node) -> ValueInfo:
    length = node.value_len_
    if length != 1:
        raw = _value_prefix(node, MAX_DETAIL_HEX)
        return ValueInfo(
            "不合法（长度≠1）",
            [("提示", "不合法（长度≠1）"), ("原始（HEX）", _hex_full(raw, length))],
        )
    raw = _value_prefix(node, 1)
    if raw[0] == 0xFF:
        return ValueInfo("TRUE", [("值", "TRUE (0xFF)")], ValueKind.BOOLEAN, "TRUE")
    if raw[0] == 0x00:
        return ValueInfo("FALSE", [("值", "FALSE (0x00)")], ValueKind.BOOLEAN, "FALSE")
    summary = "TRUE（非规范值）"
    return ValueInfo(
        summary,
        [("值", f"0x{raw[0]:02X} → TRUE（DER 要求 0x00/0xFF）")],
        ValueKind.BOOLEAN,
        summary,
    )


def _decode_null(node: Asn1Node) -> ValueInfo:
    length = node.value_len_
    if length:
        raw = _value_prefix(node, MAX_DETAIL_HEX)
        return ValueInfo(
            "不合法（值应为空）",
            [("提示", "不合法（值应为空）"), ("原始（HEX）", _hex_full(raw, length))],
        )
    return ValueInfo("", [("值", "NULL (无内容)")], ValueKind.NULL, "NULL")


def _decode_oid(node: Asn1Node) -> ValueInfo:
    length = node.value_len_
    if length == 0:
        return ValueInfo("空 OID", [("提示", "空 OID")], ValueKind.OID)
    if length > oid_db.MAX_OID_BYTES:
        summary = f"OID 过大（{length} 字节，不展开）"
        return ValueInfo(summary, [("提示", summary)], ValueKind.OID)
    raw = node.value_bytes()
    dotted = oid_db.dotted(raw)
    if dotted is None:
        return ValueInfo(
            "无法解析",
            [("提示", "无法解析"), ("原始（HEX）", _hex_full(raw, length))],
            ValueKind.OID,
        )

    info = oid_db.lookup(dotted)
    summary = dotted
    name = ""
    details: list[tuple[str, str]] = [("值", dotted)]
    if info is not None and info.exact:
        name = info.name
        summary += f" ({name})"
        details = [("名称", name), ("值", dotted)]
        if info.description:
            details.append(("说明", info.description))
    return ValueInfo(summary, details, ValueKind.OID, dotted, name)


def _decode_relative_oid(node: Asn1Node) -> ValueInfo:
    length = node.value_len_
    if length == 0:
        return ValueInfo("空 RELATIVE-OID", [("提示", "空 RELATIVE-OID")], ValueKind.RELATIVE_OID)
    if length > oid_db.MAX_OID_BYTES:
        summary = f"RELATIVE-OID 过大（{length} 字节，不展开）"
        return ValueInfo(summary, [("提示", summary)], ValueKind.RELATIVE_OID)
    raw = node.value_bytes()
    dotted = oid_db.dotted(raw, relative=True)
    if dotted is None:
        return ValueInfo(
            "无法解析",
            [("提示", "无法解析"), ("原始（HEX）", _hex_full(raw, length))],
            ValueKind.RELATIVE_OID,
        )
    return ValueInfo(dotted, [("值", dotted)], ValueKind.RELATIVE_OID, dotted)


def _decode_string(node: Asn1Node) -> ValueInfo:
    length = node.value_len_
    if length > MAX_TEXT_DECODE_BYTES:
        summary = f"{length} 字节 · 超过 64 KiB，未解码"
        return ValueInfo(summary, [("提示", summary)], ValueKind.TEXT)
    codec = _STRING_CODECS[node.tag_number]
    raw = node.value_bytes()
    try:
        text = raw.decode(codec)
    except UnicodeDecodeError:
        return ValueInfo(
            "(无法按编码解码)",
            [("提示", "(无法按编码解码)"), ("原始（HEX）", _hex_full(raw, length))],
        )
    return ValueInfo(_short_quote(text), [("值", text)], ValueKind.TEXT, text)


def _decode_time(node: Asn1Node) -> ValueInfo:
    length = node.value_len_
    if length > MAX_TIME_BYTES:
        summary = f"时间值过长（{length} 字节）"
        return ValueInfo(summary, [("警告", summary)], ValueKind.TIME)
    raw = node.value_bytes()
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        return ValueInfo("(非法时间)", [("提示", "(非法时间)"), ("原始（HEX）", raw.hex())])
    iso = _time_to_iso8601(node.tag_number, text)
    if iso is not None:
        details = [("ISO 8601", iso), ("原始", text)]
        if not _TIMEZONE_TAIL_RE.search(text):
            details.append(("提示", "时间区域未指定"))
    else:
        details = [("原始", text), ("警告", "无法解析的时间格式")]
    return ValueInfo(iso or text, details, ValueKind.TIME, iso or "")


def _decode_generic(node: Asn1Node) -> ValueInfo:
    """未知类型 / 其他类别标签：通用字节视图。"""
    length = node.value_len_
    summary = f"{length} 字节"
    if length:
        summary += " · " + _hex_preview(_value_prefix(node, 9), 8)
    raw = _value_prefix(node, MAX_DETAIL_HEX)
    details = [("HEX", _hex_full(raw, length)), ("ASCII", _ascii_of(raw, length))]
    return ValueInfo(summary, details)


# --------------------------------------------------------------------------
# OID / 时间解析辅助
# --------------------------------------------------------------------------


def _value_prefix(node: Asn1Node, limit: int) -> bytes:
    """只取节点值区的前 limit 字节，避免为大值复制整段 bytes。"""
    end = node.value_offset + min(node.value_len_, limit)
    return node.blob[node.value_offset : end]


def _normalize_tz(tail: str | None) -> str:
    if tail is None:
        return ""
    if tail == "Z":
        return "Z"
    sign = tail[0]
    digits = tail[1:]
    if len(digits) == 2:
        return f"{sign}{digits}:00"
    return f"{sign}{digits[:2]}:{digits[2:4]}"


def _valid_time_fields(
    year: int | None,
    month: int | None,
    day: int | None,
    hour: int,
    minute: int,
    second: int,
) -> bool:
    """最小时间范围校验；只校验已出现的字段，不做时区换算。"""
    if not 0 <= hour <= 23:
        return False
    if not 0 <= minute <= 59:
        return False
    if not 0 <= second <= 60:  # 允许闰秒
        return False
    if month is not None and not 1 <= month <= 12:
        return False
    if day is not None and not 1 <= day <= 31:
        return False
    if year is not None and month is not None and day is not None and 1 <= year <= 9999:
        try:
            date(year, month, day)
        except ValueError:
            return False
    return True


def _time_to_iso8601(tag_number: int, text: str) -> str | None:
    """UTCTime 'YYMMDDHH[MM[SS[.f]]](Z|±HH[MM]|±HHMM)' 与 GeneralizedTime → ISO。

    只做格式转换不涉及时区换算；解析/范围校验失败返回 None。
    """
    if tag_number == 23:  # UTCTime
        m = re.fullmatch(
            r"(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?(\d{2})?([.,]\d+)?"
            r"(Z|[+-]\d{2}\d{2}?|[+-]\d{2})?",
            text,
        )
        if m is None:
            return None
        yy = int(m.group(1))
        year = 1900 + yy if yy >= 50 else 2000 + yy
        month = int(m.group(2))
        day = int(m.group(3))
        hour = int(m.group(4))
        minute = int(m.group(5)) if m.group(5) else 0
        second = int(m.group(6)) if m.group(6) else 0
        if not _valid_time_fields(year, month, day, hour, minute, second):
            return None
        ymd = f"{year}-{month:02d}-{day:02d}"
        t = f"{hour:02d}:{minute:02d}"
        if m.group(6):
            t += f":{second:02d}"
        if m.group(7):
            t += m.group(7).replace(",", ".")
        tail = m.group(8)
    else:  # GeneralizedTime
        m = re.fullmatch(
            r"(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\d{2})?([.,]\d+)?"
            r"(Z|[+-]\d{2}\d{2}?|[+-]\d{2})?",
            text,
        )
        if m is None:
            return None
        year = int(m.group(1))
        month = int(m.group(2)) if m.group(2) else None
        day = int(m.group(3)) if m.group(3) else None
        hour = int(m.group(4)) if m.group(4) else 0
        minute = int(m.group(5)) if m.group(5) else 0
        second = int(m.group(6)) if m.group(6) else 0
        if not _valid_time_fields(year, month, day, hour, minute, second):
            return None
        ymd = m.group(1)
        if month is not None:
            ymd += f"-{month:02d}"
        if day is not None:
            ymd += f"-{day:02d}"
        t = f"{hour:02d}:{minute:02d}"
        if m.group(6):
            t += f":{second:02d}"
        if m.group(7):
            t += m.group(7).replace(",", ".")
        tail = m.group(8)
    return f"{ymd}T{t}" + _normalize_tz(tail)


# --------------------------------------------------------------------------
# 显示格式化
# --------------------------------------------------------------------------


def _hex_preview(raw: bytes, n: int) -> str:
    head = raw[:n].hex().upper()
    spaced = " ".join(head[i : i + 2] for i in range(0, len(head), 2))
    return spaced + ("…" if len(raw) > n else "")


def _hex_full(raw: bytes, total_len: int | None = None) -> str:
    total = len(raw) if total_len is None else total_len
    if total <= MAX_DETAIL_HEX:
        return " ".join(f"{b:02X}" for b in raw) or "(空)"
    shown = " ".join(f"{b:02X}" for b in raw[:MAX_DETAIL_HEX])
    return f"{shown} …（共 {total} 字节，截断显示）"


def _ascii_of(raw: bytes, total_len: int | None = None) -> str:
    total = len(raw) if total_len is None else total_len
    if len(raw) > 256:
        raw = raw[:256]
    text = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in raw)
    return text + ("…" if total > len(raw) else "")


def _short_quote(text: str) -> str:
    content = f"“{text}”"
    if len(content) > MAX_SUMMARY:
        content = content[: MAX_SUMMARY - 1] + "…”"
    return content


_HANDLERS = {
    1: _decode_boolean,
    2: _decode_integer,
    3: _decode_bit_string,
    4: _decode_octet_string,
    5: _decode_null,
    6: _decode_oid,
    9: _decode_generic,  # REAL：仅显示原始字节
    10: _decode_integer,  # ENUMERATED
    13: _decode_relative_oid,  # RELATIVE-OID
}
for _num in _STRING_CODECS:
    _HANDLERS[_num] = _decode_string
for _num in _TIME_TAGS:
    _HANDLERS[_num] = _decode_time
