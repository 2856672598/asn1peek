"""ASN.1 节点与文档模型。

原则：
- core 层零 GUI 依赖，本模块只描述解析结果的数据结构；
- 不复制值字节：节点引用整份 blob + 偏移区间，供 Hex 高亮与原始字节复制使用；
- 子节点懒解析：树展开时才解析容器内容。
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from enum import Enum, auto

# 标签类别（X.690 8.1.2.3）
CLASS_UNIVERSAL = 0
CLASS_APPLICATION = 1
CLASS_CONTEXT = 2
CLASS_PRIVATE = 3

TAG_CLASS_NAMES = {
    CLASS_UNIVERSAL: "universal",
    CLASS_APPLICATION: "application",
    CLASS_CONTEXT: "context-specific",
    CLASS_PRIVATE: "private",
}

# 通用类型编号 → 名称（X.680 Table 1）
UNIVERSAL_TYPE_NAMES = {
    0: "EOC",
    1: "BOOLEAN",
    2: "INTEGER",
    3: "BIT STRING",
    4: "OCTET STRING",
    5: "NULL",
    6: "OBJECT IDENTIFIER",
    7: "ObjectDescriptor",
    8: "EXTERNAL",
    9: "REAL",
    10: "ENUMERATED",
    11: "EMBEDDED PDV",
    12: "UTF8String",
    13: "RELATIVE-OID",
    14: "Reserved",
    15: "Reserved",
    16: "SEQUENCE",
    17: "SET",
    18: "NumericString",
    19: "PrintableString",
    20: "T61String",
    21: "VideotexString",
    22: "IA5String",
    23: "UTCTime",
    24: "GeneralizedTime",
    25: "GraphicString",
    26: "VisibleString",
    27: "GeneralString",
    28: "UniversalString",
    29: "CHARACTER STRING",
    30: "BMPString",
}

# 长度编码形态
LEN_SHORT = "short"
LEN_LONG = "long"
LEN_INDEFINITE = "indefinite"
LEN_INVALID = "invalid"  # 错误节点专用


@dataclass
class ParseState:
    """一份文档共享的解析状态与累计统计。

    懒解析容器必须复用文档级 state（而不是每次新建），否则 MAX_NODES
    会退化成"每个容器各自 10 万"，且 BER/非最小编码标志与警告统计会丢失。
    """

    max_nodes: int
    nodes: int = 0
    errors: int = 0
    warnings: int = 0
    seen_indefinite: bool = False
    seen_nonminimal: bool = False
    exhausted: bool = False
    # 内嵌 probe 的累计工作量，不参与 snapshot/restore 回滚。
    probe_work: int = 0

    def take_node(self) -> bool:
        """占用一个节点预算；超过上限时返回 False 并标记文档已耗尽。"""
        if self.nodes >= self.max_nodes:
            self.exhausted = True
            return False
        self.nodes += 1
        return True

    def note_warnings(self, warnings: list[str]) -> None:
        if not warnings:
            return
        self.warnings += len(warnings)
        self.seen_nonminimal = True

    def note_error(self) -> None:
        self.errors += 1

    def snapshot(self) -> tuple[int, int, int, bool, bool, bool, int]:
        """记录可回滚统计，供内嵌探测失败时整体回滚。

        probe_work 是跨 probe 累计的工作量，故意不包含在快照中，否则失败
        回滚会让攻击者重新获得预算。
        """
        return (
            self.nodes,
            self.errors,
            self.warnings,
            self.seen_indefinite,
            self.seen_nonminimal,
            self.exhausted,
            self.max_nodes,
        )

    def restore(self, snap: tuple[int, int, int, bool, bool, bool, int]) -> None:
        """恢复到 snapshot() 的状态（含临时调整过的 max_nodes）。"""
        (
            self.nodes,
            self.errors,
            self.warnings,
            self.seen_indefinite,
            self.seen_nonminimal,
            self.exhausted,
            self.max_nodes,
        ) = snap


class Asn1Node:
    """一个 TLV 单元。错误节点只携带错误信息，不保证其余字段。

    关键坐标约定（供 Hex 视图三色高亮）：
      [offset, offset+tag_len)                        → tag 区
      [offset+tag_len, offset+header_len)             → length 区
      [offset+header_len, content_end)                → 值区（不含 EOC）
      [content_end, next_offset)                      → EOC（仅不定长）
    """

    __slots__ = (
        "blob",
        "offset",
        "tag_class",
        "constructed",
        "tag_number",
        "tag_len",
        "length_len",
        "length_form",
        "value_len_",
        "eoc_len",
        "parent",
        "warnings",
        "error",
        "possible_embedded",
        "embedded_root",
        "is_embedded",
        "_children",
        "_vi",
        "_vi_computed",
        "_emb_checked",
        "_state",
        "_row",
        "_items",
    )

    def __init__(
        self,
        blob: bytes,
        offset: int,
        tag_class: int = CLASS_UNIVERSAL,
        constructed: bool = False,
        tag_number: int = 0,
        tag_len: int = 0,
        length_len: int = 0,
        length_form: str = LEN_INVALID,
        value_len: int = 0,
        eoc_len: int = 0,
        parent: Asn1Node | None = None,
        warnings: list[str] | None = None,
        error: str | None = None,
        possible_embedded: bool = False,
    ) -> None:
        self.blob = blob
        self.offset = offset
        self.tag_class = tag_class
        self.constructed = constructed
        self.tag_number = tag_number
        self.tag_len = tag_len
        self.length_len = length_len
        self.length_form = length_form
        # 不定长节点在找到 EOC 后由解析器回填实际值长度
        self.value_len_ = value_len
        self.eoc_len = eoc_len
        self.parent = parent
        self.warnings = warnings if warnings is not None else []
        self.error = error
        self.possible_embedded = possible_embedded
        self.embedded_root: Asn1Node | None = None
        self.is_embedded = False  # 值内嵌 DER 探测出来的根节点
        self._children: list[Asn1Node] | None = None
        self._vi: ValueInfo | None = None
        self._vi_computed = False
        self._emb_checked = False
        self._state: ParseState | None = None
        self._row = 0  # 在父级 child_items / 文档 roots 中的行号
        self._items: tuple[Asn1Node, ...] | None = None

    # ---- 坐标属性 ------------------------------------------------------

    @property
    def header_len(self) -> int:
        """tag + length 的字节数。错误节点为 0。"""
        return self.tag_len + self.length_len

    @property
    def value_offset(self) -> int:
        return self.offset + self.header_len

    @property
    def content_end(self) -> int:
        """值区结束偏移（不含 EOC）。"""
        return self.offset + self.header_len + self.value_len_

    @property
    def end(self) -> int:
        """兼容别名：值区结束偏移（不含 EOC）。

        新代码应优先使用 ``content_end``（值区）或 ``next_offset``（完整 TLV）。
        """
        return self.content_end

    @property
    def next_offset(self) -> int:
        """完整 TLV 的结束偏移：定长不含额外字节，不定长包含 EOC。"""
        return self.content_end + self.eoc_len

    @property
    def encoded_len(self) -> int:
        """完整编码长度（含 EOC）。"""
        return self.next_offset - self.offset

    # 对外语义：值区长度（错误节点为 0）
    @property
    def value_len(self) -> int:
        return 0 if self.error is not None else self.value_len_

    @property
    def error_text(self) -> str:
        """错误消息格式：`offset 0x…: 消息`，与错误节点位置一致。"""
        if self.error is None:
            return ""
        return f"offset 0x{self.offset:X}: {self.error}"

    @property
    def total_len(self) -> int:
        """完整编码长度（不定长含 EOC；错误节点为垃圾区长度）。"""
        return self.encoded_len

    @property
    def depth(self) -> int:
        d = 0
        node = self.parent
        while node is not None:
            d += 1
            node = node.parent
        return d

    def value_bytes(self) -> bytes:
        vo = self.value_offset
        return self.blob[vo : vo + self.value_len_]

    # ---- 显示名与路径 --------------------------------------------------

    @property
    def type_name(self) -> str:
        if self.error is not None:
            return "ERROR"
        if self.tag_class == CLASS_UNIVERSAL:
            return UNIVERSAL_TYPE_NAMES.get(self.tag_number, f"universal#{self.tag_number}")
        if self.tag_class == CLASS_CONTEXT:
            # context 标签使用 Context[0] 形式，而不是只显示 [0]。
            return f"Context[{self.tag_number}]"
        return f"{TAG_CLASS_NAMES[self.tag_class].capitalize()}[{self.tag_number}]"

    @property
    def path_token(self) -> str:
        if self.error is not None:
            return "ERROR"
        return self.type_name

    @property
    def path(self) -> str:
        tokens: list[str] = []
        node: Asn1Node | None = self
        while node is not None:
            tokens.append(node.path_token)
            node = node.parent
        return "/".join(reversed(tokens))

    # ---- 惰性子节点与值解码 -------------------------------------------

    @property
    def children(self) -> list[Asn1Node]:
        if self._children is None:
            from .parser import parse_children  # 局部导入避免循环依赖

            # parse_children 负责设置 parent / _row / _items
            self._children = parse_children(self)
        return self._children

    @property
    def decoded(self) -> ValueInfo | None:
        """值的多表示解码结果（惰性计算并缓存）。"""
        if not self._vi_computed:
            self._vi_computed = True
            if self.error is None:
                from .decode import value_of

                self._vi = value_of(self)
        return self._vi

    @property
    def summary(self) -> str:
        """值的单行摘要（复制子树文本等使用；结构树只显示类型，不展示摘要）。"""
        info = self.decoded
        return info.summary if info else ""

    def ensure_embedded(self) -> None:
        """OCTET/BIT STRING 值疑似 DER 时尝试解析出内嵌根节点（一次性）。"""
        if self._emb_checked or self.error is not None:
            return
        self._emb_checked = True
        if not self.possible_embedded:
            return
        from .parser import probe_embedded

        root = probe_embedded(self)
        if root is not None:
            root.parent = self
            root.is_embedded = True
            root._row = len(self.children)
            self.embedded_root = root
            self._items = None

    @property
    def child_items(self) -> tuple[Asn1Node, ...]:
        """树视图行集合：普通子节点 + 内嵌 DER 根节点（缓存为不可变 tuple）。"""
        items = self._items
        if items is None:
            if self.embedded_root is None and self.possible_embedded and not self.error:
                self.ensure_embedded()
            children = self.children
            if self.embedded_root is not None:
                items = (*children, self.embedded_root)
            else:
                items = tuple(children)
            self._items = items
        return items

    def iter_nodes(self) -> Iterator[Asn1Node]:
        """深度优先遍历（访问会触发惰性解析，调用方需要注意开销）。"""
        stack: list[Asn1Node] = [self]
        while stack:
            node = stack.pop()
            yield node
            stack.extend(reversed(node.child_items))

    def __repr__(self) -> str:  # pragma: no cover - 调试用
        pos = f"offset=0x{self.offset:X}"
        if self.error:
            return f"<Asn1Node ERROR @{pos} {self.error!r}>"
        return f"<Asn1Node {self.type_name} @{pos} total={self.total_len}>"


@dataclass
class Asn1Document:
    """一次解析的结果：若干顶层 TLV（PEM 多段 / 串接 DER）+ 元信息。"""

    data: bytes = b""
    roots: list[Asn1Node] = field(default_factory=list)
    source_kind: str = "DER"  # sniff 结果：DER/PEM/BASE64/HEX/EMPTY
    source_desc: str = ""  # 识别描述（详情面板概要页显示）
    _state: ParseState | None = field(default=None, repr=False, compare=False)

    @property
    def node_count(self) -> int:
        return self._state.nodes if self._state is not None else 0

    @property
    def error_count(self) -> int:
        return self._state.errors if self._state is not None else 0

    @property
    def warning_count(self) -> int:
        return self._state.warnings if self._state is not None else 0

    @property
    def ber_detected(self) -> bool:
        if self._state is None:
            return False
        return self._state.seen_indefinite or self._state.seen_nonminimal

    def iter_roots_deep(self) -> Iterator[Asn1Node]:
        for root in self.roots:
            yield from root.iter_nodes()

    @property
    def encoding_label(self) -> str:
        return "BER" if self.ber_detected else "DER"


class ValueKind(Enum):
    """Value 解码结果的结构化语义类型（UI 不应依赖 details 的中文 key）。"""

    GENERIC = auto()
    OID = auto()
    RELATIVE_OID = auto()
    TIME = auto()
    TEXT = auto()
    BOOLEAN = auto()
    NULL = auto()


@dataclass
class ValueInfo:
    """值的多表示解码结果：树上显示摘要 + 面板显示明细。"""

    summary: str = ""
    details: list[tuple[str, str]] = field(default_factory=list)
    kind: ValueKind = ValueKind.GENERIC
    semantic: str = ""  # OID dotted / ISO 时间 / 文本 / TRUE/FALSE / NULL
    name: str = ""  # OID 名称（仅 kind=OID 时可能有值）
