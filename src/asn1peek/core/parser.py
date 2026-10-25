"""TLV 解析引擎（BER/DER/CER）。

功能：
- 递归 TLV：多字节标签（0x1F 形式）、短/长长度、BER 不定长（EOC 终止）；
- 懒解析：容器子节点在树展开时才解析；不定长节点例外，需立即解析直接子节点
  以确定 EOC 边界；
- 安全上限：深度 / 节点数 / 长度字段长度封顶；
- 宽松解析：错误不打断全局——生成错误节点覆盖剩余区域，警告（非最小编码等）
  逐节点记录。
"""

from __future__ import annotations

from .model import (
    CLASS_UNIVERSAL,
    LEN_INDEFINITE,
    LEN_INVALID,
    LEN_LONG,
    LEN_SHORT,
    Asn1Document,
    Asn1Node,
    ParseState,
)

# 安全上限
MAX_DEPTH = 64  # 结构嵌套层数
MAX_NODES = 100_000  # 单次解析总节点数
MAX_TAG_BYTES = 8  # 标签字节最大数（高位标签号）
MAX_LENGTH_BYTES = 8  # 长度字段最大字节数（X.690 允许更多，此处封顶防炸）
MAX_LENGTH_VALUE = 1 << 32  # 单 TLV 长度合理上限（4 GiB）
EAGER_SCAN_LIMIT = 1 << 20  # ≤1MB 输入做全量扫描统计；更大文件保持懒解析
MAX_EMBEDDED_BYTES = 1 << 20  # 内嵌探测候选值上限（1 MiB）
MAX_EMBEDDED_NODES = 1000  # 单次内嵌探测的临时节点上限
# 文档生命周期内所有内嵌探测的累计工作量上限。无法回滚的失败 probe 也计入，
# 避免异常输入通过反复失败绕过 MAX_NODES。
MAX_PROBE_WORK = 200_000


class ParseError(Exception):
    """解析错误。携带出问题的 offset，便于界面定位。"""

    def __init__(self, offset: int, message: str) -> None:
        super().__init__(f"offset 0x{offset:X}: {message}")
        self.offset = offset
        self.message = message


# --------------------------------------------------------------------------
# 头部字段读取
# --------------------------------------------------------------------------


def _read_tag(data: bytes, pos: int):
    """解析标签头 → (tag_class, tag_number, constructed, tag_len)。"""
    first = data[pos]
    tag_class = first >> 6
    constructed = bool(first & 0x20)
    number = first & 0x1F
    if number < 0x1F:
        return tag_class, number, constructed, 1

    # 高位标签号：后续字节每字节有效 7 位，最高字节不得有前导 0（X.690 8.1.2.4）
    tag_len = 1
    number = 0
    while True:
        if pos + tag_len >= len(data):
            raise ParseError(pos, "标签不完整（高位标签后续字节被截断）")
        if tag_len >= MAX_TAG_BYTES:
            raise ParseError(pos, f"标签字节数超过上限（>{MAX_TAG_BYTES}）")
        b = data[pos + tag_len]
        tag_len += 1
        if number == 0 and b == 0x80:
            raise ParseError(pos, "高位标签存在前导填充 0x80（非法编码）")
        number = (number << 7) | (b & 0x7F)
        if not b & 0x80:
            break
    return tag_class, number, constructed, tag_len


def _read_length(data: bytes, pos: int, end: int, constructed: bool, warnings: list[str]):
    """解析长度字段 → (length_value, length_len, length_form)。

    不定长编码返回 length_value=None。
    """
    if pos >= end:
        raise ParseError(pos, "长度字段缺失（数据截断）")
    first = data[pos]
    if first < 0x80:
        return first, 1, LEN_SHORT
    n = first & 0x7F
    if n == 0:  # 0x80：不定长
        if not constructed:
            raise ParseError(pos, "原始类型使用了不定长编码（X.690 8.1.5 禁止）")
        return None, 1, LEN_INDEFINITE
    if n > MAX_LENGTH_BYTES:
        raise ParseError(pos, f"长度字段字节数过大（{n} > {MAX_LENGTH_BYTES}）")
    if pos + 1 + n > end or pos + 1 + n > len(data):
        raise ParseError(pos, "长度字段不完整（数据截断）")
    if data[pos + 1] == 0 and n > 1:
        warnings.append("长度存在前导 0x00 字节（非最小编码，DER 违例）")
    value = int.from_bytes(data[pos + 1 : pos + 1 + n], "big")
    if value > MAX_LENGTH_VALUE:
        raise ParseError(pos, f"长度值不合理（{value} 超出防护上限）")
    # 最小性检查（X.690 8.1.3.2/8.1.3.5）：
    # - 值 < 0x80 时应使用短形式单字节；
    # - 长形式的长度字节数应取可容纳值的最小数量。
    if value < 0x80:
        warnings.append(f"长度 {value} 应使用短形式编码（非最小编码，DER 违例）")
    else:
        min_bytes = (value.bit_length() + 7) // 8
        if n > min_bytes:
            warnings.append(
                f"长度 {value} 的长形式多了 {n - min_bytes} 字节（非最小编码，DER 违例）"
            )
    return value, n + 1, LEN_LONG


def _looks_like_embedded(
    data: bytes, vo: int, end: int, tag_class: int, tag_number: int, constructed: bool
) -> bool:
    """廉价启发：OCTET/BIT STRING 值以 0x30（SEQUENCE）开头则标记
    “可能内嵌 DER”。真正展开时再做严格试探（probe_embedded）。"""
    if constructed or tag_class != CLASS_UNIVERSAL or tag_number not in (3, 4):
        return False
    skip = 1 if tag_number == 3 else 0  # BIT STRING 首字节为未用位数
    if vo + skip >= end:
        return False
    return data[vo + skip] == 0x30


# --------------------------------------------------------------------------
# 节点解析
# --------------------------------------------------------------------------


def _attach_child(parent: Asn1Node, children: list[Asn1Node], child: Asn1Node) -> None:
    """统一挂接子节点：parent / _row 必须正确，并失效 child_items 缓存。"""
    child.parent = parent
    child._row = len(children)
    children.append(child)
    parent._items = None


def _parse_node(
    data: bytes,
    pos: int,
    end: int,
    depth: int,
    state: ParseState,
) -> Asn1Node:
    """解析 pos 处的一个 TLV（仅头部；子节点策略见下）。

    边界校验相对 `end`（所在层允许的结束位置），越界即错误。
    """
    if depth > MAX_DEPTH:
        raise ParseError(pos, f"结构嵌套过深（>{MAX_DEPTH} 层，防护上限）")
    if not state.take_node():
        raise ParseError(pos, "节点数超过防护上限，停止解析")

    warnings: list[str] = []
    tag_class, tag_number, constructed, tag_len = _read_tag(data, pos)
    length_value, length_len, length_form = _read_length(
        data, pos + tag_len, end, constructed, warnings
    )
    state.note_warnings(warnings)
    header_len = tag_len + length_len

    node = Asn1Node(
        blob=data,
        offset=pos,
        tag_class=tag_class,
        constructed=constructed,
        tag_number=tag_number,
        tag_len=tag_len,
        length_len=length_len,
        length_form=length_form,
        warnings=warnings,
        possible_embedded=_looks_like_embedded(
            data, pos + header_len, end, tag_class, tag_number, constructed
        ),
    )
    node._state = state

    if length_form == LEN_INDEFINITE:
        state.seen_indefinite = True
        # 不定长必须立即解析直接子节点（确定 EOC 边界）；更深层次在子节点
        # 内部保持懒解析（每个定长子容器的 children 仍按需展开）。
        node._children = []
        children = node._children
        pos = node.value_offset
        while True:
            # EOC 的两个字节都必须落在父容器边界内；否则不能把第二个字节
            # 算进本节点，避免 child.next_offset 越过父节点。
            if pos + 2 > end:
                if not children:
                    raise ParseError(pos, "不定长编码未找到完整 EOC 终止标记（数据截断）")
                # 已有可保留的子节点：父节点保留。若还有剩余字节，错误节点
                # 覆盖剩余区域；正好停在 end 时才用零长度标记，避免标记
                # offset 落到后续兄弟节点上。
                error_pos = pos
                error_span = end - pos
                _attach_child(
                    node,
                    children,
                    _error_node(
                        data,
                        error_pos,
                        error_span,
                        "不定长编码缺少完整 EOC 终止标记",
                        state,
                    ),
                )
                node.eoc_len = 0
                node.value_len_ = end - node.value_offset
                break
            if data[pos : pos + 2] == b"\x00\x00":
                node.eoc_len = 2
                node.value_len_ = pos - node.value_offset
                break
            try:
                child = _parse_node(data, pos, end, depth + 1, state)
                if child.next_offset > end or child.next_offset <= pos:
                    raise ParseError(pos, "子节点边界未前进或越过父容器")
            except ParseError as exc:
                # 宽松解析：保留父节点和已解析兄弟，错误覆盖剩余区域。
                _attach_child(
                    node,
                    children,
                    _error_node(data, pos, end - pos, exc.message, state),
                )
                node.eoc_len = 0
                node.value_len_ = end - node.value_offset
                break
            _attach_child(node, children, child)
            pos = child.next_offset
    else:
        # 定长：校验值区不越界
        value_end = node.value_offset + length_value
        if value_end > end or value_end > len(data):
            raise ParseError(
                pos,
                f"长度字段超出边界（声明 {length_value} 字节，此处至多 "
                f"{max(end, len(data)) - node.value_offset} 字节）",
            )
        node.value_len_ = length_value
        if constructed:
            node._children = None  # 保持 None：懒解析时才填充
        else:
            node._children = []

    return node


def parse_children(node: Asn1Node) -> list[Asn1Node]:
    """懒解析容器的直接子节点；子节点自己的子树仍保持懒解析。

    使用节点所属文档的同一个 ParseState，确保 MAX_NODES / BER / 警告
    统计在懒解析时仍然生效。遇到解析错误：生成错误子节点（覆盖剩余
    区域）并停止。
    """
    if node.error is not None or not node.constructed:
        return []
    if node._children is not None:
        return node._children

    state = node._state
    if state is None:
        state = ParseState(max_nodes=MAX_NODES)
        node._state = state
    out: list[Asn1Node] = []
    pos, value_end = node.value_offset, node.content_end
    while pos < value_end:
        try:
            child = _parse_node(node.blob, pos, value_end, node.depth + 1, state)
            if child.next_offset > value_end or child.next_offset <= pos:
                raise ParseError(pos, "子节点边界未前进或越过父容器")
        except ParseError as exc:
            _attach_child(
                node,
                out,
                _error_node(node.blob, pos, value_end - pos, exc.message, state),
            )
            break
        _attach_child(node, out, child)
        pos = child.next_offset
    node._children = out
    node._items = None
    return out


def _error_node(
    data: bytes,
    pos: int,
    span: int,
    message: str,
    state: ParseState | None = None,
) -> Asn1Node:
    """错误节点：覆盖 pos 起的垃圾/截断区域，供树与 Hex 定位错误。"""
    node = Asn1Node(
        blob=data,
        offset=pos,
        length_form=LEN_INVALID,
        value_len=span,
        error=message,
    )
    node._state = state
    if state is not None:
        state.note_error()
    return node


def probe_embedded(node: Asn1Node) -> Asn1Node | None:
    """对 OCTET/BIT STRING 值严格试探：能否完整解析为一个内嵌 TLV。

    探测复用文档主 ParseState，并用临时 max_nodes 限制本次探测；失败
    回滚节点/错误/警告/耗尽统计，成功保留。实际解析工作量（含失败探测）
    累计到 state.probe_work，不受失败回滚影响。约束：100% 覆盖、根为
    构造类型且至少有 2 个直接子节点、探测期间无错误/预算耗尽。
    """
    state = node._state
    if state is None:
        state = ParseState(max_nodes=MAX_NODES)
        node._state = state
    if state.exhausted or state.probe_work >= MAX_PROBE_WORK:
        return None

    start = 1 if node.tag_number == 3 else 0  # BIT STRING 跳过未用位计数
    candidate_len = node.value_len_ - start
    # 先按长度过滤，绝不调用 value_bytes() 复制整个值。
    if candidate_len < 6 or candidate_len > MAX_EMBEDDED_BYTES:
        return None
    root_abs = node.value_offset + start
    if root_abs + candidate_len > len(node.blob) or node.blob[root_abs] != 0x30:
        return None

    snap = state.snapshot()
    snap_errors = state.errors
    old_max = state.max_nodes
    state.max_nodes = min(old_max, state.nodes + MAX_EMBEDDED_NODES)
    success = False
    try:
        try:
            root = _parse_node(
                node.blob,
                root_abs,
                root_abs + candidate_len,
                node.depth + 1,
                state,
            )
        except ParseError:
            return None

        if (
            root.offset != root_abs
            or root.next_offset != root_abs + candidate_len
            or not root.constructed
            or root.error is not None
        ):
            return None
        # 探测期间根节点尚未挂到父节点；先挂上，使 root.depth 和后续
        # parse_children 的深度校验使用真实文档深度，而不是从 0 重新计数。
        root.parent = node
        if len(root.children) < 2:
            return None
        if any(child.error is not None for child in root.children):
            return None
        if state.errors != snap_errors or state.exhausted:
            return None

        # 上限内的深度校验：用 children（不用 child_items），避免递归
        # 触发 ensure_embedded；深层错误同样拒绝。
        stack = [root]
        seen = 0
        while stack:
            current = stack.pop()
            if current.error is not None:
                return None
            seen += 1
            if seen > MAX_EMBEDDED_NODES:
                return None
            stack.extend(current.children)
        if state.errors != snap_errors or state.exhausted:
            return None

        success = True
        return root
    finally:
        # 失败探测会 restore 节点计数，但本次实际解析工作量仍须累计。
        work = state.nodes - snap[0]
        state.max_nodes = old_max
        if not success:
            state.restore(snap)
        state.probe_work += work


def locate_node(document: Asn1Document, target: int) -> Asn1Node | None:
    """Hex → 树反向定位：找到包含 target 字节的最内层节点。"""
    best: Asn1Node | None = None
    for root in document.roots:
        if root.error is None and root.offset <= target < root.next_offset:
            best = root
            break
    if best is None:
        return None
    while True:
        nxt = None
        for child in best.child_items:
            if child.error is None and child.offset <= target < child.next_offset:
                nxt = child
                break
        if nxt is None:
            return best
        best = nxt


# --------------------------------------------------------------------------
# 文档级解析
# --------------------------------------------------------------------------


def parse_document(data: bytes, *, max_nodes: int = MAX_NODES) -> Asn1Document:
    """解析整份数据。顶层支持多个并列 TLV（PEM 多段 / 串接 DER）。"""
    state = ParseState(max_nodes=max_nodes)
    roots: list[Asn1Node] = []
    pos, n = 0, len(data)
    while pos < n:
        if data[pos] == 0x00 and data[pos : pos + 2] == b"\x00\x00":
            pos += 2  # 顶层孤独 EOC：跳过
            continue
        try:
            node = _parse_node(data, pos, n, 0, state)
        except ParseError as exc:
            err = _error_node(data, pos, n - pos, exc.message, state)
            err._row = len(roots)
            roots.append(err)
            break
        node._row = len(roots)
        roots.append(node)
        pos = node.next_offset

    doc = Asn1Document(
        data=data,
        roots=roots,
        _state=state,
    )

    # 小文件全量扫描：触发懒解析与内嵌探测，统计由 ParseState 累计。
    if 0 < n <= EAGER_SCAN_LIMIT:
        for _node in doc.iter_roots_deep():
            pass
    return doc
