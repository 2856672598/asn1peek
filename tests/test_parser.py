"""TLV 解析器单元测试。

手工构造向量覆盖 X.690 关键形态；openssl 黄金对照见 test_golden_openssl.py。
"""

from __future__ import annotations

import asn1peek.core.parser as parser_module
from asn1peek.core.export import node_bytes
from asn1peek.core.model import Asn1Node, ParseState
from asn1peek.core.parser import MAX_DEPTH, locate_node, parse_document

# %------------------------------------------------------------------------
# 构造辅助
# %------------------------------------------------------------------------


def enc_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def tlv(tag: int, content: bytes, *, long_len: bool = False) -> bytes:
    if long_len:
        # 0x81 只能表示单字节长度，必须落在 0x00..0xFF。
        assert len(content) < 0x100
        length = bytes([0x81, len(content)])
    else:
        length = enc_len(len(content))
    return bytes([tag]) + length + content


def seq(*items: bytes) -> bytes:
    return tlv(0x30, b"".join(items))


def indef(tag: int, content: bytes) -> bytes:
    return bytes([tag, 0x80]) + content + b"\x00\x00"


INT1 = tlv(0x02, b"\x05")


# %------------------------------------------------------------------------
# 结构与长度形态
# %------------------------------------------------------------------------


class TestTlv:
    def test_two_children_offsets(self):
        data = seq(INT1, b"\x05\x00")
        doc = parse_document(data)
        root = doc.roots[0]
        c0, c1 = root.children
        assert root.total_len == 7  # 头 2 + 值 5
        assert (c0.offset, c0.end) == (2, 5)
        assert (c1.offset, c1.end) == (5, 7)
        assert root.end == 7

    def test_multibyte_tag(self):
        # [25] constructed：tag = BF 19，内容为 INTEGER 2
        doc = parse_document(b"\xbf\x19\x03" + tlv(0x02, b"\x02"))
        node = doc.roots[0]
        assert node.tag_number == 25 and node.tag_class == 2
        assert node.constructed
        assert len(node.children) == 1

    def test_high_tag_number(self):
        # [25] primitive：0x9F 0x19 + content
        doc = parse_document(b"\x9f\x19\x01\x07")
        node = doc.roots[0]
        assert node.tag_class == 2 and node.tag_number == 25
        assert not node.constructed

    def test_long_form_length(self):
        data = b"\x30\x81\x05" + INT1 + b"\x05\x00"
        doc = parse_document(data)
        root = doc.roots[0]
        assert root.length_form == "long"
        assert root.length_len == 2
        assert any("非最小" in w for w in root.warnings)
        assert doc.ber_detected

    def test_long_form_length_bytes_lead_zero(self):
        # 长度 5 用 4 字节长形式：0x84 00 00 00 05 → 前导 0x00 警告
        data = b"\x30\x84\x00\x00\x00\x05" + INT1 + b"\x05\x00"
        doc = parse_document(data)
        root = doc.roots[0]
        assert root.length_len == 5
        assert any("前导" in w for w in root.warnings)

    def test_indefinite_length(self):
        data = indef(0x30, INT1 + tlv(0x02, b"\x09"))
        doc = parse_document(data)
        root = doc.roots[0]
        assert root.length_form == "indefinite"
        assert root.value_len == 6
        assert node_eoc(root) == 2
        assert len(root.children) == 2
        assert root.end == 8
        assert doc.ber_detected

    def test_packed_indefinite_in_definite(self):
        # 定长容器内含不定长子容器
        inner = indef(0x30, INT1)
        doc = parse_document(seq(inner, b"\x05\x00"))
        root = doc.roots[0]
        node = root.children[0]
        assert node.length_form == "indefinite"

    def test_indefinite_inside_indefinite(self):
        """内层 EOC 不能当作父节点结束；两个 EOC 都要被正确跨过。"""
        data = bytes.fromhex("3180308002010500000201060000")
        doc = parse_document(data)
        assert len(doc.roots) == 1
        root = doc.roots[0]
        assert root.type_name == "SET"
        assert [c.type_name for c in root.child_items] == ["SEQUENCE", "INTEGER"]
        inner, integer = root.child_items
        assert inner.length_form == "indefinite"
        assert inner.content_end == 7
        assert inner.next_offset == 9
        assert integer.summary == "6"
        assert root.next_offset == len(data)
        assert node_bytes(root) == data
        assert node_bytes(inner) == data[2:9]

    def test_indefinite_in_definite_keeps_siblings(self):
        """定长容器里的不定长子节点后还有兄弟节点，不应多出伪造 EOC 节点。"""
        data = bytes.fromhex("3009308002010500000500")
        doc = parse_document(data)
        root = doc.roots[0]
        assert [c.type_name for c in root.child_items] == ["SEQUENCE", "NULL"]
        assert all(c.type_name != "EOC" for c in root.child_items)
        assert root.child_items[0].next_offset == 9
        assert root.next_offset == len(data)
        assert node_bytes(root) == data

    def test_indefinite_eoc_cannot_cross_parent_boundary(self):
        """EOC 第二个字节越过父边界时，不能把该字节算进子节点。"""
        data = bytes.fromhex("300330800000")
        doc = parse_document(data)
        assert len(doc.roots) == 2
        root = doc.roots[0]
        assert root.type_name == "SEQUENCE"
        assert root.next_offset == 5
        assert len(root.children) == 1
        err = root.children[0]
        assert err.error and err.offset == 2 and err.next_offset == 5
        assert node_bytes(err) == data[2:5]
        assert doc.roots[1].error is not None
        assert doc.roots[1].offset == 5
        assert all(n.next_offset <= 5 for n in root.iter_nodes())

    def test_indefinite_eoc_cross_boundary_keeps_parent_with_children(self):
        """不定长父节点已有子节点时，缺 EOC 的错误覆盖剩余字节。"""
        data = bytes.fromhex("3006308002010500")
        doc = parse_document(data)
        root = doc.roots[0]
        inner = root.children[0]
        assert inner.type_name == "SEQUENCE"
        assert inner.error is None
        assert inner.eoc_len == 0
        assert inner.next_offset == len(data) == 8
        assert inner.content_end == 8
        assert [c.type_name for c in inner.children] == ["INTEGER", "ERROR"]
        err = inner.children[1]
        assert err.offset == 7 and err.next_offset == 8
        assert err.parent is inner and err._row == 1
        assert node_bytes(err) == b"\x00"
        assert node_bytes(inner) == data[2:]


def node_eoc(node: Asn1Node) -> int:
    return node.eoc_len


# %------------------------------------------------------------------------
# 宽松解析 / 错误定位 / 防护
# %------------------------------------------------------------------------


class TestErrorsAndLimits:
    def test_truncated_length(self):
        doc = parse_document(b"\x30\x81")
        node = doc.roots[0]
        assert node.error and "长度字段不完整" in node.error

    def test_truncated_value(self):
        doc = parse_document(b"\x30\x05\x02\x01\x05")  # 声明 5，实际 3
        node = doc.roots[0]
        assert node.error and "长度字段超出边界" in node.error

    def test_garbage_tail_error_node(self):
        doc = parse_document(INT1 + b"\xff\xff\xff\xff")
        assert doc.roots[0].error is None
        tail = doc.roots[1]
        assert tail.error is not None
        assert tail.offset == 3

    def test_error_child_has_parent_row_depth_path(self):
        doc = parse_document(bytes.fromhex("30020205"))
        root = doc.roots[0]
        err = root.children[0]
        assert err.error is not None
        assert err.parent is root
        assert err._row == 0
        assert err.depth == 1
        assert err.path == "SEQUENCE/ERROR"
        assert node_bytes(err) == b"\x02\x05"

    def test_indefinite_root_child_error_keeps_siblings(self):
        """不定长根内局部错误：保留根和已解析兄弟，错误覆盖剩余区域。"""
        data = bytes.fromhex("318002010502050000")
        doc = parse_document(data)
        root = doc.roots[0]
        assert root.error is None
        assert root.type_name == "SET"
        assert root.eoc_len == 0
        assert root.next_offset == len(data)
        assert [c.type_name for c in root.children] == ["INTEGER", "ERROR"]
        err = root.children[1]
        assert err.offset == 5 and err.next_offset == len(data)
        assert err.parent is root and err._row == 1
        assert doc.error_count == 1

    def test_indefinite_root_missing_eoc_keeps_children(self):
        """根有子节点但缺 EOC：保留根，在 end 处加零长度错误标记。"""
        data = bytes.fromhex("3180020105")
        doc = parse_document(data)
        root = doc.roots[0]
        assert root.error is None
        assert root.type_name == "SET"
        assert root.eoc_len == 0
        assert root.value_len_ == 3
        assert root.next_offset == len(data)
        assert [c.type_name for c in root.children] == ["INTEGER", "ERROR"]
        err = root.children[1]
        assert err.offset == len(data) and err.next_offset == len(data)
        assert err.parent is root and err._row == 1

    def test_parse_state_snapshot_restore(self):
        state = ParseState(max_nodes=10)
        state.nodes, state.errors, state.warnings = 3, 1, 2
        state.seen_indefinite = True
        state.seen_nonminimal = True
        state.exhausted = True
        state.probe_work = 4
        snap = state.snapshot()
        state.nodes, state.errors, state.warnings = 9, 5, 7
        state.seen_indefinite = False
        state.seen_nonminimal = False
        state.exhausted = False
        state.max_nodes = 1
        state.probe_work = 7
        state.restore(snap)
        assert (
            state.nodes,
            state.errors,
            state.warnings,
            state.seen_indefinite,
            state.seen_nonminimal,
            state.exhausted,
            state.max_nodes,
        ) == (3, 1, 2, True, True, True, 10)
        assert state.probe_work == 7, "probe_work 不应被 snapshot/restore 回滚"

    def test_empty_input(self):
        doc = parse_document(b"")
        assert doc.roots == []

    def test_only_zeros(self):
        doc = parse_document(b"\x00" * 7)
        # 0x00 0x00 被视作顶层 EOC 跳过，剩下的 0x05... 产生错误节点
        assert doc.roots and doc.roots[-1].error

    def test_deep_nesting_guard(self):
        data = tlv(0x02, b"\x02")
        for _ in range(MAX_DEPTH + 20):
            data = seq(data)
        doc = parse_document(data)
        # 错误节点在子树深处（根容器本身可正常解析），扫描应能发现
        assert doc.error_count >= 1
        deep = [n for n in doc.iter_roots_deep() if n.error and "嵌套过深" in n.error]
        assert deep

    def test_node_budget_top_level(self):
        data = INT1 * 10
        doc = parse_document(data, max_nodes=5)
        assert len(doc.roots) == 6  # 5 个正常根 + 1 个错误根
        assert doc.roots[-1].error and "节点数" in doc.roots[-1].error

    def test_child_budget_uses_document_state(self):
        """懒解析子节点必须复用文档预算，而不是每个容器各自 10 万。"""
        container = tlv(0x30, INT1 * 50)
        doc = parse_document(container, max_nodes=10)
        children = doc.roots[0].children
        assert doc.node_count == 10
        assert doc.error_count == 1
        assert children[-1].error and "节点数" in children[-1].error
        assert sum(c.error is None for c in children) == 9

    def test_global_budget_across_containers(self):
        """多个容器的子节点共享同一个全局节点上限。"""
        container = tlv(0x30, INT1 * 10)
        doc = parse_document(container * 3, max_nodes=20)
        assert doc.node_count == 20
        assert doc.error_count >= 1
        assert any(n.error and "节点数" in n.error for n in doc.iter_roots_deep())

    def test_tag_max_eight_bytes(self):
        # 8 字节标签（首字节 + 7 个后续字节）允许
        tag8 = bytes([0x1F]) + bytes([0x81] * 6) + bytes([0x01])
        doc = parse_document(tag8 + b"\x00")
        assert doc.roots[0].error is None
        assert doc.roots[0].tag_len == 8

    def test_tag_nine_bytes_rejected(self):
        # 9 字节标签应被 MAX_TAG_BYTES=8 拒绝
        tag9 = bytes([0x1F]) + bytes([0x81] * 7) + bytes([0x01])
        doc = parse_document(tag9 + b"\x00")
        assert doc.roots[0].error and "标签字节数超过上限" in doc.roots[0].error


# %------------------------------------------------------------------------
# 顶级多对象与定位
# %------------------------------------------------------------------------


class TestMultiRootAndLocate:
    def test_concatenated_objects(self):
        a = seq(INT1, b"\x05\x00")
        b = tlv(0x02, b"\x07")
        doc = parse_document(a + b)
        assert len(doc.roots) == 2
        assert doc.roots[1].offset == len(a)

    def test_locate_node_deepest(self):
        a = seq(INT1, b"\x05\x00")
        doc = parse_document(a)
        root = doc.roots[0]
        # 偏移 4 = children[0]（INTEGER）的值字段最后一个字节
        assert locate_node(doc, 4) is root.children[0]
        # 偏移 5 = children[1]（NULL）的 tag
        assert locate_node(doc, 5) is root.children[1]
        # 偏移 0 匹配根节点
        assert locate_node(doc, 0) is root

    def test_locate_node_eoc(self):
        """点击内层 EOC 定位内层节点，点击外层 EOC 定位外层节点。"""
        data = bytes.fromhex("3180308002010500000201060000")
        doc = parse_document(data)
        root = doc.roots[0]
        inner = root.child_items[0]
        assert locate_node(doc, 8) is inner  # 内层 EOC 第 1 字节
        assert locate_node(doc, 13) is root  # 外层 EOC 第 2 字节


# %------------------------------------------------------------------------
# 内嵌 DER 探测
# %------------------------------------------------------------------------


class TestEmbedded:
    def _octet_wrapped(self, inner: bytes) -> bytes:
        return tlv(0x04, inner)

    def test_embedded_detected(self):
        inner = seq(INT1, tlv(0x01, b"\xff"))
        doc = parse_document(self._octet_wrapped(inner))
        octet = doc.roots[0]
        assert octet.possible_embedded
        octet.ensure_embedded()
        assert octet.embedded_root is not None
        root = octet.embedded_root
        assert len(root.children) == 2
        # 绝对偏移内嵌：值区起点为 2（04 05 头）
        assert root.offset == 2
        assert root.is_embedded
        assert 0 < doc._state.probe_work < parser_module.MAX_PROBE_WORK

    def test_embedded_bit_string_skips_unused_byte(self):
        inner = seq(INT1, tlv(0x01, b"\xff"))
        doc = parse_document(tlv(0x03, b"\x00" + inner))
        bit = doc.roots[0]
        bit.ensure_embedded()
        assert bit.embedded_root is not None
        # 值偏移 2 + 1（未用位计数）
        assert bit.embedded_root.offset == 3

    def test_embedded_reject_garbage(self):
        # 声明长度与实际不符的内嵌序列 → 探测失败
        doc = parse_document(tlv(0x04, b"\x30\x05\x02\x01\x02"))
        octet = doc.roots[0]
        octet.ensure_embedded()
        assert octet.embedded_root is None
        assert octet.children == []

    def test_embedded_reject_short(self):
        doc = parse_document(tlv(0x04, seq(INT1)))  # 只有 1 个子节点 → 拒绝
        octet = doc.roots[0]
        octet.ensure_embedded()
        assert octet.embedded_root is None

    def test_embedded_probe_budget_rolls_back(self, monkeypatch):
        """主文档预算不足时探测失败，节点/错误/耗尽标志全部回滚。"""
        monkeypatch.setattr(parser_module, "EAGER_SCAN_LIMIT", 0)
        data = bytes.fromhex("040b3009020105020105020105")
        doc = parse_document(data, max_nodes=1)
        octet = doc.roots[0]
        assert doc.node_count == 1
        octet.ensure_embedded()
        assert octet.embedded_root is None
        assert doc.node_count == 1
        assert doc.error_count == 0
        assert not doc._state.exhausted

    def test_failed_probe_work_budget_stops_further_probes(self, monkeypatch):
        """连续失败 probe 的累计工作量达到上限后，后续候选不再解析。"""
        monkeypatch.setattr(parser_module, "EAGER_SCAN_LIMIT", 0)
        monkeypatch.setattr(parser_module, "MAX_PROBE_WORK", 2)
        # 候选值是合法 SEQUENCE，但只有 1 个直接子节点，因此 probe 失败；
        # 每次失败会解析根 + 1 个子节点，共消耗 2 次 probe 工作量。
        one_child = seq(tlv(0x02, b"\x05\x00"))
        data = tlv(0x04, one_child) * 3
        doc = parse_document(data)
        assert [r.possible_embedded for r in doc.roots] == [True, True, True]

        calls = []
        original = parser_module._parse_node

        def counting(*args, **kwargs):
            calls.append(args[3])
            return original(*args, **kwargs)

        monkeypatch.setattr(parser_module, "_parse_node", counting)
        for root in doc.roots:
            root.ensure_embedded()

        # 第一次失败累计 2 次工作量；预算已满后第二、第三个候选直接跳过。
        assert [r.embedded_root for r in doc.roots] == [None, None, None]
        assert len(calls) == 2
        assert doc._state.probe_work == 2
        assert doc.node_count == 3
        assert doc.error_count == 0
        assert not doc._state.exhausted

    def test_embedded_probe_cap_rolls_back(self):
        """探测自身的 1000 节点上限耗尽时拒绝，不把半棵树暴露出去。"""
        kids = INT1 * 1200
        inner = b"\x30\x82" + len(kids).to_bytes(2, "big") + kids
        data = b"\x04\x82" + len(inner).to_bytes(2, "big") + inner
        doc = parse_document(data)
        octet = doc.roots[0]
        assert octet.embedded_root is None
        assert doc.node_count == 1
        assert doc.error_count == 0
        assert not doc._state.exhausted

    def test_embedded_probe_rejects_deep_error(self):
        """直接子节点都正常、但更深层截断时也必须拒绝。"""
        data = bytes.fromhex("040a30080201053003020500")
        doc = parse_document(data)
        octet = doc.roots[0]
        assert octet.possible_embedded
        assert octet.embedded_root is None
        assert doc.node_count == 1
        assert doc.error_count == 0

    def test_embedded_probe_uses_real_document_depth(self):
        """内嵌根必须先挂到父节点再解析，否则深层内嵌会绕过 MAX_DEPTH。"""
        deep = INT1
        for _ in range(60):
            deep = seq(deep)
        # 内嵌根至少要有两个直接子节点，才会进入下方的深层校验。
        inner = seq(deep, INT1)
        data = tlv(0x04, inner)
        for _ in range(60):
            data = seq(data)
        doc = parse_document(data)
        node = doc.roots[0]
        for _ in range(60):
            node = node.child_items[0]
        assert node.type_name == "OCTET STRING"
        assert node.depth == 60
        assert node.possible_embedded
        assert node.embedded_root is None
        assert doc.error_count == 0

    def test_embedded_probe_does_not_call_value_bytes(self, monkeypatch):
        """大值先按 value_len_ 拒绝，不能调用 value_bytes() 全量复制。"""
        value = b"\x30" + b"\x00" * ((2 << 20) - 1)
        data = b"\x04\x83" + len(value).to_bytes(3, "big") + value
        doc = parse_document(data)
        octet = doc.roots[0]
        assert octet.possible_embedded

        def fail_value_bytes(_self):
            raise AssertionError("probe must not materialize value_bytes()")

        monkeypatch.setattr(Asn1Node, "value_bytes", fail_value_bytes)
        octet.ensure_embedded()
        assert octet.embedded_root is None

    def test_embedded_stats_use_document_state(self):
        """探测和后续展开共享主 state：节点、警告、BER 一次算清。"""
        data = bytes.fromhex("040b3009300402810105020106")
        doc = parse_document(data)
        octet = doc.roots[0]
        assert octet.embedded_root is not None
        assert doc.node_count == 5
        assert doc.warning_count == 1
        assert doc.ber_detected
        assert sum(1 for _ in doc.iter_roots_deep()) == 5


# %------------------------------------------------------------------------
# 文档统计
# %------------------------------------------------------------------------


class TestStats:
    def test_small_file_full_scan(self):
        data = seq(INT1, tlv(0x04, seq(INT1, tlv(0x01, b"\xff"))))
        doc = parse_document(data)
        assert doc.node_count >= 5
        assert doc.error_count == 0
        assert not doc.ber_detected

    def test_error_counted_in_subtree(self):
        # OCTET STRING 值为垃圾，但顶层可解析：展开后统计错误
        data = tlv(0x04, b"\x30\x05\x02\x01\x02")  # 内嵌解析失败（但外层 ok）
        doc = parse_document(data)
        # bit-string value 0xFF 不触发 probe
        assert doc.error_count == 0

    def test_lazy_children_update_ber_and_warnings(self, monkeypatch):
        """关闭 eager scan 后，展开子节点仍要更新 BER 标志和警告统计。"""
        monkeypatch.setattr(parser_module, "EAGER_SCAN_LIMIT", 0)
        doc = parse_document(b"\x30\x04\x02\x81\x01\x05")
        assert doc.node_count == 1
        assert doc.warning_count == 0
        assert not doc.ber_detected
        assert doc.encoding_label == "DER"

        children = doc.roots[0].children
        assert len(children) == 1
        assert doc.node_count == 2
        assert doc.warning_count == 1
        assert doc.ber_detected
        assert doc.encoding_label == "BER"
