"""值解码回归：ValueInfo 结构化语义与标签/时间边界。"""

from __future__ import annotations

from asn1peek.core.decode import value_of
from asn1peek.core.model import Asn1Node, ValueKind
from asn1peek.core.parser import parse_document


def _value(der: bytes):
    return value_of(parse_document(der).roots[0])


def _tlv(tag: int, value: bytes) -> bytes:
    """构造短格式长度的 TLV，用于验证解析后的值摘要。"""
    assert len(value) < 0x80
    return bytes([tag, len(value)]) + value


def test_oid_valueinfo_exposes_semantic_and_name():
    info = _value(bytes.fromhex("06092A864886F70D01010B"))
    assert info.kind is ValueKind.OID
    assert info.semantic == "1.2.840.113549.1.1.11"
    assert info.name == "sha256WithRSAEncryption"


def test_time_valueinfo_normalizes_comma_decimal():
    # GeneralizedTime "20240405123456,123Z"
    raw = b"20240405123456,123Z"
    info = _value(bytes([0x18, len(raw)]) + raw)
    assert info.kind is ValueKind.TIME
    assert info.semantic == "2024-04-05T12:34:56.123Z"


def test_context_specific_tag_13_is_not_relative_oid():
    """Context[13] 不能被误当作 universal RELATIVE-OID 解码。"""
    node = parse_document(bytes.fromhex("8D02852A")).roots[0]
    info = value_of(node)
    assert info.kind is ValueKind.GENERIC
    assert "682" not in info.summary
    assert all("682" not in value for _label, value in info.details)


def test_text_and_boolean_kinds():
    assert _value(b"\x0c\x02hi").kind is ValueKind.TEXT
    assert _value(b"\x01\x01\xff").kind is ValueKind.BOOLEAN
    assert _value(b"\x01\x01\xff").semantic == "TRUE"
    assert _value(b"\x05\x00").kind is ValueKind.NULL


def test_empty_relative_oid_has_summary():
    info = _value(b"\x0d\x00")
    assert info.kind is ValueKind.RELATIVE_OID
    assert info.summary == "空 RELATIVE-OID"
    assert info.semantic == ""


def test_empty_oid_has_summary():
    info = _value(b"\x06\x00")
    assert info.kind is ValueKind.OID
    assert info.summary == "空 OID"
    assert info.semantic == ""


def test_oversized_oid_reports_size_without_parsing():
    raw = b"\x2a" + b"\x81" * 2098 + b"\x00"
    der = b"\x06\x82" + len(raw).to_bytes(2, "big") + raw
    info = _value(der)
    assert info.kind is ValueKind.OID
    assert info.semantic == ""
    assert "2100 字节" in info.summary


def test_2000_byte_integer_does_not_raise():
    raw = b"\x7f" + b"\xff" * 1999
    der = b"\x02\x82" + len(raw).to_bytes(2, "big") + raw
    info = _value(der)
    assert "2000 字节" in info.summary
    assert info.semantic == ""


def test_large_text_is_not_decoded():
    raw = b"a" * (64 * 1024 + 1)
    der = b"\x0c\x83" + len(raw).to_bytes(3, "big") + raw
    info = _value(der)
    assert info.kind is ValueKind.TEXT
    assert info.semantic == ""
    assert "未解码" in info.summary
    assert len(info.summary) <= 60


def test_octet_summary_does_not_copy_full_value(monkeypatch):
    der = b"\x04\x83\x10\x00\x00" + b"\x00" * (1 << 20)
    node = parse_document(der).roots[0]
    monkeypatch.setattr(
        Asn1Node,
        "value_bytes",
        lambda self: (_ for _ in ()).throw(AssertionError("不应全量复制")),
    )
    info = value_of(node)
    assert "1048576 字节" in info.summary


def test_bit_string_summary_does_not_copy_full_value(monkeypatch):
    der = b"\x03\x83\x10\x00\x01" + b"\x00" + b"\x00" * (1 << 20)
    node = parse_document(der).roots[0]
    monkeypatch.setattr(
        Asn1Node,
        "value_bytes",
        lambda self: (_ for _ in ()).throw(AssertionError("不应全量复制")),
    )
    info = value_of(node)
    assert "1048576 字节" in info.summary


def test_time_invalid_ranges_return_none():
    raw = b"991399259999,999Z"
    info = _value(bytes([0x18, len(raw)]) + raw)
    assert info.kind is ValueKind.TIME
    assert info.semantic == ""
    assert dict(info.details)["警告"] == "无法解析的时间格式"


def test_time_no_zone_semantic_is_pure_iso():
    raw = b"240405123456"
    info = _value(bytes([0x17, len(raw)]) + raw)
    assert info.kind is ValueKind.TIME
    assert info.semantic == "2024-04-05T12:34:56"
    assert "时间区域未指定" not in info.semantic
    assert dict(info.details)["提示"] == "时间区域未指定"


class TestParsedValueSummaries:
    def test_integer_positive(self):
        doc = parse_document(_tlv(0x02, b"\x05"))
        assert doc.roots[0].summary == "5"
        assert doc.roots[0].end == 3  # 头 2 + 值 1

    def test_integer_negative(self):
        doc = parse_document(_tlv(0x02, b"\xfb"))
        assert doc.roots[0].summary == "-5"

    def test_integer_multibyte_sign(self):
        # 0xA0000001 as signed int32
        doc = parse_document(_tlv(0x02, b"\xa0\x00\x00\x01"))
        assert doc.roots[0].summary == str(-1610612735)

    def test_boolean(self):
        assert parse_document(_tlv(0x01, b"\xff")).roots[0].summary == "TRUE"
        assert parse_document(_tlv(0x01, b"\x00")).roots[0].summary == "FALSE"
        assert "非规范" in parse_document(_tlv(0x01, b"\x7f")).roots[0].summary

    def test_null_no_value(self):
        doc = parse_document(b"\x05\x00")
        node = doc.roots[0]
        assert node.type_name == "NULL" and node.value_len == 0

    def test_bit_string(self):
        doc = parse_document(_tlv(0x03, b"\x00\xff\xf0"))
        node = doc.roots[0]
        assert "未用位 0" in node.summary

    def test_oid_common_name(self):
        doc = parse_document(_tlv(0x06, b"\x55\x04\x03"))
        node = doc.roots[0]
        info = node.decoded
        assert info.summary == "2.5.4.3 (commonName)"

    def test_oid_x509_algo(self):
        # 1.2.840.113549.1.1.11 = 2a 86 48 86 f7 0d 01 01 0b
        doc = parse_document(_tlv(0x06, bytes.fromhex("2a864886f70d01010b")))
        assert "sha256WithRSAEncryption" in doc.roots[0].summary

    def test_oid_multibyte_first_subid(self):
        # 2.999.1：第一子标识符 = 80+999 = 1079 = 0x88 0x37
        doc = parse_document(_tlv(0x06, b"\x88\x37\x01"))
        assert doc.roots[0].summary == "2.999.1"

    def test_oid_truncated(self):
        doc = parse_document(_tlv(0x06, b"\x2a\x88"))
        assert doc.roots[0].summary == "无法解析"

    def test_utctime(self):
        doc = parse_document(_tlv(0x17, b"240405123456Z"))
        details = dict(doc.roots[0].decoded.details)
        assert details["ISO 8601"] == "2024-04-05T12:34:56Z"

    def test_utctime_offset_tz(self):
        doc = parse_document(_tlv(0x17, b"240405123456+0800"))
        details = dict(doc.roots[0].decoded.details)
        assert details["ISO 8601"] == "2024-04-05T12:34:56+08:00"

    def test_generalized_time(self):
        doc = parse_document(_tlv(0x18, b"20240405123456Z"))
        details = dict(doc.roots[0].decoded.details)
        assert details["ISO 8601"] == "2024-04-05T12:34:56Z"

    def test_generalized_time_fraction(self):
        doc = parse_document(_tlv(0x18, b"20240405123456.123Z"))
        details = dict(doc.roots[0].decoded.details)
        assert details["ISO 8601"] == "2024-04-05T12:34:56.123Z"

    def test_utf8_string_cjk(self):
        doc = parse_document(_tlv(0x0C, "中文".encode()))
        assert "中文" in doc.roots[0].summary

    def test_bmp_string(self):
        doc = parse_document(_tlv(0x1E, "β".encode("utf-16-be")))
        assert "β" in doc.roots[0].summary

    def test_printable_string(self):
        doc = parse_document(_tlv(0x13, b"asn1peek"))
        assert "asn1peek" in doc.roots[0].summary

    def test_octet_string_hex_summary(self):
        doc = parse_document(_tlv(0x04, b"\xde\xad\xbe\xef"))
        assert "DE AD" in doc.roots[0].summary

    def test_relative_oid(self):
        # 0x85 0x2a → 682；0x41 → 65
        doc = parse_document(_tlv(0x0D, b"\x85\x2a\x41"))
        info = doc.roots[0].decoded
        assert info.summary == "682.65"
