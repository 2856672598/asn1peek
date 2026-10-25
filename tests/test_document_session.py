"""文档装载纯逻辑单测（不依赖 QWidget）。"""

from __future__ import annotations

from asn1peek.ui.document_session import load_document


class TestLoadDocument:
    def test_empty_input_returns_empty_document(self):
        loaded = load_document(b"", "空输入")
        assert loaded.is_empty
        assert loaded.document.data == b""
        assert loaded.document.roots == []
        assert loaded.message == "空输入：内容为空"

    def test_valid_der_sets_source_metadata(self):
        loaded = load_document(bytes.fromhex("020105"), "测试")
        assert not loaded.is_empty
        assert loaded.document.source_kind == "DER"
        assert loaded.document.roots[0].type_name == "INTEGER"
        assert loaded.message == ""

    def test_all_error_document_reports_first_offset(self):
        loaded = load_document(b"\x30\x82\x99\x99\x01", "测试")
        assert not loaded.is_empty
        assert loaded.document.roots
        assert all(r.error is not None for r in loaded.document.roots)
        assert "未识别出有效 ASN.1 结构" in loaded.message
        assert f"offset 0x{loaded.document.roots[0].offset:X}" in loaded.message
