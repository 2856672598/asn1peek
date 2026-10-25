"""输入嗅探测试：同一证书四种形态识别一致。"""

from __future__ import annotations

import base64
from pathlib import Path

import pytest

from asn1peek.core.parser import parse_document
from asn1peek.core.sniff import sniff


@pytest.fixture(scope="module")
def leaf_der_bytes() -> bytes:
    p = Path(__file__).parent.parent / "samples" / "leaf.der"
    if not p.exists():
        pytest.skip("samples/leaf.der 未生成")
    data = p.read_bytes()
    # 剥掉外层 SEQUENCE 头，构造裸内容形态。
    return data


class TestSniff:
    def test_empty(self):
        result = sniff(b"")
        assert result.kind == "EMPTY"

    def test_pem_single_certificate(self, leaf_der_bytes):
        pem = (
            b"-----BEGIN CERTIFICATE-----\n"
            + base64.encodebytes(leaf_der_bytes)
            + b"-----END CERTIFICATE-----\n"
        )
        result = sniff(pem)
        assert result.kind == "PEM"
        assert "CERTIFICATE" in result.description
        assert result.blobs and result.blobs[0] == leaf_der_bytes

    def test_pem_chain_three_certs(self):
        """含 3 张证书的 chain.pem 显示 3 个并列根节点。"""
        p = Path(__file__).parent.parent / "samples" / "chain.pem"
        if not p.exists():
            pytest.skip("samples/chain.pem 未生成")
        result = sniff(p.read_bytes())
        assert result.kind == "PEM"
        # chain.pem = leaf + intermediate + root（3×CERTIFICATE）
        assert result.blobs and len(result.blobs) == 3
        # 解出 DER 串联后应得到 3 个顶层对象
        doc = parse_document(b"".join(result.blobs))
        assert len(doc.roots) == 3
        assert doc.roots[0].type_name == "SEQUENCE"

    def test_hex_text(self, leaf_der_bytes):
        text = " ".join(f"{b:02X}" for b in leaf_der_bytes).encode()
        result = sniff(text)
        assert result.kind == "HEX"
        assert result.blobs[0] == leaf_der_bytes

    def test_hex_text_newlines(self):
        result = sniff(b"30 03\n02 01 02\n")
        assert result.kind == "HEX"
        assert result.blobs[0] == bytes.fromhex("3003020102")

    def test_base64_naked(self, leaf_der_bytes):
        text = base64.encodebytes(leaf_der_bytes).replace(b"\n", b"")
        result = sniff(text)
        assert result.kind == "BASE64"
        assert result.blobs[0] == leaf_der_bytes

    def test_raw_der(self, leaf_der_bytes):
        result = sniff(leaf_der_bytes)
        assert result.kind == "DER"
        assert result.blobs == [leaf_der_bytes]

    def test_binary_junk_is_der(self):
        data = bytes(range(1, 254))
        result = sniff(data)
        assert result.kind == "DER"

    def test_pem_with_junk_between_blocks(self, leaf_der_bytes):
        raw_pem = (
            b"junk before text\n"
            b"-----BEGIN X509 CERTIFICATE-----\n"
            + base64.encodebytes(leaf_der_bytes)
            + b"-----END X509 CERTIFICATE-----\n"
            b"trailing garbage\n"
        )
        result = sniff(raw_pem)
        assert result.kind == "PEM"
        assert result.blobs[0] == leaf_der_bytes

    def test_decode_all_equals_der(self, leaf_der_bytes):
        """同一证书四形态解析根级结果一致。"""
        from asn1peek.core.parser import parse_document

        pem = (
            b"-----BEGIN CERTIFICATE-----\n"
            + base64.encodebytes(leaf_der_bytes)
            + b"-----END CERTIFICATE-----\n"
        )
        b64 = base64.encodebytes(leaf_der_bytes)
        hexed = " ".join(f"{b:02X}" for b in leaf_der_bytes).encode()

        kinds = {
            "der": parse_document(leaf_der_bytes),
            "pem": parse_document(b"".join(sniff(pem).blobs)),
            "b64": parse_document(b"".join(sniff(b64).blobs)),
            "hex": parse_document(b"".join(sniff(hexed).blobs)),
        }
        root_of = {k: v.roots[0] for k, v in kinds.items()}
        ref_offset = root_of["der"].total_len

        def sig(node):
            return (
                node.offset,
                node.total_len,
                node.type_name,
                node.tag_class,
                node.constructed,
                node.summary,
            )

        for kind, doc in kinds.items():
            root = doc.roots[0]
            assert root.total_len == ref_offset, kind
            ref = root_of["der"].children[:2]
            assert [sig(c) for c in root.children[:2]] == [sig(c) for c in ref], kind
