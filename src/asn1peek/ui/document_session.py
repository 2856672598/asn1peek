"""文档装载的纯逻辑：sniff → parse → 来源描述与状态提示。

本模块不依赖任何 QWidget，便于单元测试；MainWindow 只负责把结果装配到
树 / Hex / 详情三区，并在空输入时清空旧视图。
"""

from __future__ import annotations

from dataclasses import dataclass

from ..core.model import Asn1Document
from ..core.parser import parse_document
from ..core.sniff import sniff


@dataclass(frozen=True)
class DocumentLoad:
    """一次装载的结果：文档 + 是否需要提示（不直接操作 UI）。"""

    document: Asn1Document
    is_empty: bool = False
    message: str = ""
    message_timeout: int = 0


def empty_document() -> Asn1Document:
    """空文档（清空树 / Hex / 详情时使用）。"""
    return Asn1Document(data=b"", roots=[])


def load_document(data: bytes, source: str) -> DocumentLoad:
    """解析一段输入；source 为文件路径或来源描述。

    空输入返回空文档并给出「内容为空」提示；识别/解析结果写入
    ``source_kind`` / ``source_desc``，全错误文档附带首个错误 offset。
    """
    result = sniff(data)
    if result.kind == "EMPTY":
        return DocumentLoad(
            empty_document(),
            is_empty=True,
            message=f"{source}：内容为空",
            message_timeout=8000,
        )

    combined = b"".join(result.blobs)
    doc = parse_document(combined)
    doc.source_kind = result.kind
    doc.source_desc = result.description
    if result.warnings:
        doc.source_desc += " · " + "；".join(result.warnings)

    message = ""
    timeout = 0
    if doc.roots and doc.error_count and all(r.error is not None for r in doc.roots):
        message = (
            f"{source}：未识别出有效 ASN.1 结构"
            f"（{doc.error_count} 处错误，首个 offset 0x{doc.roots[0].offset:X}）"
        )
        timeout = 12000
    return DocumentLoad(doc, message=message, message_timeout=timeout)
