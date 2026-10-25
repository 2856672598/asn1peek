"""输入嗅探：自动识别 DER / PEM / 裸 Base64 / Hex 文本。

识别顺序（互相冲突时取后者兼容前者）：
1. PEM 文本（可含多段，覆盖常见 PEM 标记）→ 逐段 base64 解码；
2. 纯 Hex 文本（可含空白）→ hex 解码；
3. 纯 Base64 文本 → base64 解码；
4. 其余 → 原始字节按 DER/BER 处理。
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass, field

_PEM_BLOCK_RE = re.compile(
    rb"-----BEGIN ([A-Za-z0-9 ]+)-----\s*?"  # 夺取标记名
    rb"([A-Za-z0-9+/=\s]+?)"  # base64 载荷（含换行）
    rb"-----END \1-----",
    re.S,
)
_HEX_RE = re.compile(rb"^[\s0-9A-Fa-f]+$")
_B64_RE = re.compile(rb"^[A-Za-z0-9+/=\s]+$")


@dataclass
class SniffResult:
    kind: str  # DER / PEM / BASE64 / HEX / EMPTY
    description: str  # 识别描述（如 "PEM: 2×CERTIFICATE"）
    blobs: list[bytes]  # 切分后的 DER blob（聚类后由 parser 顺序解析）
    warnings: list[str] = field(default_factory=list)


def sniff(data: bytes) -> SniffResult:
    """对原始字节做格式识别并切分出 DER blob。"""
    if not data:
        return SniffResult("EMPTY", "空输入", [])

    # ---- 1. PEM --------------------------------------------------------
    matches = list(_PEM_BLOCK_RE.finditer(data))
    if matches:
        blobs: list[bytes] = []
        labels: list[str] = []
        failed = 0
        for m in matches:
            try:
                blob = base64.b64decode(m.group(2), validate=False)
            except (binascii.Error, ValueError):
                failed += 1
                continue
            if blob:
                blobs.append(blob)
                labels.append(m.group(1).decode("ascii", "replace"))
        if blobs:
            from collections import Counter

            counter = Counter(labels)
            detail = "+".join(f"{n}×{label}" for label, n in counter.items())
            desc = f"PEM: {detail}"
            if failed:
                desc += f"（{failed} 段解码失败）"
            result = SniffResult("PEM", desc, blobs)
            result.warnings.append("PEM 输入：Hex 视图显示解码后的 DER 字节")
            return result

    # ---- 2/3. 文本形态：hex 或 base64 ----------------------------------
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        try:
            data.decode("utf-8")
            text = data.decode("utf-8")  # UTF8-ish 文本，仍可试 b64/hex
        except UnicodeDecodeError:
            text = None

    if text is not None:
        compact = re.sub(r"\s+", "", text)
        if compact:
            if _HEX_RE.match(data):
                try:
                    blob = bytes.fromhex(compact)
                    return SniffResult(
                        "HEX",
                        f"Hex 文本（{len(blob)} 字节 解码后）",
                        [blob],
                    )
                except ValueError:
                    pass  # odd 长度等，一律尝试 b64 -- 无则原样回落
            if _B64_RE.match(data) and len(compact) % 4 == 0 and compact:
                try:
                    blob = base64.b64decode(compact, validate=True)
                    if blob:
                        return SniffResult(
                            "BASE64",
                            f"裸 Base64（{len(blob)} 字节 解码后）",
                            [blob],
                        )
                except (binascii.Error, ValueError):
                    pass

    # ---- 4. 原始 DER/BER ------------------------------------------------
    return SniffResult("DER", "DER 二进制", [data])
