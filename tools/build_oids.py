#!/usr/bin/env python3
"""dumpasn1.cfg → 紧凑 JSON OID 库构建脚本。

用法：
    uv run python tools/build_oids.py [dumpasn1.cfg 路径] [-o 输出.json]

- 解析 dumpasn1.cfg（Peter Gutmann，github.com/cryptlib/dumpasn1；
  采用 MIT 授权）：`#` 注释、`OID 名称` 条目、
  缩进续行并入描述；
- 与 asn1peek.core.oid.pki_supplement()（项目内置的 PKI 补充表）合并去重：
  同 dotted 补充表优先；
- 输出紧凑 JSON `src/asn1peek/core/data/oid_dumpasn1.json` 随包发布；
- 不提供 cfg 时仅用补充表构建（并告警，用于离线构建）。
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

_OID_RE = re.compile(r"^\d+(?:\.\d+)+$")


# dumpasn1.cfg 现行格式（cryptlib/dumpasn1，CRLF 行尾）：
#   OID = 2 5 4 3
#   Comment = X.520 DN component
#   Description = commonName
# 兼容旧式单行格式：2.5.4.3<TAB>commonName
# 注意：值里可能含 '#'（如 "PKCS #1"），不能做行内注释剥离。
def parse_dumpasn1_cfg(text: str) -> dict[str, tuple[str, str]]:
    entries: dict[str, tuple[str, str]] = {}
    cur_dotted: str | None = None
    cur_name = ""
    cur_desc = ""

    def flush() -> None:
        nonlocal cur_dotted, cur_name, cur_desc
        if cur_dotted is not None and cur_name:
            entries[cur_dotted] = (cur_name, cur_desc)
        cur_dotted, cur_name, cur_desc = None, "", ""

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue  # 整行注释（Warning 等独立标记行会落入下方忽略分支）

        if "=" in line:
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip()
            if key == "OID":
                flush()
                arcs = value.split()
                if arcs and all(a.isdigit() for a in arcs):
                    cur_dotted = ".".join(arcs)
                continue
            if key == "Comment" and cur_dotted is not None:
                cur_desc = value
                continue
            if key == "Description" and cur_dotted is not None:
                cur_name = value
                continue
            continue  # 其他键值行（含 Warning 之后可能的扩展）忽略

        # 旧式单行格式：dotted + 名称（如 "2.5.4.3<TAB>commonName"）
        first_token = line.split(None, 1)[0]
        if _OID_RE.match(first_token):
            flush()
            rest = line[len(first_token) :].strip().lstrip("=").strip()
            if rest:
                entries[first_token] = (rest, "")

    flush()
    return entries


def build(cfg_path: Path | None) -> tuple[dict[str, tuple[str, str]], int]:
    from asn1peek.core.oid import pki_supplement

    merged: dict[str, tuple[str, str]] = pki_supplement()
    cfg_count = 0
    if cfg_path is not None:
        cfg = parse_dumpasn1_cfg(cfg_path.read_text(encoding="utf-8", errors="replace"))
        cfg_count = len(cfg)
        for dotted, (name, desc) in cfg.items():
            if dotted in merged:  # 补充表优先（去重）
                continue
            merged[dotted] = (name, desc)
    return merged, cfg_count


def main() -> int:
    here = Path(__file__).resolve().parent
    default_out = here.parent / "src" / "asn1peek" / "core" / "data" / "oid_dumpasn1.json"
    parser = argparse.ArgumentParser(description="dumpasn1.cfg → 紧凑 JSON")
    parser.add_argument(
        "cfg", nargs="?", type=Path, default=None, help="dumpasn1.cfg 路径（缺省仅用内置补充表）"
    )
    parser.add_argument("-o", "--out", type=Path, default=default_out)
    args = parser.parse_args()

    if args.cfg is not None and not args.cfg.exists():
        parser.error(f"找不到 cfg 文件：{args.cfg}")

    merged, cfg_count = build(args.cfg)
    if cfg_count == 0:
        print(
            "[warn] 未使用 dumpasn1.cfg，仅由内置补充表构建"
            "（联网获取 cfg 后请重新执行以获得全量库）",
            file=sys.stderr,
        )

    args.out.parent.mkdir(parents=True, exist_ok=True)
    payload = {dotted: [name, desc] for dotted, (name, desc) in sorted(merged.items())}
    args.out.write_text(
        json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    print(f"[ok] {len(merged)} 条 → {args.out}（dumpasn1.cfg 贡献 {cfg_count} 条）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
