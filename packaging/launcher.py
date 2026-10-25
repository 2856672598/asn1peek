"""PyInstaller 打包入口。

`src/asn1peek/app.py` 内含相对导入（`from .ui.main_window import ...`），
被 PyInstaller 作为顶层 `__main__` 脚本执行时会直接 ImportError；本文件
以绝对导入方式在包上下文中引导 `asn1peek.app.main`，仅供打包使用。

源码运行仍用 `asn1peek` 命令或 `python -m asn1peek`。
"""

from __future__ import annotations

from asn1peek.app import main

if __name__ == "__main__":
    raise SystemExit(main())
