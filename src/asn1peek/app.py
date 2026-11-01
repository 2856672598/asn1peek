"""GUI 应用入口：`asn1peek [file]` 启动，命令行文件参数会直接打开。

另提供两个供打包产物自检的开关（在创建 QApplication 之前处理，无需显示环境）：

- ``--version``：打印版本号后退出。
- ``--smoke-test <file>``：打开文件后自动退出，用于 AppImage / deb 的产物级冒烟。
"""

from __future__ import annotations

import sys

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication

from . import __version__
from .ui.main_window import MainWindow


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv if argv is None else argv)

    if "--version" in args:
        print(__version__)
        return 0

    smoke_file: str | None = None
    if "--smoke-test" in args:
        idx = args.index("--smoke-test")
        if idx + 1 >= len(args):
            print("用法：asn1peek --smoke-test <文件>", file=sys.stderr)
            return 2
        smoke_file = args[idx + 1]
        del args[idx : idx + 2]

    app = QApplication(args)
    app.setApplicationName("asn1peek")
    app.setOrganizationName("asn1peek")

    window = MainWindow()
    window.show()

    if smoke_file is not None:
        window.open_file(smoke_file)
        QTimer.singleShot(200, app.quit)
        return app.exec()

    # 命令行携带文件则直接打开
    cli_files = args[1:]
    if cli_files:
        window.open_file(cli_files[0])

    return app.exec()


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
