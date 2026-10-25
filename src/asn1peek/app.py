"""GUI 应用入口：`asn1peek [file]` 启动，命令行文件参数会直接打开。"""

from __future__ import annotations

import sys

from PySide6.QtWidgets import QApplication

from .ui.main_window import MainWindow


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv if argv is None else argv)
    app = QApplication(args)
    app.setApplicationName("asn1peek")
    app.setOrganizationName("asn1peek")

    window = MainWindow()
    window.show()

    # 命令行携带文件则直接打开
    cli_files = args[1:]
    if cli_files:
        window.open_file(cli_files[0])

    return app.exec()


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
