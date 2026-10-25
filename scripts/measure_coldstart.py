#!/usr/bin/env python3
"""冷启动计时（无显示器/无 root 环境可用）。

测量：进程启动（Popen 前夕为 t0，含数毫秒 fork/exec 偏差）至
- 首次打开 samples/leaf.der（inotify IN_OPEN/IN_ACCESS；≈ 窗口已构造、文件已解析）；
- AppImage 额外统计应用进程（comm==asn1peek）首次出现的时刻，用于估算打包链开销。

说明：AppImage 不能用 strace 测（fusermount 的 setuid 在 ptrace 下失效，
挂载会被内核拒绝）；本脚本用 inotify + /proc 轮询，对三种形态均可用。
每条命令 3 次取中位数；页缓存热态（无 root 无法 drop_caches）。

用法：
    .venv/bin/python scripts/measure_coldstart.py
"""

from __future__ import annotations

import ctypes
import os
import signal
import statistics
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "samples" / "leaf.der"
IN_OPEN = 0x00000020
IN_ACCESS = 0x00000001

libc = ctypes.CDLL("libc.so.6", use_errno=True)


def discover_commands() -> dict[str, list[str]]:
    cmds: dict[str, list[str]] = {}
    cmds["venv 模块 (python -m asn1peek)"] = [sys.executable, "-m", "asn1peek"]
    onedir = ROOT / "build" / "pyinstaller" / "asn1peek" / "asn1peek"
    if onedir.exists():
        cmds["PyInstaller onedir 二进制"] = [str(onedir)]
    appimages = sorted((ROOT / "dist").glob("*.AppImage"))
    if appimages:
        cmds[f"AppImage ({appimages[0].name})"] = [str(appimages[0])]
    return cmds


def _sniff_inner(comm_wanted: str, stop: threading.Event, result: dict) -> None:
    """轮询 /proc/*/comm，记录运行期新建进程中首个 comm == comm_wanted 的时刻。"""
    baseline = {p for p in os.listdir("/proc") if p.isdigit()}
    while not stop.is_set():
        try:
            for pid in os.listdir("/proc"):
                if not pid.isdigit() or pid in baseline:
                    continue
                try:
                    with open(f"/proc/{pid}/comm") as fh:
                        if fh.read().strip() == comm_wanted:
                            if "t" not in result:
                                result["t"] = time.monotonic()
                            return
                except OSError:
                    pass
        except OSError:
            pass
        time.sleep(0.001)


def run_once(cmd: list[str], timeout: float = 8.0) -> dict:
    ifd = libc.inotify_init1(os.O_NONBLOCK)
    if libc.inotify_add_watch(ifd, str(SAMPLE).encode(), IN_OPEN | IN_ACCESS) < 0:
        raise OSError("inotify_add_watch 失败")
    opened: dict = {"t": None}
    stop = threading.Event()

    def watcher() -> None:
        while not stop.is_set() and opened["t"] is None:
            try:
                data = os.read(ifd, 4096)
            except BlockingIOError:
                time.sleep(0.0005)
                continue
            if data:
                opened["t"] = time.monotonic()
                return

    inner: dict = {}
    threads = [
        threading.Thread(target=watcher, daemon=True),
        threading.Thread(target=_sniff_inner, args=("asn1peek", stop, inner), daemon=True),
    ]
    for th in threads:
        th.start()

    env = dict(os.environ, QT_QPA_PLATFORM="offscreen")
    t0 = time.monotonic()
    proc = subprocess.Popen(
        cmd + [str(SAMPLE)],
        cwd=str(ROOT),
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    deadline = t0 + timeout
    while time.monotonic() < deadline and opened["t"] is None:
        if proc.poll() is not None:
            break
        time.sleep(0.002)
    t_open = opened["t"]
    time.sleep(0.4)  # 宽限：给 /proc 轮询捕获内部进程留时间；不影响已记时间点
    t_inner = inner.get("t")

    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait(timeout=3)
    stop.set()
    os.close(ifd)
    for th in threads:
        th.join(timeout=1)
    return {
        "inner_ms": None if t_inner is None else (t_inner - t0) * 1000,
        "open_ms": None if t_open is None else (t_open - t0) * 1000,
        "exit": proc.returncode,
    }


def main() -> int:
    if not SAMPLE.exists():
        print(f"缺少样例 {SAMPLE}", file=sys.stderr)
        return 2
    for label, cmd in discover_commands().items():
        runs = [run_once(cmd) for _ in range(3)]
        opens = [r["open_ms"] for r in runs if r["open_ms"] is not None]
        inners = [r["inner_ms"] for r in runs if r["inner_ms"] is not None]
        print(f"[{label}]")
        for r in runs:
            inner_s = "-" if r["inner_ms"] is None else f"{round(r['inner_ms'])}ms"
            open_s = "-" if r["open_ms"] is None else f"{round(r['open_ms'])}ms"
            print(f"  inner={inner_s:>7} open={open_s:>7} exit={r['exit']}")
        if opens:
            med_open = round(statistics.median(opens))
            med_inner = "-" if not inners else f"{round(statistics.median(inners))}ms"
            print(f"  → 中位数: 打包链开销 {med_inner}, 至样例已打开/解析 {med_open}ms")
    return 0


if __name__ == "__main__":
    sys.exit(main())
