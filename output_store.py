# /// script
# requires-python = ">=3.11"
# ///
"""output_store —— 远端命令的全文日志落本机，只把「头 + 省略标记 + 尾」回给 Agent。

落本机而不落远端有两层原因：ro 主机上「把输出写到远端文件」本身就是越权写；
rw 主机上则是往别人机器里堆调试垃圾，还得替它做清理。

内存带（_Band）只留头尾两截，全文走文件，所以 max_output_bytes 现在是**落盘单文件上限**，
不再是「能回给 Agent 的字节数」—— 后者由 read_output 的分模式窗口控制。
"""

from __future__ import annotations

import io
import re
import time
from collections import deque
from pathlib import Path

STREAMS = ("out", "err")
MODES = ("head", "tail", "grep", "lines")
RUN_ID_RE = re.compile(r"[0-9a-f]{8,36}")
_MAX_HITS = 200


def _end_at_newline(data: bytes) -> bytes:
    cut = data.rfind(b"\n")
    return data[: cut + 1] if cut >= 0 else data


def _start_at_newline(data: bytes) -> bytes:
    """把窗口对齐到行首：丢掉开头那半行。

    若整窗恰好就是「一条以换行收尾的行」（真机出现过 14 字节的尾巴
    `MCP_TAIL_MARK\\n`），此时 find 到的换行就是最后一个字节，按原写法会把
    整窗当半行丢光 —— 那种情况整窗保留。
    """
    cut = data.find(b"\n")
    if cut < 0 or cut == len(data) - 1:
        return data
    return data[cut + 1 :]


class _Band:
    """一条流的内存带：全文进文件，内存只留头 head_budget 与尾 tail_budget。"""

    def __init__(self, head_budget: int, tail_budget: int) -> None:
        self.head_budget = head_budget
        self.tail_budget = tail_budget
        self.total = 0
        self.lines = 0
        self._full: list[bytes] = []
        self._head = b""
        self._tail: deque[bytes] = deque()
        self._tail_len = 0
        self._clipped = False

    def feed(self, chunk: bytes) -> None:
        self.total += len(chunk)
        self.lines += chunk.count(b"\n")
        if self._clipped:
            self._push_tail(chunk)
            return
        self._full.append(chunk)
        if self.total <= self.head_budget + self.tail_budget:
            return  # 没超预算，整条留在内存里，一次都不用丢
        # 先收进 _full 再定型，否则「单个 chunk 就超预算」（SSH 一次 recv 就是 64KB）
        # 会把这一段头部数据直接丢掉
        blob = b"".join(self._full)
        self._full = []
        self._head = blob[: self.head_budget]
        self._clipped = True
        if len(blob) > self.head_budget:
            self._push_tail(blob[self.head_budget :])

    def _push_tail(self, chunk: bytes) -> None:
        if not chunk:
            # 空 chunk 不带任何数据，却会让 popleft 的"至少留一个"保护失效：
            # 真实尾部被全部驱逐，只剩这个空元素，内联就变成"有头无尾"
            return
        self._tail.append(chunk)
        self._tail_len += len(chunk)
        #  deque 只需兜住「够切出预算内最后一个整行」，2 倍预算足够，且内存有界
        while self._tail_len > 2 * self.tail_budget and len(self._tail) > 1:
            self._tail_len -= len(self._tail.popleft())

    @property
    def clipped(self) -> bool:
        return self._clipped

    def render(self) -> str:
        if not self._clipped:
            return b"".join(self._full).decode("utf-8", "replace")
        head = _end_at_newline(self._head[: self.head_budget])
        tail = _start_at_newline(b"".join(self._tail)[-self.tail_budget :])
        omitted = self.total - len(head) - len(tail)
        omitted_lines = max(0, self.lines - head.count(b"\n") - tail.count(b"\n"))
        # head 以换行收尾时不能再补换行，否则省略标记前会多出一个空行
        sep = "" if head.endswith(b"\n") else "\n"
        mark = f"{sep}... [省略 {omitted} 字节 / {omitted_lines} 行] ...\n".encode()
        return (head + mark + tail).decode("utf-8", "replace")


class Spill:
    """一次执行的落盘句柄 + 两条内存带。文件按需创建，空输出不留空文件。"""

    def __init__(self, root: Path, run_id: str, file_cap: int, budgets: dict[str, tuple[int, int]]) -> None:
        self.run_id = run_id
        self.file_cap = file_cap
        self.root = root
        # 目录在这儿就建：让「写不了」在开跑前就炸出来，而不是拖到第一个 chunk 才失败
        root.mkdir(parents=True, exist_ok=True)
        self._bands = {s: _Band(*budgets[s]) for s in STREAMS}
        self._budgets = budgets
        self._fh: dict[str, io.BufferedWriter] = {}
        self.written = {s: 0 for s in STREAMS}
        self.overflow: set[str] = set()

    def reset(self) -> None:
        """重连重试前抹掉上一次的半截输出，日志只反映真正跑完的那一次。"""
        for stream in STREAMS:
            fh = self._fh.pop(stream, None)
            if fh is not None:
                fh.close()
            self.path(stream).unlink(missing_ok=True)
            self._bands[stream] = _Band(*self._budgets[stream])
            self.written[stream] = 0
        self.overflow.clear()

    def _handle(self, stream: str) -> io.BufferedWriter:
        fh = self._fh.get(stream)
        if fh is None:
            fh = self.path(stream).open("wb")
            self._fh[stream] = fh
        return fh

    def path(self, stream: str) -> Path:
        return self.root / f"{self.run_id}.{stream}.log"

    def write(self, stream: str, chunk: bytes) -> None:
        self._bands[stream].feed(chunk)
        room = self.file_cap - self.written[stream]
        if room <= 0:
            self.overflow.add(stream)
            return
        if len(chunk) > room:
            chunk = chunk[:room]
            self.overflow.add(stream)
        self._handle(stream).write(chunk)
        self.written[stream] += len(chunk)

    def inline(self, stream: str) -> str:
        return self._bands[stream].render()

    def close(self) -> None:
        for fh in self._fh.values():
            fh.close()  # type: ignore[union-attr]

    @property
    def clipped(self) -> bool:
        return any(b.clipped for b in self._bands.values())

    def stats(self) -> dict:
        return {
            s: {"bytes": self._bands[s].total, "lines": self._bands[s].lines, "overflow": s in self.overflow}
            for s in STREAMS
        }


def prune(root: Path, keep_runs: int, keep_bytes: int, keep_days: int) -> int:
    """按 run 分组删：mtime 新到旧排，条数 / 总量 / 超龄 三个预算任一命中就删掉整组。"""
    if not root.is_dir():
        return 0
    groups: dict[str, list[Path]] = {}
    for entry in root.iterdir():
        if entry.suffix != ".log":
            continue
        groups.setdefault(entry.name.split(".")[0], []).append(entry)
    cutoff = time.time() - keep_days * 86400
    ordered = sorted(groups.items(), key=lambda kv: max(f.stat().st_mtime for f in kv[1]), reverse=True)
    removed = kept_bytes = 0
    for rank, (_, files) in enumerate(ordered):
        size = sum(f.stat().st_size for f in files)
        expired = min(f.stat().st_mtime for f in files) < cutoff
        if rank >= keep_runs or kept_bytes + size > keep_bytes or expired:
            for handle in files:
                handle.unlink(missing_ok=True)
            removed += 1
        else:
            kept_bytes += size
    return removed


def read_output(
    root: Path,
    run_id: str,
    stream: str = "out",
    mode: str = "tail",
    start: int = 1,
    end: int = 0,
    pattern: str = "",
    limit: int = 16384,
) -> dict:
    """按引用回捞全文。run_id 必须是十六进制串 —— 它直接拼进文件路径。"""
    if not _valid_run_id(run_id):
        raise ValueError(f"run_id 形态非法：{run_id!r}")
    if stream not in STREAMS:
        raise ValueError(f"stream 只能是 {STREAMS}，收到 {stream!r}")
    if mode not in MODES:
        raise ValueError(f"mode 只能是 {MODES}，收到 {mode!r}")
    path = root / f"{run_id}.{stream}.log"
    if not path.is_file():
        return {"run_id": run_id, "stream": stream, "mode": mode, "found": False, "hint": "该 run 没有落盘文件（可能已被轮转清理）"}
    size = path.stat().st_size
    total_lines = _count_lines(path)
    body, matched, truncated = _slice(path, mode, start, end, pattern, limit)
    return {
        "run_id": run_id,
        "stream": stream,
        "mode": mode,
        "found": True,
        "bytes_total": size,
        "lines_total": total_lines,
        "matched": matched,
        "truncated": truncated,
        "text": body,
    }


def _valid_run_id(run_id: str) -> bool:
    return bool(RUN_ID_RE.fullmatch(run_id or ""))


def _count_lines(path: Path) -> int:
    """换行数；末行没有换行符也要算一行。空文件算 0 行。"""
    count = 0
    last = b"\n"
    with path.open("rb") as fh:
        while chunk := fh.read(1 << 16):
            count += chunk.count(b"\n")
            last = chunk[-1:]
    return count + (1 if last != b"\n" else 0)


def _slice(path: Path, mode: str, start: int, end: int, pattern: str, limit: int) -> tuple[str, int, bool]:
    """返回（正文, 命中行数, 是否因 limit 被截）。"""
    size = path.stat().st_size
    if mode == "head":
        with path.open("rb") as fh:
            raw = fh.read(min(size, limit))
        return _end_at_newline(raw).decode("utf-8", "replace"), 0, size > limit
    if mode == "tail":
        with path.open("rb") as fh:
            if size > limit:
                fh.seek(size - limit)
                raw = _start_at_newline(fh.read(limit))
            else:
                raw = fh.read(size)
        return raw.decode("utf-8", "replace"), 0, size > limit
    if mode == "grep":
        return _grep(path, pattern, limit)
    return _lines(path, start, end or start + 200, limit)


def _grep(path: Path, pattern: str, limit: int) -> tuple[str, int, bool]:
    hits: list[str] = []
    used = matched = 0
    truncated = False
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for number, line in enumerate(fh, 1):
            if pattern not in line:
                continue
            matched += 1
            row = f"{number}: {line.rstrip()}\n"
            if used + len(row.encode("utf-8")) > limit or len(hits) >= _MAX_HITS:
                truncated = True
                break
            hits.append(row)
            used += len(row.encode("utf-8"))
    return "".join(hits), matched, truncated


def _lines(path: Path, start: int, end: int, limit: int) -> tuple[str, int, bool]:
    picked: list[str] = []
    used = 0
    truncated = False
    start = max(1, start)
    end = max(start, end)
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for number, line in enumerate(fh, 1):
            if number > end:
                break
            if number < start:
                continue
            row = f"{number}: {line}" if line.endswith("\n") else f"{number}: {line}\n"
            if used + len(row.encode("utf-8")) > limit:
                truncated = True
                break
            picked.append(row)
            used += len(row.encode("utf-8"))
    return "".join(picked), len(picked), truncated
