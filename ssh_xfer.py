"""分片传输：断点续传 + md5 校验，纯 stdlib + 传入的 sftp 对象（便于离线测）。

为什么按片而不是字节续传（用户定的形态，实测支撑）：
  - paramiko 的 `put`/`get` 没有 offset 参数（签名实测：put(localpath, remotepath,
    callback, confirm)），续传只能自己用 `sftp.file()` + seek 拼。
  - 但 `sftp.file()` 的写法要挑：整块写 2.8 MB/s、8MB 分片 4.0、非 pipelined 5.2、
    pipelined 不逐片 flush 5.9 —— 只有 **pipelined + 每片 flush** 才拿到 10.1 MB/s，
    与 `sftp.put` 持平。逐片 flush 不是代价，是既快又让 part 状态确定的唯一组合。

part 文件路径由 (方向, 源, 目标) 定名且不带随机后缀 —— 这是"下次调用能接着传"的前提。
"""

from __future__ import annotations

import hashlib
import os
import time
from dataclasses import dataclass

# 1MB：实测与 sftp.put 同速的最优分片，同时给续传足够细的粒度
DEFAULT_CHUNK = 1024 * 1024
PART_SUFFIX = ".sshmcp-part"


@dataclass
class Transfer:
    bytes: int
    chunks: int
    resumed_from: int
    seconds: float
    timed_out: bool = False
    cancelled: bool = False

    @property
    def rate(self) -> float:
        return self.bytes / self.seconds / 1e6 if self.seconds else 0.0


class TransferAborted(Exception):
    """超过 deadline 或撞上大小上限：part 保留，下次从该片重来。"""


def part_path_for(target: str) -> str:
    return f"{target}{PART_SUFFIX}"


def resume_from(part_size: int, chunk: int) -> tuple[int, int]:
    """part 已有字节数 -> (要写的第一片下标, 应截断到的偏移)。

    只信任"整片写完"的部分：末尾若有半片（中断时正在写），把它砍掉重来。
    片内不连续的情况由最终的整文件 md5 兜住，不在这里做逐片校验。
    """
    idx = part_size // chunk
    return idx, idx * chunk


def md5_of_file(path: str, chunk: int = DEFAULT_CHUNK, deadline: float | None = None) -> str:
    h = hashlib.md5()
    with open(path, "rb") as fh:
        for block in _read_blocks(fh, chunk, deadline):
            h.update(block)
    return h.hexdigest()


def _read_blocks(fh, chunk: int, deadline: float | None):
    while True:
        if deadline is not None and time.monotonic() >= deadline:
            raise TransferAborted("读取超时")
        block = fh.read(chunk)
        if not block:
            return
        yield block


def _write_blocks(fh, src, chunk: int, deadline: float | None, total: int, sent_cb=None):
    """逐片写并逐片 flush。

    为什么不"只 flush 收尾"：pipelined 写是异步入队的，中途抛异常或提前关通道时，
    已入队的写还会继续落服务端 —— 于是 part 的实际字节数在我们读完之后还会漂移，
    续传点就建立在假状态上（100 上实测：中断时 12MB，下次看变成 60MB）。
    每片 flush 实测同样 10.1 MB/s（不 flush 反而只有 5.9），既确定又不亏速度。
    """
    sent = 0
    while sent < total:
        if deadline is not None and time.monotonic() >= deadline:
            raise TransferAborted("传输超时")
        block = src.read(min(chunk, total - sent))
        if not block:
            break
        fh.write(block)
        fh.flush()
        sent += len(block)
        if sent_cb:
            sent_cb(sent)
    return sent


def push(sftp, local: str, part: str, *, chunk: int = DEFAULT_CHUNK, deadline: float | None = None,
         total_limit: int | None = None) -> Transfer:
    """本机 -> 远端 part。已存在的 part 按整片截断后从缺口继续。"""
    size = os.path.getsize(local)
    if total_limit is not None and size > total_limit:
        raise TransferAborted(f"文件 {size} 字节超过上限 {total_limit}")

    have = _remote_size(sftp, part)
    _, base = resume_from(have, chunk)
    if have > base:
        _truncate_remote(sftp, part, base)

    start = time.monotonic()
    mode = "ab" if base else "wb"
    with open(local, "rb") as src, sftp.file(part, mode) as fh:
        if hasattr(fh, "set_pipelined"):
            fh.set_pipelined(True)
        fh.seek(base)
        src.seek(base)
        sent = _write_blocks(fh, src, chunk, deadline, size - base)
    return Transfer(
        bytes=size,
        chunks=(size + chunk - 1) // chunk,
        resumed_from=base,
        seconds=time.monotonic() - start,
    )


def pull(sftp, remote: str, part: str, *, chunk: int = DEFAULT_CHUNK, deadline: float | None = None,
         total_limit: int | None = None) -> Transfer:
    """远端 -> 本机 part。方向相反，续传逻辑对称。"""
    size = sftp.stat(remote).st_size
    if total_limit is not None and size > total_limit:
        raise TransferAborted(f"远端文件 {size} 字节超过上限 {total_limit}")

    have = _local_size(part)
    _, base = resume_from(have, chunk)
    if have > base:
        with open(part, "r+b") as fh:
            fh.truncate(base)

    start = time.monotonic()
    with open(part, "ab" if base else "wb") as dst, sftp.open(remote, "rb") as src:
        # 先定位再预取：续传点之后的区间才是我们要的，先 prefetch 会预读已拥有的那一段
        src.seek(base)
        src.prefetch()
        _write_blocks(dst, src, chunk, deadline, size - base)
    return Transfer(
        bytes=size,
        chunks=(size + chunk - 1) // chunk,
        resumed_from=base,
        seconds=time.monotonic() - start,
    )


def _remote_size(sftp, path: str) -> int:
    try:
        return sftp.stat(path).st_size
    except IOError:
        return 0


def _local_size(path: str) -> int:
    return os.path.getsize(path) if os.path.exists(path) else 0


def _truncate_remote(sftp, path: str, size: int) -> None:
    with sftp.file(path, "r+b") as fh:
        fh.truncate(size)
