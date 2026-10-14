# /// script
# requires-python = ">=3.11"
# ///
"""分片续传与写目标清单的离线用例：裸 python，不装 paramiko 也不碰网络。

    python test_ssh_xfer.py
"""

from __future__ import annotations

import hashlib
import os
import time
import unittest
from pathlib import Path
import tempfile

import ssh_guard as G
import ssh_xfer as X


class FakeHandle:
    # 对齐 paramiko：类常量、实例可覆盖（ssh_xfer 会在打开后覆盖它）
    MAX_REQUEST_SIZE = 32768

    def __init__(self, buf: bytearray, mode: str, owner: "FakeSFTP | None" = None):
        self.buf = buf
        self.mode = mode
        self.pos = 0
        self.pipelined = False
        self.owner = owner

    def set_pipelined(self, val=True):
        self.pipelined = val

    def prefetch(self, file_size=None):
        self.prefetched = True
        self.prefetch_size = file_size

    def flush(self):
        if self.owner is not None:
            self.owner.flushes += 1

    def seek(self, n):
        self.pos = n

    def read(self, n=-1):
        out = self.buf[self.pos : self.pos + (n if n > 0 else len(self.buf))]
        self.pos += len(out)
        return out

    def write(self, data):
        end = self.pos + len(data)
        if end > len(self.buf):
            self.buf.extend(b"\0" * (end - len(self.buf)))
        self.buf[self.pos : end] = data
        self.pos = end

    def truncate(self, size):
        del self.buf[size:]

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class FakeSFTP:
    """只实现 ssh_xfer 用到的那几个方法，多一个都不给。"""

    def __init__(self):
        self.files: dict[str, bytearray] = {}
        self.flushes = 0

    def stat(self, path):
        if path not in self.files:
            raise IOError("No such file")
        buf = self.files[path]
        return type("S", (), {"st_size": len(buf)})()

    def file(self, path, mode="r", bufsize=-1):
        buf = self.files.setdefault(path, bytearray())
        if "w" in mode:
            buf.clear()
        return FakeHandle(buf, mode, self)

    def open(self, path, mode="rb"):
        if path not in self.files:
            raise IOError("No such file")
        return FakeHandle(self.files[path], mode, self)

    def remove(self, path):
        self.files.pop(path, None)

    def rename(self, old, new):
        if new in self.files:
            raise IOError("Failure")          # 照抄 openssh：目标存在就失败
        self.files[new] = self.files.pop(old)

    def posix_rename(self, old, new):
        self.files[new] = self.files.pop(old)


CH = 1024


class ResumeMath(unittest.TestCase):
    def test_partial_chunk_is_cut_off(self):
        # 中断时正在写的那半片不可信：截到整片边界，从该片重来
        self.assertEqual(X.resume_from(3 * CH + 7, CH), (3, 3 * CH))
        self.assertEqual(X.resume_from(0, CH), (0, 0))
        self.assertEqual(X.resume_from(4 * CH, CH), (4, 4 * CH))


class PushPull(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="xfer-test-"))
        self.data = os.urandom(10 * CH + 5)
        self.local = self.tmp / "src.bin"
        self.local.write_bytes(self.data)
        self.md5 = hashlib.md5(self.data).hexdigest()
        self.sftp = FakeSFTP()

    def test_push_then_full_md5_matches(self):
        tr = X.push(self.sftp, str(self.local), "/r/part", chunk=CH)
        self.assertEqual(bytes(self.sftp.files["/r/part"]), self.data)
        self.assertEqual(tr.bytes, len(self.data))
        self.assertEqual(tr.chunks, 11)
        self.assertEqual(tr.resumed_from, 0)

    def test_push_resumes_from_the_interrupted_chunk(self):
        part = "/r/part"
        try:
            X.push(self.sftp, str(self.local), part, chunk=CH, deadline=time.monotonic() + 0.0001)
            # 小 deadline 不一定能在写满前退出，这里显式造一个"只写了 4 片"的中断现场
        except X.TransferAborted:
            pass
        self.sftp.files[part] = bytearray(self.data[: 4 * CH + 11])  # 4 整片 + 半片
        before = len(self.sftp.files[part])
        tr = X.push(self.sftp, str(self.local), part, chunk=CH)
        self.assertEqual(tr.resumed_from, 4 * CH, "半片被截掉，从第 4 片重来")
        self.assertLess(tr.bytes, before + len(self.data), "没把前 4 片重传")
        self.assertEqual(bytes(self.sftp.files[part]), self.data)
        self.assertEqual(hashlib.md5(bytes(self.sftp.files[part])).hexdigest(), self.md5)

    def test_pull_resumes_symmetrically(self):
        self.sftp.files["/r/big.bin"] = bytearray(self.data)
        part = str(self.tmp / "dst.sshmcp-part")
        Path(part).write_bytes(self.data[: 6 * CH])
        tr = X.pull(self.sftp, "/r/big.bin", part, chunk=CH)
        self.assertEqual(tr.resumed_from, 6 * CH)
        self.assertEqual(Path(part).read_bytes(), self.data)

    def test_over_limit_aborts_before_writing(self):
        with self.assertRaises(X.TransferAborted):
            X.push(self.sftp, str(self.local), "/r/part", chunk=CH, total_limit=10)
        self.assertNotIn("/r/part", self.sftp.files)

    def test_deadline_keeps_the_part_for_resume(self):
        part = "/r/part"
        with self.assertRaises(X.TransferAborted):
            X.push(self.sftp, str(self.local), part, chunk=CH, deadline=time.monotonic() - 1)
        # part 可能没建（第一片前就超时），也可能留了半截：两种都算可续
        self.assertTrue(X.resume_from(len(self.sftp.files.get(part, b"")), CH)[0] <= 10)

    def test_pipelined_is_turned_on(self):
        seen = {}
        real_file = self.sftp.file

        def spy(path, mode="r", bufsize=-1):
            h = real_file(path, mode, bufsize)
            orig = h.set_pipelined
            h.set_pipelined = lambda v=True: (seen.setdefault("pipelined", v), orig(v))[0]
            return h

        self.sftp.file = spy
        X.push(self.sftp, str(self.local), "/r/part", chunk=CH)
        self.assertTrue(seen.get("pipelined"), "不开 pipelined 实测慢一半（5.2 vs 10.1 MB/s）")

    def test_request_size_is_raised_on_push(self):
        """32KB 请求同场配对实测慢一档（15/16、中位 +5%）：push 打开的句柄必须放大单条请求。"""
        captured = []
        real_file = self.sftp.file

        def spy(path, mode="r", bufsize=-1):
            h = real_file(path, mode, bufsize)
            captured.append(h)
            return h

        self.sftp.file = spy
        X.push(self.sftp, str(self.local), "/r/part", chunk=CH)
        self.assertEqual(captured[-1].MAX_REQUEST_SIZE, X.REQUEST_SIZE)

    def test_request_size_is_raised_on_pull(self):
        """方向对称：pull 的远端句柄同样放大，否则下载仍是 32KB 一停。"""
        self.sftp.files["/r/big.bin"] = bytearray(self.data)
        captured = []
        real_open = self.sftp.open

        def spy(path, mode="rb"):
            h = real_open(path, mode)
            captured.append(h)
            return h

        self.sftp.open = spy
        X.pull(self.sftp, "/r/big.bin", str(self.tmp / "dst.bin"), chunk=CH)
        self.assertEqual(captured[-1].MAX_REQUEST_SIZE, X.REQUEST_SIZE)

    def test_fresh_pull_also_prefetches(self):
        """全新下载也要预取（实测 256MiB：4.5 → 36.7 MiB/s）；传整文件大小，避免内部 stat。"""
        self.sftp.files["/r/big.bin"] = bytearray(self.data)
        captured = []
        real_open = self.sftp.open

        def spy(path, mode="rb"):
            h = real_open(path, mode)
            captured.append(h)
            return h

        self.sftp.open = spy
        X.pull(self.sftp, "/r/big.bin", str(self.tmp / "dst.bin"), chunk=CH)
        self.assertTrue(getattr(captured[-1], "prefetched", False), "全新下载没走预取")
        self.assertEqual(captured[-1].prefetch_size, len(self.data), "预取要给到整文件大小")

    def test_stale_part_larger_than_source_is_discarded(self):
        """源文件被重新生成过（变小了）：旧 part 前缀已不对应任何有效状态，必须从头来，
        不能把"比整个文件还长"的旧字节当已传部分。"""
        part = "/r/stale.part"
        self.sftp.files[part] = bytearray(b"\xff" * (30 * CH))
        small = self.tmp / "small.bin"
        small.write_bytes(b"brand new" * 100)
        tr = X.push(self.sftp, str(small), part, chunk=CH)
        self.assertEqual(tr.resumed_from, 0)
        self.assertEqual(bytes(self.sftp.files[part]), small.read_bytes())

    def test_stale_local_part_larger_than_remote_is_discarded(self):
        self.sftp.files["/r/small.bin"] = bytearray(b"tiny" * 10)
        part = self.tmp / "dst.sshmcp-part"
        part.write_bytes(b"\xff" * (9 * CH))
        tr = X.pull(self.sftp, "/r/small.bin", str(part), chunk=CH)
        self.assertEqual(tr.resumed_from, 0)
        self.assertEqual(part.read_bytes(), b"tiny" * 10)

    def test_every_chunk_is_flushed(self):
        """逐片 flush 是续传状态确定的前提：异步入队的写在异常后会继续落盘，part 字节数会漂移。"""
        X.push(self.sftp, str(self.local), "/r/part", chunk=CH)
        self.assertGreaterEqual(self.sftp.flushes, 11, "11 片就该至少 flush 11 次")


class WriteTargetGuard(unittest.TestCase):
    """SFTP 的写不经过命令串，必须由传输自己走同一份敏感名单。"""

    def test_sensitive_targets_blocked(self):
        for p in ("/home/qy/.ssh/authorized_keys", "~/.ssh/authorized_keys", "/etc/ssh/sshd_config",
                  "/etc/sudoers", "x/fstab"):
            hit = G.check_write_target(p)
            self.assertIsNotNone(hit, f"应当拦下：{p}")
            self.assertIn("写入敏感文件", hit.rule)

    def test_ordinary_targets_pass(self):
        for p in ("/tmp/build.log", "/home/qy/app/config.yaml", "/var/tmp/x.part", "/home/qy/report.pdf"):
            self.assertIsNone(G.check_write_target(p), f"不该拦：{p}")

    def test_root_spellings_normalized(self):
        self.assertIsNotNone(G.check_write_target("/etc/../etc/ssh/sshd_config"))


class PartNaming(unittest.TestCase):
    def test_part_name_is_deterministic(self):
        # 续传的前提：同一个目标每次算出同一个 part 名
        self.assertEqual(X.part_path_for("/r/x.bin"), X.part_path_for("/r/x.bin"))
        self.assertTrue(X.part_path_for("/r/x.bin").endswith(X.PART_SUFFIX))

    def test_md5_of_file_roundtrips(self):
        tmp = Path(tempfile.mkdtemp(prefix="xfer-md5-")) / "a.bin"
        tmp.write_bytes(self_bytes := os.urandom(3 * CH))
        self.assertEqual(X.md5_of_file(str(tmp), chunk=CH), hashlib.md5(self_bytes).hexdigest())


class UnknownSizePull(unittest.TestCase):
    """st_size 不可信的两类现场：/proc 报 0（现在按长度未知读到 EOF）、/sys 报 4096 实际更短。"""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="xfer-unknown-"))
        self.sftp = FakeSFTP()

    def _force_stat(self, path: str, size: int):
        real = self.sftp.stat

        def stat(p):
            return type("S", (), {"st_size": size})() if p == path else real(p)

        self.sftp.stat = stat

    def test_zero_size_streams_to_eof(self):
        content = b"processor : 0\nmodel name : x\n" * 40
        self.sftp.files["/r/proc"] = bytearray(content)
        self._force_stat("/r/proc", 0)
        part = self.tmp / "dst.sshmcp-part"
        tr = X.pull(self.sftp, "/r/proc", str(part), chunk=CH)
        self.assertEqual(part.read_bytes(), content, "0 字节的伪文件要按 EOF 读全，不是落 0 字节")
        self.assertEqual(tr.bytes, len(content))
        self.assertEqual(tr.resumed_from, 0)

    def test_zero_size_discards_stale_part(self):
        self.sftp.files["/r/proc"] = bytearray(b"new content")
        self._force_stat("/r/proc", 0)
        part = self.tmp / "dst.sshmcp-part"
        part.write_bytes(b"\xff" * (3 * CH))
        tr = X.pull(self.sftp, "/r/proc", str(part), chunk=CH)
        self.assertEqual(tr.resumed_from, 0, "长度未知就不续传")
        self.assertEqual(part.read_bytes(), b"new content")

    def test_zero_size_still_respects_total_limit(self):
        self.sftp.files["/r/proc"] = bytearray(b"\x00" * (4 * CH))
        self._force_stat("/r/proc", 0)
        part = self.tmp / "p.part"
        with self.assertRaises(X.TransferAborted):
            X.pull(self.sftp, "/r/proc", str(part), chunk=CH, total_limit=2 * CH + 5)
        self.assertLessEqual(len(part.read_bytes()), 2 * CH + 5, "上限按已写字节判")

    def test_stat_larger_than_content_reports_actual_bytes(self):
        """100 上实测：/sys 报 4096、内容 18 字节 —— bytes/chunks 必须是实际落盘量。"""
        content = b"00:00:00:00:00:00\n"
        self.sftp.files["/sys/x"] = bytearray(content)
        self._force_stat("/sys/x", 4096)
        part = self.tmp / "sys.part"
        tr = X.pull(self.sftp, "/sys/x", str(part), chunk=CH)
        self.assertEqual(tr.bytes, len(content))
        self.assertEqual(tr.chunks, 1)
        self.assertEqual(part.read_bytes(), content)


if __name__ == "__main__":
    unittest.main(verbosity=2)
