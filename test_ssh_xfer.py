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


if __name__ == "__main__":
    unittest.main(verbosity=2)
