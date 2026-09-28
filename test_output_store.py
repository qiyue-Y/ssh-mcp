# /// script
# requires-python = ">=3.11"
# ///
"""output_store 离线验收：行边界头尾、落盘上限、轮转、按引用回捞、路径穿越。

    python test_output_store.py      # 纯 stdlib，不碰网络也不碰 paramiko
"""

from __future__ import annotations

import os
import tempfile
import time
import unittest
from pathlib import Path

import output_store as OS

ROOT = Path(tempfile.mkdtemp(prefix="ssh-mcp-output-test-"))
RUN = "0f1e2d3c4b5a6978"  # 32 位以外的合法十六进制串也行，fullmatch 只看形态


def make(run_id: str = RUN, file_cap: int = 1 << 20, head: int = 4096, tail: int = 4096, err_head: int = 1024, err_tail: int = 2048) -> OS.Spill:
    return OS.Spill(ROOT, run_id, file_cap, {"out": (head, tail), "err": (err_head, err_tail)})


def feed_lines(spill: OS.Spill, count: int, template: str = "line-{n:06d}-" + "x" * 40) -> tuple[int, bytes]:
    total = 0
    last = b""
    for n in range(1, count + 1):
        chunk = f"{template.format(n=n)}\n".encode()
        spill.write("out", chunk)
        total += len(chunk)
        last = chunk
    return total, last


class InlineBand(unittest.TestCase):
    def test_small_output_passes_through_untouched(self):
        spill = make()
        feed_lines(spill, 5)
        spill.close()
        text = spill.inline("out")
        self.assertFalse(spill.clipped)
        self.assertIn("line-000001", text)
        self.assertIn("line-000005", text)
        self.assertNotIn("省略", text)

    def test_large_output_keeps_both_ends_on_line_boundaries(self):
        spill = make(head=2048, tail=2048)
        total, last_line = feed_lines(spill, 5000)
        spill.close()
        text = spill.inline("out")
        self.assertTrue(spill.clipped)
        self.assertIn("省略", text)
        self.assertIn("line-000001", text, "头部丢了")
        self.assertIn(last_line.decode().strip(), text, "尾部丢了 —— 编译报错就在这一带")
        # 头尾都必须在整行边界上：不允许出现被腰斩的半行
        for row in text.splitlines():
            if row.startswith("... [") or row.startswith("line-"):
                continue
            self.fail(f"出现非整行碎片：{row!r}")

    def test_marker_does_not_introduce_a_blank_line(self):
        spill = make(head=256, tail=256)
        feed_lines(spill, 800)
        spill.close()
        rows = spill.inline("out").splitlines()
        self.assertNotIn("", rows, "head 以换行收尾时，省略标记前不该再多出一个空行")

    def test_inline_size_is_bounded_by_budget_not_by_chunking(self):
        """内联长度只该由 head+tail 预算决定。曾有 64KB 的「对齐余量」把它撑到 73KB。"""
        spill = make(head=2048, tail=2048)
        feed_lines(spill, 20000, template="row-{n:06d}-" + "y" * 60)
        spill.close()
        size = len(spill.inline("out").encode())
        self.assertLess(size, 2048 + 2048 + 200, f"内联 {size} 字节，超出预算太多")

    def test_single_chunk_larger_than_budget_keeps_both_ends(self):
        """SSH 一次 recv 就是 64KB：首块就跨过预算时头尾都得保住。

        这条是真机跑出来的回归 —— 早先用 _head 的真值当「是否进入环形」的标志，
        首块超预算时 _head 恰好定型成空串，整段输出直接丢光且 truncated=False。
        """
        spill = make(head=4096, tail=4096)
        blob = b"".join(f"row-{n:06d}\n".encode() for n in range(1, 60000))
        spill.write("out", blob)  # 一次性喂 ~450KB
        spill.close()
        text = spill.inline("out")
        self.assertTrue(spill.clipped)
        self.assertIn("row-000001", text, "头部丢了")
        self.assertIn("row-059999", text, "尾部丢了")
        self.assertNotIn("", text.splitlines(), "省略标记前后不该出现空行")
        self.assertLess(len(text.encode()), 4096 + 4096 + 200)

    def test_no_double_print_when_band_fits(self):
        """刚好卡在预算线上时，全文只在 full 缓冲里存一份，不能头尾各印一遍。"""
        spill = make(head=100, tail=100)
        payload = b"abcdefgh\n" * 12  # 108 字节，超了 head+tail=200 以内
        spill.write("out", payload)
        spill.close()
        self.assertFalse(spill.clipped)
        self.assertEqual(spill.inline("out").count("abcdefgh"), 12)

    def test_multibyte_not_cut_mid_character(self):
        spill = make(head=50, tail=50)
        for n in range(200):
            spill.write("out", f"第{n}行：中文输出测试\n".encode())
        spill.close()
        text = spill.inline("out")
        self.assertNotIn("\ufffd", text, "按字节切会把多字节字符切出替换符")

    def test_stats_report_bytes_and_lines_per_stream(self):
        spill = make()
        spill.write("out", b"a\nb\n")
        spill.write("err", b"boom\n")
        spill.close()
        stats = spill.stats()
        self.assertEqual((stats["out"]["bytes"], stats["out"]["lines"]), (4, 2))
        self.assertEqual((stats["err"]["bytes"], stats["err"]["lines"]), (5, 1))


class FileCap(unittest.TestCase):
    def test_reset_clears_band_and_file_for_the_retry(self):
        """断线重连会重跑一次命令，日志只该留最后那次 —— 否则全文是双份。"""
        rid = "5e5a5b5c5d5e5f60"
        spill = make(run_id=rid)
        feed_lines(spill, 300)
        spill.write("out", b"FIRST ATTEMPT TAIL\n")
        spill.reset()
        self.assertFalse((ROOT / f"{rid}.out.log").exists())
        self.assertEqual(spill.inline("out"), "")
        self.assertFalse(spill.clipped)
        self.assertEqual(spill.stats()["out"]["bytes"], 0)
        feed_lines(spill, 5)
        spill.close()
        text = spill.inline("out")
        self.assertNotIn("FIRST ATTEMPT TAIL", text, "上一次的输出还混在日志里")
        self.assertIn("line-000005", text)

    def test_file_cap_stops_writing_and_flags_overflow(self):
        spill = make(file_cap=500, head=64, tail=64)
        feed_lines(spill, 100)
        spill.close()
        self.assertIn("out", spill.overflow)
        self.assertEqual((ROOT / f"{RUN}.out.log").stat().st_size, 500)

    def test_empty_stream_creates_no_file(self):
        spill = make(run_id="aabbccddeeff0011")
        spill.write("out", b"hi\n")
        spill.close()
        self.assertTrue((ROOT / "aabbccddeeff0011.out.log").is_file())
        self.assertFalse((ROOT / "aabbccddeeff0011.err.log").exists(), "没数据的流不该留下空文件")


class ReadBack(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spill = make(run_id="1122334455667788", file_cap=1 << 20, head=128, tail=128)
        for n in range(1, 3001):
            spill.write("out", f"row {n:05d} normal output\n".encode())
            if n in (1234, 2500):
                spill.write("err", f"error at step {n}\n".encode())
        spill.close()

    def test_head_and_tail_align_to_lines(self):
        head = OS.read_output(ROOT, "1122334455667788", "out", "head", limit=200)
        tail = OS.read_output(ROOT, "1122334455667788", "out", "tail", limit=200)
        self.assertTrue(head["text"].startswith("row 00001"))
        self.assertTrue(tail["text"].rstrip().endswith("row 03000 normal output"))
        self.assertEqual(head["lines_total"], 3000)
        for row in (head["text"] + tail["text"]).splitlines():
            self.assertRegex(row, r"^row \d{5} normal output$")

    def test_grep_returns_line_numbers_then_lines_fetches_context(self):
        # err 流里只有两行（step 1234 与 step 2500 各一条），所以行号是 2 而不是 2500
        found = OS.read_output(ROOT, "1122334455667788", "err", "grep", pattern="error at step 2500")
        self.assertEqual(found["matched"], 1)
        self.assertEqual(int(found["text"].split(":", 1)[0]), 2)
        context = OS.read_output(ROOT, "1122334455667788", "err", "lines", start=1, end=5)
        self.assertIn("2: error at step 2500", context["text"])

    def test_grep_over_out_stream_finds_every_hit(self):
        found = OS.read_output(ROOT, "1122334455667788", "out", "grep", pattern="row 01234")
        self.assertEqual(found["matched"], 1)
        self.assertTrue(found["text"].startswith("1234: "))

    def test_lines_byte_limit_truncates_and_flags(self):
        got = OS.read_output(ROOT, "1122334455667788", "out", "lines", start=1, end=2000, limit=300)
        self.assertTrue(got["truncated"])
        self.assertLess(len(got["text"].encode()), 300)
        self.assertLess(got["matched"], 2000, "超预算就该少给几行")

    def test_missing_run_reports_not_raises(self):
        self.assertFalse(OS.read_output(ROOT, "deadbeefdeadbeef", "out", "tail")["found"])


class InputValidation(unittest.TestCase):
    def test_path_traversal_rejected(self):
        for bad in ["../../etc/passwd", "../0f1e2d3c4b5a6978.out", "0f1e/passwd", "", "0f1e2d3c4b5a6978.sh"]:
            with self.subTest(run_id=bad):
                with self.assertRaises(ValueError):
                    OS.read_output(ROOT, bad, "out", "tail")

    def test_non_hex_and_uppercase_rejected(self):
        for bad in ["ZZZZZZZZZZZZZZZZ", "0f1e2d3c4b5a697g", "0f1e2d3c4b5a6978;rm -rf /"]:
            with self.subTest(run_id=bad):
                with self.assertRaises(ValueError):
                    OS.read_output(ROOT, bad, "out", "tail")

    def test_bad_stream_and_mode_rejected(self):
        with self.assertRaises(ValueError):
            OS.read_output(ROOT, RUN, "shell", "tail")
        with self.assertRaises(ValueError):
            OS.read_output(ROOT, RUN, "out", "cat")


class Rotation(unittest.TestCase):
    @staticmethod
    def _seed(root: Path, ids: tuple[str, ...], size: int) -> None:
        """按给定顺序造若干 run，mtime 递增（最后一个最新）。

        时间基准取 now 附近：轮转有 keep_days 一档，用 2023 年的固定时间戳会整组判过期。
        """
        base = time.time()
        for i, rid in enumerate(ids):
            spill = OS.Spill(root, rid, 1 << 20, {"out": (64, 64), "err": (64, 64)})
            spill.write("out", b"x" * size)
            spill.close()
            stamp = base - (len(ids) - i) * 60
            for path in root.glob(f"{rid}.*"):
                os.utime(path, (stamp, stamp))

    def test_keep_runs_drops_oldest_groups(self):
        root = Path(tempfile.mkdtemp(prefix="rot-"))
        self._seed(root, ("a" * 16, "b" * 16, "c" * 16), 10)
        self.assertEqual(OS.prune(root, keep_runs=2, keep_bytes=1 << 30, keep_days=999), 1)
        self.assertFalse((root / ("a" * 16 + ".out.log")).exists())
        self.assertTrue((root / ("c" * 16 + ".out.log")).exists())

    def test_byte_budget_drops_older_until_under(self):
        root = Path(tempfile.mkdtemp(prefix="rot2-"))
        self._seed(root, ("d" * 16, "e" * 16, "f" * 16), 4000)
        self.assertGreaterEqual(OS.prune(root, keep_runs=999, keep_bytes=5000, keep_days=999), 2, "4000 字节的组只该留最新一个")

    def test_expired_runs_deleted_even_when_under_both_budgets(self):
        root = Path(tempfile.mkdtemp(prefix="rot3-"))
        rid = "9" * 16
        self._seed(root, (rid,), 10)
        path = root / f"{rid}.out.log"
        old = 1_600_000_000  # 远早于 7 天
        os.utime(path, (old, old))
        self.assertEqual(OS.prune(root, keep_runs=999, keep_bytes=1 << 30, keep_days=7), 1)
        self.assertFalse(path.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
