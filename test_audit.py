# /// script
# requires-python = ">=3.11"
# ///
"""审计离线验收：调用留痕、错误留痕、轮转、14 天保留、按主机回看。

    python test_audit.py      # 纯 stdlib，不碰网络也不碰 paramiko
"""

from __future__ import annotations

import asyncio
import json
import os
import tempfile
import time
import unittest
from pathlib import Path

import ssh_mcp as S


class AuditBase(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="ssh-mcp-audit-test-"))
        self._old_path = S.AUDIT_PATH
        self._old_keep = S.AUDIT_KEEP_DAYS
        S.AUDIT_PATH = self.dir / "ssh-mcp.jsonl"
        S.AUDIT_KEEP_DAYS = 14
        with S._OUTPUT_HOSTS_LOCK:
            S._OUTPUT_HOSTS.clear()

    def tearDown(self):
        S.AUDIT_PATH = self._old_path
        S.AUDIT_KEEP_DAYS = self._old_keep
        with S._OUTPUT_HOSTS_LOCK:
            S._OUTPUT_HOSTS.clear()

    def records(self) -> list[dict]:
        return S.audit_tail(None, 1000)


class AuditWrites(AuditBase):
    def test_call_and_result_share_call_id(self):
        @S._audited("exec")
        async def tool(host: str, command: str, force: bool = False) -> dict:
            return {"host": host, "command": command, "exit_code": 0,
                    "stdout": "x" * 5000, "stderr": "", "timed_out": None,
                    "output_id": "abc123"}

        asyncio.run(tool("h1", "uptime"))
        recs = self.records()
        self.assertEqual([r["event"] for r in recs], ["result", "call"])
        self.assertEqual(recs[0]["call_id"], recs[1]["call_id"])
        self.assertEqual(recs[0]["tool"], "exec")
        self.assertEqual(recs[1]["args"]["command"], "uptime")
        self.assertTrue(recs[0]["ok"])
        self.assertEqual(recs[0]["result"]["output_id"], "abc123")
        self.assertNotIn("stdout", json.dumps(recs, ensure_ascii=False), "返回正文不该进审计")

    def test_error_is_recorded_and_reraised(self):
        @S._audited("get_file")
        async def tool(host: str, remote: str) -> dict:
            raise RuntimeError("sftp 断了")

        with self.assertRaises(RuntimeError):
            asyncio.run(tool("h1", "/etc/hosts"))
        recs = self.records()
        self.assertEqual(recs[0]["event"], "error")
        self.assertIn("RuntimeError: sftp 断了", recs[0]["error"])
        self.assertIn("Traceback", recs[0]["traceback"])
        self.assertEqual(recs[0]["call_id"], recs[1]["call_id"])

    def test_failed_result_marks_not_ok(self):
        @S._audited("put_file")
        async def tool(host: str, local: str, remote: str) -> dict:
            return {"host": host, "verified": False, "aborted": "timeout", "bytes": 12}

        asyncio.run(tool("h1", "a", "/tmp/a"))
        result = self.records()[0]
        self.assertFalse(result["ok"])
        self.assertEqual(result["result"]["aborted"], "timeout")

    def test_failed_exec_keeps_stderr_head(self):
        @S._audited("exec")
        async def tool(host: str, command: str) -> dict:
            return {"host": host, "command": command, "exit_code": -1, "timed_out": "connect_failed",
                    "stdout": "", "stderr": "AuthenticationException: nope"}

        asyncio.run(tool("h1", "uptime"))
        result = self.records()[0]
        self.assertFalse(result["ok"])
        self.assertEqual(result["result"]["stderr_head"], "AuthenticationException: nope")

    def test_command_failure_is_ok_but_not_command_ok(self):
        @S._audited("exec")
        async def tool(host: str, command: str) -> dict:
            return {"host": host, "command": command, "exit_code": 7, "timed_out": None,
                    "stdout": "", "stderr": "cat: nope: No such file"}

        asyncio.run(tool("h1", "cat nope"))
        result = self.records()[0]
        self.assertTrue(result["ok"])
        self.assertFalse(result["result"]["command_ok"])
        self.assertIn("No such file", result["result"]["stderr_head"])

    def test_read_output_resolves_host_from_memory(self):
        @S._audited("read_output")
        async def tool(output_id: str, stream: str = "out", mode: str = "tail",
                       start: int = 1, end: int = 0, pattern: str = "", limit: int = 16384) -> dict:
            return {"found": True, "text": "x"}

        S._remember_output_host("run-mem", "100")
        asyncio.run(tool("run-mem"))
        recs = self.records()
        self.assertEqual({r["host"] for r in recs}, {"100"})
        self.assertEqual(recs[0]["event"], "result")

    def test_read_output_resolves_host_from_audit_after_restart(self):
        S.audit({"host": "66", "event": "executed", "output_id": "run-disk"})
        with S._OUTPUT_HOSTS_LOCK:
            S._OUTPUT_HOSTS.clear()  # 模拟服务重启后内存表为空

        @S._audited("read_output")
        async def tool(output_id: str, stream: str = "out", mode: str = "tail",
                       start: int = 1, end: int = 0, pattern: str = "", limit: int = 16384) -> dict:
            return {"found": True, "text": "x"}

        asyncio.run(tool("run-disk"))
        self.assertEqual({r["host"] for r in self.records()}, {"66"})

    def test_old_file_is_rotated(self):
        S.audit({"host": "h1", "event": "old"})
        old = time.time() - 2 * 86400
        os.utime(S.AUDIT_PATH, (old, old))

        S.audit({"host": "h1", "event": "new"})
        expected = f"ssh-mcp.{time.strftime('%Y%m%d', time.gmtime(old))}.jsonl"
        self.assertTrue((self.dir / expected).is_file(), f"应按日期轮转到 {expected}")
        self.assertEqual([r["event"] for r in self.records()], ["new", "old"])

    def test_rotated_file_older_than_keep_days_is_pruned(self):
        stale = self.dir / "ssh-mcp.20200101.jsonl"
        stale.write_text(json.dumps({"host": "old", "event": "intent"}) + "\n", encoding="utf-8")
        old = time.time() - 15 * 86400
        os.utime(stale, (old, old))

        S.audit({"host": "h1", "event": "new"})
        self.assertFalse(stale.exists(), "超过 14 天的归档应删除")
        self.assertEqual([r["event"] for r in self.records()], ["new"])

    def test_audit_tail_orders_rotated_before_current_and_filters_host(self):
        S.audit({"host": "h1", "event": "old"})
        os.utime(S.AUDIT_PATH, (time.time() - 2 * 86400,) * 2)
        S.audit({"host": "h1", "event": "new"})
        S.audit({"host": "h2", "event": "other"})
        self.assertEqual([r["event"] for r in S.audit_tail("h1", 10)], ["new", "old"])
        self.assertEqual([r["event"] for r in S.audit_tail(None, 2)], ["other", "new"])


class AuditThreadContext(AuditBase):
    def test_call_id_reaches_worker_thread(self):
        try:
            import anyio.to_thread
        except ImportError:
            self.skipTest("anyio 未安装")

        @S._audited("job_status")
        async def tool(host: str, job_id: str) -> dict:
            def work():
                S.audit({"host": host, "event": "nested"})
                return {"state": "running"}

            return await anyio.to_thread.run_sync(work)

        asyncio.run(tool("h1", "j1"))
        recs = self.records()
        nested = [r for r in recs if r["event"] == "nested"][0]
        result = [r for r in recs if r["event"] == "result"][0]
        self.assertEqual(nested["call_id"], result["call_id"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
