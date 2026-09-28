# /// script
# requires-python = ">=3.11"
# dependencies = ["paramiko>=3.4", "mcp>=1.2"]
# ///
"""连接拒绝路径的集成测试：不依赖真实凭据，验证四类拒连与审计落盘。

    uv run test_connect_refusals.py
"""

from __future__ import annotations

import json
import os
import socket
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent

# 必须在 import ssh_mcp 之前设好，模块在导入期读环境变量
_TMP = Path(tempfile.mkdtemp(prefix="ssh-mcp-selftest-"))
_HOSTS = _TMP / "hosts.json"
_AUDIT = _TMP / "audit.jsonl"
os.environ["SSHMCP_HOSTS"] = str(_HOSTS)
os.environ["SSHMCP_AUDIT"] = str(_AUDIT)
os.environ["SSHMCP_GRANTS"] = str(_TMP / "grants.json")
os.environ["SSHMCP_OUTPUT"] = str(_TMP / "output")
os.environ["SSHMCP_POLICY"] = str(HERE / "policy.json")

import ssh_mcp as M  # noqa: E402
import ssh_policy as P  # noqa: E402

REAL_IP = "10.81.2.100"
WRONG_FP = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"


def write_hosts(entries: dict) -> None:
    _HOSTS.write_text(json.dumps(entries, ensure_ascii=False), encoding="utf-8")
    M.HOSTS._mtime = None


def _port_open(ip: str, port: int = 22, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


class Refusals(unittest.TestCase):
    def test_unknown_host_never_connects(self):
        write_hosts({})
        res = M.execute("nosuchhost", "hostname")
        self.assertFalse(res["allowed"])
        self.assertEqual(res["reason"], "unknown_host")

    def test_credential_missing(self):
        write_hosts({})
        res = M.execute("100", "cat /etc/os-release")
        self.assertFalse(res["allowed"])
        self.assertEqual(res["reason"], "credential_missing")

    def test_host_key_unpinned_refused(self):
        write_hosts({"100": {"address": REAL_IP, "username": "user", "auth": "password", "password": "x"}})
        res = M.execute("100", "hostname")
        self.assertFalse(res["allowed"])
        self.assertEqual(res["reason"], "host_key_unpinned")

    def test_ro_policy_denied_before_connection(self):
        write_hosts(
            {
                "100": {
                    "address": REAL_IP,
                    "username": "user",
                    "auth": "password",
                    "password": "x",
                    "hostKey": WRONG_FP,
                }
            }
        )
        res = M.execute("100", "rm -rf /tmp/whatever")
        self.assertFalse(res["allowed"])
        self.assertEqual(res["reason"], "not_in_allowlist")

    def test_wrong_hostkey_blocks_before_auth(self):
        """指纹不符必须在认证之前就把连接掐掉，且不去试密码。"""
        if not _port_open(REAL_IP):
            self.skipTest(f"{REAL_IP}:22 不可达 —— 这条要真握手才能拿到对方主机密钥，离开校园网跑不了")
        write_hosts(
            {
                "100": {
                    "address": REAL_IP,
                    "username": "user",
                    "auth": "password",
                    "password": "definitely-wrong",
                    "hostKey": WRONG_FP,
                }
            }
        )
        res = M.execute("100", "hostname")
        self.assertTrue(res["allowed"], "策略放行，但连接应失败")
        self.assertEqual(res["exit_code"], -1)
        self.assertEqual(res["timed_out"], "connect_failed")
        self.assertIn("指纹不匹配", res["stderr"])

    def test_audit_records_every_decision(self):
        write_hosts({})
        M.execute("nosuchhost", "hostname")
        M.execute("100", "rm -rf /tmp/x")
        lines = [json.loads(l) for l in _AUDIT.read_text(encoding="utf-8").splitlines()]
        denies = [r for r in lines if r["decision"] == "deny"]
        self.assertGreaterEqual(len(denies), 2)
        blob = _AUDIT.read_text(encoding="utf-8")
        self.assertNotIn("definitely-wrong", blob, "审计里绝不能出现凭据")

    def test_list_hosts_has_no_password(self):
        write_hosts(
            {
                "100": {
                    "address": REAL_IP,
                    "username": "user",
                    "auth": "password",
                    "password": "super-secret",
                    "hostKey": WRONG_FP,
                    "rw_allowed": True,
                }
            }
        )
        blob = json.dumps(M._tool_list_hosts(), ensure_ascii=False)
        self.assertNotIn("super-secret", blob)
        entry = next(h for h in M._tool_list_hosts()["hosts"] if h["alias"] == "100")
        self.assertTrue(entry["rw_allowed"])
        self.assertEqual(entry["effective_mode"], "rw", "非 root + rw_allowed 应长期 rw")


class AgentCannotSelfApprove(unittest.TestCase):
    """实测：Git Bash 的 stdin.isatty() 在 Agent 侧返回 True，所以真正的把关是原生确认框。"""

    @unittest.skipIf(os.name != "nt", "依赖 Windows MessageBoxW")
    def test_grant_without_click_writes_nothing(self):
        import subprocess

        hosts = _TMP / "grant_fixture.json"
        hosts.write_text(
            json.dumps(
                {
                    "100": {
                        "address": REAL_IP,
                        "username": "user",
                        "auth": "password",
                        "password": "x",
                        "hostKey": WRONG_FP,
                        "rw_allowed": True,
                    }
                }
            ),
            encoding="utf-8",
        )
        grants = _TMP / "grant_out.json"
        env = {
            **os.environ,
            "SSHMCP_HOSTS": str(hosts),
            "SSHMCP_GRANTS": str(grants),
            "SSHMCP_AUDIT": str(_TMP / "grant_audit.jsonl"),
            "SSHMCP_POLICY": str(HERE / "policy.json"),
            "SSHMCP_CONFIRM_TIMEOUT": "1",
            "PYTHONIOENCODING": "utf-8",
        }
        proc = subprocess.run(
            ["uv", "run", "--quiet", str(HERE / "ssh_mcp.py"), "grant", "100", "--scope", "host", "--for", "30m"],
            cwd=str(HERE),
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
        )
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("未获得人工确认", proc.stderr)
        self.assertFalse(grants.exists(), "没点确认就绝不能落盘 grants.json")


class KeyLoading(unittest.TestCase):
    """paramiko 5.x 删了 DSSKey，早先写死的 loader 列表会让所有 key 认证抛 AttributeError。"""

    def test_default_key_discovery_works(self):
        key = M._load_private_key(M.HostCred(alias="probe", address="x", username="u", auth="key"))
        self.assertIn(type(key).__name__, ("Ed25519Key", "RSAKey", "ECDSAKey"))

    def test_explicit_key_path(self):
        from pathlib import Path

        real = Path.home() / ".ssh" / "id_ed25519"
        if not real.is_file():
            self.skipTest("没有 id_ed25519")
        cred = M.HostCred(alias="probe", address="x", username="u", auth="key", key_path=str(real))
        self.assertIsNotNone(M._load_private_key(cred))

    def test_missing_key_gives_actionable_error(self):
        # agent 里有 key 的机器上不该走报错分支，这里把 agent 钉成空的，保证跨机器稳定
        with mock.patch("paramiko.agent.Agent") as agent_cls:
            agent_cls.return_value.get_keys.return_value = []
            cred = M.HostCred(alias="probe", address="x", username="u", auth="key", key_path="Z:\\nope\\id_x")
            with self.assertRaises(RuntimeError) as ctx:
                M._load_private_key(cred)
        self.assertIn("key_path", str(ctx.exception))

    def test_agent_fallback_when_file_key_unusable(self):
        """带 passphrase 的文件私钥解不开时改问 ssh-agent，并取它给的第一把 key。"""
        garbage = _TMP / "passphrase_key"
        garbage.write_text("-----BEGIN OPENSSH PRIVATE KEY-----\n不是真私钥\n", encoding="utf-8")
        sentinel = object()
        with mock.patch("paramiko.agent.Agent") as agent_cls:
            agent_cls.return_value.get_keys.return_value = [sentinel]
            key = M._load_private_key(M.HostCred(alias="probe", address="x", username="u", auth="key", key_path=str(garbage)))
        self.assertIs(key, sentinel)

    def test_agent_absent_is_reported_not_swallowed(self):
        """Windows 上 ssh-agent 默认 Stopped/Disabled，paramiko 会直接抛 —— 不能静默当成认证失败。"""
        cred = M.HostCred(alias="probe", address="x", username="u", auth="key", key_path="Z:\\nope\\id_x")
        with mock.patch("paramiko.agent.Agent", side_effect=OSError("no agent pipe")):
            with self.assertRaises(RuntimeError) as ctx:
                M._load_private_key(cred)
        self.assertIn("ssh-agent", str(ctx.exception))


class ModeTable(unittest.TestCase):
    CRED = {"address": REAL_IP, "username": "root", "auth": "password", "password": "x", "hostKey": WRONG_FP}

    def test_root_without_rw_allowed_is_always_ro(self):
        write_hosts({"admin": dict(self.CRED)})
        self.assertEqual(M.long_lived_mode(M.HOSTS.get()["admin"]).mode, "ro")

    def test_root_with_rw_allowed_still_ro_without_grant(self):
        write_hosts({"admin": {**self.CRED, "rw_allowed": True}})
        cred = M.HOSTS.get()["admin"]
        self.assertTrue(cred.privileged)
        info = M.resolve_mode("admin", "touch /tmp/a", cred)
        self.assertEqual(info.mode, "ro")

    def test_nonroot_with_rw_allowed_is_long_lived_rw(self):
        write_hosts({"100": {**self.CRED, "username": "user", "rw_allowed": True}})
        info = M.resolve_mode("100", "touch /tmp/a", M.HOSTS.get()["100"])
        self.assertEqual(info.mode, "rw")


class ExecWiring(unittest.TestCase):
    """execute → 全文落盘 → read_output → 审计 的接线。

    run_command 被换掉，所以这条不需要网络也能覆盖到「大输出会不会被完整捞回」这一段
    —— 真机可达性另说，别把这条测试当成远端验证。
    """

    CRED = {"address": REAL_IP, "username": "user", "auth": "password", "password": "x", "hostKey": WRONG_FP, "rw_allowed": True}

    @staticmethod
    def _fake_run(cred, command, cwd, idle_s, max_s, spill):
        for n in range(1, 5001):
            spill.write("out", f"row {n:05d} compiling\n".encode())
        spill.write("err", b"make: *** [Makefile:12: all] Error 2\n")
        spill.close()
        return M.RunResult(
            exit_code=2,
            stdout=spill.inline("out"),
            stderr=spill.inline("err"),
            truncated=spill.clipped,
            timed_out=None,
            output_id=spill.run_id,
            stats=spill.stats(),
        )

    def test_big_output_is_clipped_inline_but_reachable_by_reference(self):
        write_hosts({"100": dict(self.CRED)})
        with mock.patch.object(M, "run_command", self._fake_run):
            res = M.execute("100", "make -j8")
        self.assertTrue(res["allowed"])
        self.assertEqual(res["exit_code"], 2)
        self.assertTrue(res["truncated"])
        self.assertIn("省略", res["stdout"], "内联该是头尾两截")
        self.assertLess(len(res["stdout"].encode()), 12000, "内联不该把 80KB 全灌回 Agent")
        self.assertIn("Error 2", res["stderr"], "报错就在尾部，绝不能被丢掉")

        oid = res["output_id"]
        self.assertTrue((M.OUTPUT_ROOT / f"{oid}.out.log").is_file())
        found = M._tool_read_output(oid, "out", "grep", pattern="row 04321")
        self.assertEqual(found["matched"], 1)
        self.assertTrue(found["text"].startswith("4321: "), found["text"][:40])
        tail = M._tool_read_output(oid, "out", "tail", limit=4096)
        self.assertIn("row 05000 compiling", tail["text"])

    def test_audit_carries_the_output_reference(self):
        write_hosts({"100": dict(self.CRED)})
        with mock.patch.object(M, "run_command", self._fake_run):
            res = M.execute("100", "make -j8")
        hit = [r for r in M.audit_tail(None, 30) if r.get("output_id") == res["output_id"]]
        self.assertEqual(len(hit), 1, "审计必须能顺 output_id 走到全文")
        self.assertEqual(hit[0]["exit_code"], 2)
        self.assertEqual(hit[0]["output"]["out"]["lines"], 5000)

    def test_bad_output_id_is_a_payload_not_an_exception(self):
        bad = M._tool_read_output("../../etc/passwd", "out", "tail")
        self.assertFalse(bad["found"])
        self.assertIn("run_id", bad["error"])

    def test_unwritable_output_dir_fails_closed(self):
        """写不了全文日志就不执行：与审计同为必备件，不许静默降级成「只有内存里那份」。"""
        write_hosts({"100": dict(self.CRED)})
        with mock.patch.object(M, "OUTPUT_ROOT", Path("Z:\\nope\\output")):
            res = M.execute("100", "make -j8")
        self.assertFalse(res["allowed"])
        self.assertEqual(res["reason"], "output_unwritable")


class GrantUnlock(unittest.TestCase):
    """root + rw_allowed 的解锁路径。

    100 验不到这段：它是「非 root + rw_allowed → 长期 rw」，而 resolve_mode 在
    base.mode == \"rw\" 时直接 return，压根不读 grant（ssh_mcp.py:204）。
    所以真机上签的条子对 100 是空转，只有 root 账号才会消费它。
    """

    CRED = {"address": REAL_IP, "username": "root", "auth": "password", "password": "x", "hostKey": WRONG_FP, "rw_allowed": True}

    def setUp(self):
        write_hosts({"admin": dict(self.CRED)})
        M.save_grants(M.GrantFile(grants=[]))

    def _issue(self, **kw) -> None:
        kw.setdefault("id", "g-test")
        kw.setdefault("expires_at", (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat())
        M.save_grants(M.GrantFile(grants=[M.P.Grant(alias="admin", **kw)]))

    def test_root_without_grant_stays_ro(self):
        cred = M.HOSTS.get()["admin"]
        info = M.resolve_mode("admin", "touch /tmp/a", cred)
        self.assertEqual(info.mode, "ro")
        self.assertIsNone(info.grant)

    def test_host_grant_unlocks_root(self):
        self._issue(scope="host")
        info = M.resolve_mode("admin", "touch /tmp/a", M.HOSTS.get()["admin"])
        self.assertEqual(info.mode, "rw")
        self.assertEqual(info.grant.id, "g-test")

    def test_expired_grant_does_not_unlock(self):
        self._issue(scope="host", expires_at=(datetime.now(timezone.utc) - timedelta(seconds=5)).isoformat())
        self.assertEqual(M.resolve_mode("admin", "touch /tmp/a", M.HOSTS.get()["admin"]).mode, "ro")

    def test_execute_consumes_cmd_grant(self):
        """cmd scope 才计数；host scope 靠 TTL，用完不减 —— 这条把消费链跑通。"""
        self._issue(scope="cmd", command="touch /tmp/mcp-grant-probe", uses_left=1)

        def ok_run(cred, command, cwd, idle_s, max_s, spill):
            spill.write("out", b"created\n")
            spill.close()
            return M.RunResult(
                exit_code=0, stdout=spill.inline("out"), stderr="", truncated=False,
                timed_out=None, output_id=spill.run_id, stats=spill.stats(),
            )

        with mock.patch.object(M, "run_command", ok_run):
            res = M.execute("admin", "touch /tmp/mcp-grant-probe")
        self.assertTrue(res["allowed"])
        self.assertEqual(res["decision"]["grant_id"], "g-test", "审计与返回都得带上是谁批的")
        self.assertEqual(M.grants_for("admin"), [], "cmd grant 用一次就该没了")


if __name__ == "__main__":
    unittest.main(verbosity=2)
