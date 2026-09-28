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
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent

# 必须在 import ssh_mcp 之前设好，模块在导入期读环境变量
_TMP = Path(tempfile.mkdtemp(prefix="ssh-mcp-selftest-"))
_HOSTS = _TMP / "hosts.json"
_AUDIT = _TMP / "audit.jsonl"
os.environ["SSHMCP_HOSTS"] = str(_HOSTS)
os.environ["SSHMCP_AUDIT"] = str(_AUDIT)
os.environ["SSHMCP_GRANTS"] = str(_TMP / "grants.json")
os.environ["SSHMCP_POLICY"] = str(HERE / "policy.json")

import ssh_mcp as M  # noqa: E402

REAL_IP = "10.81.2.100"
WRONG_FP = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"


def write_hosts(entries: dict) -> None:
    _HOSTS.write_text(json.dumps(entries, ensure_ascii=False), encoding="utf-8")
    M.HOSTS._mtime = None


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
        cred = M.HostCred(alias="probe", address="x", username="u", auth="key", key_path="Z:\\nope\\id_x")
        with self.assertRaises(RuntimeError) as ctx:
            M._load_private_key(cred)
        self.assertIn("key_path", str(ctx.exception))


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


if __name__ == "__main__":
    unittest.main(verbosity=2)
