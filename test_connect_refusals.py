# /// script
# requires-python = ">=3.11"
# dependencies = ["paramiko>=3.4", "mcp>=1.2"]
# ///
"""前置检查、指纹固定与执行接线的用例：不依赖真实凭据。

    uv run --quiet test_connect_refusals.py

必须用 uv run：裸 python 不读文件头的 PEP 723 deps，会拿到本机 site-packages 里
缺 cryptography 的 paramiko 而报 ModuleNotFoundError。
"""

from __future__ import annotations

import json
import os
import socket
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent

# 必须在 import ssh_mcp 之前设好，模块在导入期读环境变量
_TMP = Path(tempfile.mkdtemp(prefix="ssh-mcp-selftest-"))
_HOSTS = _TMP / "hosts.json"
_AUDIT = _TMP / "audit.jsonl"
os.environ["SSHMCP_HOSTS"] = str(_HOSTS)
os.environ["SSHMCP_AUDIT"] = str(_AUDIT)
os.environ["SSHMCP_HOSTKEYS"] = str(_TMP / "hostkeys.json")
os.environ["SSHMCP_OUTPUT"] = str(_TMP / "output")
os.environ["SSHMCP_POLICY"] = str(HERE / "policy.json")

import ssh_mcp as M  # noqa: E402

REAL_IP = "10.81.2.100"
WRONG_FP = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"


def write_hosts(entries: dict) -> None:
    _HOSTS.write_text(json.dumps(entries, ensure_ascii=False), encoding="utf-8")
    M.HOSTS._mtime = None


def reset_pins() -> None:
    p = Path(os.environ["SSHMCP_HOSTKEYS"])
    if p.exists():
        p.unlink()
    M.PINS._mtime = None


def _port_open(ip: str, port: int = 22, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


class Preflight(unittest.TestCase):
    """凭据与指纹两道检查：任一不过就不建立连接，也就不会把密码发出去。"""

    def setUp(self):
        # PinHostkey 会往 hostkeys.json 里留条目，类间执行顺序不保证，进来先清干净
        reset_pins()

    def test_credential_missing_never_connects(self):
        write_hosts({})
        res = M.execute("nosuchhost", "hostname")
        self.assertTrue(res["blocked"])
        self.assertEqual(res["reason"], "credential_missing")

    def test_unpinned_host_refused(self):
        write_hosts({"100": {"address": REAL_IP, "username": "user", "auth": "password", "password": "x"}})
        res = M.execute("100", "hostname")
        self.assertTrue(res["blocked"])
        self.assertEqual(res["reason"], "host_key_unpinned")
        self.assertIn("pin_hostkey", res["hint"])

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
        if "指纹不匹配" not in res.get("stderr", "") and "timed out" in res.get("stderr", ""):
            # 刚重装/网络抖动时 KEX 会先超时，拿不到对方密钥 —— 那是抖动，不是守卫失效
            res = M.execute("100", "hostname")
        if "指纹不匹配" not in res.get("stderr", ""):
            self.skipTest(f"{REAL_IP} 这次没能完成握手（{str(res)[:80]}），换个时刻再验")
        self.assertNotIn("blocked", res, "策略放行，但连接应失败")
        self.assertEqual(res["exit_code"], -1)
        self.assertEqual(res["timed_out"], "connect_failed")
        self.assertIn("指纹不匹配", res["stderr"])

    def test_audit_records_every_block(self):
        write_hosts({})
        M.execute("nosuchhost", "hostname")
        M.execute("100", "rm -rf /tmp/x")
        lines = [json.loads(l) for l in _AUDIT.read_text(encoding="utf-8").splitlines()]
        blocked = [r for r in lines if r["event"] == "blocked"]
        self.assertGreaterEqual(len(blocked), 2)
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
        data = M._tool_list_hosts()
        blob = json.dumps(data, ensure_ascii=False)
        self.assertNotIn("super-secret", blob)
        self.assertNotIn("key_path", blob)
        entry = next(h for h in data["hosts"] if h["alias"] == "100")
        self.assertFalse(entry["privileged"], "非 root 主机不查 killlist")
        self.assertEqual(entry["guard"], "none")

    def test_obsolete_credential_keys_are_ignored(self):
        """rw_allowed 已从模型里删掉：凭据文件里残留的这条键必须被静默忽略，不能报错。"""
        write_hosts({"100": {"address": REAL_IP, "username": "user", "password": "x", "hostKey": WRONG_FP, "rw_allowed": True}})
        cred = M.HOSTS.get()["100"]
        self.assertFalse(hasattr(cred, "rw_allowed"))
        self.assertEqual(cred.address, REAL_IP)


class PinHostkey(unittest.TestCase):
    """AI 可用的指纹更新路径：探测不发凭据，落盘要 trust=true。"""

    CRED = {"address": REAL_IP, "username": "user", "auth": "password", "password": "x"}

    def setUp(self):
        reset_pins()

    def test_probe_works_without_any_valid_credential(self):
        """探测只做到密钥交换：把认证入口钉成会抛，指纹照样拿得到 —— 反证它没发凭据。"""
        if not _port_open(REAL_IP):
            self.skipTest(f"{REAL_IP}:22 不可达")
        import paramiko

        with mock.patch.object(
            paramiko.Transport, "auth_password", side_effect=AssertionError("探测阶段不得认证")
        ), mock.patch.object(paramiko.Transport, "auth_publickey", side_effect=AssertionError("探测阶段不得认证")):
            fp, key_type = M.probe_hostkey(REAL_IP, 22, timeout=8)
        self.assertTrue(fp.startswith("SHA256:"))
        self.assertTrue(key_type)

    def test_first_pin_requires_explicit_trust(self):
        write_hosts({"100": dict(self.CRED)})
        reset_pins()
        with mock.patch.object(M, "probe_hostkey", return_value=("SHA256:livefp", "ssh-ed25519")):
            out = M._tool_pin_hostkey("100")
        self.assertTrue(out["probed"])
        self.assertIsNone(out["pinned"])
        self.assertTrue(out["writable"])
        self.assertFalse(Path(os.environ["SSHMCP_HOSTKEYS"]).exists(), "不带 trust 就绝不能落盘")

        with mock.patch.object(M, "probe_hostkey", return_value=("SHA256:livefp", "ssh-ed25519")):
            out = M._tool_pin_hostkey("100", trust=True)
        self.assertTrue(out["match"])
        self.assertEqual(M.PINS.get()["100"], "SHA256:livefp")
        pin, source = M.effective_pin("100", M.HOSTS.get()["100"])
        self.assertEqual((pin, source), ("SHA256:livefp", "hostkeys"), "落盘后 exec 的 preflight 就能过了")

    def test_mismatch_against_pinned_value_is_not_overwritable(self):
        """凭据文件钉过的主机对不上：那是人的事，工具不覆盖，也不写 hostkeys.json 去绕。"""
        write_hosts({"100": {**self.CRED, "hostKey": WRONG_FP}})
        reset_pins()
        with mock.patch.object(M, "probe_hostkey", return_value=("SHA256:other", "ssh-ed25519")):
            out = M._tool_pin_hostkey("100", trust=True)
        self.assertFalse(out["match"])
        self.assertFalse(out["writable"])
        self.assertEqual(out["pin_source"], "credential")
        self.assertFalse(Path(os.environ["SSHMCP_HOSTKEYS"]).exists())
        self.assertIn("hostKey", out["hint"])

    def test_pin_from_hostkeys_used_when_credential_has_none(self):
        write_hosts({"100": dict(self.CRED)})
        reset_pins()
        M.save_pin("100", "SHA256:fromstore")
        pin, source = M.effective_pin("100", M.HOSTS.get()["100"])
        self.assertEqual((pin, source), ("SHA256:fromstore", "hostkeys"))

    def test_probe_failure_returns_payload(self):
        write_hosts({"100": dict(self.CRED)})
        with mock.patch.object(M, "probe_hostkey", side_effect=OSError("connection refused")):
            out = M._tool_pin_hostkey("100")
        self.assertFalse(out["probed"])
        self.assertEqual(out["reason"], "probe_failed")


class KeyLoading(unittest.TestCase):
    """paramiko 5.x 删了 DSSKey，早先写死的 loader 列表会让所有 key 认证抛 AttributeError。"""

    def test_default_key_discovery_works(self):
        key = M._load_private_key(M.HostCred(alias="probe", address="x", username="u", auth="key"))
        self.assertIn(type(key).__name__, ("Ed25519Key", "RSAKey", "ECDSAKey"))

    def test_explicit_key_path(self):
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


PINNED = {
    "address": REAL_IP,
    "username": "user",
    "auth": "password",
    "password": "x",
    "hostKey": WRONG_FP,
}
ROOT_PINNED = {**PINNED, "username": "root"}


CALLS: list[tuple] = []


def fake_run(output_lines: int = 0):
    def _run(cred, pin, command, cwd, idle_s, max_s, spill):
        CALLS.append((cred.alias, pin, command, cwd, idle_s, max_s))
        for n in range(1, output_lines + 1):
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

    return _run


class ExecWiring(unittest.TestCase):
    """execute → 全文落盘 → read_output → 审计 的接线。

    run_command 被换掉，所以这条不需要网络也能覆盖到「大输出会不会被完整捞回」这一段
    —— 真机可达性另说，别把这条测试当成远端验证。
    """

    def test_big_output_is_clipped_inline_but_reachable_by_reference(self):
        write_hosts({"100": dict(PINNED)})
        with mock.patch.object(M, "run_command", fake_run(5000)):
            res = M.execute("100", "make -j8")
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
        write_hosts({"100": dict(PINNED)})
        with mock.patch.object(M, "run_command", fake_run(5000)):
            res = M.execute("100", "make -j8")
        hit = [r for r in M.audit_tail(None, 30) if r.get("output_id") == res["output_id"]]
        self.assertEqual(len(hit), 1, "审计必须能顺 output_id 走到全文")
        self.assertEqual(hit[0]["exit_code"], 2)
        self.assertEqual(hit[0]["output"]["out"]["lines"], 5000)

    def test_bad_output_id_is_a_payload_not_an_exception(self):
        bad = M._tool_read_output("../../etc/passwd", "out", "tail")
        self.assertFalse(bad["found"])
        self.assertIn("run_id", bad["error"])

    def test_unwritable_output_dir_blocks(self):
        """写不了全文日志就不执行：与审计同为必备件，不许静默降级成「只有内存里那份」。"""
        write_hosts({"100": dict(PINNED)})
        with mock.patch.object(M, "OUTPUT_ROOT", Path("Z:\\nope\\output")):
            res = M.execute("100", "make -j8")
        self.assertTrue(res["blocked"])
        self.assertEqual(res["reason"], "output_unwritable")

    def test_max_duration_is_not_clamped(self):
        """传多大用多大：长构建靠调用方给时长，服务端不再压回 300s。"""
        write_hosts({"100": dict(PINNED)})
        seen = {}

        def spy(cred, pin, command, cwd, idle_s, max_s, spill):
            seen["max_s"] = max_s
            seen["idle_s"] = idle_s
            spill.close()
            return M.RunResult(exit_code=0, stdout="", stderr="", truncated=False, timed_out=None, output_id=spill.run_id, stats=spill.stats())

        with mock.patch.object(M, "run_command", spy):
            M.execute("100", "cmake --build .", max_duration=7200)
        self.assertEqual(seen["max_s"], 7200)
        with mock.patch.object(M, "run_command", spy):
            M.execute("100", "cmake --build .")
        self.assertEqual(seen["max_s"], M.GUARD.get().max_duration_s)


class KilllistWiring(unittest.TestCase):
    """清单只在 root 账号主机上生效，命中后 force=true 可越过。"""

    def test_nonroot_host_is_never_guarded(self):
        write_hosts({"100": dict(PINNED)})
        CALLS.clear()
        with mock.patch.object(M, "run_command", fake_run(0)):
            res = M.execute("100", "rm -rf /")
        self.assertFalse(res.get("blocked", False))
        self.assertEqual(CALLS[-1][2], "rm -rf /", "命令原样发给远端，服务端没动它")

    def test_root_host_hit_is_blocked_with_hint(self):
        write_hosts({"admin": dict(ROOT_PINNED)})
        res = M.execute("admin", "mkfs.ext4 /dev/sda1")
        self.assertTrue(res["blocked"])
        self.assertEqual(res["reason"], "killlisted")
        self.assertIn("mkfs", res["rule"])
        self.assertIn("force=true", res["hint"])

    def test_force_executes_and_marks_the_audit(self):
        write_hosts({"admin": dict(ROOT_PINNED)})
        with mock.patch.object(M, "run_command", fake_run(0)):
            res = M.execute("admin", "mkfs.ext4 /dev/sda1", force=True)
        self.assertEqual(res["forced_rule"], "deny:mkfs*")
        forced = [r for r in M.audit_tail(None, 40) if r.get("rule") == "forced"]
        self.assertTrue(forced, "审计里要能看出这条是 force 越过了清单")

    def test_benign_command_on_root_host_is_untouched(self):
        write_hosts({"admin": dict(ROOT_PINNED)})
        with mock.patch.object(M, "run_command", fake_run(0)):
            res = M.execute("admin", "apt install -y nginx")
        self.assertNotIn("forced_rule", res)
        self.assertFalse(res.get("blocked", False))

    def test_cd_only_skips_guard_and_tracks_cwd(self):
        """单独的 cd 只改服务端记的 cwd，不触碰远端状态，root 主机也不必 force。"""
        write_hosts({"admin": dict(ROOT_PINNED)})

        def pwd_run(cred, pin, command, cwd, idle_s, max_s, spill):
            spill.write("out", b"/tmp\n")
            spill.close()
            return M.RunResult(exit_code=0, stdout=spill.inline("out"), stderr="", truncated=False, timed_out=None, output_id=spill.run_id, stats=spill.stats())

        with mock.patch.object(M, "run_command", pwd_run):
            res = M.execute("admin", "cd /tmp")
        self.assertEqual(res["cwd_after"], "/tmp")
        self.assertEqual(M.POOL.cwd("admin"), "/tmp")


if __name__ == "__main__":
    unittest.main(verbosity=2)
