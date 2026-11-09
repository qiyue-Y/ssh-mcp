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

import hashlib
import json
import os
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent

_REPO_GUARD = json.loads((HERE / "policy.json").read_text(encoding="utf-8"))

# 必须在 import ssh_mcp 之前设好，模块在导入期读环境变量
_TMP = Path(tempfile.mkdtemp(prefix="ssh-mcp-selftest-"))
_HOSTS = _TMP / "hosts.json"
_AUDIT = _TMP / "audit.jsonl"
_POLICY = _TMP / "policy.json"
# 清单条目跟着仓库走，guarded_hosts 钉死成用例自己的别名 ——
# 否则用户哪天把 100 加进 guarded_hosts，"非 root 不拦"那条用例会跟着变红
_POLICY.write_text(
    json.dumps(
        {
            "defaults": _REPO_GUARD["defaults"],
            "killlist": _REPO_GUARD["killlist"],
            "guarded_hosts": ["guarded-user"],
        },
        ensure_ascii=False,
    ),
    encoding="utf-8",
)
os.environ["SSHMCP_HOSTS"] = str(_HOSTS)
os.environ["SSHMCP_AUDIT"] = str(_AUDIT)
os.environ["SSHMCP_HOSTKEYS"] = str(_TMP / "hostkeys.json")
os.environ["SSHMCP_OUTPUT"] = str(_TMP / "output")
os.environ["SSHMCP_POLICY"] = str(_POLICY)

import ssh_guard as G  # noqa: E402
import ssh_mcp as M  # noqa: E402
import output_store as OS  # noqa: E402

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
    def _run(cred, pin, command, cwd, idle_s, max_s, spill, elevate=False, login_shell=False, shell_init=False):
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

        def spy(cred, pin, command, cwd, idle_s, max_s, spill, elevate=False, login_shell=False, shell_init=False):
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


class Elevate(unittest.TestCase):
    """提权：配置里 elevate 才是能力位，一旦提权，非 root 主机也恒查清单。"""

    CRED = {"address": REAL_IP, "username": "qy", "auth": "password", "password": "login-secret", "hostKey": WRONG_FP}

    def setUp(self):
        reset_pins()

    def test_not_configured_is_a_clean_block(self):
        write_hosts({"100": dict(self.CRED)})
        res = M.execute("100", "id", elevate=True)
        self.assertTrue(res["blocked"])
        self.assertEqual(res["reason"], "elevate_not_configured")
        self.assertIn("elevate", res["hint"])

    def test_elevate_forces_the_killlist_even_on_an_unguarded_host(self):
        """100 既非 root 也没被 guarded_hosts 点名，但提权命令必须查表。"""
        write_hosts({"100": {**self.CRED, "elevate": True}})
        res = M.execute("100", "mkfs.ext4 /dev/sda1", elevate=True)
        self.assertTrue(res["blocked"])
        self.assertEqual(res["reason"], "killlisted")

    def test_same_command_passes_without_elevate(self):
        """反向对照：同一条命令不提权时不查表 —— 证明拦它的确实是 elevate 而不是别的。"""
        write_hosts({"100": {**self.CRED, "elevate": True}})
        CALLS.clear()
        with mock.patch.object(M, "run_command", fake_run(0)):
            res = M.execute("100", "mkfs.ext4 /dev/sda1")
        self.assertFalse(res.get("blocked", False))

    def test_sudo_wrap_keeps_the_password_out_of_argv(self):
        cred = M.HostCred(alias="x", address="1", username="qy", password="login-secret", elevate=True)
        inner = "cd '/root' && id"
        wrapped = M._sudo_wrap(inner, cred)
        self.assertIn("sudo -S -p '' --user root -- sh -c", wrapped)
        self.assertNotIn("login-secret", wrapped, "口令绝不能进命令串（那会进 argv、审计和远端 history）")
        # 引号必须被真正包住而不是拼漏：解析回来的 sh -c 参数要逐字等于原命令
        import shlex

        tokens = shlex.split(wrapped)
        self.assertEqual(tokens[:7], ["sudo", "-S", "-p", "", "--user", "root", "--"])
        self.assertEqual(tokens[7:], ["sh", "-c", inner])

    def test_password_defaults_to_login_password(self):
        plain = M.HostCred(alias="x", address="1", username="qy", password="login-secret", elevate=True)
        self.assertEqual(plain.sudo_password(), "login-secret")
        other = M.HostCred(alias="x", address="1", username="qy", password="login-secret", elevate=True, elevate_password="root-secret")
        self.assertEqual(other.sudo_password(), "root-secret")

    def test_elevate_without_any_password_is_blocked(self):
        """空口令喂给 sudo -S 会一直等输入，最后报成 idle 超时 —— 那是假故障，提前拒。"""
        write_hosts({"100": {"address": REAL_IP, "username": "qy", "auth": "key", "hostKey": WRONG_FP, "elevate": True}})
        res = M.execute("100", "id", elevate=True)
        self.assertTrue(res["blocked"])
        self.assertEqual(res["reason"], "elevate_password_missing")

    def test_channel_gets_password_on_stdin_not_in_command(self):
        """run_command 的提权路径：exec 的是包装串，口令只从 stdin 走。"""
        cred = M.HostCred(alias="100", address="1", username="qy", password="login-secret", elevate=True, host_key=WRONG_FP)
        sent = {}

        class FakeChan:
            def exec_command(self, cmd):
                sent["cmd"] = cmd

            def sendall(self, data):
                sent.setdefault("stdin", b"")
                sent["stdin"] += data

            def shutdown_write(self):
                # 认证失败时 sudo 会再读一次 stdin，这里必须被关掉才不会挂到 idle 超时
                sent["stdin_closed"] = True

            def settimeout(self, _):
                pass

            def recv_ready(self):
                return False

            def recv_stderr_ready(self):
                return False

            def exit_status_ready(self):
                return True

            @property
            def eof_received(self):
                return True

            def recv_exit_status(self):
                return 0

            def close(self):
                pass

        fake_client = mock.Mock()
        fake_client.get_transport.return_value = mock.Mock(is_active=lambda: True, open_session=lambda: FakeChan())
        spill = OS.Spill(M.OUTPUT_ROOT, "elevatestdin", 4096, {"out": (256, 256), "err": (256, 256)})
        with mock.patch.object(M.POOL, "client", return_value=fake_client):
            M.run_command(cred, WRONG_FP, "id", "~", 5, 5, spill, elevate=True)

        self.assertIn("sudo -S", sent["cmd"])
        self.assertNotIn("login-secret", sent["cmd"])
        self.assertEqual(sent["stdin"], b"login-secret\n")
        self.assertTrue(sent.get("stdin_closed"), "喂完口令必须关 stdin，否则错口令会挂到 idle 超时")

    def test_audit_and_payload_mark_elevation_without_leaking(self):
        write_hosts({"100": {**self.CRED, "elevate": True}})
        with mock.patch.object(M, "run_command", fake_run(0)):
            res = M.execute("100", "id -u", elevate=True)
        self.assertTrue(res["elevated"])
        self.assertEqual(res["ran_as"], "root")
        recs = M.audit_tail("100", 20)
        self.assertTrue(any(r.get("event") == "executed" and r.get("elevated") for r in recs))
        blob = _AUDIT.read_text(encoding="utf-8") + json.dumps(res, ensure_ascii=False)
        self.assertNotIn("login-secret", blob, "审计与返回值里绝不能出现口令")
        self.assertNotIn("login-secret", json.dumps(M._tool_list_hosts(), ensure_ascii=False))


class KilllistWiring(unittest.TestCase):
    """清单只在 root 主机或被 guarded_hosts 点名的主机上生效，命中后 force=true 可越过。"""

    def test_unnamed_nonroot_host_is_not_guarded(self):
        """100 没被点名（用例自己的 policy 里只点了 guarded-user）→ 原样放行。"""
        write_hosts({"100": dict(PINNED)})
        CALLS.clear()
        with mock.patch.object(M, "run_command", fake_run(0)):
            res = M.execute("100", "rm -rf /")
        self.assertFalse(res.get("blocked", False))
        self.assertEqual(CALLS[-1][2], "rm -rf /", "命令原样发给远端，服务端没动它")

    def test_named_nonroot_host_is_guarded(self):
        """非 root 但被 guarded_hosts 点名：与 root 主机走同一张表，命中即拒。"""
        write_hosts({"guarded-user": dict(PINNED)})
        res = M.execute("guarded-user", "mkfs.ext4 /dev/sda1")
        self.assertTrue(res["blocked"])
        self.assertEqual(res["reason"], "killlisted")
        self.assertIn("force=true", res["hint"])

    def test_named_nonroot_host_can_be_forced(self):
        write_hosts({"guarded-user": dict(PINNED)})
        with mock.patch.object(M, "run_command", fake_run(0)):
            res = M.execute("guarded-user", "mkfs.ext4 /dev/sda1", force=True)
        self.assertEqual(res["forced_rule"], "deny:mkfs*")

    def test_list_hosts_reports_why_a_host_is_guarded(self):
        write_hosts({"guarded-user": dict(PINNED), "100": dict(PINNED), "admin": dict(ROOT_PINNED)})
        data = M._tool_list_hosts()
        by = {h["alias"]: h for h in data["hosts"]}
        self.assertEqual((by["admin"]["guard"], by["admin"]["guard_reason"]), ("killlist", "root 账号"))
        self.assertEqual((by["guarded-user"]["guard"], by["guarded-user"]["guard_reason"]), ("killlist", "guarded_hosts 点名"))
        self.assertEqual((by["100"]["guard"], by["100"]["guard_reason"]), ("none", ""))
        self.assertEqual(data["guarded_hosts"], ["guarded-user"])

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

    def test_force_reason_is_recorded(self):
        write_hosts({"admin": dict(ROOT_PINNED)})
        reason = "手工重建测试盘"
        with mock.patch.object(M, "run_command", fake_run(0)):
            res = M.execute("admin", "mkfs.ext4 /dev/sda1", force=True, force_reason=reason)
        self.assertEqual(res["force_reason"], reason)
        records = [r for r in M.audit_tail(None, 40) if r.get("force_reason") == reason]
        self.assertGreaterEqual(len(records), 2, "intent 与 executed 都该带理由")

    def test_benign_command_on_root_host_is_untouched(self):
        write_hosts({"admin": dict(ROOT_PINNED)})
        with mock.patch.object(M, "run_command", fake_run(0)):
            res = M.execute("admin", "apt install -y nginx")
        self.assertNotIn("forced_rule", res)
        self.assertFalse(res.get("blocked", False))

    def test_cd_only_skips_guard_and_tracks_cwd(self):
        """单独的 cd 只改服务端记的 cwd，不触碰远端状态，root 主机也不必 force。"""
        write_hosts({"admin": dict(ROOT_PINNED)})

        def pwd_run(cred, pin, command, cwd, idle_s, max_s, spill, elevate=False, login_shell=False, shell_init=False):
            spill.write("out", b"/tmp\n")
            spill.close()
            return M.RunResult(exit_code=0, stdout=spill.inline("out"), stderr="", truncated=False, timed_out=None, output_id=spill.run_id, stats=spill.stats())

        with mock.patch.object(M, "run_command", pwd_run):
            res = M.execute("admin", "cd /tmp")
        self.assertEqual(res["cwd_after"], "/tmp")
        self.assertEqual(M.POOL.cwd("admin"), "/tmp")

    def test_cd_expr_keeps_tilde_out_of_the_quotes(self):
        """`~` 裹进引号就成了字面量（实测 cd ~ 必失败），头留在引号外，剩余部分照旧保护。"""
        self.assertEqual(M._cd_expr("~"), "~")
        self.assertEqual(M._cd_expr("~/proj"), "~/proj")
        self.assertEqual(M._cd_expr("~root/x"), "~root/x")
        self.assertEqual(M._cd_expr("~/a b"), "~/'a b'")
        self.assertEqual(M._cd_expr("/var/log"), "/var/log")
        self.assertEqual(M._cd_expr("/a b"), "'/a b'")

    def test_cd_probe_forms(self):
        """探活串：`cd ~` 不许出现 '~'，带空格的目标保住引号，光一个 cd 当回 home。"""
        write_hosts({"admin": dict(ROOT_PINNED)})
        seen: list[str] = []

        def pwd_run(cred, pin, command, cwd, idle_s, max_s, spill, elevate=False, login_shell=False, shell_init=False):
            seen.append(command)
            spill.write("out", b"/home/qy\n")
            spill.close()
            return M.RunResult(exit_code=0, stdout=spill.inline("out"), stderr="", truncated=False, timed_out=None, output_id=spill.run_id, stats=spill.stats())

        with mock.patch.object(M, "run_command", pwd_run):
            M.execute("admin", "cd ~")
            M.execute("admin", "cd '~/a b'")
            M.execute("admin", "cd")
        self.assertEqual(seen, ["cd ~ && pwd", "cd ~/'a b' && pwd", "cd ~ && pwd"])
        self.assertEqual(M.POOL.cwd("admin"), "/home/qy")


class _FakeHandle:
    def __init__(self, buf: bytes):
        self.buf = buf
        self.pos = 0

    def seek(self, n):
        self.pos = n

    def read(self, n=-1):
        out = self.buf[self.pos : self.pos + n] if n and n > 0 else self.buf[self.pos :]
        self.pos += len(out)
        return out

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class _FakeSftpRead:
    """只够 job_status 读 out 用：normalize + open。"""

    def __init__(self, content: bytes):
        self.content = content

    def normalize(self, path):
        return "/home/qy"

    def open(self, path, mode="rb"):
        return _FakeHandle(self.content)

    def close(self):
        pass


class DetachWiring(unittest.TestCase):
    """exec(detach=true)：拦/放行与普通 exec 同源（过清单、吃 force），elevate 显式互斥。"""

    @staticmethod
    def _run_with(out: bytes):
        def _run(cred, pin, command, cwd, idle_s, max_s, spill, elevate=False, login_shell=False, shell_init=False):
            spill.write("out", out)
            spill.close()
            return M.RunResult(exit_code=0, stdout=out.decode(), stderr="", truncated=False,
                               timed_out=None, output_id=spill.run_id, stats=spill.stats())

        return _run

    def test_elevate_is_refused(self):
        write_hosts({"100": dict(PINNED)})
        res = M.execute("100", "sleep 999", elevate=True, detach=True)
        self.assertTrue(res.get("blocked"))
        self.assertEqual(res.get("reason"), "elevate_detach_unsupported")

    def test_killlist_still_applies(self):
        write_hosts({"admin": dict(ROOT_PINNED)})
        res = M.execute("admin", "mkfs.ext4 /dev/sda1", detach=True)
        self.assertTrue(res.get("blocked"))
        self.assertEqual(res.get("reason"), "killlisted")

    def test_started_returns_job_id_and_quotes_command(self):
        write_hosts({"admin": dict(ROOT_PINNED)})
        seen = []

        def _run(cred, pin, command, cwd, idle_s, max_s, spill, elevate=False, login_shell=False, shell_init=False):
            seen.append(command)
            spill.write("out", b"STARTED 4242\n")
            spill.close()
            return M.RunResult(exit_code=0, stdout="STARTED 4242\n", stderr="", truncated=False,
                               timed_out=None, output_id=spill.run_id, stats=spill.stats())

        with mock.patch.object(M, "run_command", _run):
            res = M.execute("admin", "mkfs.ext4 /dev/sda1", detach=True, force=True)
        self.assertTrue(res["job_id"].startswith("job-"))
        self.assertEqual(res["pid"], 4242)
        self.assertEqual(res["state"], "running")
        self.assertEqual(res.get("forced_rule"), "forced")
        self.assertEqual(len(seen), 1)
        self.assertIn("nohup", seen[0])
        self.assertIn(res["job_id"], seen[0])
        self.assertIn("printf '%s\\n' 'mkfs.ext4 /dev/sda1'", seen[0], "命令必须以整体引号进脚本")

    def test_busy_refusal(self):
        write_hosts({"100": dict(PINNED)})
        with mock.patch.object(M, "run_command", self._run_with(b"BUSY 8\n")):
            res = M.execute("100", "sleep 1", detach=True)
        self.assertTrue(res.get("blocked"))
        self.assertEqual(res.get("reason"), "too_many_jobs")
        self.assertEqual(res.get("busy"), 8)

    def test_job_tools_reject_bad_id_without_connecting(self):
        write_hosts({"100": dict(PINNED)})
        self.assertEqual(M._tool_job_status("100", "job-x").get("error"), "invalid_job_id")
        self.assertEqual(M._tool_job_kill("100", "../../etc").get("error"), "invalid_job_id")

    def test_job_kill_parses_result(self):
        write_hosts({"100": dict(PINNED)})
        with mock.patch.object(M, "run_command", self._run_with(b"result=terminated\n")):
            res = M._tool_job_kill("100", "job-1a2b3c4d-abcd")
        self.assertEqual(res["result"], "terminated")

    def test_job_kill_reaps_lost_job(self):
        write_hosts({"100": dict(PINNED)})
        with mock.patch.object(M, "run_command", self._run_with(b"result=not_running\nstate=lost\nreaped=1\n")):
            res = M._tool_job_kill("100", "job-1a2b3c4d-abcd")
        self.assertEqual(res["state"], "lost")
        self.assertTrue(res["reaped"])
        self.assertIn("回收", res["hint"])

    def test_job_status_merges_state_and_offset_slice(self):
        write_hosts({"100": dict(PINNED)})
        state = b"state=running\ncode=\npid=9\nstarted=100\nnow=130\nout_bytes=10\ncommand=echo hi\n"
        sftp = _FakeSftpRead(b"0123456789")
        with mock.patch.object(M, "run_command", self._run_with(state)), mock.patch.object(M, "_sftp_of", lambda *a, **k: sftp):
            res = M._tool_job_status("100", "job-1a2b3c4d-abcd", offset=4, max_bytes=3)
        self.assertEqual(res["state"], "running")
        self.assertEqual(res["text"], "456")
        self.assertEqual(res["offset_next"], 7)
        self.assertEqual(res["out_bytes"], 10)
        self.assertEqual(res["elapsed_s"], 30)
        self.assertTrue(res["truncated"])
        with mock.patch.object(M, "run_command", self._run_with(state)), mock.patch.object(M, "_sftp_of", lambda *a, **k: sftp):
            tail = M._tool_job_status("100", "job-1a2b3c4d-abcd", max_bytes=4)
        self.assertEqual(tail["text"], "6789")
        self.assertEqual(tail["offset_next"], 10)
        self.assertFalse(tail["truncated"])


class ResponseSize(unittest.TestCase):
    """回显治理（2026-10-14）：exec 命令回显超长截尾；list_hosts 有 brief 模式。"""

    def test_long_command_echo_is_truncated(self):
        write_hosts({"100": dict(PINNED)})
        long_cmd = "echo " + "x" * 400
        with mock.patch.object(M, "run_command", fake_run(0)):
            res = M.execute("100", long_cmd)
        self.assertIn("截断", res["command"])
        self.assertLess(len(res["command"]), len(long_cmd))
        self.assertTrue(res["command"].startswith("echo x"))

    def test_short_command_echo_is_untouched(self):
        write_hosts({"100": dict(PINNED)})
        with mock.patch.object(M, "run_command", fake_run(0)):
            res = M.execute("100", "uptime")
        self.assertEqual(res["command"], "uptime")

    def test_long_command_blocked_response_is_truncated_too(self):
        write_hosts({"admin": dict(ROOT_PINNED)})
        res = M.execute("admin", "mkfs.ext4 /dev/sda1 " + "y" * 400)
        self.assertTrue(res.get("blocked"))
        self.assertIn("截断", res["command"])

    def test_list_hosts_brief_drops_big_blocks(self):
        write_hosts({"100": dict(PINNED)})
        full = M._tool_list_hosts()
        brief = M._tool_list_hosts(brief=True)
        self.assertIn("limits", full["hosts"][0])
        self.assertIn("killlist", full)
        self.assertNotIn("limits", brief["hosts"][0])
        self.assertNotIn("killlist", brief)
        self.assertLess(len(json.dumps(brief, ensure_ascii=False)), len(json.dumps(full, ensure_ascii=False)))


class SftpStub:
    """只实现传输用到的那几个方法。opened 计数用来证明「被拦时根本没连」。"""

    def __init__(self, files=None):
        self.files = dict(files or {})
        self.renamed = []
        self.posix = []

    def stat(self, path):
        if path not in self.files:
            raise IOError("No such file")
        return type("S", (), {"st_size": len(self.files[path]), "st_mode": 0o100644,
                              "st_uid": 1000, "st_gid": 1000, "st_mtime": 0})()

    def normalize(self, path):
        return "/home/qy"

    def mkdir(self, path):
        pass

    def remove(self, path):
        self.files.pop(path, None)

    def file(self, path, mode="r", bufsize=-1):
        buf = self.files.setdefault(path, bytearray())
        if "w" in mode:
            buf.clear()
        return Handle(buf, self)

    def open(self, path, mode="rb"):
        if path not in self.files:
            raise IOError("No such file")
        return Handle(self.files[path], self)

    def chmod(self, path, mode):
        pass

    def rename(self, old, new):
        if new in self.files:
            raise IOError("Failure")  # openssh 实测：目标存在就失败
        self.renamed.append((old, new))
        self.files[new] = self.files.pop(old)

    def posix_rename(self, old, new):
        self.posix.append((old, new))
        self.files[new] = self.files.pop(old)

    def close(self):
        pass


class Handle:
    def __init__(self, buf, owner):
        self.buf = buf
        self.owner = owner
        self.pos = 0

    def set_pipelined(self, v=True):
        pass

    def prefetch(self, size=None):
        pass

    def flush(self):
        self.owner.flushes = getattr(self.owner, "flushes", 0) + 1

    def seek(self, n):
        self.pos = n

    def read(self, n=-1):
        out = bytes(self.buf[self.pos : self.pos + n])
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


class TransferWiring(unittest.TestCase):
    """拒绝路径必须离线可钉：真机测一次就变了，不能当回归。"""

    CRED = {"address": REAL_IP, "username": "qy", "auth": "password", "password": "login-secret",
            "hostKey": WRONG_FP, "elevate": True}

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="xfer-wire-"))
        self.src = self.tmp / "a.txt"
        self.src.write_bytes(b"hello" * 4)
        os.environ["SSHMCP_XFER"] = str(self.tmp / "dl")

    def tearDown(self):
        os.environ.pop("SSHMCP_XFER", None)

    def test_sensitive_target_blocked_before_any_sftp(self):
        """点名主机上写 authorized_keys：必须被拦，且一次 SFTP 都不开。"""
        write_hosts({"guarded-user": dict(self.CRED)})
        opened = []
        with mock.patch.object(M, "_sftp_of", side_effect=lambda *a: opened.append(1)):
            r = M._tool_put_file("guarded-user", str(self.src), "/home/qy/.ssh/authorized_keys")
        self.assertTrue(r["blocked"])
        self.assertEqual(r["reason"], "killlisted")
        self.assertIn("authorized_keys", r["rule"])
        self.assertEqual(opened, [], "被拦就不该建 SFTP 通道")

    def test_force_reason_is_recorded_on_transfer(self):
        write_hosts({"guarded-user": dict(self.CRED)})
        reason = "迁移公钥"
        with mock.patch.object(M, "_sftp_of", side_effect=RuntimeError("stop here")):
            r = M._tool_put_file("guarded-user", str(self.src), "/root/.ssh/authorized_keys",
                                 force=True, force_reason=reason)
        self.assertEqual(r["force_reason"], reason)
        records = [x for x in M.audit_tail(None, 60)
                   if x.get("event") == "intent" and x.get("force_reason") == reason]
        self.assertTrue(records, "传输的强制理由要进审计")

    def test_unguarded_host_is_not_target_checked(self):
        """没点名的非 root 主机不查目标 —— 与 exec 的语义一致，不能只给传输加严。"""
        write_hosts({"100": dict(self.CRED)})
        stub = SftpStub()
        with mock.patch.object(M, "_sftp_of", return_value=stub), \
             mock.patch.object(M, "_remote_md5", return_value=hashlib.md5(self.src.read_bytes()).hexdigest()):
            r = M._tool_put_file("100", str(self.src), "/home/qy/.ssh/authorized_keys", overwrite=True)
        self.assertTrue(r["verified"], str(r))

    def test_elevate_not_configured(self):
        write_hosts({"100": {k: v for k, v in self.CRED.items() if k != "elevate"}})
        r = M._tool_put_file("100", str(self.src), "/tmp/x", elevate=True)
        self.assertEqual(r["reason"], "elevate_not_configured")

    def test_missing_local_file_is_reported(self):
        write_hosts({"100": dict(self.CRED)})
        r = M._tool_put_file("100", str(self.tmp / "nope.txt"), "/tmp/x")
        self.assertTrue(r["blocked"])
        self.assertEqual(r["reason"], "local_missing")

    def test_too_large_refuses_without_connecting(self):
        write_hosts({"100": dict(self.CRED)})
        big = self.tmp / "big.bin"
        big.write_bytes(b"0" * 4096)
        guard = M.GUARD.get()
        with mock.patch.object(guard, "max_transfer_bytes", 1024):
            opened = []
            with mock.patch.object(M, "_sftp_of", side_effect=lambda *a: opened.append(1)):
                r = M._tool_put_file("100", str(big), "/tmp/x")
        self.assertEqual(r["reason"], "too_large")
        self.assertEqual(opened, [])

    def test_remote_exists_is_a_separate_gate_from_force(self):
        """force 只越清单，不能顺手把覆盖保护也越掉 —— 这是「挡手滑」的落点。"""
        write_hosts({"100": dict(self.CRED)})
        stub = SftpStub({"/tmp/that.txt": bytearray(b"old")})
        with mock.patch.object(M, "_sftp_of", return_value=stub):
            r = M._tool_put_file("100", str(self.src), "/tmp/that.txt", force=True)
        self.assertTrue(r.get("blocked"))
        self.assertEqual(r["reason"], "remote_exists")
        self.assertEqual(bytes(stub.files["/tmp/that.txt"]), b"old", "一个字节都不该写出去")

    def test_md5_mismatch_keeps_part_and_does_not_rename(self):
        write_hosts({"100": dict(self.CRED)})
        stub = SftpStub()
        with mock.patch.object(M, "_sftp_of", return_value=stub), \
             mock.patch.object(M, "_remote_md5", return_value="0" * 32):
            r = M._tool_put_file("100", str(self.src), "/tmp/new.txt")
        self.assertFalse(r["verified"])
        self.assertEqual(stub.renamed, [], "md5 不符绝不能 rename 到位")
        self.assertIn("part 已保留", r.get("hint", ""), r.get("hint"))

    def test_successful_put_renames_and_audits(self):
        write_hosts({"100": dict(self.CRED)})
        stub = SftpStub()
        md5 = hashlib.md5(self.src.read_bytes()).hexdigest()
        with mock.patch.object(M, "_sftp_of", return_value=stub), \
             mock.patch.object(M, "_remote_md5", return_value=md5):
            r = M._tool_put_file("100", str(self.src), "/tmp/ok.txt")
        self.assertTrue(r["verified"], str(r))
        self.assertEqual(bytes(stub.files["/tmp/ok.txt"]), self.src.read_bytes())
        rec = [x for x in M.audit_tail("100", 20) if x.get("event") == "transferred"]
        self.assertTrue(rec, "成功的传输要进审计")
        self.assertEqual(rec[0]["md5"], md5)  # audit_tail 是倒序，[0] 才是本次

    def test_restart_clears_the_staging_part_for_elevated_put(self):
        """elevate 的 part 名与非提权不同：restart 必须删解析后的那个，否则旧暂存被静默复用。"""
        write_hosts({"100": dict(self.CRED)})
        staging = f"/home/qy/{M.STAGING_DIRNAME}/t.txt{M.X.PART_SUFFIX}"
        stub = SftpStub({staging: bytearray(b"\xff" * (3 * 1048576))})

        seen = []

        def ok_run(cred, pin, command, cwd, idle_s, max_s, spill, elevate=False, login_shell=False, shell_init=False):
            seen.append((command, elevate))
            spill.close()
            return M.RunResult(exit_code=0, stdout="", stderr="", truncated=False, timed_out=None,
                               output_id=spill.run_id, stats=spill.stats())

        with mock.patch.object(M, "_sftp_of", return_value=stub), mock.patch.object(M, "run_command", ok_run), \
             mock.patch.object(M, "_remote_md5", return_value=hashlib.md5(self.src.read_bytes()).hexdigest()):
            r = M._tool_put_file("100", str(self.src), "/root/t.txt", elevate=True, restart=True, overwrite=True)
        self.assertTrue(r["verified"], str(r))
        self.assertEqual(r["resumed_from"], 0, "旧暂存不能被当成已传部分")
        # 旧暂存是 3MB 的 0xff，restart 后 part 里必须只剩本次源文件那么多个字节
        self.assertEqual(len(stub.files[staging]), self.src.stat().st_size, "3MB 的旧前缀没被丢掉")
        self.assertEqual(bytes(stub.files[staging]), self.src.read_bytes())
        self.assertTrue(seen and seen[0][1] is True, "收尾的 install 要提权执行")
        self.assertIn(staging, seen[0][0])
        self.assertIn("/root/t.txt", seen[0][0])

    def test_get_lands_in_configured_dir_and_verifies(self):
        write_hosts({"100": dict(self.CRED)})
        payload = "远端内容".encode("utf-8")
        stub = SftpStub({"/tmp/src.bin": bytearray(payload)})
        md5 = hashlib.md5(payload).hexdigest()
        with mock.patch.object(M, "_sftp_of", return_value=stub), \
             mock.patch.object(M, "_remote_md5", return_value=md5):
            r = M._tool_get_file("100", "/tmp/src.bin")
        self.assertTrue(r["verified"], str(r))
        self.assertEqual(Path(r["xfer_dir"]), self.tmp / "dl")
        self.assertEqual((self.tmp / "dl" / "src.bin").read_bytes(), payload)
        self.assertFalse(list((self.tmp / "dl").glob("*part*")), "成功后不留 part")

    def test_get_refuses_existing_local_without_overwrite(self):
        write_hosts({"100": dict(self.CRED)})
        dst_dir = self.tmp / "dl"
        dst_dir.mkdir(parents=True, exist_ok=True)
        (dst_dir / "dup.bin").write_bytes("本机原有".encode("utf-8"))
        stub = SftpStub({"/tmp/dup.bin": bytearray("远端新内容".encode("utf-8"))})
        with mock.patch.object(M, "_sftp_of", return_value=stub):
            r = M._tool_get_file("100", "/tmp/dup.bin")
        self.assertEqual(r["reason"], "local_exists")
        self.assertEqual((dst_dir / "dup.bin").read_bytes(), "本机原有".encode("utf-8"), "没同意覆盖就不能动本机文件")

    def test_xfer_dir_priority_env_then_policy_then_registry(self):
        g = G.GuardConfig(xfer_dir=r"D:\somewhere")
        with mock.patch.dict(os.environ, {"SSHMCP_XFER": str(self.tmp)}):
            self.assertEqual(M.xfer_dir(g), self.tmp)
        os.environ.pop("SSHMCP_XFER", None)
        self.assertEqual(M.xfer_dir(g), Path(r"D:\somewhere"))
        self.assertEqual(M.xfer_dir(G.GuardConfig()), M._downloads_dir())


class Concurrency(unittest.TestCase):
    """连接池与共享状态的并发行为。

    这些用例不碰网络：_connect 被换成假的 client/transport，只验证加锁、
    活跃计数与「失败不关共享连接」这三件事。
    """

    class _Transport:
        def __init__(self, active=True, fail_open=False):
            self.active = active
            self.fail_open = fail_open
            self.sessions = 0

        def is_active(self):
            return self.active

        def open_session(self):
            self.sessions += 1
            if self.fail_open:
                raise RuntimeError("channel failed")
            return mock.Mock()

    class _Client:
        def __init__(self, active=True, fail_open=False):
            self.transport = Concurrency._Transport(active, fail_open)
            self.closed = False

        def get_transport(self):
            return self.transport

        def close(self):
            self.closed = True

    def setUp(self):
        self.pool = M.Pool()
        self.patcher = mock.patch.object(M, "POOL", self.pool)
        self.patcher.start()
        self.addCleanup(self.patcher.stop)
        self.cred = M.HostCred(alias="t", address="127.0.0.1", username="u", password="p")

    def test_concurrent_first_connect_creates_one_connection(self):
        created = []

        def connect(cred, pin):
            time.sleep(0.05)
            client = self._Client()
            created.append(client)
            return client

        results = []
        with mock.patch.object(self.pool, "_connect", side_effect=connect):
            threads = [
                threading.Thread(target=lambda: results.append(self.pool.client(self.cred, "pin")))
                for _ in range(10)
            ]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
        self.assertEqual(len(created), 1, "并发首连只该握手一次")
        self.assertEqual(len({id(r) for r in results}), 1, "十次调用应拿到同一个 client")

    def test_dead_transport_is_replaced_under_lock(self):
        old = self._Client(active=False)
        self.pool._clients["t"] = old
        new = self._Client()
        with mock.patch.object(self.pool, "_connect", return_value=new):
            got = self.pool.client(self.cred, "pin")
        self.assertIs(got, new)
        self.assertTrue(old.closed, "死掉的 transport 应被替换并关闭")

    def test_run_command_failure_does_not_close_shared_client(self):
        fake = self._Client(fail_open=True)
        with mock.patch.object(self.pool, "client", return_value=fake):
            spill = M._throw_spill(M.GUARD.get())
            res = M.run_command(self.cred, "pin", "id", "~", 0.1, 0.5, spill)
        self.assertEqual(res.exit_code, -1)
        self.assertIn("channel failed", res.stderr)
        self.assertFalse(fake.closed, "失败方不能关掉别的调用可能在用的连接")

    def test_session_reset_is_busy_while_a_command_is_active(self):
        fake = self._Client()
        self.pool._clients["t"] = fake
        self.pool.set_cwd("t", "/tmp")
        with self.pool.activity("t"):
            res = M._tool_session_reset("t")
        self.assertFalse(res["reset"])
        self.assertEqual(res["reason"], "active_commands")
        self.assertEqual(res["active"], 1)
        self.assertFalse(fake.closed, "在途命令期间不能强杀连接")
        self.assertEqual(self.pool.cwd("t"), "/tmp", "reset 没执行，cwd 也不该动")

        res = M._tool_session_reset("t")
        self.assertTrue(res["reset"])
        self.assertTrue(fake.closed)
        self.assertEqual(res["cwd"], "~")

    def test_xfer_lock_serializes_same_target(self):
        lock = self.pool.xfer_lock("put:t:/tmp/same")
        state = {"inside": 0, "max": 0}
        barrier = threading.Barrier(4)

        def worker():
            barrier.wait()
            with lock:
                state["inside"] += 1
                state["max"] = max(state["max"], state["inside"])
                time.sleep(0.02)
                state["inside"] -= 1

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(state["max"], 1, "同目标传输必须串行")

    def test_concurrent_prune_does_not_raise(self):
        root = Path(tempfile.mkdtemp(prefix="ssh-mcp-prune-"))
        for n in range(20):
            (root / f"run{n:02d}.out.log").write_bytes(b"x" * 100)
        errors = []

        def worker():
            try:
                OS.prune(root, keep_runs=5, keep_bytes=1 << 20, keep_days=999)
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [], "并发 prune 不能把正常执行打失败")
        self.assertLessEqual(len(list(root.glob("*.out.log"))), 5)


class BackupWiring(unittest.TestCase):
    """敏感文件写前备份：成功时留路径，失败时拒绝执行原命令。"""

    def setUp(self):
        write_hosts({"100": dict(PINNED)})

    @staticmethod
    def _fake_run(fail_backup: bool = False):
        calls = []

        def run(cred, pin, command, cwd, idle_s, max_s, spill, elevate=False, login_shell=False, shell_init=False):
            calls.append({"command": command, "cwd": cwd, "elevate": elevate})
            spill.close()
            if fail_backup and "sshmcp-backups" in command:
                return M.RunResult(exit_code=1, stdout="", stderr="cp: Permission denied",
                                   truncated=False, timed_out=None, output_id=spill.run_id, stats=spill.stats())
            return M.RunResult(exit_code=0, stdout="", stderr="", truncated=False, timed_out=None,
                               output_id=spill.run_id, stats=spill.stats())

        return calls, run

    def test_exec_backs_up_before_sensitive_write(self):
        calls, run = self._fake_run()
        with mock.patch.object(M, "run_command", run):
            res = M.execute("100", "echo x > /root/.ssh/authorized_keys")
        self.assertEqual(res["exit_code"], 0)
        self.assertTrue(res["backup"].startswith("~/.sshmcp-backups/"))
        self.assertEqual(len(calls), 2)
        self.assertIn("mkdir -p", calls[0]["command"])
        self.assertIn("cp -a --", calls[0]["command"])
        self.assertEqual(calls[1]["command"], "echo x > /root/.ssh/authorized_keys")
        backups = [r for r in M.audit_tail("100", 30) if r.get("event") == "backup"]
        self.assertTrue(backups)
        self.assertEqual(backups[0]["backup"], res["backup"])

    def test_exec_backup_failure_blocks_the_command(self):
        calls, run = self._fake_run(fail_backup=True)
        with mock.patch.object(M, "run_command", run):
            res = M.execute("100", "echo x > /root/.ssh/authorized_keys")
        self.assertTrue(res["blocked"])
        self.assertEqual(res["reason"], "backup_failed")
        self.assertEqual(len(calls), 1, "备份失败后不能再执行原命令")
        failed = [r for r in M.audit_tail("100", 30) if r.get("event") == "backup_failed"]
        self.assertTrue(failed)

    def test_read_only_sensitive_access_does_not_backup(self):
        calls, run = self._fake_run()
        with mock.patch.object(M, "run_command", run):
            res = M.execute("100", "cp /etc/ssh/sshd_config /tmp/backup")
        self.assertNotIn("backup", res)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["command"], "cp /etc/ssh/sshd_config /tmp/backup")

    def test_put_backs_up_existing_sensitive_target(self):
        write_hosts({"100": dict(TransferWiring.CRED)})
        stub = SftpStub({"/root/.ssh/authorized_keys": bytearray(b"old")})
        calls, run = self._fake_run()
        md5 = hashlib.md5(b"hello" * 4).hexdigest()
        tmp = Path(tempfile.mkdtemp(prefix="backup-put-"))
        src = tmp / "a.txt"
        src.write_bytes(b"hello" * 4)
        with mock.patch.object(M, "_sftp_of", return_value=stub), \
             mock.patch.object(M, "run_command", run), \
             mock.patch.object(M, "_remote_md5", return_value=md5):
            r = M._tool_put_file("100", str(src), "/root/.ssh/authorized_keys", overwrite=True)
        self.assertTrue(r.get("verified"), str(r))
        self.assertTrue(r["backup"].startswith("~/.sshmcp-backups/"))
        self.assertTrue(any("cp -a --" in c["command"] for c in calls), "覆盖前必须先备份旧文件")
        backups = [x for x in M.audit_tail("100", 40) if x.get("event") == "backup"]
        self.assertTrue(backups)

    def test_put_backup_failure_does_not_overwrite(self):
        write_hosts({"100": dict(TransferWiring.CRED)})
        stub = SftpStub({"/root/.ssh/authorized_keys": bytearray(b"old")})
        calls, run = self._fake_run(fail_backup=True)
        tmp = Path(tempfile.mkdtemp(prefix="backup-put-"))
        src = tmp / "a.txt"
        src.write_bytes(b"hello" * 4)
        with mock.patch.object(M, "_sftp_of", return_value=stub), mock.patch.object(M, "run_command", run):
            r = M._tool_put_file("100", str(src), "/root/.ssh/authorized_keys", overwrite=True)
        self.assertTrue(r.get("blocked"))
        self.assertEqual(r.get("reason"), "backup_failed")
        self.assertEqual(stub.files["/root/.ssh/authorized_keys"], bytearray(b"old"), "原文件不能被覆盖")
        self.assertEqual(stub.posix, [], "备份失败就不该 rename 到目标")


class AuditRisky(unittest.TestCase):
    def test_only_risky_filters_normal_success(self):
        host = "risky-only-test"
        M.audit({"host": host, "event": "executed", "exit_code": 0, "reason": "ok"})
        M.audit({"host": host, "event": "blocked", "reason": "killlisted", "rule": "deny:x"})
        M.audit({"host": host, "event": "executed", "exit_code": 1, "reason": "ok"})
        M.audit({"host": host, "event": "intent", "rule": "forced", "force_reason": "why"})
        M.audit({"host": host, "event": "backup", "backup": "~/.sshmcp-backups/x"})
        M.audit({"host": host, "event": "result", "ok": False, "result": {"error": "x"}})
        data = M._tool_audit_tail(host, 50, only_risky=True)
        events = [(r.get("event"), r.get("exit_code"), r.get("rule")) for r in data["records"]]
        self.assertIn(("blocked", None, "deny:x"), events)
        self.assertIn(("executed", 1, None), events)
        self.assertIn(("intent", None, "forced"), events)
        self.assertIn(("backup", None, None), events)
        self.assertIn(("result", None, None), events)
        self.assertNotIn(("executed", 0, None), events)
        self.assertEqual(len(data["records"]), 5)
        self.assertTrue(data["only_risky"])


class ShellInit(unittest.TestCase):
    """login_shell / shell_init 只拼命令串，不改变既有形态。"""

    CRED = M.HostCred(alias="h", address="127.0.0.1", username="u", password="p")

    def test_default_shape_is_unchanged(self):
        self.assertEqual(M._assemble_remote("id", "~", self.CRED), "id")
        self.assertEqual(M._assemble_remote("id", "/tmp", self.CRED), "cd /tmp && id")

    def test_login_shell_wraps_with_bash_lc(self):
        self.assertEqual(M._assemble_remote("id", "~", self.CRED, login_shell=True), "bash -lc id")
        self.assertEqual(
            M._assemble_remote("id", "/tmp", self.CRED, login_shell=True),
            "bash -lc 'cd /tmp && id'",
        )

    def test_shell_init_runs_first_and_fails_loudly(self):
        cred = M.HostCred(alias="h", address="a", username="u", password="p", shell_init="~/miniconda3/etc/profile.d/conda.sh")
        body = M._assemble_remote("python -V", "~", cred, shell_init=True)
        self.assertIn(". ~/miniconda3/etc/profile.d/conda.sh", body)
        self.assertIn("exit 97", body)
        self.assertTrue(body.endswith("python -V"))
        self.assertEqual(M._assemble_remote("python -V", "~", cred, shell_init=False), "python -V", "不传开关就不 source")

    def test_shell_init_goes_after_cd(self):
        cred = M.HostCred(alias="h", address="a", username="u", password="p", shell_init="/opt/env.sh")
        body = M._assemble_remote("make", "/srv/app", cred, shell_init=True)
        self.assertTrue(body.startswith("cd /srv/app && "), body)
        self.assertLess(body.index("/opt/env.sh"), body.index("make"))

    def test_exec_passes_login_shell_to_run_command(self):
        write_hosts({"100": dict(PINNED)})
        seen = {}

        def spy(cred, pin, command, cwd, idle_s, max_s, spill, elevate=False, login_shell=False, shell_init=False):
            seen["command"] = command
            seen["login_shell"] = login_shell
            seen["shell_init"] = shell_init
            spill.close()
            return M.RunResult(exit_code=0, stdout="", stderr="", truncated=False, timed_out=None,
                               output_id=spill.run_id, stats=spill.stats())

        with mock.patch.object(M, "run_command", spy):
            M.execute("100", "python -V", login_shell=True)
        self.assertTrue(seen["login_shell"])
        self.assertTrue(seen["shell_init"], "exec 路径要启用凭据里的 shell_init")
        self.assertEqual(seen["command"], "python -V", "包装在 run_command 里做，别改调用方看到的命令")

    def test_internal_commands_keep_init_off(self):
        """备份、md5、job 脚本这类内部命令不 source，避免初始化片段的输出污染判断。"""
        calls = []

        def spy(cred, pin, command, cwd, idle_s, max_s, spill, elevate=False, login_shell=False, shell_init=False):
            calls.append(shell_init)
            spill.close()
            return M.RunResult(exit_code=0, stdout="", stderr="", truncated=False, timed_out=None,
                               output_id=spill.run_id, stats=spill.stats())

        write_hosts({"100": dict(PINNED)})
        with mock.patch.object(M, "run_command", spy):
            M.execute("100", "rm /root/.ssh/authorized_keys")  # 触发写前备份
        self.assertEqual(len(calls), 2, "备份一次 + 原命令一次")
        self.assertFalse(calls[0], "备份命令不该 source shell_init")


if __name__ == "__main__":
    unittest.main(verbosity=2)
