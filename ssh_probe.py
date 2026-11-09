# /// script
# requires-python = ">=3.11"
# dependencies = ["paramiko>=3.4"]
# ///
"""ssh_probe —— 指纹探测、私钥加载与一次性连测。

从 ssh_mcp.py 抽出来，让主机配置窗口（hosts_gui.py）只依赖 paramiko，
不用为了点一下"探测指纹"去 import 整个 MCP 服务模块。

**探测不发凭据**：probe_hostkey 只走到密钥交换，服务端拿不到用户名与口令。
这是把探测交给 AI 也能安全的前提，别改成连上再问指纹。
"""

from __future__ import annotations

import base64
import hashlib
import socket
import time
from dataclasses import dataclass
from pathlib import Path


class HostKeyMismatch(Exception):
    """指纹不符或未固定：连接必须停在这里，不能"先连上再说"。"""


def sha256_fingerprint(key) -> str:
    blob = key.asbytes()
    digest = base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii")
    return f"SHA256:{digest.rstrip('=')}"


def probe_hostkey(address: str, port: int = 22, timeout: float = 10.0) -> tuple[str, str]:
    """只走到密钥交换为止取对方主机密钥，一个凭据都不发。"""
    import paramiko

    sock = socket.create_connection((address, port), timeout=timeout)
    transport = None
    try:
        transport = paramiko.Transport(sock)
        transport.start_client(timeout=timeout)
        key = transport.get_remote_server_key()
        return sha256_fingerprint(key), key.get_name()
    finally:
        if transport is not None:
            try:
                transport.close()
            except Exception:  # noqa: BLE001 - 探测收尾的断开失败不影响已取到的密钥
                pass
        sock.close()


def build_pinned_policy(expected: str):
    import paramiko

    class _Pinned(paramiko.MissingHostKeyPolicy):
        def missing_host_key(self, client, hostname, key):  # noqa: ARG002
            got = sha256_fingerprint(key)
            if expected and got != expected:
                raise HostKeyMismatch(f"{hostname} 指纹不匹配：期望 {expected}，实际 {got}")
            if not expected:
                raise HostKeyMismatch(f"{hostname} 未固定主机指纹，拒绝连接（先探测并确认）")

    return _Pinned()


def from_ssh_agent():
    """把私钥交给 ssh-agent 签名：带 passphrase 的私钥不必进进程内存。

    只取 agent 里的第一把 key。逐把试认证会连着打远端的失败次数。
    """
    try:
        from paramiko.agent import Agent

        keys = Agent().get_keys()
    except Exception:  # noqa: BLE001 - agent 服务没起时 paramiko 直接抛，按"没有可用 key"处理
        return None
    return keys[0] if keys else None


def load_private_key(cred) -> object:
    """按 key_path / ~/.ssh 常见文件名 / ssh-agent 的顺序找一把能用的私钥。"""
    import paramiko

    candidates = [cred.key_path] if getattr(cred, "key_path", "") else []
    if not candidates:
        ssh_dir = Path.home() / ".ssh"
        candidates = [ssh_dir / n for n in ("id_ed25519", "id_rsa", "id_ecdsa", "id_dsa")]
    loaders = [
        getattr(paramiko, name)
        for name in ("Ed25519Key", "RSAKey", "ECDSAKey", "DSSKey")
        if hasattr(paramiko, name)
    ]  # paramiko 5.x 删了 DSSKey，写死列表会让整条 key 认证炸掉
    for raw in candidates:
        path = Path(str(raw)).expanduser()
        if not path.is_file():
            continue
        for loader in loaders:
            try:
                return loader.from_private_key_file(str(path))
            except Exception:  # noqa: BLE001 - 类型不匹配是正常尝试路径
                continue
    key = from_ssh_agent()
    if key is not None:
        return key
    raise RuntimeError(
        "找不到可用私钥：候选文件都解不开（带 passphrase 的文件私钥不支持），ssh-agent 里也没有 key。"
        "请让 key_path 指向无口令私钥，或把私钥 ssh-add 进 agent"
    )


@dataclass
class ProbeCred:
    """只给 GUI / 连测用的轻量凭据；字段名与服务端 HostCred 对齐。"""

    address: str
    port: int = 22
    username: str = ""
    auth: str = "password"
    password: str = ""
    key_path: str = ""
    alias: str = "probe"


PROBE_COMMAND = "cat /etc/os-release 2>/dev/null | head -2; uname -m"


def test_connection(cred, expected_pin: str = "", timeout: float = 10.0) -> dict:
    """用给定凭据连一次，跑一条固定探针并断开。

    只跑 `PROBE_COMMAND`，不开放任意命令输入 —— 这个工具是配主机的，不是第二个终端。
    """
    import paramiko

    started = time.monotonic()
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(build_pinned_policy(expected_pin))
    kwargs = {
        "hostname": cred.address,
        "port": int(cred.port or 22),
        "username": cred.username,
        "timeout": timeout,
        "banner_timeout": timeout,
        "auth_timeout": timeout,
        "look_for_keys": False,
        "allow_agent": False,
    }
    if cred.auth == "key":
        kwargs["pkey"] = load_private_key(cred)
        kwargs["allow_agent"] = True
    else:
        kwargs["password"] = cred.password
    out: dict = {"address": cred.address, "port": int(cred.port or 22)}
    try:
        client.connect(**kwargs)
        transport = client.get_transport()
        out["server"] = getattr(transport, "remote_version", "") if transport else ""
        stdin, stdout, stderr = client.exec_command(PROBE_COMMAND, timeout=timeout)
        text = stdout.read().decode("utf-8", "replace").strip()
        err = stderr.read().decode("utf-8", "replace").strip()
        lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
        if len(lines) >= 3 and "=" in lines[0]:
            out["os"] = " / ".join(lines[:2])
            out["arch"] = lines[-1]
        elif lines:
            out["os"] = lines[0]
            out["arch"] = lines[-1] if len(lines) > 1 else ""
        if err:
            out["stderr"] = err[:200]
        out["ok"] = True
    except HostKeyMismatch as exc:
        out.update({"ok": False, "error": str(exc), "reason": "host_key_mismatch"})
    except Exception as exc:  # noqa: BLE001 - 网络/认证错误形态太杂，原样回给界面
        out.update({"ok": False, "error": f"{type(exc).__name__}: {exc}", "reason": "connect_failed"})
    finally:
        try:
            client.close()
        except Exception:  # noqa: BLE001
            pass
        out["elapsed_ms"] = round((time.monotonic() - started) * 1000)
    return out
