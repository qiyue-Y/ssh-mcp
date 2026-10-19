# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "mcp>=1.2",
#     "paramiko>=3.4",
# ]
# ///
"""ssh-mcp —— 常驻 SSH 会话的 MCP 服务：连接复用、全文日志、凭据注入。

2026-09-29 起解除权限控制：原 ro 白名单 / rw 黑名单 / 人工 grant 三层判定全部移除
（命令过滤挡不住蓄意绕行的 AI，却给每一条正常命令加了一轮往返）。服务端只在
`username == "root"` 的主机上查一张自杀清单（policy.json 的 killlist），命中可由
exec(force=true) 直接放行。真正的边界是远端账号自己的权限。

用法：
    ssh_mcp.py [serve]                                  # 作为 MCP 服务跑（stdio）
    ssh_mcp.py doctor                                   # 检查配置与凭据
    ssh_mcp.py list                                     # 列出主机与指纹固定状态

约定：stdout 被 MCP 协议独占，本文件所有日志一律走 stderr。
"""

from __future__ import annotations

import argparse
import base64
import contextvars
import functools
import hashlib
import inspect
import json
import os
import shlex
import shutil
import socket
import stat
import sys
import threading
import time
import traceback
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import ssh_guard as G  # noqa: E402
import ssh_jobs as J  # noqa: E402
import ssh_xfer as X  # noqa: E402
import output_store as OS  # noqa: E402


def _downloads_dir() -> Path:
    """本机默认下载目录。Windows 的下载目录可能被重定向到别的盘，所以读注册表而不是猜。"""
    if os.name == "nt":
        try:
            import winreg

            with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
            ) as key:
                raw, _ = winreg.QueryValueEx(key, "{374DE290-123F-4565-9164-39C4925E467B}")
            return Path(os.path.expandvars(str(raw)))
        except OSError:
            return Path.home() / "Downloads"
    return Path.home() / "Downloads"


def xfer_dir(guard: G.GuardConfig) -> Path:
    """优先级：SSHMCP_XFER 环境变量 > policy.json 的 defaults.xfer_dir > 平台下载目录。"""
    if os.environ.get("SSHMCP_XFER"):
        return Path(os.environ["SSHMCP_XFER"]).expanduser()
    if guard.xfer_dir:
        return Path(guard.xfer_dir).expanduser()
    return _downloads_dir()


def _path_from_env(var: str, default: Path) -> Path:
    raw = os.environ.get(var)
    return Path(raw).expanduser() if raw else default


HOME_DIR = _path_from_env("SSHMCP_HOME", HERE)
POLICY_PATH = _path_from_env("SSHMCP_POLICY", HOME_DIR / "policy.json")
HOSTS_PATH = _path_from_env("SSHMCP_HOSTS", HOME_DIR / "ssh_mcp_hosts.json")
HOSTKEYS_PATH = _path_from_env("SSHMCP_HOSTKEYS", HOME_DIR / "hostkeys.json")
AUDIT_PATH = _path_from_env("SSHMCP_AUDIT", HOME_DIR / "audit" / "ssh-mcp.jsonl")
OUTPUT_ROOT = _path_from_env("SSHMCP_OUTPUT", HOME_DIR / "output")

# 回给 Agent 的内联预算（字节）。全文在 output/ 里，想看随时 read_output 捞。
INLINE_OUT = (4096, 4096)
INLINE_ERR = (1024, 2048)
OUTPUT_KEEP_RUNS = int(os.environ.get("SSHMCP_OUTPUT_KEEP_RUNS", "200"))
OUTPUT_KEEP_BYTES = int(os.environ.get("SSHMCP_OUTPUT_KEEP_BYTES", str(500 * 1024 * 1024)))
OUTPUT_KEEP_DAYS = int(os.environ.get("SSHMCP_OUTPUT_KEEP_DAYS", "14"))
AUDIT_KEEP_DAYS = int(os.environ.get("SSHMCP_AUDIT_KEEP_DAYS", "14"))


def log(msg: str) -> None:
    print(f"[ssh-mcp] {msg}", file=sys.stderr, flush=True)


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds")


# --------------------------------------------------------------------------------------
# 配置：limits/killlist 与 hostkeys 都按 mtime 热加载，改完不必重启服务
# --------------------------------------------------------------------------------------


class CachedJson:
    def __init__(self, path: Path, loader):
        self.path = path
        self.loader = loader
        self._mtime: float | None = None
        self._value: Any = None
        self._lock = threading.Lock()

    def get(self):
        with self._lock:
            try:
                mtime = self.path.stat().st_mtime
            except FileNotFoundError:
                if self._mtime != -1:
                    self._mtime, self._value = -1, self.loader(None)
                return self._value
            if mtime != self._mtime:
                try:
                    raw = json.loads(self.path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError) as exc:
                    log(f"读取 {self.path} 失败：{exc}（沿用上一次配置）")
                    if self._value is not None:
                        return self._value
                    raise
                self._mtime, self._value = mtime, self.loader(raw)
            return self._value


@dataclass
class HostCred:
    alias: str
    address: str
    port: int = 22
    username: str = ""
    auth: str = "password"
    password: str = ""
    key_path: str = ""
    host_key: str = ""
    purpose: str = ""
    # 提权项：elevate=true 表示这台允许 exec(..., elevate=true) 以 root 跑单条命令。
    # sudo 校验的是登录用户自己的口令，所以 elevate_password 留空就复用上面的 password；
    # 只有「root 口令与登录口令不同」的机器才需要单独填。
    elevate: bool = False
    elevate_user: str = "root"
    elevate_password: str = ""

    @property
    def privileged(self) -> bool:
        # root 账号恒查 killlist；非 root 要靠 policy.json 的 guarded_hosts 点名
        return self.username == "root"

    def sudo_password(self) -> str:
        return self.elevate_password or self.password


_KEY_ALIASES = {
    "hostKey": "host_key",
    "hostkey": "host_key",
    "keyPath": "key_path",
    "elevateUser": "elevate_user",
    "elevatePassword": "elevate_password",
}


def _load_hosts(raw: dict | None) -> dict[str, HostCred]:
    if not raw:
        return {}
    out: dict[str, HostCred] = {}
    known = set(HostCred.__dataclass_fields__)
    for alias, entry in raw.items():
        if not isinstance(entry, dict) or alias.startswith("_"):
            continue
        data = {
            _KEY_ALIASES.get(k, k): v
            for k, v in entry.items()
            if _KEY_ALIASES.get(k, k) in known
        }
        out[alias] = HostCred(alias=alias, **data)
    return out


GUARD = CachedJson(POLICY_PATH, G.load_guard)
HOSTS = CachedJson(HOSTS_PATH, _load_hosts)


def _load_pins(raw: dict | None) -> dict[str, str]:
    """alias -> SHA256:xxx。只给凭据文件里没钉 hostKey 的主机兜底。"""
    return {k: str(v) for k, v in (raw or {}).items() if not k.startswith("_")}


PINS = CachedJson(HOSTKEYS_PATH, _load_pins)


def save_pin(alias: str, fingerprint: str) -> None:
    HOSTKEYS_PATH.parent.mkdir(parents=True, exist_ok=True)
    data = dict(PINS.get())
    data[alias] = fingerprint
    tmp = HOSTKEYS_PATH.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, HOSTKEYS_PATH)
    PINS._mtime = None  # 强制下次重读


def effective_pin(alias: str, cred: HostCred | None) -> tuple[str, str]:
    """返回 (指纹, 来源)。凭据文件优先 —— 那里钉过就得由人去改，AI 写的 pin 不算。"""
    if cred is not None and cred.host_key:
        return cred.host_key, "credential"
    pin = PINS.get().get(alias, "")
    return (pin, "hostkeys") if pin else ("", "")


# --------------------------------------------------------------------------------------
# 自杀清单：只对 username == "root" 的主机查（见 execute）
# --------------------------------------------------------------------------------------



# --------------------------------------------------------------------------------------
# 审计
# --------------------------------------------------------------------------------------


_CALL_ID: contextvars.ContextVar[str | None] = contextvars.ContextVar("ssh_mcp_call_id", default=None)
_CALL_TOOL: contextvars.ContextVar[str | None] = contextvars.ContextVar("ssh_mcp_call_tool", default=None)
_AUDIT_LOCK = threading.Lock()
_OUTPUT_HOSTS: dict[str, str] = {}
_OUTPUT_HOSTS_LOCK = threading.Lock()
_OUTPUT_HOSTS_MAX = 4096


def audit(record: dict) -> None:
    call_id = _CALL_ID.get()
    if call_id:
        record.setdefault("call_id", call_id)
    tool = _CALL_TOOL.get()
    if tool:
        record.setdefault("tool", tool)
    record.setdefault("ts", iso(now_utc()))
    line = json.dumps(record, ensure_ascii=False) + "\n"
    with _AUDIT_LOCK:
        AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
        try:
            _rotate_audit()
            _prune_audit()
        except OSError as exc:  # 轮转失败不该挡执行：继续写当前文件
            log(f"审计轮转失败（继续写当前文件）：{exc}")
        with AUDIT_PATH.open("a", encoding="utf-8") as fh:
            fh.write(line)


def _audit_files() -> list[Path]:
    """当前文件 + 轮转出去的 ssh-mcp.YYYYMMDD[-n].jsonl，按 mtime 从旧到新。"""
    if not AUDIT_PATH.parent.is_dir():
        return []
    stem, suffix = AUDIT_PATH.stem, AUDIT_PATH.suffix
    rotated: list[Path] = []
    for path in AUDIT_PATH.parent.glob(f"{stem}.*{suffix}"):
        if not path.is_file():
            continue
        middle = path.name[len(stem) + 1 : len(path.name) - len(suffix)]
        head = middle.split("-")[0]
        if len(head) == 8 and head.isdigit():
            rotated.append(path)
    files = rotated + ([AUDIT_PATH] if AUDIT_PATH.is_file() else [])

    def mtime(path: Path) -> float:
        try:
            return path.stat().st_mtime
        except OSError:
            return 0.0

    return sorted(files, key=lambda p: (mtime(p), p.name))


def _rotate_audit() -> None:
    """写新一天的第一条记录前，把旧文件按最后写入日期改名归档。"""
    try:
        mtime = AUDIT_PATH.stat().st_mtime
    except FileNotFoundError:
        return
    day = datetime.fromtimestamp(mtime, timezone.utc).date()
    if day >= now_utc().date():
        return
    dest = AUDIT_PATH.with_name(f"{AUDIT_PATH.stem}.{day:%Y%m%d}{AUDIT_PATH.suffix}")
    n = 1
    while dest.exists():
        dest = AUDIT_PATH.with_name(f"{AUDIT_PATH.stem}.{day:%Y%m%d}-{n}{AUDIT_PATH.suffix}")
        n += 1
    AUDIT_PATH.rename(dest)


def _prune_audit() -> None:
    cutoff = time.time() - AUDIT_KEEP_DAYS * 86400
    for path in _audit_files():
        if path == AUDIT_PATH:
            continue
        try:
            if path.stat().st_mtime < cutoff:
                path.unlink()
        except FileNotFoundError:
            pass


def audit_tail(alias: str | None, limit: int) -> list[dict]:
    out: list[dict] = []
    for path in reversed(_audit_files()):  # 新文件在前
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except FileNotFoundError:
            continue
        for line in reversed(lines):
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if alias and rec.get("host") != alias:
                continue
            out.append(rec)
            if len(out) >= limit:
                return out
    return out


def _remember_output_host(output_id: str | None, host: str | None) -> None:
    """记 output_id 属于哪台主机，供 read_output 的审计补 host。"""
    if not output_id or not host:
        return
    with _OUTPUT_HOSTS_LOCK:
        _OUTPUT_HOSTS.pop(output_id, None)
        _OUTPUT_HOSTS[output_id] = host
        while len(_OUTPUT_HOSTS) > _OUTPUT_HOSTS_MAX:
            _OUTPUT_HOSTS.pop(next(iter(_OUTPUT_HOSTS)))


def _host_of_output(output_id: str | None) -> str | None:
    """先查内存表；服务重启后表为空，就回扫审计里的同 output_id 记录。"""
    if not output_id:
        return None
    with _OUTPUT_HOSTS_LOCK:
        host = _OUTPUT_HOSTS.get(output_id)
    if host:
        return host
    for path in reversed(_audit_files()):
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except FileNotFoundError:
            continue
        for line in reversed(lines):
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if rec.get("output_id") == output_id and rec.get("host"):
                _remember_output_host(output_id, rec["host"])
                return rec["host"]
    return None


# 每次工具调用统一留痕：入口记 call，出口记 result/error，大内容只记引用不复制。
_AUDIT_ARGS = {
    "list_hosts": ("brief",),
    "exec": ("host", "command", "cwd", "idle_timeout", "max_duration", "force", "elevate", "detach"),
    "pin_hostkey": ("host", "trust"),
    "put_file": ("host", "local", "remote", "overwrite", "force", "elevate", "restart", "mode"),
    "get_file": ("host", "remote", "local", "overwrite", "elevate", "restart"),
    "xfer_stat": ("host", "remote"),
    "session_reset": ("host",),
    "audit_tail": ("host", "limit"),
    "read_output": ("output_id", "stream", "mode", "start", "end", "pattern", "limit"),
    "job_status": ("host", "job_id", "offset", "max_bytes"),
    "job_kill": ("host", "job_id"),
    "job_list": ("host", "limit"),
}

_RESULT_FIELDS = (
    "host", "blocked", "reason", "hint", "error", "aborted", "exit_code", "timed_out",
    "truncated", "output_id", "bytes", "verified", "md5", "md5_local", "md5_remote", "md5_match",
    "state", "job_id", "pid", "result", "probed", "match", "pinned", "fingerprint", "key_type",
    "address", "writable", "exists", "size", "mode", "found", "reset", "final", "part",
    "bytes_total", "lines_total", "matched", "count", "out_bytes", "offset_next", "elapsed_s",
    "rate_mb_s", "resumed_from",
)


def _clip(value, limit: int = 300):
    if isinstance(value, str) and len(value) > limit:
        return value[:limit] + f"…[{len(value)} chars]"
    return value


def _audit_args(tool: str, bound: inspect.BoundArguments) -> dict:
    return {name: bound.arguments[name] for name in _AUDIT_ARGS.get(tool, ()) if name in bound.arguments}


def _result_ok(tool: str, result) -> bool:
    if not isinstance(result, dict):
        return True
    if result.get("blocked") or result.get("error") or result.get("aborted"):
        return False
    if result.get("timed_out") or result.get("verified") is False or result.get("probed") is False:
        return False
    if tool == "exec" and result.get("exit_code") == -1:
        return False
    return True


def _summarize_result(tool: str, result) -> dict:
    """返回值的摘要：只留诊断字段和引用，正文不复制；失败时最多留 stderr 前 300 字符。"""
    if not isinstance(result, dict):
        return {"type": type(result).__name__}
    out = {k: _clip(result[k]) for k in _RESULT_FIELDS if k in result and result[k] is not None}
    if tool == "list_hosts":
        out["host_count"] = len(result.get("hosts") or [])
    elif tool == "audit_tail":
        out["record_count"] = len(result.get("records") or [])
    elif tool == "read_output":
        out["text_chars"] = len(result.get("text") or "")
    elif tool == "job_status":
        out["text_bytes"] = len((result.get("text") or "").encode("utf-8"))
    elif tool == "job_list":
        out["job_count"] = result.get("count", len(result.get("jobs") or []))
    if result.get("stderr") and (not _result_ok(tool, result) or result.get("exit_code") not in (None, 0)):
        out["stderr_head"] = _clip(result["stderr"])
    if "exit_code" in out:
        out["command_ok"] = out["exit_code"] in (0, None)
    return out


def _audit_safe(record: dict) -> None:
    try:
        audit(record)
    except Exception as exc:  # 审计只是留痕，不能反过来把工具弄挂；exec 自己那条仍是 fail closed
        log(f"审计写入失败：{exc}")


def _audited(tool: str):
    def deco(fn):
        sig = inspect.signature(fn)

        @functools.wraps(fn)
        async def wrapper(*args, **kwargs):
            call_id = uuid.uuid4().hex[:16]
            id_token = _CALL_ID.set(call_id)
            tool_token = _CALL_TOOL.set(tool)
            started = time.monotonic()
            try:
                bound = sig.bind(*args, **kwargs)
                bound.apply_defaults()
                host = bound.arguments.get("host")
                if host is None and tool == "read_output":
                    host = _host_of_output(str(bound.arguments.get("output_id") or ""))
                _audit_safe({"event": "call", "host": host, "args": _audit_args(tool, bound)})
                try:
                    result = await fn(*args, **kwargs)
                except Exception as exc:
                    _audit_safe({
                        "event": "error",
                        "host": host,
                        "duration_ms": round((time.monotonic() - started) * 1000, 1),
                        "error": f"{type(exc).__name__}: {_clip(str(exc))}",
                        "traceback": _clip(traceback.format_exc(), 2000),
                    })
                    raise
                _audit_safe({
                    "event": "result",
                    "host": host,
                    "ok": _result_ok(tool, result),
                    "duration_ms": round((time.monotonic() - started) * 1000, 1),
                    "result": _summarize_result(tool, result),
                })
                return result
            finally:
                _CALL_TOOL.reset(tool_token)
                _CALL_ID.reset(id_token)

        return wrapper

    return deco


# --------------------------------------------------------------------------------------
# SSH 连接池
# --------------------------------------------------------------------------------------


def sha256_fingerprint(key) -> str:
    blob = key.asbytes()
    digest = base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii")
    return f"SHA256:{digest.rstrip('=')}"


def probe_hostkey(address: str, port: int = 22, timeout: float = 10.0) -> tuple[str, str]:
    """只走到密钥交换为止取对方主机密钥，一个凭据都不发。

    这是 pin_hostkey 能安全交给 AI 的前提：探测阶段不提交用户名/密码，
    所以即便对端是台冒充的机器，密码也不会漏出去。
    """
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


class HostKeyMismatch(Exception):
    pass


def _build_pinned_policy(expected: str):
    import paramiko

    class _Pinned(paramiko.MissingHostKeyPolicy):
        def missing_host_key(self, client, hostname, key):  # noqa: ARG002
            got = sha256_fingerprint(key)
            if expected and got != expected:
                raise HostKeyMismatch(f"{hostname} 指纹不匹配：期望 {expected}，实际 {got}")
            if not expected:
                raise HostKeyMismatch(f"{hostname} 未固定主机指纹，拒绝连接（先调 pin_hostkey）")

    return _Pinned()


def _from_ssh_agent():
    """把私钥交给 ssh-agent 签名：带 passphrase 的私钥不必进服务进程内存。

    只取 agent 里的第一把 key。逐把试认证会连着打远端的失败次数，
    NO_RETRY 那条教训（认证类错误重试只会喂 fail2ban）说的就是这个。
    """
    try:
        from paramiko.agent import Agent

        keys = Agent().get_keys()
    except Exception:  # noqa: BLE001 - agent 服务没起时 paramiko 直接抛，按"没有可用 key"处理
        return None
    return keys[0] if keys else None


def _load_private_key(cred: HostCred):
    import paramiko

    candidates = [cred.key_path] if cred.key_path else []
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
    key = _from_ssh_agent()
    if key is not None:
        return key
    raise RuntimeError(
        "找不到可用私钥：候选文件都解不开（带 passphrase 的文件私钥不支持），ssh-agent 里也没有 key。"
        "请让 key_path 指向无口令私钥，或把私钥 ssh-add 进 agent"
    )


class Pool:
    def __init__(self):
        self._clients: dict[str, Any] = {}
        self._cwd: dict[str, str] = {}
        self._locks: dict[str, threading.Lock] = {}
        self._guard = threading.Lock()

    def lock(self, alias: str) -> threading.Lock:
        with self._guard:
            return self._locks.setdefault(alias, threading.Lock())

    def cwd(self, alias: str) -> str:
        return self._cwd.get(alias, "~")

    def set_cwd(self, alias: str, path: str) -> None:
        self._cwd[alias] = path

    def _connect(self, cred: HostCred, pin: str):
        import paramiko

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(_build_pinned_policy(pin))
        kwargs = {
            "hostname": cred.address,
            "port": cred.port,
            "username": cred.username,
            "timeout": 10,
            "banner_timeout": 15,
            "auth_timeout": 15,
        }
        if cred.auth == "key":
            kwargs["pkey"] = _load_private_key(cred)
            kwargs["look_for_keys"] = False
            kwargs["allow_agent"] = True
        else:
            if not cred.password:
                raise RuntimeError(f"{cred.alias} 的 auth=password 但 password 为空")
            kwargs["password"] = cred.password
            kwargs["look_for_keys"] = False
            kwargs["allow_agent"] = False
        client.connect(**kwargs)
        transport = client.get_transport()
        if transport is not None:
            transport.set_keepalive(30)
        return client

    def client(self, cred: HostCred, pin: str, reconnect: bool = False):
        existing = self._clients.get(cred.alias)
        if existing is not None and not reconnect:
            transport = existing.get_transport()
            if transport is not None and transport.is_active():
                return existing
            self.close(cred.alias)
        client = self._connect(cred, pin)
        self._clients[cred.alias] = client
        return client

    def close(self, alias: str, reset_cwd: bool = False) -> None:
        client = self._clients.pop(alias, None)
        if client is not None:
            try:
                client.close()
            except Exception as exc:  # noqa: BLE001
                log(f"关闭 {alias} 连接时报错（忽略）：{exc}")
        if reset_cwd:
            self._cwd.pop(alias, None)

    def connected(self, alias: str) -> bool:
        client = self._clients.get(alias)
        if client is None:
            return False
        transport = client.get_transport()
        return bool(transport and transport.is_active())


POOL = Pool()


@dataclass
class RunResult:
    exit_code: int
    stdout: str
    stderr: str
    truncated: bool
    timed_out: str | None
    output_id: str | None = None
    stats: dict | None = None


def _drain(chan, idle_s: float, deadline: float, spill: OS.Spill) -> RunResult:
    """按双计时器收流：idle 靠 recv 超时（有新输出就重置），max 靠 deadline。

    每个 chunk 先全量落盘，内存里只留头尾两截，所以再大的输出也不会把服务撑爆，
    也不会像早先那样「留头弃尾」把 make 的报错行整块丢掉。
    """
    timed_out: str | None = None
    why = "unknown"

    def take(chunk: bytes, is_err: bool) -> None:
        spill.write("err" if is_err else "out", chunk)

    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            timed_out = "duration"
            why = "duration"
            break
        # 这一轮 wait 由谁定，超时就该算成谁：拿 monotonic() 和 deadline 比会踩在边界上抖动
        wait = min(idle_s, remaining)
        bound = "duration" if remaining <= idle_s else "idle"
        chan.settimeout(wait)
        try:
            if chan.recv_ready():
                take(chan.recv(65536), False)
                continue
            if chan.recv_stderr_ready():
                take(chan.recv_stderr(65536), True)
                continue
            if chan.exit_status_ready() and chan.eof_received:
                # 只看 exit_status_ready 会提前收工：远端可以先报退出状态、数据还在路上，
                # 此时 close 通道就把尾巴丢了，而 exit_code 依旧报 0（实测丢过 670KB）
                why = "exit_and_eof"
                break
            chunk = chan.recv(65536)  # 无数据时阻塞，超时抛 socket.timeout —— 即 idle
        except socket.timeout:
            # recv 超时是 min(idle, 剩余时长)，先到哪个就算哪种：
            # 传小 max_duration 时报成 idle 会让调用方以为自己的时长没生效
            timed_out = bound
            why = bound
            break
        except (socket.error, OSError) as exc:
            take(f"\n[ssh-mcp] 通道异常：{type(exc).__name__}: {exc}".encode(), True)
            why = f"channel_error:{type(exc).__name__}"
            break
        if not chunk:
            why = "eof"
            break
        take(chunk, False)

    # 出主循环时缓冲区可能还压着尾巴（chan.recv 只看 stdout，stderr 得另抽），
    # exit-status 报文也可能比数据晚到一步，这里补掉；上限 2s 且从不越过 deadline
    until = min(deadline, time.monotonic() + 2.0)
    while time.monotonic() < until:
        if chan.recv_ready():
            take(chan.recv(65536), False)
        elif chan.recv_stderr_ready():
            take(chan.recv_stderr(65536), True)
        elif chan.exit_status_ready() or timed_out:
            break
        else:
            time.sleep(0.02)
    if timed_out or why not in ("exit_and_eof", "eof"):
        # 正常收流不打日志（stderr 会被 MCP 客户端原样带出去），只在真的不对时吭一声
        log(
            f"drain 退出 原因={why} 已收 out={spill.written['out']}B err={spill.written['err']}B "
            f"eof={getattr(chan, 'eof_received', '?')} closed={getattr(chan, 'closed', '?')} "
            f"exit_ready={chan.exit_status_ready()}"
        )
    try:
        code = chan.recv_exit_status() if chan.exit_status_ready() else -1
    except Exception:  # noqa: BLE001
        code = -1
    try:
        chan.close()
    except Exception:  # noqa: BLE001
        pass
    spill.close()
    return RunResult(
        exit_code=code,
        stdout=spill.inline("out"),
        stderr=spill.inline("err"),
        truncated=spill.clipped,
        timed_out=timed_out,
        output_id=spill.run_id,
        stats=spill.stats(),
    )


NO_RETRY = ("AuthenticationException", "HostKeyMismatch", "BadAuthenticationType", "PasswordRequiredException")


def _sudo_wrap(inner: str, cred: HostCred) -> str:
    """把整段（含 cd 前缀）塞进一条 sudo -S。

    `-p ''` 把口令提示置空，否则 "sudo: terminal required" 那类信息会污染 stderr。
    口令本身走 channel stdin，不进 argv、不进本机审计、也不进远端 shell history。
    """
    target = cred.elevate_user or "root"
    return f"sudo -S -p '' --user {shlex.quote(target)} -- sh -c {shlex.quote(inner)}"


def _cd_expr(path: str) -> str:
    """拼 cd 目标：波浪号头留在引号外，交给远端 shell 展开。

    shlex.quote 会把 `~` 裹成字面量 `'~'`（实测 `cd ~` 报「没有那个文件或目录」），
    所以只把 `~` / `~user` 与第一个 `/` 之前的头摘出来，剩余部分照旧引号保护。
    """
    head, sep, rest = path.partition("/")
    if head[:1] == "~" and all(c.isalnum() or c in "._-" for c in head[1:]):
        if not sep:
            return head
        return f"{head}/{shlex.quote(rest)}" if rest else f"{head}/"
    return shlex.quote(path)


def run_command(cred: HostCred, pin: str, command: str, cwd: str, idle_s: float, max_s: float, spill: OS.Spill, elevate: bool = False) -> RunResult:
    """在远端执行一条命令。cwd 由服务端记录，发送前才拼上。"""
    sent = command if cwd in ("", "~") else f"cd {_cd_expr(cwd)} && {command}"
    stdin: bytes | None = None
    if elevate:
        stdin = (cred.sudo_password() + "\n").encode("utf-8")
        sent = _sudo_wrap(sent, cred)
    last_exc: Exception | None = None
    for attempt in range(2):
        try:
            client = POOL.client(cred, pin, reconnect=attempt > 0)
            transport = client.get_transport()
            if transport is None or not transport.is_active():
                raise RuntimeError("transport 不可用")
            chan = transport.open_session()
            chan.exec_command(sent)
            if stdin is not None:
                # 必须紧跟 exec 之后立刻喂：sudo 的 -S 读不到就整条挂到 idle 超时
                chan.sendall(stdin)
                # 关掉 stdin：认证失败时 sudo 会回头再读一次重试，不关就阻塞到 idle 超时
                # （实测错口令要挂 21s 才报 timed_out=idle，关掉后 sudo 立刻放弃并 exit 1）
                try:
                    chan.shutdown_write()
                except Exception:  # noqa: BLE001 - 通道已被远端关闭时无需再管
                    pass
            return _drain(chan, idle_s, time.monotonic() + max_s, spill)
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            # 认证与指纹类错误重试只会喂 fail2ban，直接停
            if type(exc).__name__ in NO_RETRY:
                POOL.close(cred.alias)
                break
            POOL.close(cred.alias)
            if attempt == 0:
                spill.reset()  # 上一次可能已经写进去半截，不清掉日志会出现重复内容
                continue
            break
    assert last_exc is not None
    spill.write("err", f"{type(last_exc).__name__}: {last_exc}".encode("utf-8", "replace"))
    spill.close()
    return RunResult(
        exit_code=-1,
        stdout="",
        stderr=spill.inline("err"),
        truncated=False,
        timed_out="connect_failed",
        output_id=spill.run_id,
        stats=spill.stats(),
    )


# --------------------------------------------------------------------------------------
# 核心执行入口（工具与 CLI 共用）
# --------------------------------------------------------------------------------------


def _cd_only_segment(command: str) -> str | None:
    try:
        tokens = G.tokenize(G.split_separators(command))
    except G.GuardSyntaxError:
        return None
    segments = G.split_segments(tokens)
    if len(segments) != 1 or segments[0][0] != "cd" or len(segments[0]) > 2:
        return None
    return segments[0][1] if len(segments[0]) == 2 else "~"  # 光一个 cd 就是回 home


def _preflight(alias: str, command: str) -> tuple[dict | None, HostCred | None, str]:
    """凭据与指纹两道前置检查：任一不过就不建立连接，也就不会把密码发出去。"""
    cred = HOSTS.get().get(alias)
    if cred is None:
        return (
            _block(
                alias,
                command,
                "credential_missing",
                "no_credential",
                f"凭据文件 {HOSTS_PATH} 里缺 {alias} 这一条，请你自行补上（我不读不写该文件）",
            ),
            None,
            "",
        )
    pin, _ = effective_pin(alias, cred)
    if not pin:
        return (
            _block(
                alias,
                command,
                "host_key_unpinned",
                "no_hostKey",
                f"调 pin_hostkey(host='{alias}') 取实际指纹，报给用户核对后带 trust=true 再调一次写入",
            ),
            None,
            "",
        )
    return (None, cred, pin)


def execute(alias: str, command: str, cwd: str | None = None, idle_timeout: float | None = None, max_duration: float | None = None, force: bool = False, elevate: bool = False, detach: bool = False) -> dict:
    refusal, cred, pin = _preflight(alias, command)
    if refusal is not None:
        return refusal

    if detach and elevate:
        # 口令注入与 setsid 的组合没验过，v1 明确不做：先见 README「后台任务」
        return _block(alias, command, "elevate_detach_unsupported", "no_elevate_detach",
                      "v1 不支持 elevate 的后台任务，去掉 elevate 再发（要 root 就先想别的办法）")
    if elevate and not cred.elevate:
        return _block(alias, command, "elevate_not_configured", "no_elevate", f"凭据文件里为 {alias} 打开 elevate（那文件我不写）")
    if elevate and not cred.sudo_password():
        # 空口令喂进 stdin 会让 sudo 一直等输入，最后撞 idle 超时，报出来的还是假故障
        return _block(alias, command, "elevate_password_missing", "no_elevate_password", f"elevate_password 与 password 都为空，在凭据文件里补一个")

    guard = GUARD.get()
    cd_target = None if detach else _cd_only_segment(command)
    # 清单查不查：root 账号恒查，非 root 看 guarded_hosts 点没点名，提权一律查 ——
    # 一旦以 root 落地，破坏面和 root 账号完全同级，不该因为登录账号是 qy 就免检
    # 单独的 cd 只改服务端记的 cwd，不触碰远端状态，也不必查
    guarded = G.applies(cred.privileged, alias, guard) or elevate
    hit = None if cd_target is not None or not guarded else G.check(command, guard)
    if hit is not None and not force:
        return _block(alias, command, "killlisted", hit.rule, "确需执行请带 force=true 重发同一条命令")
    rule = "cd_only" if cd_target is not None else ("forced" if hit else "pass")

    # fail closed：审计写不进去就不执行
    try:
        audit({"host": alias, "command": command, "event": "intent", "rule": rule, "guarded": guarded, "elevated": elevate or None, "detach": detach or None})
    except OSError as exc:
        return _block(alias, command, "audit_write_failed", "audit_unwritable", f"审计目录不可写：{exc}")

    idle_s = float(idle_timeout or guard.idle_timeout_s)
    max_s = float(max_duration or guard.max_duration_s)
    start_cwd = cwd or POOL.cwd(alias)

    if detach:
        return _start_job(alias, command, cred, pin, guard, start_cwd, rule, idle_s)

    # 全文落盘和审计同级：写不了就不执行，别把输出留在只有内存知道的地方
    try:
        spill = OS.Spill(OUTPUT_ROOT, uuid.uuid4().hex, guard.max_output_bytes, {"out": INLINE_OUT, "err": INLINE_ERR})
    except OSError as exc:
        return _block(alias, command, "output_unwritable", "output_unwritable", f"output 目录不可写：{exc}（全文日志与审计同为必备件）")
    removed = OS.prune(OUTPUT_ROOT, OUTPUT_KEEP_RUNS, OUTPUT_KEEP_BYTES, OUTPUT_KEEP_DAYS)
    if removed:
        log(f"output/ 轮转清理了 {removed} 个 run")

    if cd_target is not None:
        # cd 的探活探测也按 elevate 走：`cd /root` 用主账号验会假失败，验过了才记 cwd
        res = run_command(cred, pin, f"cd {_cd_expr(cd_target)} && pwd", start_cwd, idle_s, max_s, spill, elevate)
        end_cwd = res.stdout.strip().splitlines()[-1] if res.exit_code == 0 and res.stdout.strip() else start_cwd
        if res.exit_code == 0:
            POOL.set_cwd(alias, end_cwd)
    else:
        res = run_command(cred, pin, command, start_cwd, idle_s, max_s, spill, elevate)
        end_cwd = start_cwd

    _remember_output_host(res.output_id, alias)
    audit(
        {
            "host": alias,
            "command": command,
            "event": "executed",
            "reason": res.timed_out or "ok",
            "rule": rule,
            "elevated": elevate or None,
            "ran_as": (cred.elevate_user or "root") if elevate else None,
            "exit_code": res.exit_code,
            "output_id": res.output_id,
            "output": res.stats,
            **({"stderr_head": res.stderr[:300]} if res.stderr and (res.timed_out or res.exit_code != 0) else {}),
        }
    )
    return _ok(alias, command, res, start_cwd, end_cwd, hit.rule if hit else None, elevate, cred.elevate_user or "root")


ECHO_LIMIT = 200  # 回显给调用方的命令原文上限；全文始终在审计里，回显只是给对照用


def _echo(command: str) -> str:
    if len(command) <= ECHO_LIMIT:
        return command
    return f"{command[:ECHO_LIMIT]}…[截断，全文 {len(command)} 字符，见 audit_tail]"


def _block(alias: str, command: str, reason: str, rule: str, hint: str) -> dict:
    try:  # 被拒也要留痕，但拒本身不需要 fail closed
        audit({"host": alias, "command": command, "event": "blocked", "reason": reason, "rule": rule})
    except OSError as exc:
        log(f"审计写入失败：{exc}")
    return {"host": alias, "command": _echo(command), "blocked": True, "reason": reason, "rule": rule, "hint": hint}


def _ok(alias, command, res: RunResult, cwd_before, cwd_after, forced_rule: str | None = None, elevate: bool = False, ran_as: str = "root") -> dict:
    payload = {
        "host": alias,
        "command": _echo(command),
        "exit_code": res.exit_code,
        "stdout": res.stdout,
        "stderr": res.stderr,
        "truncated": res.truncated,
        "timed_out": res.timed_out,
        "cwd_before": cwd_before,
        "cwd_after": cwd_after,
    }
    if elevate:
        payload["elevated"] = True
        payload["ran_as"] = ran_as
    if forced_rule:
        payload["forced_rule"] = forced_rule
    if res.timed_out == "duration":
        payload["hint"] = "撞到 max_duration：命令可能还在远端跑，已收的部分可 read_output 捞；要等完就传更大的 max_duration"
    if res.output_id:
        payload["output_id"] = res.output_id
        payload["output"] = res.stats
        if res.truncated:
            payload["read_full"] = (
                f"内联已按行边界省略，全文在本地日志：read_output(output_id={res.output_id}, "
                "mode='grep', pattern='error') 拿行号，再用 mode='lines', start, end 取上下文"
            )
    return payload


# --------------------------------------------------------------------------------------
# MCP 工具
# --------------------------------------------------------------------------------------


def _tool_list_hosts(brief: bool = False) -> dict:
    guard = GUARD.get()
    creds = HOSTS.get()
    hosts = []
    for alias in sorted(creds):
        cred = creds[alias]
        pin, source = effective_pin(alias, cred)
        guarded = G.applies(cred.privileged, alias, guard)
        hosts.append(
            {
                "alias": alias,
                "purpose": cred.purpose,
                "address": f"{cred.address}:{cred.port}",
                "username": cred.username,
                "privileged": cred.privileged,
                "auth": cred.auth,
                "host_key_pinned": bool(pin),
                "pin_source": source or None,
                "guard": "killlist" if guarded else "none",
                "guard_reason": "root 账号" if cred.privileged else ("guarded_hosts 点名" if alias in guard.guarded_hosts else ""),
                "elevate_available": cred.elevate,
                "elevate_as": cred.elevate_user or "root",
                "elevate_password_from": "elevate_password" if cred.elevate_password else ("password" if cred.password else "未配置"),
                "connected": POOL.connected(alias),
                "cwd": POOL.cwd(alias),
                "limits": {
                    "idle_timeout_s": guard.idle_timeout_s,
                    "max_duration_s": f"{guard.max_duration_s}（缺省，可被 max_duration 参数任意覆盖，不再夹制）",
                    "max_output_file_bytes": guard.max_output_bytes,
                    "inline_output": f"stdout 头 {INLINE_OUT[0]}B + 尾 {INLINE_OUT[1]}B（stderr {INLINE_ERR[0]}/{INLINE_ERR[1]}），全文用 read_output(output_id) 回捞",
                    "output_retention": f"{OUTPUT_KEEP_DAYS} 天 / ≤{OUTPUT_KEEP_RUNS} run / ≤{OUTPUT_KEEP_BYTES // 1048576}MB",
                    "audit_retention": f"{AUDIT_KEEP_DAYS} 天（按天轮转，SSHMCP_AUDIT_KEEP_DAYS）",
                    "xfer_dir": str(xfer_dir(guard)),
                    "max_transfer_bytes": guard.max_transfer_bytes,
                    "xfer_chunk_bytes": guard.xfer_chunk_bytes,
                    "xfer_timeout_s": guard.xfer_timeout_s,
                },
            }
        )
    if brief:
        for h in hosts:
            h.pop("purpose", None)
            h.pop("limits", None)
        return {
            "hosts": hosts,
            "guarded_hosts": sorted(guard.guarded_hosts),
            "unpinned": [a for a in sorted(creds) if not effective_pin(a, creds[a])[0]],
            "note": "brief 模式：每台的 limits 与全量 killlist 没带，要全量用 list_hosts(brief=false)",
        }
    return {
        "hosts": hosts,
        "killlist": [p.raw for p in guard.kill_prefixes],
        "guarded_hosts": sorted(guard.guarded_hosts),
        "unpinned": [a for a in sorted(creds) if not effective_pin(a, creds[a])[0]],
        "note": "无权限控制：killlist（root 账号恒查 + guarded_hosts 点名的非 root 主机 + 任何带 elevate 的命令，exec 用 force=true 可越过）之外一律放行，真正的边界是远端账号自己的权限。被拦下的命令不会建立连接。",
    }


def _tool_exec(host: str, command: str, cwd: str | None = None, idle_timeout: float | None = None, max_duration: float | None = None, force: bool = False, elevate: bool = False, detach: bool = False) -> dict:
    return execute(host, command, cwd, idle_timeout, max_duration, force, elevate, detach)


def _tool_pin_hostkey(host: str, trust: bool = False) -> dict:
    """探测并（经确认后）写入主机指纹。全程不发送任何凭据。"""
    cred = HOSTS.get().get(host)
    if cred is None:
        return {"host": host, "probed": False, "reason": "credential_missing", "hint": f"凭据文件里缺 {host}"}
    try:
        actual, key_type = probe_hostkey(cred.address, cred.port)
    except Exception as exc:  # noqa: BLE001 - 网络/握手失败形态太杂，原样回给调用方
        return {"host": host, "address": f"{cred.address}:{cred.port}", "probed": False, "reason": "probe_failed", "hint": f"{type(exc).__name__}: {exc}"}
    expected, source = effective_pin(host, cred)
    out = {
        "host": host,
        "address": f"{cred.address}:{cred.port}",
        "probed": True,
        "key_type": key_type,
        "fingerprint": actual,
        "pinned": expected or None,
        "pin_source": source or None,
        "match": bool(expected) and expected == actual,
    }
    if out["match"]:
        out["hint"] = "指纹一致，exec 可直接用"
        return out
    if source == "credential":
        out["writable"] = False
        out["hint"] = (
            f"凭据文件钉的 {expected} 与实际 {actual} 不符。我不写凭据文件：请你自行核对 {HOSTS_PATH} 的 hostKey "
            "（可能是主机重装过，也可能真是中间人）"
        )
        return out
    if not trust:
        out["writable"] = True
        out["hint"] = "把 pinned 与 fingerprint 两个值并报给用户，核对无误后带 trust=true 再调一次才会写入"
        return out
    save_pin(host, actual)
    audit({"host": host, "command": f"<pin_hostkey {'replace' if expected else 'first'}>", "event": "hostkey_pinned", "previous": expected or None, "fingerprint": actual})
    out.update({"pinned": actual, "pin_source": "hostkeys", "match": True, "hint": "已写入 hostkeys.json，exec 可用"})
    return out


STAGING_DIRNAME = ".sshmcp-xfer"


def _sftp_of(alias: str, cred: HostCred, pin: str):
    return POOL.client(cred, pin).open_sftp()


def _remote_home(sftp) -> str:
    return sftp.normalize(".")


def _transfer_guard(cred: HostCred, alias: str, remote: str, elevate: bool, force: bool) -> dict | None:
    """传输落点必须和 exec 走同一张清单，否则 SFTP 就是清单的绕过口。"""
    guard = GUARD.get()
    if not (G.applies(cred.privileged, alias, guard) or elevate):
        return None
    hit = G.check_write_target(remote)
    if hit is None or force:
        return None
    return _block(alias, f"<put> {remote}", "killlisted", hit.rule, "确需写入请带 force=true 重发")


def _tool_put_file(host: str, local: str, remote: str, overwrite: bool = False, force: bool = False,
                   elevate: bool = False, restart: bool = False, mode: str = "") -> dict:
    guard = GUARD.get()
    refusal, cred, pin = _preflight(host, f"<put> {local} -> {remote}")
    if refusal is not None:
        return refusal
    if elevate and not cred.elevate:
        return _block(host, f"<put> {remote}", "elevate_not_configured", "no_elevate", f"凭据文件里为 {host} 打开 elevate")
    blocked = _transfer_guard(cred, host, remote, elevate, force)
    if blocked is not None:
        return blocked

    src = Path(local).expanduser()
    if not src.is_file():
        return _block(host, f"<put> {remote}", "local_missing", "no_local", f"本机没有文件：{src}")
    size = src.stat().st_size
    if size > guard.max_transfer_bytes:
        return _block(host, f"<put> {remote}", "too_large", "max_transfer_bytes",
                      f"{size} 字节 > 上限 {guard.max_transfer_bytes}（policy.json 的 defaults.max_transfer_bytes）")

    try:
        audit({"host": host, "command": f"<put> {src} -> {remote}", "event": "intent",
               "rule": "forced" if force else "pass", "elevated": elevate or None, "bytes": size})
    except OSError as exc:
        return _block(host, f"<put> {remote}", "audit_write_failed", "audit_unwritable", f"审计目录不可写：{exc}")

    deadline = time.monotonic() + guard.xfer_timeout_s
    out: dict = {"host": host, "direction": "put", "local": str(src), "remote": remote, "bytes": size}
    sftp = None
    try:
        sftp = _sftp_of(host, cred, pin)
        existing = _remote_stat_size(sftp, remote)
        if existing is not None and not overwrite:
            out["hint"] = f"远端已存在 {remote}（{existing} 字节）。确认要覆盖就带 overwrite=true"
            out["blocked"] = True
            out["reason"] = "remote_exists"
            return out

        if elevate:
            stage = f"{_remote_home(sftp)}/{STAGING_DIRNAME}"
            _ensure_remote_dir(sftp, stage)
            part = X.part_path_for(f"{stage}/{Path(remote).name}")
        else:
            part = X.part_path_for(remote)
        # restart 必须删"解析之后"的那个 part：提权路径的名字与非提权不同，
        # 早先按非提权名删是空操作，旧暂存会被静默复用
        if restart:
            _drop_remote(sftp, part)

        out["part"] = part
        have = _remote_stat_size(sftp, part) or 0
        tr = X.push(sftp, str(src), part, chunk=guard.xfer_chunk_bytes, deadline=deadline,
                    total_limit=guard.max_transfer_bytes)
        out.update({"seconds": round(tr.seconds, 2), "rate_mb_s": round(tr.rate, 1),
                    "resumed_from": tr.resumed_from, "chunks": tr.chunks,
                    "part_before": have})

        local_md5 = X.md5_of_file(str(src), deadline=deadline)
        remote_md5 = _remote_md5(cred, pin, part, host, deadline)
        out.update({"md5_local": local_md5, "md5_remote": remote_md5, "md5_match": local_md5 == remote_md5})
        if remote_md5 is None or local_md5 != remote_md5:
            out["verified"] = False
            out["hint"] = "md5 不符或算不出来，part 已保留：修好后带同一参数重调会从缺口继续（不是从头重传）"
            return out

        if elevate:
            install = f"install -m {shlex.quote(mode or '0644')} -- {shlex.quote(part)} {shlex.quote(remote)} && rm -f -- {shlex.quote(part)}"
            res = run_command(cred, pin, install, "~", guard.idle_timeout_s, guard.xfer_timeout_s,
                              _throw_spill(guard), elevate=True)
            out["finalize_exit_code"] = res.exit_code
            out["finalize_stderr"] = res.stderr
            if res.exit_code != 0:
                out["verified"] = False
                out["hint"] = f"install 失败，part 留在 {part}：看 finalize_stderr 后重调同一参数续传"
                return out
        else:
            sftp.chmod(part, int(mode or "0644", 8))
            _remote_rename(sftp, part, remote, overwrite)
        out["verified"] = True
        out["final"] = remote
        audit({"host": host, "command": f"<put> {src} -> {remote}", "event": "transferred", "bytes": size,
               "md5": local_md5, "resumed_from": tr.resumed_from, "seconds": out["seconds"],
               "elevated": elevate or None})
    except X.TransferAborted as exc:
        out.update({"verified": False, "aborted": str(exc), "hint": "part 已保留，重调同一参数即从缺口续传"})
    except Exception as exc:  # noqa: BLE001 - SFTP/OSError 形态太杂，原样回给调用方
        out.update({"verified": False, "error": f"{type(exc).__name__}: {exc}"})
    finally:
        if sftp is not None:
            sftp.close()
    return out


def _tool_get_file(host: str, remote: str, local: str = "", overwrite: bool = False,
                   elevate: bool = False, restart: bool = False) -> dict:
    guard = GUARD.get()
    refusal, cred, pin = _preflight(host, f"<get> {remote}")
    if refusal is not None:
        return refusal
    if elevate and not cred.elevate:
        return _block(host, f"<get> {remote}", "elevate_not_configured", "no_elevate", f"凭据文件里为 {host} 打开 elevate")

    root = xfer_dir(guard)
    dest = Path(local).expanduser() if local else root / Path(remote).name
    out: dict = {"host": host, "direction": "get", "remote": remote, "local": str(dest),
                 "xfer_dir": str(root)}

    try:
        audit({"host": host, "command": f"<get> {remote} -> {dest}", "event": "intent",
               "rule": "pass", "elevated": elevate or None})
    except OSError as exc:
        return _block(host, f"<get> {remote}", "audit_write_failed", "audit_unwritable", f"审计目录不可写：{exc}")

    deadline = time.monotonic() + guard.xfer_timeout_s
    sftp = None
    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
        sftp = _sftp_of(host, cred, pin)
        src = remote
        if elevate:
            stage = f"{_remote_home(sftp)}/{STAGING_DIRNAME}"
            _ensure_remote_dir(sftp, stage)
            src = X.part_path_for(f"{stage}/{Path(remote).name}.in")
            dump = f"cat -- {shlex.quote(remote)} > {shlex.quote(src)}"
            res = run_command(cred, pin, dump, "~", guard.idle_timeout_s, guard.xfer_timeout_s,
                              _throw_spill(guard), elevate=True)
            if res.exit_code != 0:
                out.update({"verified": False, "error": f"远端读取失败：{res.stderr[:200]}"})
                return out

        st = sftp.stat(src)
        size = st.st_size
        if stat.S_ISFIFO(getattr(st, "st_mode", 0) or 0):
            # FIFO 的 st_size 是 0，流式读到 EOF 会挂住等写者（最长到 xfer 超时）
            return {**out, "bytes": size, "verified": False, "reason": "fifo",
                    "hint": "FIFO 没有固定长度，get_file 会挂住等写者，直接拒；看内容用 exec 的 cat"}
        if size > guard.max_transfer_bytes:
            return {**out, "bytes": size, "verified": False, "reason": "too_large",
                    "hint": f"{size} 字节 > defaults.max_transfer_bytes={guard.max_transfer_bytes}"}
        free = shutil.disk_usage(str(dest.parent)).free
        if free < size:
            return {**out, "bytes": size, "verified": False, "reason": "local_no_space",
                    "hint": f"{dest.parent} 只剩 {free} 字节，放不下 {size}"}
        if dest.exists() and not overwrite:
            return {**out, "blocked": True, "reason": "local_exists",
                    "hint": f"本机已有 {dest}。要覆盖带 overwrite=true，或换 local="}

        part = dest.with_name(dest.name + X.PART_SUFFIX)
        if restart and part.exists():
            part.unlink()
        out["part"] = str(part)
        have = part.stat().st_size if part.exists() else 0
        tr = X.pull(sftp, src, str(part), chunk=guard.xfer_chunk_bytes, deadline=deadline,
                    total_limit=guard.max_transfer_bytes)
        out.update({"bytes": tr.bytes, "seconds": round(tr.seconds, 2), "rate_mb_s": round(tr.rate, 1),
                    "resumed_from": tr.resumed_from, "chunks": tr.chunks, "part_before": have})

        local_md5 = X.md5_of_file(str(part), deadline=deadline)
        if size == 0:
            # st_size=0（/proc 类）：两次读取的内容可能天然不同，二次读取算 md5 只会假红，跳过并说明
            out.update({"md5_local": local_md5, "md5_check": "skipped_st_size_0",
                        "hint": "该路径 st_size=0（如 /proc 伪文件），已按读到 EOF 取回；未做远端二次读取的 md5 校验（这类文件两次读取可能内容不同）"})
        else:
            remote_md5 = _remote_md5(cred, pin, src, host, deadline)
            out.update({"md5_local": local_md5, "md5_remote": remote_md5, "md5_match": local_md5 == remote_md5})
            if remote_md5 is None or local_md5 != remote_md5:
                out["verified"] = False
                out["hint"] = "md5 不符，part 已保留：重调同一参数从缺口续传"
                return out

        os.replace(part, dest)
        out.update({"verified": True, "final": str(dest)})
        if elevate:
            _remote_rm(cred, pin, src, host, guard)
        audit({"host": host, "command": f"<get> {remote} -> {dest}", "event": "transferred", "bytes": out["bytes"],
               "md5": local_md5, "resumed_from": tr.resumed_from, "seconds": out["seconds"],
               "elevated": elevate or None})
    except X.TransferAborted as exc:
        out.update({"verified": False, "aborted": str(exc),
                    "hint": "part 已保留，重调同一参数续传（st_size=0 的文件不续传，重调即整篇重读）"})
    except Exception as exc:  # noqa: BLE001
        out.update({"verified": False, "error": f"{type(exc).__name__}: {exc}"})
    finally:
        if sftp is not None:
            sftp.close()
    return out


def _tool_xfer_stat(host: str, remote: str) -> dict:
    refusal, cred, pin = _preflight(host, f"<stat> {remote}")
    if refusal is not None:
        return refusal
    try:
        sftp = _sftp_of(host, cred, pin)
        try:
            st = sftp.stat(remote)
        finally:
            sftp.close()
        return {
            "host": host,
            "remote": remote,
            "exists": True,
            "size": st.st_size,
            "mode": oct(st.st_mode or 0),
            "uid": st.st_uid,
            "gid": st.st_gid,
            "mtime": st.st_mtime,
        }
    except IOError as exc:
        hint = "路径不存在，或它只有 root 可读 —— 那种情况用 exec(elevate=true) 的 stat 看"
        return {"host": host, "remote": remote, "exists": False, "error": str(exc), "hint": hint}


def _throw_spill(guard):
    """给 run_command 用的临时 Spill：finalize 步骤只关心退出码，不要输出。"""
    return OS.Spill(OUTPUT_ROOT, uuid.uuid4().hex, guard.max_output_bytes, {"out": INLINE_OUT, "err": INLINE_ERR})


def _remote_stat_size(sftp, path: str) -> int | None:
    try:
        return sftp.stat(path).st_size
    except IOError:
        return None


def _ensure_remote_dir(sftp, path: str) -> None:
    try:
        sftp.mkdir(path)
    except IOError:
        pass  # 已存在是正常路径，报错交给后续写入


def _drop_remote(sftp, path: str) -> None:
    try:
        sftp.remove(path)
    except IOError:
        pass


def _remote_rename(sftp, part: str, target: str, replace: bool) -> None:
    """覆盖必须走 posix_rename：普通 rename 在目标已存在时回 Failure（100 实测）。"""
    if replace:
        sftp.posix_rename(part, target)
    else:
        sftp.rename(part, target)


def _remote_md5(cred: HostCred, pin: str, path: str, alias: str, deadline: float) -> str | None:
    """远端算 md5 而不是把文件读回来算：实测 md5sum 0.12s/200MB，
    而用 SFTP 读回来算要 18s（11 MB/s），差两个数量级。"""
    guard = GUARD.get()
    cmd = f"md5sum -- {shlex.quote(path)} | cut -d' ' -f1"
    res = run_command(cred, pin, cmd, "~", guard.idle_timeout_s, max(60.0, deadline - time.monotonic()), _throw_spill(guard))
    if res.exit_code != 0:
        return None
    text = res.stdout.strip()
    return text.splitlines()[-1] if text else None


def _remote_rm(cred: HostCred, pin: str, path: str, alias: str, guard) -> None:
    run_command(cred, pin, f"rm -f -- {shlex.quote(path)}", "~", guard.idle_timeout_s, 60.0, _throw_spill(guard))


# --------------------------------------------------------------------------------------
# 后台任务（detach）：状态存远端文件，服务重启/断连/换会话都不丢
# --------------------------------------------------------------------------------------


def _start_job(alias: str, command: str, cred: HostCred, pin: str, guard, start_cwd: str, rule: str, idle_s: float) -> dict:
    """detach=true 的落点：把命令丢到远端后台，立刻带 job_id 回来。"""
    try:
        spill = _throw_spill(guard)
    except OSError as exc:
        return _block(alias, command, "output_unwritable", "output_unwritable", f"output 目录不可写：{exc}（全文日志与审计同为必备件）")
    job_id = J.new_job_id()
    directory = "" if start_cwd in ("", "~") else start_cwd
    script = J.build_start_script(job_id, command, directory, guard.job_retention_days, guard.job_max_concurrent)
    res = run_command(cred, pin, script, "~", idle_s, 60.0, spill)
    parsed = J.parse_start(res.stdout)
    if parsed["result"] == "busy":
        out = _block(alias, command, "too_many_jobs", "job_max_concurrent",
                     f"在跑或失联的任务已达上限 {guard.job_max_concurrent}（policy.json defaults.job_max_concurrent）：先 job_list 看清、job_kill 收尾再发")
        out["busy"] = parsed.get("busy")
        return out
    if parsed["result"] != "started":
        try:
            audit({"host": alias, "command": command, "event": "job_start_failed", "rule": rule,
                   "job_id": job_id, "reason": parsed["result"], "stderr": res.stderr[:300]})
        except OSError:
            pass
        return {"host": alias, "command": _echo(command), "job_id": job_id, "detached": True, "state": "unknown",
                "error": "job_not_started", "reason": parsed["result"], "exit_code": res.exit_code,
                "stdout": res.stdout[:300], "stderr": res.stderr[:300],
                "hint": "远端没写出 pid 文件：看 stdout/stderr（NOPID 多为目录不可写或缺 setsid/nohup）"}
    audit({"host": alias, "command": command, "event": "job_started", "rule": rule, "job_id": job_id,
           "pid": parsed.get("pid"), "dir": directory or "~"})
    out = {"host": alias, "command": _echo(command), "job_id": job_id, "detached": True, "state": "running",
           "pid": parsed.get("pid"), "cwd": start_cwd,
           "next": f"job_status(host='{alias}', job_id='{job_id}') 看状态与输出；job_kill 停它"}
    if rule == "forced":
        out["forced_rule"] = rule
    return out


def _bad_job_id(host: str, job_id: str) -> dict | None:
    try:
        J.validate_job_id(job_id)
    except ValueError as exc:
        return {"host": host, "job_id": job_id, "error": "invalid_job_id", "hint": str(exc)}
    return None


def _tool_job_status(host: str, job_id: str, offset: int | None = None, max_bytes: int = 65536) -> dict:
    bad = _bad_job_id(host, job_id)
    if bad is not None:
        return bad
    refusal, cred, pin = _preflight(host, f"<job_status> {job_id}")
    if refusal is not None:
        return refusal
    guard = GUARD.get()
    limit = max(1, min(int(max_bytes), 1 << 20))
    res = run_command(cred, pin, J.build_state_script(job_id), "~", guard.idle_timeout_s, 60.0, _throw_spill(guard))
    if res.exit_code != 0:
        return {"host": host, "job_id": job_id, "error": "state_probe_failed",
                "exit_code": res.exit_code, "stderr": res.stderr[:300]}
    st = J.parse_kv(res.stdout)
    state = st.get("state") or "unknown"
    if state == "missing":
        return {"host": host, "job_id": job_id, "state": "missing",
                "hint": "没有这个任务（从未启动过，或已过保留期被清）"}
    size = int(st["out_bytes"]) if (st.get("out_bytes") or "").isdigit() else 0
    start = max(0, size - limit) if offset is None else max(0, min(int(offset), size))
    raw = b""
    sftp = None
    try:  # out 读不到不该把状态也吞掉：状态照报，内容留空
        sftp = _sftp_of(host, cred, pin)
        with sftp.open(f"{_remote_home(sftp)}/{J.JOBS_DIRNAME}/{job_id}/out", "rb") as fh:
            fh.seek(start)
            if size > start:
                raw = fh.read(min(limit, size - start))
    except Exception:  # noqa: BLE001
        raw = b""
    finally:
        if sftp is not None:
            sftp.close()
    out = {
        "host": host, "job_id": job_id, "state": state,
        "exit_code": int(st["code"]) if (st.get("code") or "").isdigit() else None,
        "started": int(st["started"]) if (st.get("started") or "").isdigit() else None,
        "out_bytes": size,
        "offset_next": start + len(raw),
        "truncated": start + len(raw) < size,
        "text": raw.decode("utf-8", "replace"),
    }
    if (st.get("pid") or "").isdigit():
        out["pid"] = int(st["pid"])
    if out["started"] and (st.get("now") or "").isdigit():
        out["elapsed_s"] = max(0, int(st["now"]) - out["started"])
    if (st.get("command") or "").strip():
        out["command"] = st["command"]
    return out


def _tool_job_kill(host: str, job_id: str) -> dict:
    bad = _bad_job_id(host, job_id)
    if bad is not None:
        return bad
    refusal, cred, pin = _preflight(host, f"<job_kill> {job_id}")
    if refusal is not None:
        return refusal
    guard = GUARD.get()
    res = run_command(cred, pin, J.build_kill_script(job_id), "~", guard.idle_timeout_s, 30.0, _throw_spill(guard))
    kv = J.parse_kv(res.stdout)
    result = kv.get("result") or "unknown"
    try:
        audit({"host": host, "command": f"<job_kill> {job_id}", "event": "job_killed", "job_id": job_id,
               "result": result, "state": kv.get("state"), "probe_exit": res.exit_code})
    except OSError:
        pass
    out = {"host": host, "job_id": job_id, "result": result}
    if kv.get("state"):
        out["state"] = kv["state"]
    if (kv.get("code") or "").isdigit():
        out["exit_code"] = int(kv["code"])
    if kv.get("reaped"):
        out["reaped"] = True
        out["hint"] = "任务已失联（进程不在、也没有退出标记）：已补写 killed 标记完成回收——不再占并发名额，7 天后自动清"
    elif result == "missing":
        out["hint"] = "没有这个任务（从未启动过，或已过保留期被清）"
    elif result == "not_running":
        out["hint"] = "任务已经不在跑（看 state/exit_code），没有可停的东西"
    if res.exit_code != 0:
        out["stderr"] = res.stderr[:300]
    return out


def _tool_job_list(host: str, limit: int = 20) -> dict:
    refusal, cred, pin = _preflight(host, "<job_list>")
    if refusal is not None:
        return refusal
    guard = GUARD.get()
    n = max(1, min(int(limit), 200))
    res = run_command(cred, pin, J.build_list_script(n), "~", guard.idle_timeout_s, 60.0, _throw_spill(guard))
    if res.exit_code != 0:
        return {"host": host, "error": "list_failed", "exit_code": res.exit_code, "stderr": res.stderr[:300]}
    jobs = J.parse_list(res.stdout)
    return {"host": host, "count": len(jobs), "jobs": jobs,
            "limits": {"retention_days": guard.job_retention_days, "max_concurrent": guard.job_max_concurrent}}


def _tool_session_reset(host: str) -> dict:
    POOL.close(host, reset_cwd=True)
    return {"host": host, "reset": True, "cwd": POOL.cwd(host)}


def _tool_audit_tail(host: str | None = None, limit: int = 50) -> dict:
    return {"records": audit_tail(host, min(max(1, limit), 500))}


def _tool_read_output(
    output_id: str,
    stream: str = "out",
    mode: str = "tail",
    start: int = 1,
    end: int = 0,
    pattern: str = "",
    limit: int = 16384,
) -> dict:
    try:
        return OS.read_output(OUTPUT_ROOT, output_id, stream, mode, start, end, pattern, min(max(512, limit), 65536))
    except ValueError as exc:
        return {"found": False, "error": str(exc)}


def _import_highlevel_server():
    """mcp 1.x 叫 FastMCP，2.x 改名 MCPServer，装饰器与 run() 用法一致。"""
    try:
        from mcp.server.fastmcp import FastMCP

        return FastMCP
    except ImportError:
        from mcp.server.mcpserver import MCPServer

        return MCPServer


def build_server():
    server_class = _import_highlevel_server()
    server = server_class("ssh-mcp")

    @server.tool(name="list_hosts", description="列出凭据文件里的主机、指纹固定状态、是否受 killlist 保护及其原因。brief=true 只回短字段（不带每台的 limits 与全量 killlist），省上下文。不含任何密码。")
    @_audited("list_hosts")
    async def _list_hosts(brief: bool = False) -> dict:
        return _tool_list_hosts(brief)

    @server.tool(
        name="exec",
        description=(
            "在远端执行一条离散命令（不开交互 shell）。服务端不做权限控制，命令原样交给远端 shell；"
            "只有受保护主机（username=root，或被 policy.json 的 guarded_hosts 点名，或本次带 elevate）"
            "会查一张自杀清单，命中时带 force=true 即可放行。被拦下时不建立连接。"
            "cwd 由服务端按主机记忆，可用参数覆盖；max_duration 传多大就用多大。"
            "elevate=true 以 root 跑这一条（凭据里该主机须 elevate:true）——服务端用 sudo -S 并把口令写进"
            "channel stdin，口令不进命令行、不进审计、不进远端 history；提权命令一律查清单。"
            "detach=true 把这条命令丢到远端后台跑并立刻返回 job_id（用 job_status 取状态与输出、job_kill 停掉）"
            "——状态存在远端 ~/.sshmcp-jobs/，服务重启/断连/换会话都不丢；v1 与 elevate 互斥。"
        ),
    )
    @_audited("exec")
    async def _exec(
        host: str,
        command: str,
        cwd: str | None = None,
        idle_timeout: float | None = None,
        max_duration: float | None = None,
        force: bool = False,
        elevate: bool = False,
        detach: bool = False,
    ) -> dict:
        import anyio

        return await anyio.to_thread.run_sync(
            lambda: _tool_exec(host, command, cwd, idle_timeout, max_duration, force, elevate, detach)
        )

    @server.tool(
        name="pin_hostkey",
        description=(
            "探测主机的实际 SSH 指纹（SHA256:base64）并在人工确认后写入本机 hostkeys.json。"
            "用于 exec 返回 reason=host_key_unpinned / 指纹不匹配 的场合：先不带 trust 调一次拿到 fingerprint，"
            "把它与已有 pinned 一并报给用户核对，确认无误后再带 trust=true 调一次落盘。"
            "探测只做到密钥交换，不发送用户名与密码。凭据文件里已钉的 hostKey 由人自己改，这里覆盖不了。"
        ),
    )
    @_audited("pin_hostkey")
    async def _pin_hostkey(host: str, trust: bool = False) -> dict:
        import anyio

        return await anyio.to_thread.run_sync(lambda: _tool_pin_hostkey(host, trust))

    @server.tool(
        name="put_file",
        description=(
            "本机 -> 远端，分片断点续传 + 整文件 md5 校验。中断后再调同一参数会从缺口那片继续，不重头传。"
            "写入目标受 exec 那张清单约束（authorized_keys/sshd_config/sudoers 之类会被拦），force=true 可越过。"
            "远端已存在同名文件时默认拒绝，要覆盖带 overwrite=true。"
            "elevate=true 走两段式：先落到远端 ~/.sshmcp-xfer/ 再 sudo install 到目标（/root、/etc 只有这样才能写）。"
            "上限取 policy.json 的 defaults.max_transfer_bytes（现 4GB）。"
        ),
    )
    @_audited("put_file")
    async def _put_file(
        host: str,
        local: str,
        remote: str,
        overwrite: bool = False,
        force: bool = False,
        elevate: bool = False,
        restart: bool = False,
        mode: str = "",
    ) -> dict:
        import anyio

        return await anyio.to_thread.run_sync(
            lambda: _tool_put_file(host, local, remote, overwrite, force, elevate, restart, mode)
        )

    @server.tool(
        name="get_file",
        description=(
            "远端 -> 本机，落盘目录取 policy.json 的 defaults.xfer_dir（默认是系统下载目录），local 可覆盖。"
            "同样分片续传 + md5 校验；part 文件按目标名固定，中断后重调同一参数续传。"
            "读 root 才可见的文件用 elevate=true（服务端先 sudo cat 到暂存再取回）。"
        ),
    )
    @_audited("get_file")
    async def _get_file(
        host: str,
        remote: str,
        local: str = "",
        overwrite: bool = False,
        elevate: bool = False,
        restart: bool = False,
    ) -> dict:
        import anyio

        return await anyio.to_thread.run_sync(
            lambda: _tool_get_file(host, remote, local, overwrite, elevate, restart)
        )

    @server.tool(
        name="xfer_stat",
        description="取远端文件的 size/mode/uid/mtime，用于传前判断该不该传（比 exec ls -l 少一次文本解析）。不建立传输。",
    )
    @_audited("xfer_stat")
    async def _xfer_stat(host: str, remote: str) -> dict:
        import anyio

        return await anyio.to_thread.run_sync(lambda: _tool_xfer_stat(host, remote))

    @server.tool(name="session_reset", description="丢弃某主机的 SSH 连接与 cwd 状态并重新握手。")
    @_audited("session_reset")
    async def _session_reset(host: str) -> dict:
        import anyio

        return await anyio.to_thread.run_sync(lambda: _tool_session_reset(host))

    @server.tool(name="audit_tail", description="读回最近的审计记录（含被拒命令），用于自查拒绝原因。")
    @_audited("audit_tail")
    async def _audit_tail(host: str | None = None, limit: int = 50) -> dict:
        return _tool_audit_tail(host, limit)

    @server.tool(
        name="read_output",
        description=(
            "按 exec 返回的 output_id 回捞该命令的完整本机日志（exec 内联只给头尾两截）。"
            "mode：head/tail 按行边界取，grep 返回带行号的命中（pattern 是子串匹配，不是正则），lines 取 [start,end] 行。"
            "典型用法：grep 'error' 拿到行号，再用 lines(start=行号-20, end=行号+40) 看上下文。"
        ),
    )
    @_audited("read_output")
    async def _read_output(
        output_id: str,
        stream: str = "out",
        mode: str = "tail",
        start: int = 1,
        end: int = 0,
        pattern: str = "",
        limit: int = 16384,
    ) -> dict:
        return _tool_read_output(output_id, stream, mode, start, end, pattern, limit)

    @server.tool(
        name="job_status",
        description=(
            "读远端后台任务（exec detach=true 起的）的状态与输出增量。"
            "不给 offset 就回最后 max_bytes 字节；给了 offset 就从该字节读，返回值里的 offset_next 供下次只取新增部分。"
            "state：running/exited/killed/lost/missing。输出在远端 out 文件里，不占本机 output/ 配额。"
        ),
    )
    @_audited("job_status")
    async def _job_status(host: str, job_id: str, offset: int | None = None, max_bytes: int = 65536) -> dict:
        import anyio

        return await anyio.to_thread.run_sync(lambda: _tool_job_status(host, job_id, offset, max_bytes))

    @server.tool(
        name="job_kill",
        description=(
            "停掉一个远端后台任务：先对整个进程组 SIGTERM，5 秒不退再 SIGKILL，外加子进程树兜底。"
            "杀前核对进程命令行里确实是这个 job id（防 PID 复用误杀）；已结束的任务只会返回 not_running。"
        ),
    )
    @_audited("job_kill")
    async def _job_kill(host: str, job_id: str) -> dict:
        import anyio

        return await anyio.to_thread.run_sync(lambda: _tool_job_kill(host, job_id))

    @server.tool(
        name="job_list",
        description=(
            "列远端最近的后台任务及状态（running/exited/killed/lost），用于找孤儿任务与清理。"
            "保留期与并发上限取 policy.json 的 defaults.job_retention_days / job_max_concurrent。"
        ),
    )
    @_audited("job_list")
    async def _job_list(host: str, limit: int = 20) -> dict:
        import anyio

        return await anyio.to_thread.run_sync(lambda: _tool_job_list(host, limit))

    return server


# --------------------------------------------------------------------------------------
# CLI：doctor / list / serve
# --------------------------------------------------------------------------------------


def cmd_doctor(_: argparse.Namespace) -> int:
    print(f"limits : {POLICY_PATH}")
    print(f"凭据   : {HOSTS_PATH}{'（不存在）' if not HOSTS_PATH.exists() else ''}")
    print(f"指纹   : {HOSTKEYS_PATH}{'（不存在）' if not HOSTKEYS_PATH.exists() else ''}")
    print(f"audit  : {AUDIT_PATH}（保留 {AUDIT_KEEP_DAYS} 天，按天轮转）")
    try:
        guard = GUARD.get()
    except Exception as exc:  # noqa: BLE001
        print(f"policy.json 解析失败：{exc}")
        return 1
    creds = HOSTS.get()
    print(
        f"\n主机 {len(creds)} 台，killlist {len(guard.kill_prefixes)} 条"
        f"（root 账号恒查；非 root 只有 guarded_hosts 点名才查：{sorted(guard.guarded_hosts) or '空'}）"
    )
    for alias, cred in sorted(creds.items()):
        pin, source = effective_pin(alias, cred)
        flags = []
        if not pin:
            flags.append("未固定指纹(pin_hostkey)")
        if cred.auth == "password" and not cred.password:
            flags.append("password为空")
        print(
            f"  {alias:<8} {cred.username:<8} guard={'killlist' if G.applies(cred.privileged, alias, guard) else 'none':<8} "
            f"pin={source or '-':<11} elevate={'on' if cred.elevate else 'off':<4}({'+' if cred.elevate_password else '复用登录口令'}) {' '.join(flags)}"
        )
    try:
        AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
        probe = AUDIT_PATH.parent / ".write_probe"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        print("\n审计目录可写 ✓")
    except OSError as exc:
        print(f"\n审计目录不可写：{exc}（服务会 fail-closed 拒绝执行）")
        return 1
    try:
        OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)
        probe = OUTPUT_ROOT / ".write_probe"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        logs = list(OUTPUT_ROOT.glob("*.log"))
        runs = len({f.name.split(".")[0] for f in logs})
        used = sum(f.stat().st_size for f in logs)
        print(
            f"全文日志目录可写 ✓ {OUTPUT_ROOT}\n"
            f"  现存 {runs} 个 run / {used / 1048576:.1f} MB；轮转预算：{OUTPUT_KEEP_DAYS} 天内、"
            f"≤{OUTPUT_KEEP_RUNS} 个 run、≤{OUTPUT_KEEP_BYTES // 1048576} MB，单文件上限取自 defaults.max_output_bytes"
        )
    except OSError as exc:
        print(f"\noutput 目录不可写：{exc}（全文日志与审计同为必备件，会 fail-closed 拒绝执行）")
        return 1
    for mod in ("paramiko", "mcp"):
        try:
            __import__(mod)
            print(f"{mod} 可导入 ✓")
        except ImportError as exc:
            print(f"{mod} 导入失败：{exc}")
    dest = xfer_dir(guard)
    try:
        dest.mkdir(parents=True, exist_ok=True)
        probe = dest / ".sshmcp-write-probe"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        free = shutil.disk_usage(str(dest)).free
        print(
            f"下载目录可写 ✓ {dest}\n"
            f"  空闲 {free / 1024**3:.1f} GB，单文件上限 {guard.max_transfer_bytes / 1024**3:.0f} GB，"
            f"分片 {guard.xfer_chunk_bytes // 1024} KB，单次超时 {guard.xfer_timeout_s:.0f}s"
        )
        if free < guard.max_transfer_bytes:
            print(f"  注意：空闲不足一个上限文件，传大文件前先挪东西")
    except OSError as exc:
        print(f"\n下载目录不可写：{exc}（get_file 会直接失败）")
        return 1
    return 0


def cmd_list(_: argparse.Namespace) -> int:
    for h in _tool_list_hosts()["hosts"]:
        print(
            f"{h['alias']:<8} {'root' if h['privileged'] else 'user':<5} guard={h['guard']:<8} "
            f"pin={h['pin_source'] or '未固定':<10} elevate={'on' if h['elevate_available'] else 'off':<3} "
            f"connected={h['connected']} cwd={h['cwd']}  {h['purpose']}"
        )
    return 0


def cmd_serve(_: argparse.Namespace) -> int:
    try:
        server = build_server()
    except ImportError as exc:
        log(f"MCP 依赖缺失：{exc}")
        return 1
    log(f"stdio 服务启动，policy={POLICY_PATH.name} hosts={HOSTS_PATH.name}")
    server.run()
    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="ssh-mcp", description="常驻 SSH 会话的 MCP 服务")
    sub = ap.add_subparsers(dest="sub")
    sub.add_parser("serve", help="以 stdio 跑 MCP 服务（默认）").set_defaults(func=cmd_serve)
    sub.add_parser("doctor", help="检查配置/凭据/依赖").set_defaults(func=cmd_doctor)
    sub.add_parser("list", help="列出主机与指纹固定状态").set_defaults(func=cmd_list)
    return ap


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0].startswith("-"):
        argv.insert(0, "serve")
    args = build_parser().parse_args(argv)
    # MCP stdio 规定 UTF-8，而 Windows 上流默认 cp936：不转的话含中文的载荷会按 GBK 写字节
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, OSError):
            pass
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
