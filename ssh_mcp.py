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
import hashlib
import json
import os
import shlex
import socket
import sys
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import ssh_guard as G  # noqa: E402
import output_store as OS  # noqa: E402


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
OUTPUT_KEEP_DAYS = int(os.environ.get("SSHMCP_OUTPUT_KEEP_DAYS", "7"))


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


def audit(record: dict) -> None:
    record.setdefault("ts", iso(now_utc()))
    AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with AUDIT_PATH.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False) + "\n")


def audit_tail(alias: str | None, limit: int) -> list[dict]:
    try:
        lines = AUDIT_PATH.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return []
    out: list[dict] = []
    for line in reversed(lines):
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if alias and rec.get("host") != alias:
            continue
        out.append(rec)
        if len(out) >= limit:
            break
    return out


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


def run_command(cred: HostCred, pin: str, command: str, cwd: str, idle_s: float, max_s: float, spill: OS.Spill, elevate: bool = False) -> RunResult:
    """在远端执行一条命令。cwd 由服务端记录，发送前才拼上。"""
    sent = command if cwd in ("", "~") else f"cd {shlex.quote(cwd)} && {command}"
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
    spill.close()
    return RunResult(
        exit_code=-1,
        stdout="",
        stderr=f"{type(last_exc).__name__}: {last_exc}",
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
    if len(segments) != 1 or len(segments[0]) != 2 or segments[0][0] != "cd":
        return None
    return segments[0][1]


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


def execute(alias: str, command: str, cwd: str | None = None, idle_timeout: float | None = None, max_duration: float | None = None, force: bool = False, elevate: bool = False) -> dict:
    refusal, cred, pin = _preflight(alias, command)
    if refusal is not None:
        return refusal

    if elevate and not cred.elevate:
        return _block(alias, command, "elevate_not_configured", "no_elevate", f"凭据文件里为 {alias} 打开 elevate（那文件我不写）")
    if elevate and not cred.sudo_password():
        # 空口令喂进 stdin 会让 sudo 一直等输入，最后撞 idle 超时，报出来的还是假故障
        return _block(alias, command, "elevate_password_missing", "no_elevate_password", f"elevate_password 与 password 都为空，在凭据文件里补一个")

    guard = GUARD.get()
    cd_target = _cd_only_segment(command)
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
        audit({"host": alias, "command": command, "event": "intent", "rule": rule, "guarded": guarded, "elevated": elevate or None})
    except OSError as exc:
        return _block(alias, command, "audit_write_failed", "audit_unwritable", f"审计目录不可写：{exc}")

    idle_s = float(idle_timeout or guard.idle_timeout_s)
    max_s = float(max_duration or guard.max_duration_s)
    start_cwd = cwd or POOL.cwd(alias)

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
        res = run_command(cred, pin, f"cd {shlex.quote(cd_target)} && pwd", start_cwd, idle_s, max_s, spill, elevate)
        end_cwd = res.stdout.strip().splitlines()[-1] if res.exit_code == 0 and res.stdout.strip() else start_cwd
        if res.exit_code == 0:
            POOL.set_cwd(alias, end_cwd)
    else:
        res = run_command(cred, pin, command, start_cwd, idle_s, max_s, spill, elevate)
        end_cwd = start_cwd

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
        }
    )
    return _ok(alias, command, res, start_cwd, end_cwd, hit.rule if hit else None, elevate, cred.elevate_user or "root")


def _block(alias: str, command: str, reason: str, rule: str, hint: str) -> dict:
    try:  # 被拒也要留痕，但拒本身不需要 fail closed
        audit({"host": alias, "command": command, "event": "blocked", "reason": reason, "rule": rule})
    except OSError as exc:
        log(f"审计写入失败：{exc}")
    return {"host": alias, "command": command, "blocked": True, "reason": reason, "rule": rule, "hint": hint}


def _ok(alias, command, res: RunResult, cwd_before, cwd_after, forced_rule: str | None = None, elevate: bool = False, ran_as: str = "root") -> dict:
    payload = {
        "host": alias,
        "command": command,
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


def _tool_list_hosts() -> dict:
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
                },
            }
        )
    return {
        "hosts": hosts,
        "killlist": [p.raw for p in guard.kill_prefixes],
        "guarded_hosts": sorted(guard.guarded_hosts),
        "unpinned": [a for a in sorted(creds) if not effective_pin(a, creds[a])[0]],
        "note": "无权限控制：killlist（root 账号恒查 + guarded_hosts 点名的非 root 主机 + 任何带 elevate 的命令，exec 用 force=true 可越过）之外一律放行，真正的边界是远端账号自己的权限。被拦下的命令不会建立连接。",
    }


def _tool_exec(host: str, command: str, cwd: str | None = None, idle_timeout: float | None = None, max_duration: float | None = None, force: bool = False, elevate: bool = False) -> dict:
    return execute(host, command, cwd, idle_timeout, max_duration, force, elevate)


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

    @server.tool(name="list_hosts", description="列出凭据文件里的主机、指纹固定状态、是否受 killlist 保护及其原因、限额。不含任何密码。")
    async def _list_hosts() -> dict:
        return _tool_list_hosts()

    @server.tool(
        name="exec",
        description=(
            "在远端执行一条离散命令（不开交互 shell）。服务端不做权限控制，命令原样交给远端 shell；"
            "只有受保护主机（username=root，或被 policy.json 的 guarded_hosts 点名，或本次带 elevate）"
            "会查一张自杀清单，命中时带 force=true 即可放行。被拦下时不建立连接。"
            "cwd 由服务端按主机记忆，可用参数覆盖；max_duration 传多大就用多大。"
            "elevate=true 以 root 跑这一条（凭据里该主机须 elevate:true）——服务端用 sudo -S 并把口令写进"
            "channel stdin，口令不进命令行、不进审计、不进远端 history；提权命令一律查清单。"
        ),
    )
    async def _exec(
        host: str,
        command: str,
        cwd: str | None = None,
        idle_timeout: float | None = None,
        max_duration: float | None = None,
        force: bool = False,
        elevate: bool = False,
    ) -> dict:
        import anyio

        return await anyio.to_thread.run_sync(
            lambda: _tool_exec(host, command, cwd, idle_timeout, max_duration, force, elevate)
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
    async def _pin_hostkey(host: str, trust: bool = False) -> dict:
        import anyio

        return await anyio.to_thread.run_sync(lambda: _tool_pin_hostkey(host, trust))

    @server.tool(name="session_reset", description="丢弃某主机的 SSH 连接与 cwd 状态并重新握手。")
    async def _session_reset(host: str) -> dict:
        import anyio

        return await anyio.to_thread.run_sync(lambda: _tool_session_reset(host))

    @server.tool(name="audit_tail", description="读回最近的审计记录（含被拒命令），用于自查拒绝原因。")
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

    return server


# --------------------------------------------------------------------------------------
# CLI：doctor / list / serve
# --------------------------------------------------------------------------------------


def cmd_doctor(_: argparse.Namespace) -> int:
    print(f"limits : {POLICY_PATH}")
    print(f"凭据   : {HOSTS_PATH}{'（不存在）' if not HOSTS_PATH.exists() else ''}")
    print(f"指纹   : {HOSTKEYS_PATH}{'（不存在）' if not HOSTKEYS_PATH.exists() else ''}")
    print(f"audit  : {AUDIT_PATH}")
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
