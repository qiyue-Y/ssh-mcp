# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "mcp>=1.2",
#     "paramiko>=3.4",
# ]
# ///
"""ssh-mcp —— 常驻 SSH 会话的 MCP 服务，带服务端策略与人工授权。

用法：
    ssh_mcp.py [serve]                                  # 作为 MCP 服务跑（stdio）
    ssh_mcp.py doctor                                   # 检查配置与凭据
    ssh_mcp.py list                                     # 列出主机与当前 mode
    ssh_mcp.py grant 100 --scope host --for 30m         # 人工授权（必须 TTY）
    ssh_mcp.py revoke 100 --all

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
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import ssh_policy as P  # noqa: E402


def _path_from_env(var: str, default: Path) -> Path:
    raw = os.environ.get(var)
    return Path(raw).expanduser() if raw else default


HOME_DIR = _path_from_env("SSHMCP_HOME", HERE)
POLICY_PATH = _path_from_env("SSHMCP_POLICY", HOME_DIR / "policy.json")
HOSTS_PATH = _path_from_env("SSHMCP_HOSTS", HOME_DIR / "ssh_mcp_hosts.json")
GRANTS_PATH = _path_from_env("SSHMCP_GRANTS", HOME_DIR / "grants.json")
AUDIT_PATH = _path_from_env("SSHMCP_AUDIT", HOME_DIR / "audit" / "ssh-mcp.jsonl")
CONFIRM_TIMEOUT = int(os.environ.get("SSHMCP_CONFIRM_TIMEOUT", "120"))


def log(msg: str) -> None:
    print(f"[ssh-mcp] {msg}", file=sys.stderr, flush=True)


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds")


# --------------------------------------------------------------------------------------
# 配置：policy 与 grants 都按 mtime 热加载，grant 完不必重启服务
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
    rw_allowed: bool = False
    purpose: str = ""

    @property
    def privileged(self) -> bool:
        # SPEC §8 决议：只按 username 判，不做远端探测。
        return self.username == "root"

    def public(self) -> dict:
        data = asdict(self)
        data.pop("password", None)
        data["privileged"] = self.privileged
        data["host_key_pinned"] = bool(self.host_key)
        return data


_KEY_ALIASES = {"hostKey": "host_key", "hostkey": "host_key", "keyPath": "key_path"}


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


POLICY = CachedJson(POLICY_PATH, lambda raw: P.load_policy(raw or {}))
HOSTS = CachedJson(HOSTS_PATH, _load_hosts)


@dataclass
class GrantFile:
    grants: list[P.Grant] = field(default_factory=list)


def _load_grants(raw: dict | None) -> GrantFile:
    grants: list[P.Grant] = []
    for item in (raw or {}).get("grants", []):
        known = {f for f in P.Grant.__dataclass_fields__}
        grants.append(P.Grant(**{k: v for k, v in item.items() if k in known}))
    return GrantFile(grants=grants)


GRANTS = CachedJson(GRANTS_PATH, _load_grants)


def save_grants(store: GrantFile) -> None:
    GRANTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    payload = {"grants": [asdict(g) for g in store.grants]}
    tmp = GRANTS_PATH.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, GRANTS_PATH)
    GRANTS._mtime = None  # 强制下次重读


def grants_for(alias: str) -> list[P.Grant]:
    return [g for g in GRANTS.get().grants if g.alias == alias and g.is_live()]


# --------------------------------------------------------------------------------------
# 权限判定
# --------------------------------------------------------------------------------------


@dataclass
class ModeInfo:
    mode: str
    reason: str
    grant: P.Grant | None = None


def long_lived_mode(cred: HostCred) -> ModeInfo:
    if not cred.rw_allowed:
        return ModeInfo("ro", "rw_allowed 未设置 → 一律只读")
    if not cred.privileged:
        return ModeInfo("rw", "非 root + rw_allowed → 长期可写")
    return ModeInfo("ro", "root 账号：需人工 grant 才可写")


def resolve_mode(alias: str, command: str, cred: HostCred) -> ModeInfo:
    base = long_lived_mode(cred)
    if base.mode == "rw":
        return base
    if not cred.rw_allowed:
        return base
    for grant in grants_for(alias):
        if grant.scope == "host":
            return ModeInfo("rw", f"host grant {grant.id}（TTL 内）", grant)
    for grant in grants_for(alias):
        if grant.scope == "cmd" and P.grant_matches(grant, command, POLICY.get()):
            return ModeInfo("rw", f"cmd grant {grant.id} 命中前缀 {grant.command!r}", grant)
    return ModeInfo(base.mode, base.reason + "；无有效 grant")


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
                raise HostKeyMismatch(f"{hostname} 未在凭据里钉 hostKey，拒绝连接")

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

    def _connect(self, cred: HostCred):
        import paramiko

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(_build_pinned_policy(cred.host_key))
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

    def client(self, cred: HostCred, reconnect: bool = False):
        existing = self._clients.get(cred.alias)
        if existing is not None and not reconnect:
            transport = existing.get_transport()
            if transport is not None and transport.is_active():
                return existing
            self.close(cred.alias)
        client = self._connect(cred)
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


def _drain(chan, idle_s: float, deadline: float, cap: int) -> RunResult:
    """按双计时器收流：idle 靠 recv 超时（有新输出就重置），max 靠 deadline。"""
    out: list[bytes] = []
    err: list[bytes] = []
    out_len = err_len = 0
    truncated = False
    timed_out: str | None = None

    def take(chunk: bytes, is_err: bool) -> None:
        nonlocal out_len, err_len, truncated
        buf = err if is_err else out
        have = err_len if is_err else out_len
        room = cap - have
        if room <= 0:
            truncated = True
            return
        if len(chunk) > room:
            buf.append(chunk[:room])
            truncated = True
        else:
            buf.append(chunk)
        if is_err:
            err_len += len(chunk)
        else:
            out_len += len(chunk)

    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            timed_out = "duration"
            break
        chan.settimeout(min(idle_s, remaining))
        try:
            if chan.recv_ready():
                take(chan.recv(65536), False)
                continue
            if chan.recv_stderr_ready():
                take(chan.recv_stderr(65536), True)
                continue
            if chan.exit_status_ready():
                break
            chunk = chan.recv(65536)  # 无数据时阻塞，超时抛 socket.timeout —— 即 idle
        except socket.timeout:
            timed_out = "idle"
            break
        except (socket.error, OSError) as exc:
            err.append(f"\n[ssh-mcp] 通道异常：{type(exc).__name__}: {exc}".encode())
            break
        if not chunk:
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
    try:
        code = chan.recv_exit_status() if chan.exit_status_ready() else -1
    except Exception:  # noqa: BLE001
        code = -1
    try:
        chan.close()
    except Exception:  # noqa: BLE001
        pass
    return RunResult(
        exit_code=code,
        stdout=b"".join(out).decode("utf-8", "replace"),
        stderr=b"".join(err).decode("utf-8", "replace"),
        truncated=truncated,
        timed_out=timed_out,
    )


NO_RETRY = ("AuthenticationException", "HostKeyMismatch", "BadAuthenticationType", "PasswordRequiredException")


def run_command(cred: HostCred, command: str, cwd: str, idle_s: float, max_s: float, cap: int) -> RunResult:
    """在远端执行一条命令。cwd 由服务端记录，发送前才拼上，不参与策略判定。"""
    sent = command if cwd in ("", "~") else f"cd {shlex.quote(cwd)} && {command}"
    last_exc: Exception | None = None
    for attempt in range(2):
        try:
            client = POOL.client(cred, reconnect=attempt > 0)
            transport = client.get_transport()
            if transport is None or not transport.is_active():
                raise RuntimeError("transport 不可用")
            chan = transport.open_session()
            chan.exec_command(sent)
            return _drain(chan, idle_s, time.monotonic() + max_s, cap)
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            # 认证与指纹类错误重试只会喂 fail2ban，直接停
            if type(exc).__name__ in NO_RETRY:
                POOL.close(cred.alias)
                break
            POOL.close(cred.alias)
            if attempt == 0:
                continue
            break
    assert last_exc is not None
    return RunResult(
        exit_code=-1,
        stdout="",
        stderr=f"{type(last_exc).__name__}: {last_exc}",
        truncated=False,
        timed_out="connect_failed",
    )


# --------------------------------------------------------------------------------------
# 核心执行入口（工具与 CLI 共用）
# --------------------------------------------------------------------------------------


def _cd_only_segment(command: str) -> str | None:
    try:
        tokens = P.tokenize(command)
    except P.PolicySyntaxError:
        return None
    segments = P.split_segments(tokens)
    if len(segments) != 1 or len(segments[0]) != 2 or segments[0][0] != "cd":
        return None
    return segments[0][1]


def execute(alias: str, command: str, cwd: str | None = None, idle_timeout: float | None = None, max_duration: float | None = None) -> dict:
    policy = POLICY.get()
    if alias not in policy.hosts:
        return _refuse(alias, command, "unknown_host", "not_in_policy", "主机不在 policy.json 的 hosts 白名单里，即使凭据文件有这台也不给连", "ro")
    cred = HOSTS.get().get(alias)
    if cred is None:
        return _refuse(
            alias,
            command,
            "credential_missing",
            "no_credential",
            f"凭据文件 {HOSTS_PATH} 里缺 {alias} 这一条，请你自行补上（我不读不写该文件）",
            "ro",
        )
    if not cred.host_key:
        return _refuse(alias, command, "host_key_unpinned", "no_hostKey", f"请在凭据里为 {alias} 填 hostKey 指纹", "ro")

    mode_info = resolve_mode(alias, command, cred)
    cd_target = _cd_only_segment(command)
    if cd_target is None:
        decision = P.decide(command, mode_info.mode, policy)
        if not decision.allowed:
            return _refuse(alias, command, decision.reason, decision.matched_rule, _hint_for(decision, cred, mode_info), mode_info.mode)
    else:
        # 单独的 cd 只改服务端记的 cwd，不触碰远端状态，两种 mode 都放行
        decision = P.Decision(True, matched_rule="cd_only", segments=[["cd", cd_target]])

    # fail closed：审计写不进去就不执行
    try:
        audit({"host": alias, "command": command, "decision": "intent", "reason": "ok", "matched_rule": decision.matched_rule, "mode": mode_info.mode, "grant_id": mode_info.grant.id if mode_info.grant else None, "stage": "intent"})
    except OSError as exc:
        return _refuse(alias, command, "audit_write_failed", "audit_unwritable", f"审计目录不可写：{exc}", mode_info.mode)

    cap = policy.max_output_bytes
    idle_s = float(idle_timeout or policy.idle_timeout_s)
    max_s = min(float(max_duration or policy.max_duration_s), policy.max_duration_s)
    start_cwd = cwd or POOL.cwd(alias)

    if cd_target is not None:
        res = run_command(cred, f"cd {shlex.quote(cd_target)} && pwd", start_cwd, idle_s, max_s, cap)
        end_cwd = res.stdout.strip().splitlines()[-1] if res.exit_code == 0 and res.stdout.strip() else start_cwd
        if res.exit_code == 0:
            POOL.set_cwd(alias, end_cwd)
    else:
        res = run_command(cred, command, start_cwd, idle_s, max_s, cap)
        end_cwd = start_cwd

    broad = mode_info.grant is not None and P.broad_grant_hit(decision.segments, policy)
    if mode_info.grant is not None and mode_info.grant.scope == "cmd":
        _consume_grant(mode_info.grant)
    audit(
        {
            "host": alias,
            "command": command,
            "decision": "executed",
            "reason": res.timed_out or "ok",
            "matched_rule": decision.matched_rule,
            "mode": mode_info.mode,
            "exit_code": res.exit_code,
            "grant_id": mode_info.grant.id if mode_info.grant else None,
            "broad_grant": broad or None,
            "stage": "result",
        }
    )
    return _ok(alias, command, res, start_cwd, end_cwd, mode_info, decision, broad)


def _refuse(alias: str, command: str, reason: str, rule: str, hint: str, mode: str) -> dict:
    try:  # 被拒也要留痕，但拒本身不需要 fail closed
        audit({"host": alias, "command": command, "decision": "deny", "reason": reason, "matched_rule": rule, "mode": mode, "stage": "result"})
    except OSError as exc:
        log(f"审计写入失败：{exc}")
    return _denied(alias, command, reason, hint, rule, mode)


def _consume_grant(grant: P.Grant) -> None:
    store = GRANTS.get()
    target = next((g for g in store.grants if g.id == grant.id), None)
    if target is None:
        return
    target.consume()
    if target.uses_left == 0:
        store.grants.remove(target)
    save_grants(store)


def _denied(alias: str, command: str, reason: str, hint: str, rule: str = "", mode: str = "ro") -> dict:
    return {
        "allowed": False,
        "host": alias,
        "command": command,
        "reason": reason,
        "matched_rule": rule,
        "mode": mode,
        "hint": hint,
    }


def _ok(alias, command, res: RunResult, cwd_before, cwd_after, mode_info: ModeInfo, decision, broad=False) -> dict:
    payload = {
        "allowed": True,
        "host": alias,
        "exit_code": res.exit_code,
        "stdout": res.stdout,
        "stderr": res.stderr,
        "truncated": res.truncated,
        "timed_out": res.timed_out,
        "cwd_before": cwd_before,
        "cwd_after": cwd_after,
        "decision": {
            "allowed": True,
            "mode": mode_info.mode,
            "mode_reason": mode_info.reason,
            "matched_rule": decision.matched_rule,
            "grant_id": mode_info.grant.id if mode_info.grant else None,
            "broad_grant": bool(broad),
        },
    }
    if res.timed_out == "duration":
        payload["hint"] = "撞到 max_duration：静默长任务应改用 detach（M2 提供）"
    return payload


def _hint_for(decision, cred: HostCred, mode_info: ModeInfo) -> str:
    # 能力位是第一层：rw_allowed 为假时 resolve_mode 根本不查 grant，叫 Agent 去 grant 是死路
    if not cred.rw_allowed and decision.reason in (
        "not_in_allowlist",
        "redirect_not_allowed_in_ro",
        "command_substitution_not_allowed_in_ro",
        "interpreter_not_allowed_in_ro",
        "secret_path_not_readable_in_ro",
    ):
        return f"{cred.alias} 凭据未设 rw_allowed，grant 解不开只读（CLI grant 同样会拒）。要写请先在凭据文件里为 {cred.alias} 打开 rw_allowed"
    if decision.reason == "not_in_allowlist":
        return f"{cred.alias} 当前只读。要执行请申请 grant：grant {cred.alias} --scope cmd --cmd \"<命令>\" --for 30m"
    if decision.reason in ("redirect_not_allowed_in_ro", "command_substitution_not_allowed_in_ro", "interpreter_not_allowed_in_ro"):
        return f"{cred.alias} 只读模式下禁止该形态。若确需写入请申请 grant：grant {cred.alias} --scope host --for 30m"
    if decision.reason == "denylisted":
        return f"命中 rw 硬黑名单 {decision.matched_rule}，grant 也解不开"
    if decision.reason == "secret_path_not_readable_in_ro":
        return "该路径在 ro 下不可读（私钥/shadow/sudoers 类）。需要读请临时给 host scope grant"
    return mode_info.reason


# --------------------------------------------------------------------------------------
# MCP 工具
# --------------------------------------------------------------------------------------


def _tool_list_hosts() -> dict:
    policy = POLICY.get()
    creds = HOSTS.get()
    hosts = []
    for alias in policy.aliases:
        cred = creds.get(alias)
        entry = {"alias": alias, **(policy.hosts.get(alias) or {})}
        if cred is None:
            entry.update({"credential_present": False, "effective_mode": "unreachable", "mode_reason": "凭据文件里缺这一条"})
            hosts.append(entry)
            continue
        mode_info = long_lived_mode(cred)
        live = [g for g in grants_for(alias)]
        entry.update(
            {
                "credential_present": True,
                "address": f"{cred.address}:{cred.port}",
                "username": cred.username,
                "privileged": cred.privileged,
                "auth": cred.auth,
                "host_key_pinned": bool(cred.host_key),
                "rw_allowed": cred.rw_allowed,
                "effective_mode": mode_info.mode,
                "mode_reason": mode_info.reason,
                "grant_expires_at": max((g.expires_at or "" for g in live), default=None),
                "grant_count": len(live),
                "connected": POOL.connected(alias),
                "cwd": POOL.cwd(alias),
                "limits": {
                    "idle_timeout_s": policy.idle_timeout_s,
                    "max_duration_s": policy.max_duration_s,
                    "max_output_bytes": policy.max_output_bytes,
                },
            }
        )
        hosts.append(entry)
    return {
        "hosts": hosts,
        "ro_allowlist": [p.raw for p in policy.ro_allowlist],
        "hard_denies": [p.raw for p in policy.rw_denylist],
        "secret_paths_denied_in_ro": list(policy.ro_deny_paths),
        "note": "被拒命令不会建立连接；grant 只能由人在 TTY 里敲，我不能自批。",
    }


def _tool_exec(host: str, command: str, cwd: str | None = None, idle_timeout: float | None = None, max_duration: float | None = None) -> dict:
    return execute(host, command, cwd, idle_timeout, max_duration)


def _tool_session_reset(host: str) -> dict:
    POOL.close(host, reset_cwd=True)
    return {"host": host, "reset": True, "cwd": POOL.cwd(host)}


def _tool_audit_tail(host: str | None = None, limit: int = 50) -> dict:
    return {"records": audit_tail(host, min(max(1, limit), 500))}


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

    @server.tool(name="list_hosts", description="列出可连主机及其权限约束、当前 effective_mode 与限额。不含任何密码。")
    async def _list_hosts() -> dict:
        return _tool_list_hosts()

    @server.tool(
        name="exec",
        description=(
            "在远端执行一条离散命令（不开交互 shell）。服务端按 policy.json 判定 ro/rw 并做命令级校验；"
            "被拒时不建立连接，返回 reason 与下一步建议。cwd 由服务端按主机记忆，可用参数覆盖。"
        ),
    )
    async def _exec(
        host: str,
        command: str,
        cwd: str | None = None,
        idle_timeout: float | None = None,
        max_duration: float | None = None,
    ) -> dict:
        import anyio

        return await anyio.to_thread.run_sync(
            lambda: _tool_exec(host, command, cwd, idle_timeout, max_duration)
        )

    @server.tool(name="session_reset", description="丢弃某主机的 SSH 连接与 cwd 状态并重新握手。")
    async def _session_reset(host: str) -> dict:
        import anyio

        return await anyio.to_thread.run_sync(lambda: _tool_session_reset(host))

    @server.tool(name="audit_tail", description="读回最近的审计记录（含被拒命令），用于自查拒绝原因。")
    async def _audit_tail(host: str | None = None, limit: int = 50) -> dict:
        return _tool_audit_tail(host, limit)

    return server


# --------------------------------------------------------------------------------------
# CLI：doctor / list / grant / revoke / serve
# --------------------------------------------------------------------------------------


def cmd_doctor(_: argparse.Namespace) -> int:
    print(f"policy : {POLICY_PATH}")
    print(f"凭据   : {HOSTS_PATH}{'（不存在）' if not HOSTS_PATH.exists() else ''}")
    print(f"grants : {GRANTS_PATH}{'（不存在）' if not GRANTS_PATH.exists() else ''}")
    print(f"audit  : {AUDIT_PATH}")
    try:
        policy = POLICY.get()
    except Exception as exc:  # noqa: BLE001
        print(f"policy.json 解析失败：{exc}")
        return 1
    print(f"\n可连主机白名单 {len(policy.hosts)} 台，ro 白名单 {len(policy.ro_allowlist)} 条，rw 黑名单 {len(policy.rw_denylist)} 条")
    creds = HOSTS.get()
    missing = [a for a in policy.aliases if a not in creds]
    if missing:
        print(f"  缺凭据（policy 列了但凭据文件没有）：{', '.join(missing)}")
    for alias, cred in sorted(creds.items()):
        flags = []
        if not cred.host_key:
            flags.append("缺hostKey")
        if alias not in policy.hosts:
            flags.append("不在policy_hosts")
        if cred.auth == "password" and not cred.password:
            flags.append("password为空")
        mode = long_lived_mode(cred)
        print(f"  {alias:<8} {cred.username:<8} {mode.mode:<3}  {mode.reason}  {' '.join(flags)}")
    try:
        AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
        probe = AUDIT_PATH.parent / ".write_probe"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        print("\n审计目录可写 ✓")
    except OSError as exc:
        print(f"\n审计目录不可写：{exc}（服务会 fail-closed 拒绝执行）")
        return 1
    for mod in ("paramiko", "mcp"):
        try:
            __import__(mod)
            print(f"{mod} 可导入 ✓")
        except ImportError as exc:
            print(f"{mod} 导入失败：{exc}")
    return 0


def cmd_list(_: argparse.Namespace) -> int:
    data = _tool_list_hosts()
    for h in data["hosts"]:
        print(f"{h['alias']:<8} {h.get('effective_mode','?'):<4} grant={h.get('grant_count', 0)}  {h.get('mode_reason','') or h.get('purpose','')}")
    return 0


def human_confirm(title: str, body: str, timeout_s: int = 120) -> bool:
    """弹 Windows 原生模态框，要人真的点「确定」。

    为什么不用 stdin.isatty() 把关：实测在 Agent 的 Bash 工具里 isatty() 返回 True
    （Git Bash 经 conpty 伪装成终端），那道校验拦不住 Agent 自批。对话框由子进程弹出，
    Agent 没有桌面点击能力，超时就连子进程一起杀掉，等于自动取消。
    """
    if os.name != "nt":
        return False
    import subprocess

    flags = 0x00000001 | 0x00000030 | 0x00001000  # MB_OKCANCEL | MB_ICONWARNING | MB_SYSTEMMODAL
    code = (
        "import ctypes,sys;r=ctypes.windll.user32.MessageBoxW(0,"
        f"{body!r},{title!r},{flags});sys.exit(0 if r==1 else 1)"
    )
    try:
        proc = subprocess.Popen([sys.executable, "-c", code])
    except OSError as exc:
        log(f"无法弹出确认框：{exc}")
        return False
    try:
        return proc.wait(timeout=timeout_s) == 0
    except subprocess.TimeoutExpired:
        proc.kill()
        return False


def cmd_grant(args: argparse.Namespace) -> int:
    if not sys.stdin.isatty():
        print("stdin 不是终端，拒绝签发。", file=sys.stderr)
        return 2
    policy = POLICY.get()
    if args.alias not in policy.hosts:
        print(f"{args.alias} 不在 policy.hosts 里，先加进 policy.json", file=sys.stderr)
        return 1
    creds = HOSTS.get().get(args.alias)
    if creds is None:
        print(f"{args.alias} 没有凭据条目", file=sys.stderr)
        return 1
    if not creds.rw_allowed:
        print(f"{args.alias} 未设 rw_allowed，grant 解不开只读（能力位是第一层）", file=sys.stderr)
        return 1
    if args.scope == "cmd" and not args.cmd:
        print("--scope cmd 必须给 --cmd", file=sys.stderr)
        return 1
    ttl = P.parse_duration(args.for_)
    grant = P.Grant(
        id=f"g-{uuid.uuid4().hex[:8]}",
        alias=args.alias,
        scope=args.scope,
        command=args.cmd or "",
        uses_left=args.uses,
        expires_at=iso(now_utc() + timedelta(seconds=ttl)),
        granted_via="pending",
        why=args.why,
    )
    body = (
        f"主机   {grant.alias}  ({creds.username}@{creds.address})\n"
        f"root?  {creds.privileged}\n"
        f"范围   {grant.scope}  {grant.command or '(该主机 rw 全开)'}\n"
        f"时长   {ttl} 秒    次数   {'TTL 内不限' if grant.uses_left < 0 else grant.uses_left}\n"
        f"理由   {grant.why or '(未填)'}\n\n"
        "点「确定」签发该 rw 授权；「取消」或超时不写入。"
    )
    print(body)
    if not human_confirm("ssh-mcp：确认签发 rw 授权？", body, timeout_s=CONFIRM_TIMEOUT):
        print("未获得人工确认，已取消。", file=sys.stderr)
        return 1
    grant.granted_via = "user32.MessageBoxW"
    store = GRANTS.get()
    store.grants.append(grant)
    save_grants(store)
    audit({"host": grant.alias, "command": f"<grant {grant.scope} {grant.command}>", "decision": "grant", "reason": "issued", "matched_rule": grant.id, "broad_grant": None})
    print(f"已签发 {grant.id}，有效期至 {grant.expires_at}。服务端下次 exec 自动读到，无需重启。")
    return 0


def cmd_revoke(args: argparse.Namespace) -> int:
    store = GRANTS.get()
    before = len(store.grants)
    if args.all:
        store.grants = [g for g in store.grants if g.alias != args.alias]
    else:
        store.grants = [g for g in store.grants if not (g.alias == args.alias and (args.id is None or g.id == args.id))]
    save_grants(store)
    print(f"撤销 {before - len(store.grants)} 条")
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
    sub.add_parser("list", help="列出主机与当前 mode").set_defaults(func=cmd_list)
    g = sub.add_parser("grant", help="签发 rw 授权（必须 TTY）")
    g.add_argument("alias")
    g.add_argument("--scope", choices=["host", "cmd"], default="host")
    g.add_argument("--cmd", default="", help="cmd scope 的前缀，如 'apt install nginx'")
    g.add_argument("--for", dest="for_", default="30m")
    g.add_argument("--uses", type=int, default=1, help="可消费次数，-1 为 TTL 内不限次")
    g.add_argument("--why", default="")
    g.set_defaults(func=cmd_grant)
    r = sub.add_parser("revoke", help="撤销授权")
    r.add_argument("alias")
    r.add_argument("--id", default=None)
    r.add_argument("--all", action="store_true")
    r.set_defaults(func=cmd_revoke)
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
