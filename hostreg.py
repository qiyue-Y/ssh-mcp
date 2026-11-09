# /// script
# requires-python = ">=3.11"
# ///
"""hostreg —— 主机清单的读写与校验，凭据文件只有这一个写入口。

供两个调用方共用：
  - `hosts_gui.py`（tkinter 窗口，用户本人跑）
  - `gen_hosts.py`（命令行薄壳）

设计约束：
  - **纯 stdlib**，不 import paramiko / mcp，方便离线测。
  - 保存是原子的：先写同目录临时文件再 `os.replace`，服务端按 mtime 热加载，
    不会读到半截 JSON。
  - 保存前自动备份成 `<文件名>.bak-<时间戳>`，只留最近若干份。
  - `_` 开头的注释键原样保留；条目里服务端不认识的键也原样保留（GUI 只改它认识的字段）。
  - password 留空 = 沿用旧口令（GUI 不回填明文，避免出现在截图里）。

本模块注意：**服务进程（ssh_mcp.py）只读凭据文件**，写只在用户自己的工具里发生。
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_NAME = "ssh_mcp_hosts.json"
BACKUP_KEEP = 10
SKIP_HOSTS = {"github.com"}  # 没有 shell 可 exec 的目标

# 服务端 HostCred 认识的字段；GUI 表单按这张表生成
FIELDS = (
    "address", "port", "username", "auth", "password", "key_path", "hostKey", "purpose",
    "elevate", "elevate_user", "elevate_password", "shell_init",
    "disabled", "critical", "xfer",
)
FLAG_FIELDS = ("elevate", "disabled", "critical", "xfer")
ALIAS_RE = re.compile(r"^[A-Za-z0-9._:@+-]+$")
HOSTKEY_RE = re.compile(r"^SHA256:[A-Za-z0-9+/]+$")

# 与 paramiko Transport._preferred_keys 前几档一致（本机实测 paramiko 5.0.0）
KEY_RANK = {
    "ssh-ed25519": 0,
    "ecdsa-sha2-nistp256": 1,
    "ecdsa-sha2-nistp384": 2,
    "ecdsa-sha2-nistp521": 3,
    "rsa-sha2-512": 4,
    "rsa-sha2-256": 4,
    "ssh-rsa": 4,
}


class HostregError(ValueError):
    """凭据文件本身不可用（JSON 坏了、顶层不是对象）：拒绝写入，别覆盖用户数据。"""


def hosts_path() -> Path:
    if raw := os.environ.get("SSHMCP_HOSTS"):
        return Path(raw).expanduser()
    base = Path(os.environ["SSHMCP_HOME"]).expanduser() if os.environ.get("SSHMCP_HOME") else HERE
    return base / DEFAULT_NAME


def is_entry(value) -> bool:
    return isinstance(value, dict)


def hosts(raw: dict) -> dict[str, dict]:
    """只取真正的条目：跳过 `_` 注释键与非对象值。"""
    return {k: v for k, v in (raw or {}).items() if not str(k).startswith("_") and is_entry(v)}


def normalize(entry: dict) -> dict:
    """把值收敛成服务端能直接吃的形态；未知键原样保留。"""
    out = dict(entry)
    for key in ("port",):
        if key in out:
            try:
                out[key] = int(out[key])
            except (TypeError, ValueError):
                pass
    for key in FLAG_FIELDS:
        if key in out:
            out[key] = bool(out[key])
    for key in ("address", "username", "auth", "password", "key_path", "hostKey", "purpose",
                "elevate_user", "elevate_password", "shell_init"):
        if key in out and out[key] is None:
            out[key] = ""
    return out


def validate(alias: str, entry: dict, existing_aliases: set[str] | None = None,
             is_new: bool = True) -> tuple[list[str], list[str]]:
    """返回 (errors, warnings)。errors 非空时不该保存；warnings 只是提示。"""
    errors: list[str] = []
    warnings: list[str] = []
    if not alias:
        errors.append("别名不能为空")
    elif alias.startswith("_"):
        errors.append("别名不能以 _ 开头（服务端会当成注释跳过）")
    elif not ALIAS_RE.match(alias):
        errors.append("别名只能含字母、数字与 . _ : @ + -")
    elif existing_aliases and is_new and alias in existing_aliases:
        errors.append(f"别名 {alias} 已存在")

    address = str(entry.get("address") or "").strip()
    if not address:
        errors.append("address 不能为空")
    elif any(c.isspace() for c in address):
        errors.append("address 不能含空白")

    port_raw = entry.get("port", 22)
    try:
        port = int(port_raw)
        if not (1 <= port <= 65535):
            errors.append("port 必须在 1–65535")
    except (TypeError, ValueError):
        errors.append("port 不是整数")

    if not str(entry.get("username") or "").strip():
        warnings.append("username 为空：连不上，保存后记得补")

    auth = str(entry.get("auth") or "password")
    if auth not in ("password", "key"):
        errors.append("auth 只能是 password 或 key")
    if auth == "password":
        keep_existing = not is_new and not str(entry.get("password") or "")
        if not str(entry.get("password") or "") and not keep_existing:
            warnings.append("auth=password 但口令为空：exec 会失败")
    else:
        key_path = str(entry.get("key_path") or "").strip()
        if key_path and not Path(key_path).expanduser().is_file():
            warnings.append(f"key_path 指向的文件不存在：{key_path}（运行时还会再找 ssh-agent）")

    host_key = str(entry.get("hostKey") or "").strip()
    if host_key and not HOSTKEY_RE.match(host_key):
        errors.append("hostKey 形如 SHA256:xxxx（不带末尾 =）")
    if not host_key:
        warnings.append("hostKey 为空：先探测指纹并确认，否则 exec 会被拒")
    return errors, warnings


@dataclass
class Candidate:
    alias: str
    entry: dict
    notes: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)  # 不可导入的原因，非空时 GUI 置灰

    @property
    def importable(self) -> bool:
        return not self.reasons


class Registry:
    """一个凭据文件的读写句柄。每次写都会重新读盘，避免覆盖别人期间的改动。"""

    def __init__(self, path: Path | None = None):
        self.path = Path(path or hosts_path()).expanduser()
        self.raw: dict = {}
        self.error: str = ""
        self.reload()

    def reload(self) -> None:
        self.error = ""
        if not self.path.exists():
            self.raw = {}
            return
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            self.raw = {}
            self.error = f"{self.path.name} 无法解析：{exc}"
            return
        if not isinstance(raw, dict):
            self.raw = {}
            self.error = f"{self.path.name} 顶层不是对象"
            return
        self.raw = raw

    @property
    def writable(self) -> bool:
        return not self.error

    def entries(self) -> dict[str, dict]:
        return hosts(self.raw)

    def aliases(self) -> set[str]:
        return set(self.entries())

    def get(self, alias: str) -> dict:
        return dict(self.entries().get(alias) or {})

    def _backup(self) -> str:
        """保存前备份旧文件，返回备份文件名（没有旧文件时为空）。"""
        if not self.path.exists():
            return ""
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        dest = self.path.with_name(f"{self.path.name}.bak-{stamp}")
        n = 1
        while dest.exists():
            dest = self.path.with_name(f"{self.path.name}.bak-{stamp}-{n}")
            n += 1
        shutil.copy2(self.path, dest)
        self._prune_backups()
        return dest.name

    def _prune_backups(self) -> None:
        baks = sorted(self.path.parent.glob(f"{self.path.name}.bak-*"), key=lambda p: p.name)
        for old in baks[:-BACKUP_KEEP]:
            try:
                old.unlink()
            except OSError:
                pass

    def save(self) -> str:
        """原子写 + 备份。返回备份文件名；失败抛 HostregError/OSError。"""
        if not self.writable:
            raise HostregError(self.error)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        backup = self._backup()
        tmp = self.path.with_name(f"{self.path.name}.tmp")
        payload = json.dumps(self.raw, indent=2, ensure_ascii=False) + "\n"
        with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(payload)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, self.path)
        return backup

    def upsert(self, alias: str, entry: dict, keep_password_if_empty: bool = True) -> dict:
        """新增或更新一条；保留旧条目里的未知键，password 留空时沿用旧口令。

        注意：空字符串不会清掉旧值（这是「留空即不改」的实现），布尔与数字照常覆盖。
        """
        merged = dict(self.entries().get(alias) or {})
        merged.update({k: v for k, v in normalize(entry).items() if v != "" or k not in merged})
        if keep_password_if_empty and not merged.get("password"):
            old = self.entries().get(alias) or {}
            if old.get("password"):
                merged["password"] = old["password"]
        self.raw[alias] = merged
        return merged

    def remove(self, alias: str) -> bool:
        if alias in self.entries():
            self.raw.pop(alias, None)
            return True
        return False

    def set_flag(self, alias: str, field_name: str, value: bool) -> bool:
        if field_name not in FLAG_FIELDS or alias not in self.entries():
            return False
        self.raw[alias][field_name] = bool(value)
        return True


# --------------------------------------------------------------------------------------
# 从本机 ~/.ssh 扫描候选（gen_hosts 与 GUI 共用）
# --------------------------------------------------------------------------------------


def fingerprint(blob_b64: str) -> str:
    digest = hashlib.sha256(base64.b64decode(blob_b64)).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def read_known_hosts(path: Path | None = None) -> tuple[dict[tuple[str, int], dict[str, str]], int]:
    path = path or (Path.home() / ".ssh" / "known_hosts")
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except FileNotFoundError:
        return {}, 0
    found: dict[tuple[str, int], dict[str, str]] = {}
    hashed = 0
    for line in lines:
        line = line.strip()
        if not line or line[0] in "#@":
            continue
        parts = line.split()
        if len(parts) < 3:
            continue
        names, keytype, blob = parts[0], parts[1], parts[2]
        if names.startswith("|"):  # HashKnownHosts 过的行反查不出主机名
            hashed += 1
            continue
        try:
            fp = fingerprint(blob)
        except ValueError:
            continue
        for name in names.split(","):
            if name.startswith("["):
                body, _, port_s = name[1:].partition("]:")
                if not port_s.isdigit():
                    continue
                addr, port = body, int(port_s)
            else:
                addr, port = name, 22
            found.setdefault((addr, port), {})[keytype] = fp
    return found, hashed


def read_ssh_config(path: Path | None = None) -> dict[str, dict[str, str]]:
    path = path or (Path.home() / ".ssh" / "config")
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except FileNotFoundError:
        return {}
    out: dict[str, dict[str, str]] = {}
    tokens: list[str] = []
    opts: dict[str, str] = {}

    def flush() -> None:
        if tokens and not any("*" in t or "?" in t or t.startswith("!") for t in tokens):
            for token in tokens:
                out.setdefault(token, dict(opts))

    for raw in lines:
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        chunks = re.split(r"[=\s]+", line, maxsplit=1)
        key = chunks[0].lower()
        value = chunks[1] if len(chunks) > 1 else ""
        if key == "host":
            flush()
            tokens, opts = value.split(), {}
        elif tokens:
            opts[key] = value
    flush()
    return out


def build_candidates(raw: dict, connected: dict[tuple[str, int], dict[str, str]],
                     config: dict[str, dict[str, str]]) -> list[Candidate]:
    """按地址去重，生成候选清单；已有的地址与别名标成不可导入。"""
    existing = hosts(raw)
    existing_by_addr: dict[tuple[str, int], str] = {}
    for alias, entry in existing.items():
        addr = str(entry.get("address") or "")
        port_raw = entry.get("port", 22)
        if addr:
            existing_by_addr[(addr, int(port_raw) if str(port_raw).isdigit() else 22)] = alias

    entries: dict[tuple[str, int], dict] = {}
    for token, opts in config.items():
        addr = opts.get("hostname") or token
        port_raw = opts.get("port", "")
        port = int(port_raw) if port_raw.isdigit() else 22
        entries.setdefault((addr, port), {}).setdefault("username", opts.get("user", ""))
    for key, types in connected.items():
        entries.setdefault(key, {})["types"] = types

    tails: dict[str, int] = {}
    for addr, _ in entries:
        tails[addr.rsplit(".", 1)[-1]] = tails.get(addr.rsplit(".", 1)[-1], 0) + 1

    out: list[Candidate] = []
    for (addr, port), info in sorted(entries.items()):
        tail = addr.rsplit(".", 1)[-1]
        alias = tail if tails[tail] == 1 and tail not in existing else addr
        if port != 22:
            alias = f"{alias}:{port}"
        types: dict[str, str] = info.get("types", {})
        host_key = types[min(types, key=lambda t: KEY_RANK.get(t, 9))] if types else ""
        cand = Candidate(alias=alias, entry={
            "address": addr, "port": port,
            "username": info.get("username", ""),
            "auth": "password", "password": "", "hostKey": host_key,
        })
        if addr in SKIP_HOSTS:
            cand.reasons.append("不是可 exec 的机器")
        if (addr, port) in existing_by_addr:
            cand.reasons.append(f"已在清单里：{existing_by_addr[(addr, port)]}")
        if alias in existing:
            cand.reasons.append(f"别名冲突：{alias}")
        if not host_key:
            cand.notes.append("known_hosts 里没有它的指纹，需要探测")
        if not cand.entry["username"]:
            cand.notes.append("ssh config 没给 username，需要手填")
        cand.notes.append("password 需要手填")
        out.append(cand)
    return out
