"""纯标准库的自杀清单守卫：只在 root 账号主机上生效，挡手滑，不挡绕过。

与 ssh_mcp.py 分开是为了让单测不需要装 paramiko 和 mcp 就能跑。

原 `ssh_policy.py` 的 ro 白名单 / rw 黑名单 / grant / 包装器剥壳 / 解释器特判已全部移除
（2026-09-29 决策：命令过滤挡不住蓄意绕行的 AI，代价是每轮往返）。这里只留三类
「把自己搞死」形态：毁盘、锁在门外、把 ssh 关掉。

查不查这张表：`username == "root"` 的主机恒查；非 root 主机要在 `policy.json` 的
`guarded_hosts` 里点名才查（比如跑着共享业务的机器，账号不是 root 也值得挡一手手滑）。
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field

OPERATOR_TOKENS = frozenset({";", "&&", "||", "|", "&"})
SEP_CHARS = ";|&"
REDIRECT_TOKENS = frozenset({">", ">>", "<", "<<<", "1>", "2>", "&>", "&>>", "<>", ">|"})
# 读/非文件重定向：`<` 只读，`<<`/`<<<` 是 heredoc / here-string 的分隔词，都不写文件。
# 收进「写目标」会把只读探查看成写 —— 2026-10-14 实测 `wc -l < 密钥文件` 被 deny:写入敏感文件 拦下。
READ_REDIRECTS = frozenset({"<", "<<", "<<<"})
# `2>&1` 只复制描述符，不落文件，不该当成写
FD_DUP = re.compile(r"^\d*<&\d+$|^\d*>&\d*$")
REDIRECT_SPLIT = re.compile(r"^(\d*)(>>|<<|<>|>\||>|<)(.*)$")

# 深度 ≤1 的路径：`/`、`/etc`、`/var`。`/tmp/build` 这种第二层不算。
# 判深度而不是逐目录列条目，是因为「少写一段路径」正是 rm 最常见的手滑形态。
TOP_LEVEL_DEPTH = 1

# 覆写这些文件 = 下次登录不上（sshd_config/authorized_keys）或提权面失控（sudoers/shadow）。
SENSITIVE_WRITE_TARGETS = (
    "authorized_keys",
    "sshd_config",
    "ssh_config",
    "sudoers",
    "fstab",
    "/etc/shadow",
    "/etc/passwd",
    "inittab",
)


@dataclass(frozen=True)
class Prefix:
    """一条 token 前缀规则，如 'systemctl stop sshd' -> ("systemctl", "stop", "sshd")。"""

    raw: str
    tokens: tuple[str, ...]


@dataclass
class Hit:
    rule: str
    segment: list[str]


@dataclass
class GuardConfig:
    idle_timeout_s: float = 30.0
    max_duration_s: float = 300.0
    max_output_bytes: int = 204800
    kill_prefixes: list[Prefix] = field(default_factory=list)
    guarded_hosts: frozenset[str] = frozenset()
    # 传输预算：上限 4GB，单次调用默认给 30 分钟（实测 10 MB/s 下 4GB 约 7 分钟，留足往返抖动）
    xfer_timeout_s: float = 1800.0
    max_transfer_bytes: int = 4 * 1024**3
    xfer_chunk_bytes: int = 1024 * 1024
    xfer_dir: str = ""
    # 后台任务（job）：保留期与并发上限
    job_retention_days: int = 7
    job_max_concurrent: int = 8


class GuardSyntaxError(ValueError):
    pass


def _basename(token: str) -> str:
    return token.rsplit("/", 1)[-1] if "/" in token else token


def _is_env_assignment(token: str) -> bool:
    name, sep, _ = token.partition("=")
    return bool(sep) and name[:1].isalpha() and name.replace("_", "").isalnum()


def first_program(tokens: list[str]) -> tuple[int, str] | None:
    """跳过 `FOO=bar cmd` 形式的环境赋值，返回 (下标, 可执行文件名)。"""
    for idx, tok in enumerate(tokens):
        if _is_env_assignment(tok):
            continue
        return idx, _basename(tok)
    return None


def tokenize(command: str) -> list[str]:
    try:
        return shlex.split(command, posix=True)
    except ValueError as exc:
        raise GuardSyntaxError(str(exc)) from exc


def _is_sep(masked: str, i: int) -> bool:
    if masked[i] not in SEP_CHARS:
        return False
    if masked[i] == "&" and (masked[i - 1 : i] in ("<", ">") or masked[i + 1 : i + 2] in ("<", ">")):
        return False  # `2>&1` / `&>` 这类重定向构造里的 &
    return True


def mask_quotes(command: str) -> str:
    """把引号内的内容换成 x（保留长度与引号本身），让引号内的 `;` 不被当分隔符。"""
    out: list[str] = []
    quote: str | None = None
    prev_backslash = False
    for ch in command:
        if prev_backslash:
            out.append(ch)
            prev_backslash = False
            continue
        if ch == "\\" and quote != "'":
            out.append(ch)
            prev_backslash = True
            continue
        if quote:
            if ch == quote:
                quote = None
                out.append(ch)
            else:
                out.append("x" if not ch.isspace() else ch)
            continue
        if ch in ("'", '"'):
            quote = ch
        out.append(ch)
    return "".join(out)


def split_separators(command: str) -> str:
    """在引号外的 ; | & 两侧补空格，好让它们成为独立 token。

    shell 里 `uptime;rm -rf /` 是两条命令，但 shlex 会把 `;` 粘回前一个 token
    （得到 `uptime;rm` 这种假 token），清单就整条失效 —— 危险那半根本没被看过。
    """
    masked = mask_quotes(command)
    out: list[str] = []
    i = 0
    while i < len(command):
        if _is_sep(masked, i):
            j = i
            while j < len(command) and _is_sep(masked, j):
                j += 1
            out.append(f" {command[i:j]} ")
            i = j
        else:
            out.append(command[i])
            i += 1
    return "".join(out)


def split_segments(tokens: list[str]) -> list[list[str]]:
    segments: list[list[str]] = []
    current: list[str] = []
    for tok in tokens:
        if tok in OPERATOR_TOKENS:
            if current:
                segments.append(current)
                current = []
            continue
        current.append(tok)
    if current:
        segments.append(current)
    return [seg for seg in segments if seg]


def redirect_targets(tokens: list[str]) -> list[str]:
    """抽出**写**重定向目标；`1>/tmp/a`、`>>x` 这类连写形式也要认，`<`/`<<`/`<<<` 不算写。"""
    targets: list[str] = []
    idx = 0
    while idx < len(tokens):
        tok = tokens[idx]
        if FD_DUP.match(tok):
            idx += 1
            continue
        if tok in REDIRECT_TOKENS and tok not in READ_REDIRECTS:
            if idx + 1 < len(tokens):
                targets.append(tokens[idx + 1])
            idx += 2
            continue
        m = REDIRECT_SPLIT.match(tok)
        if m and m.group(3) and m.group(2) not in READ_REDIRECTS:
            targets.append(m.group(3))
        idx += 1
    return targets


def _collapse_path(token: str) -> str:
    """归一绝对路径的写法变体：//、/./、尾部斜杠、`/*` 都回到同一个目标。

    不归一就是留绕过口 —— `rm -rf /*` 删的是和 `rm -rf /` 完全同一批目录，
    而 `*` 展平发生在远端 shell 里。
    """
    if not token.startswith("/"):
        return token
    parts = [p for p in token.split("/") if p not in ("", ".")]
    if parts[-1:] == ["*"]:
        parts.pop()
    return "/" + "/".join(parts)


def _depth(token: str) -> int:
    return _collapse_path(token).count("/")


def _token_matches(arg: str, want: str) -> bool:
    arg = _collapse_path(arg)
    if want.endswith("*"):
        return arg.startswith(want[:-1])
    if "=" in want:
        return arg.startswith(want)
    if want.isdigit() and arg.isdigit():
        # 权限位八进制等价：0777 与 777 对内核是同一个模式
        return int(want) == int(arg)
    if want.startswith("/"):
        base = _collapse_path(want)
        # "/" 只认根本身，否则任何绝对路径都会被误判成根目录
        return arg == base or (base != "/" and arg.startswith(base + "/"))
    return arg == want


def _prefix_matches(tokens: list[str], prefix: Prefix) -> bool:
    """program 必须是段首，其余项出现在任意位置即命中。宁可错杀，不可放过。

    任意位置而非逐位对齐，是为了 `dd if=x of=/dev/sda` 这种参数不在第二位的形态。
    """
    found = first_program(tokens)
    if found is None:
        return False
    start, program = found
    if not _token_matches(program, prefix.tokens[0]):
        return False
    args = tokens[start:]
    if len(args) < len(prefix.tokens):
        return False
    for want in prefix.tokens[1:]:
        if not any(_token_matches(arg, want) for arg in args[1:]):
            return False
    return True


def _is_recursive_flag(arg: str) -> bool:
    if arg == "--recursive":
        return True
    # -r / -R / -rf / -fr / -Rvf 全都算递归
    return arg.startswith("-") and not arg.startswith("--") and "r" in arg.lower()


def _rm_slashes_system_dir(tokens: list[str]) -> str | None:
    """`rm -rf /`、`rm -fr /etc`：递归 flag + 任一参数归一后深度 ≤1。"""
    found = first_program(tokens)
    if found is None or found[1] != "rm":
        return None
    args = tokens[found[0] + 1 :]
    if not any(_is_recursive_flag(a) for a in args):
        return None
    for arg in args:
        if arg.startswith("-"):
            continue
        if arg.startswith("/") and _depth(arg) <= TOP_LEVEL_DEPTH:
            return arg
    return None


# 能就地改写文件的命令：光查重定向/tee 会漏掉 sed -i、cp、mv、rm 这些形态。
# 值表示检查哪些非选项参数："all" = 全部，"last" = 最后一个（通常是目标文件）。
_WRITE_OPERAND_COMMANDS = {
    "rm": "all",
    "truncate": "all",
    "mv": "all",
    "sed": "last",
    "cp": "last",
    "install": "last",
    "ln": "last",
}


def _sensitive_operand(tokens: list[str]) -> str | None:
    """命令会就地改写敏感文件时返回那个操作数；否则 None。

    只看非选项参数，不做 shell 展开。`sed` 取最后一个参数，是为了避开脚本里的
    `s/authorized_keys/x/` 这类误报（真正的目标文件通常在最后）。
    """
    found = first_program(tokens)
    if found is None:
        return None
    start, program = found
    mode = _WRITE_OPERAND_COMMANDS.get(program)
    if mode is None:
        return None
    args = [tok for tok in tokens[start + 1 :] if not tok.startswith("-")]
    if not args:
        return None
    for arg in (args if mode == "all" else args[-1:]):
        target = _collapse_path(arg)
        if any(s in target for s in SENSITIVE_WRITE_TARGETS):
            return arg
    return None


def parse_prefixes(entries: list[str]) -> list[Prefix]:
    out: list[Prefix] = []
    for raw in entries:
        toks = tuple(shlex.split(raw, posix=True))
        if toks:
            out.append(Prefix(raw=raw, tokens=toks))
    return out


def load_guard(data: dict | None) -> GuardConfig:
    defaults = (data or {}).get("defaults") or {}
    return GuardConfig(
        idle_timeout_s=float(defaults.get("idle_timeout_s", 30)),
        max_duration_s=float(defaults.get("max_duration_s", 300)),
        max_output_bytes=int(defaults.get("max_output_bytes", 204800)),
        xfer_timeout_s=float(defaults.get("xfer_timeout_s", 1800)),
        max_transfer_bytes=int(defaults.get("max_transfer_bytes", 4 * 1024**3)),
        xfer_chunk_bytes=int(defaults.get("xfer_chunk_bytes", 1024 * 1024)),
        xfer_dir=str(defaults.get("xfer_dir") or ""),
        job_retention_days=int(defaults.get("job_retention_days", 7)),
        job_max_concurrent=int(defaults.get("job_max_concurrent", 8)),
        kill_prefixes=parse_prefixes((data or {}).get("killlist") or []),
        guarded_hosts=frozenset((data or {}).get("guarded_hosts") or []),
    )


def check_write_target(path: str) -> Hit | None:
    """传输落点检查：写这些文件 = 下次登录不上或提权面失控。

    和 exec 的重定向/tee 检查共用同一份 SENSITIVE_WRITE_TARGETS。SFTP 的写不经过
    命令串，100 上实测「exec 追加 authorized_keys 被拦、SFTP 打开同一路径畅通」，
    所以这一道必须由传输通道自己走，否则传输就是清单的绕过口。
    """
    target = _collapse_path(path)
    hit = next((s for s in SENSITIVE_WRITE_TARGETS if s in target), None)
    if hit is None:
        return None
    return Hit(rule=f"deny:写入敏感文件 {target}", segment=[])



def applies(cred_privileged: bool, alias: str, config: GuardConfig) -> bool:
    """root 账号恒查；非 root 只有在 guarded_hosts 里点名了才查。"""
    return cred_privileged or alias in config.guarded_hosts


def check(command: str, config: GuardConfig) -> Hit | None:
    """命中返回 Hit（只给一个最短原因），没命中返回 None。调用方决定要不要放行。"""
    try:
        tokens = tokenize(split_separators(command))
    except GuardSyntaxError:
        return None  # 引号都没闭合，远端 shell 自己也走不到执行
    for seg in split_segments(tokens):
        hit = _check_segment(seg, config)
        if hit:
            return hit
    return None


def _check_segment(seg: list[str], config: GuardConfig) -> Hit | None:
    for prefix in config.kill_prefixes:
        if _prefix_matches(seg, prefix):
            return Hit(rule=f"deny:{prefix.raw}", segment=seg)
    trashed = _rm_slashes_system_dir(seg)
    if trashed:
        return Hit(rule=f"deny:rm 递归删一级目录 {trashed}", segment=seg)
    for target in redirect_targets(seg):
        if any(s in target for s in SENSITIVE_WRITE_TARGETS):
            return Hit(rule=f"deny:写入敏感文件 {target}", segment=seg)
    found = first_program(seg)
    if found and found[1] == "tee":
        for arg in seg[found[0] + 1 :]:
            if not arg.startswith("-") and any(s in arg for s in SENSITIVE_WRITE_TARGETS):
                return Hit(rule=f"deny:tee 写入敏感文件 {arg}", segment=seg)
    touched = _sensitive_operand(seg)
    if touched:
        return Hit(rule=f"deny:敏感文件被就地改写 {touched}", segment=seg)
    return None
