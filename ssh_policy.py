"""纯标准库策略引擎：分段判定 / ro 白名单 / rw 黑名单 / grant 前缀匹配。

与 ssh_mcp.py 分开是为了让单测不需要装 paramiko 和 mcp 就能跑。
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field
from datetime import datetime, timezone

OPERATOR_TOKENS = frozenset({";", "&&", "||", "|", "&"})
REDIRECT_TOKENS = frozenset({">", ">>", "<", "<<<", "1>", "2>", "&>", "&>>", "<>", ">|"})
# `2>&1` 这类只是复制描述符，不落到文件，ro 下不必当成写
FD_DUP = re.compile(r"^\d*<&\d+$|^\d*>&\d*$")
REDIRECT_SPLIT = re.compile(r"^(\d*)(>>|<<|<>|>\||>|<)(.*)$")
SUBSTITUTION_MARKERS = ("$(", "${", "`")
GLOB_MARKERS = ("*", "?", "[")

SENSITIVE_WRITE_TARGETS = (
    "authorized_keys",
    "sshd_config",
    "ssh_config",
    "sudoers",
    "fstab",
    "/etc/shadow",
    "/etc/passwd",
    "inittab",
    "crontab",
)

CURL_DATA_FLAGS = frozenset(
    {
        "-d",
        "--data",
        "--data-raw",
        "--data-binary",
        "--data-urlencode",
        "-F",
        "--form",
        "--form-string",
        "-T",
        "--upload-file",
        "--config",
        "-K",
    }
)
CURL_ALLOWED_SCHEMES = ("http://", "https://")
CURL_FORBIDDEN_SCHEMES = ("file://", "gopher://", "telnet://", "dict://", "ftp://", "ldap://")


class PolicySyntaxError(ValueError):
    pass


@dataclass(frozen=True)
class Prefix:
    """一条 token 前缀规则，如 'systemctl status' -> ("systemctl", "status")。"""

    raw: str
    tokens: tuple[str, ...]

    @property
    def program(self) -> str:
        return self.tokens[0]


@dataclass
class Grant:
    id: str
    alias: str
    scope: str  # "host" | "cmd"
    command: str = ""
    uses_left: int = -1
    expires_at: str | None = None
    granted_via: str = "tty"
    why: str = ""

    def prefix_tokens(self) -> tuple[str, ...]:
        return tuple(shlex.split(self.command, posix=True)) if self.command else ()

    def is_live(self, now: datetime | None = None) -> bool:
        if self.expires_at is None:
            return True
        try:
            exp = datetime.fromisoformat(self.expires_at)
        except ValueError:
            return False
        return (now or datetime.now(timezone.utc)) < exp

    def consume(self) -> None:
        if self.uses_left > 0:
            self.uses_left -= 1


@dataclass
class Decision:
    allowed: bool
    reason: str = ""
    matched_rule: str = ""
    segments: list[list[str]] = field(default_factory=list)
    broad_grant: bool = False
    grant_id: str | None = None


@dataclass
class Policy:
    idle_timeout_s: float = 30.0
    max_duration_s: float = 300.0
    max_output_bytes: int = 204800
    grant_ttl_default_s: int = 1800
    hosts: dict[str, dict] = field(default_factory=dict)
    ro_allowlist: list[Prefix] = field(default_factory=list)
    ro_deny_flags: dict[str, tuple[str, ...]] = field(default_factory=dict)
    rw_denylist: list[Prefix] = field(default_factory=list)
    broad_grant_markers: frozenset[str] = frozenset()
    interpreters: frozenset[str] = frozenset()
    ro_deny_paths: tuple[str, ...] = ()

    @property
    def aliases(self) -> list[str]:
        return sorted(self.hosts)


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
        raise PolicySyntaxError(str(exc)) from exc


SEP_CHARS = ";|&"


def _is_sep(masked: str, i: int) -> bool:
    if masked[i] not in SEP_CHARS:
        return False
    if masked[i] == "&" and (masked[i - 1 : i] in ("<", ">") or masked[i + 1 : i + 2] in ("<", ">")):
        return False  # `2>&1` / `&>` 这类重定向构造里的 &
    return True


def split_separators(command: str) -> str:
    """在引号外的 ; | & 两侧补空格，好让它们成为独立 token。

    shell 里 `df -h;rm -rf /var` 是两条命令，但 shlex 会把 `;` 粘回前一个 token
    （得到 `df` + `-h;rm` 这种假 token），分段判定就整条失效了 —— 危险的那半
    根本没被看过一眼。引号内的分隔符由 mask_quotes 掩成 x，不受影响。
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


def mask_quotes(command: str) -> str:
    """把引号内的内容换成 x（保留长度与引号本身）。

    目的：`grep '<div>' file` 里的 `<` 是被引号保护的普通字符，不该被当成重定向；
    而 shell 真正会看到的重定向一定出现在引号外。
    """
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


def has_substitution(command: str) -> bool:
    return any(marker in command for marker in SUBSTITUTION_MARKERS)


def has_glob(command: str) -> bool:
    return any(marker in command for marker in GLOB_MARKERS)


def redirect_targets(tokens: list[str]) -> list[str]:
    """抽出重定向目标；`1>/tmp/a`、`>>x` 这类连写形式也要认。"""
    targets: list[str] = []
    idx = 0
    while idx < len(tokens):
        tok = tokens[idx]
        if FD_DUP.match(tok):
            idx += 1
            continue
        if tok in REDIRECT_TOKENS:
            if idx + 1 < len(tokens):
                targets.append(tokens[idx + 1])
            idx += 2
            continue
        m = REDIRECT_SPLIT.match(tok)
        if m and m.group(3):
            targets.append(m.group(3))
        idx += 1
    return targets


def has_redirect(tokens: list[str]) -> bool:
    """ro 下重定向视为改状态，唯一例外是 /dev/null（既伤不到系统也泄不了密）。"""
    idx = 0
    while idx < len(tokens):
        tok = tokens[idx]
        if FD_DUP.match(tok):
            idx += 1
            continue
        if tok in REDIRECT_TOKENS:
            nxt = tokens[idx + 1] if idx + 1 < len(tokens) else ""
            if nxt and nxt != "/dev/null":
                return True
            idx += 2
            continue
        m = REDIRECT_SPLIT.match(tok)
        if m:
            if m.group(3) and m.group(3) != "/dev/null":
                return True
            idx += 1
            continue
        if ">" in tok or "<" in tok:
            return True
        idx += 1
    return False


def _prefix_matches(tokens: list[str], prefix: Prefix, positional: bool = True) -> bool:
    """token 边界前缀匹配，含 '=' 的前缀项按 startswith 比（用于 `dd of=/dev/`）。

    positional=True 给白名单用：必须逐位对齐，否则 `python -c evil --version`
    会冒充 `python --version` 过关。
    positional=False 给黑名单用：后续项出现在任意位置即命中，`dd if=x of=/dev/sda`
    这种参数不在第二位的情况也要拦得住。宁可错杀，不可放过。
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
    if positional:
        for idx, want in enumerate(prefix.tokens):
            got = _basename(args[idx]) if idx == 0 else args[idx]
            if not _token_matches(got, want):
                return False
        return True
    for want in prefix.tokens[1:]:
        if not any(_token_matches(arg, want) for arg in args[1:]):
            return False
    return True


def _collapse_path(token: str) -> str:
    """归一绝对路径的写法变体：//、/./、尾部斜杠、以及 `/*` 都回到同一个目标。

    不归一就是留绕过口 —— `rm -rf /*` 删的是和 `rm -rf /` 完全同一批目录，
    而展平成 /bin /boot ... 发生在远端 shell 里，即策略放行之后。
    """
    if not token.startswith("/"):
        return token
    parts = [p for p in token.split("/") if p not in ("", ".")]
    if parts[-1:] == ["*"]:
        parts.pop()
    return "/" + "/".join(parts)


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


def parse_prefixes(entries: list[str]) -> list[Prefix]:
    out: list[Prefix] = []
    for raw in entries:
        toks = tuple(shlex.split(raw, posix=True))
        if toks:
            out.append(Prefix(raw=raw, tokens=toks))
    return out


def load_policy(data: dict) -> Policy:
    defaults = data.get("defaults") or {}
    ro_entries = data.get("ro_allowlist") or []
    deny_entries = data.get("rw_denylist") or []
    flags = data.get("ro_deny_flags") or {}
    return Policy(
        idle_timeout_s=float(defaults.get("idle_timeout_s", 30)),
        max_duration_s=float(defaults.get("max_duration_s", 300)),
        max_output_bytes=int(defaults.get("max_output_bytes", 204800)),
        grant_ttl_default_s=_parse_duration(defaults.get("grant_ttl_default", "30m")),
        hosts=data.get("hosts") or {},
        ro_allowlist=parse_prefixes(ro_entries),
        ro_deny_flags={k: tuple(v) for k, v in flags.items()},
        rw_denylist=parse_prefixes(deny_entries),
        broad_grant_markers=frozenset(data.get("broad_grant_markers") or []),
        interpreters=frozenset(data.get("interpreters") or []),
        ro_deny_paths=tuple(data.get("ro_deny_paths") or ()),
    )


def _parse_duration(text: str | int) -> int:
    if isinstance(text, int):
        return text
    text = str(text).strip().lower()
    for suffix, factor in (("ms", 0.001), ("m", 60), ("h", 3600), ("s", 1)):
        if text.endswith(suffix):
            try:
                return max(1, int(float(text[: -len(suffix)].strip()) * factor))
            except ValueError:
                break
    try:
        return max(1, int(text))
    except ValueError as exc:
        raise ValueError(f"无法解析时长: {text!r}") from exc


parse_duration = _parse_duration


def _check_curl(tokens: list[str], program: str) -> Decision:
    found = first_program(tokens)
    if found is None:
        return Decision(True)
    start = found[0]
    rest = tokens[start + 1 :]
    for pos, tok in enumerate(rest):
        head = tok.split("=", 1)[0]
        if head in CURL_DATA_FLAGS or tok in CURL_DATA_FLAGS:
            return Decision(False, "curl_data_forbidden", f"curl_flag:{head}")
        if tok.startswith("-") and ("upload-file" in tok or "config" in tok):
            return Decision(False, "curl_data_forbidden", f"curl_flag:{head}")
        if tok.startswith(CURL_FORBIDDEN_SCHEMES):
            return Decision(False, "curl_scheme_forbidden", f"curl_scheme:{tok.split('://')[0]}")
        if not tok.startswith("-") and "://" in tok and not tok.startswith(CURL_ALLOWED_SCHEMES):
            return Decision(False, "curl_scheme_forbidden", f"curl_scheme:{tok.split('://')[0]}")
        if tok in ("-o", "--output") or tok.startswith("--output="):
            target = tok.split("=", 1)[1] if "=" in tok else (rest[pos + 1] if pos + 1 < len(rest) else "")
            if any(s in target for s in SENSITIVE_WRITE_TARGETS):
                return Decision(False, "sensitive_write_target", f"curl_output:{target}")
    return Decision(True)


def _decide_ro_segment(tokens: list[str], policy: Policy, redirect_view: list[str]) -> Decision:
    found = first_program(tokens)
    if found is None:
        return Decision(False, "empty_segment")
    start, program = found
    if has_redirect(redirect_view):
        return Decision(False, "redirect_not_allowed_in_ro", "redirect")
    matched: Prefix | None = None
    for prefix in policy.ro_allowlist:
        if not _token_matches(program, prefix.tokens[0]):
            continue
        if _prefix_matches(tokens, prefix):
            matched = prefix
            break
    if matched is None:
        # 白名单没中才轮到解释器判定；`python --version` 这类显式白名单条目因此仍可用，
        # 但 `python -c ... --version` 位置对不上，会落到这里被拦。
        if program in policy.interpreters:
            return Decision(False, "interpreter_not_allowed_in_ro", f"interpreter:{program}")
        return Decision(False, "not_in_allowlist", f"prefix:{program}")
    if len(matched.tokens) == 1 and program in policy.interpreters:
        # 有人手滑把裸 `awk` 加进白名单也不行
        return Decision(False, "interpreter_not_allowed_in_ro", f"interpreter:{program}")
    if program in policy.interpreters:
        consumed = set(matched.tokens[1:])
        extra = [t for t in tokens[start + 1 :] if t not in consumed and t.startswith("-")]
        if extra:
            # `python --version -c 'import os'` 前缀对得上但夹带了 -c，必须拒
            return Decision(False, "interpreter_extra_flag", f"{program} {extra[0]}")
    for flag in policy.ro_deny_flags.get(program, ()):  # find -exec / -delete 之类逃逸口
        if any(tok == flag or tok.startswith((flag + ";", flag + "=", flag + ",")) for tok in tokens[start + 1 :]):
            return Decision(False, "deny_flag", f"{program} {flag}")
    if program in ("curl", "wget"):
        return _check_curl(tokens, program)
    for arg in tokens[start + 1 :]:
        if arg.startswith("-"):
            continue
        hit = next((p for p in policy.ro_deny_paths if p in arg), None)
        if hit:  # ro 只限制"不改状态"，不限制读；私钥/shadow 这类得单独钉
            return Decision(False, "secret_path_not_readable_in_ro", f"path:{hit}")
    return Decision(True, matched_rule=f"allow:{matched.raw}")


# 前缀包装器：真命令在它们后面。只列纯执行包装（改了调度/环境但不改变语义的那类），
# 命中条件是"剥壳后仍被黑名单拦"，所以不会误伤 `nice -n 10 make` 这类正常用法。
WRAPPERS = frozenset(
    {
        "env", "nice", "ionice", "nohup", "time", "timeout", "stdbuf", "chrt",
        "taskset", "unshare", "setarch", "strace", "ltrace", "watch", "script",
        "busybox", "toybox", "xargs",
    }
)
# 收 shell 字符串的解释器：-c 后面就是条 shell 命令，可以原样再判一遍
SHELLS = frozenset({"sh", "bash", "dash", "ksh", "zsh"})


def _unwrap_candidates(args: list[str]) -> list[list[str]]:
    """包装器后面每个非选项 token 都当一次"真命令起点"复检。

    不逐个解析包装器自己的参数规则（env 吃 FOO=bar、timeout 吃时长、nice 吃 -n 0），
    是因为漏解析一种就是一个绕过口；多复检几遍的代价只是几微秒。
    """
    return [args[i:] for i, tok in enumerate(args) if not tok.startswith("-")]


def _dash_c_scripts(args: list[str]) -> list[str]:
    return [args[i + 1] for i, tok in enumerate(args) if tok == "-c" and i + 1 < len(args)]


def _decide_rw_segment(tokens: list[str], policy: Policy) -> Decision:
    found = first_program(tokens)
    if found is None:
        return Decision(False, "empty_segment")
    start, program = found
    args = tokens[start:]
    if program in WRAPPERS:
        # rw 是黑名单制，不剥壳的话 `nohup rm -rf /` 一个前缀词就废掉整张表
        for inner in _unwrap_candidates(args[1:]):
            decision = _decide_rw_segment(inner, policy)
            if not decision.allowed:
                return decision
    elif program in SHELLS:
        # -c 后面就是一条 shell 命令，整条重跑判定（分段与剥壳都复用到）
        for script in _dash_c_scripts(args[1:]):
            decision = decide(script, "rw", policy)
            if not decision.allowed:
                return decision
    for prefix in policy.rw_denylist:
        if _prefix_matches(tokens, prefix, positional=False):
            return Decision(False, "denylisted", f"deny:{prefix.raw}")
    for target in redirect_targets(tokens):
        if any(s in target for s in SENSITIVE_WRITE_TARGETS):
            return Decision(False, "sensitive_write_target", f"redirect:{target}")
    return Decision(True, matched_rule=f"rw:{program}")


def decide(command: str, mode: str, policy: Policy) -> Decision:
    """对整条命令做判定。mode 由调用方按 §5.1 判定表算好后传入。"""
    try:
        command = split_separators(command)
        tokens = tokenize(command)
        masked = tokenize(mask_quotes(command))
    except PolicySyntaxError:
        return Decision(False, "unparsable")
    segments = split_segments(tokens)
    if not segments:
        return Decision(False, "empty_command")
    if mode == "ro" and has_substitution(command):
        return Decision(False, "command_substitution_not_allowed_in_ro", "substitution")
    # 掩码后 token 数一致才能按位对齐；对不上就退回用原始 token（宁可多拒）
    masked_segments = split_segments(masked) if len(split_segments(masked)) == len(segments) else segments
    for seg, red_view in zip(segments, masked_segments):
        if seg and all(_is_env_assignment(t) for t in seg):
            # 纯赋值段（`X=1; ls` 的前半）对自身什么都不做，按 no-op 放行；
            # 变量间接寻址本就超出静态分析能力，同 export R=/; rm -rf $R 一起归入已知边界
            continue
        res = _decide_ro_segment(seg, policy, red_view) if mode == "ro" else _decide_rw_segment(seg, policy)
        if not res.allowed:
            res.segments = segments
            return res
    return Decision(True, matched_rule=f"mode:{mode}", segments=segments)


def grant_matches(grant: Grant, command: str, policy: Policy) -> bool:
    """SPEC §5.3 三条硬约束：token 边界前缀、只匹配单段、含通配/替换则不匹配。"""
    if grant.scope != "cmd":
        return False
    prefix = grant.prefix_tokens()
    if not prefix:
        return False
    if has_glob(command) or has_substitution(command):
        return False
    try:
        tokens = tokenize(command)
    except PolicySyntaxError:
        return False
    segments = split_segments(tokens)
    if len(segments) != 1:
        return False
    seg = segments[0]
    if has_redirect(split_segments(tokenize(mask_quotes(command)))[0]):
        return False
    return _prefix_matches(seg, Prefix(raw=grant.command, tokens=prefix))


def broad_grant_hit(segments: list[list[str]], policy: Policy) -> bool:
    for seg in segments:
        found = first_program(seg)
        if found and found[1] in policy.broad_grant_markers:
            return True
    return False
