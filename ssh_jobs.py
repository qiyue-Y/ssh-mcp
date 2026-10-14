"""远端后台任务（detach）：脚本构造与状态解析。

形状照抄 classfang/ssh-mcp-server v1.10.0 的 `src/utils/remote-jobs.ts`（逐行核过），
三处刻意不同：

  - job id 由本机生成、只做白名单校验（它从不需要转义，因为它只可能是那套字符）；
  - 状态脚本输出 key=value 而不是人类可读块，解析不用正则；
  - 输出内容不经过命令通道，由 SFTP 按 offset 读（二进制安全、不用引号拼 `head -c`）。

为什么状态存远端文件系统而不是服务进程内存：MCP 服务重启、SSH 断连、Agent 换会话
之后仍能接着轮询（对照：tufantunc 的 session 在内存 Map 里，服务一死全丢）。

纯 stdlib、纯函数，可离线测。脚本一律 POSIX sh、不含顶层 `exit`、不用 heredoc
—— 这条是为将来可能的 shell/交互通道留的（片段会被粘进活 shell，`exit` 会杀会话）。
"""

from __future__ import annotations

import re
import secrets
import shlex
import time

# 远端 $HOME 下的目录名：只在这里定义一处，脚本和 SFTP 路径都从这里取
JOBS_DIRNAME = ".sshmcp-jobs"
JOB_ID_RE = re.compile(r"job-[a-z0-9]{6,14}-[0-9a-f]{4}")

# 四态判定，顺序固定：exit > killed > 存活且确实是我们的进程 > lost。
# `job_is_ours` 是防 PID 复用的关键：`kill -0` 只证明"有进程占着这个 pid"。
# /proc 先读是因为 busybox 的 ps 没有 -p；/proc 不可用（macOS/BSD）再退到 ps -o args=。
_STATE_FN = (
    'job_is_ours() { if [ -r "/proc/$pid/cmdline" ]; then tr "\\0" " " < "/proc/$pid/cmdline" | grep -q "$ID"; '
    'else ps -o args= -p "$pid" 2>/dev/null | grep -q "$ID"; fi; }; '
    'job_state() { J="$1"; ID="$2"; code=""; pid=$(cat "$J/pid" 2>/dev/null); '
    'if [ -f "$J/exit" ]; then state=exited; code=$(cat "$J/exit"); '
    'elif [ -f "$J/killed" ]; then state=killed; '
    'elif [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null && job_is_ours; then state=running; '
    "else state=lost; fi; }"
)

# children 先杀：父进程一死，子进程会被 init 收养，pgrep -P 就找不到它们了。
# 有 setsid 时整个任务是一个进程组，`kill -- -pid` 一把带走（下面先走这条）。
_KILL_TREE_FN = 'kill_tree() { for c in $(pgrep -P "$1" 2>/dev/null); do kill_tree "$c" "$2"; done; kill -s "$2" "$1" 2>/dev/null; }'

# 在 nohup [setsid] sh -c 里跑；$1 = 任务目录，$2 = 工作目录（可为空）。
# 工作目录要自己展开 `~`：引号里的波浪号不会展开（`cd -- "~/x"` 实测必失败）。
_WRAPPER = (
    'echo $$ > "$1/pid"; '
    'if [ -n "$2" ]; then '
    'case "$2" in "~") _d="$HOME";; "~/"*) _d="$HOME/${2#\\~/}";; *) _d="$2";; esac; '
    'cd -- "$_d" || { echo "cannot cd to $2"; echo 1 > "$1/exit.tmp" && mv "$1/exit.tmp" "$1/exit"; exit 1; }; '
    'fi; '
    'if command -v bash >/dev/null 2>&1; then bash "$1/cmd"; else sh "$1/cmd"; fi; '
    'echo $? > "$1/exit.tmp" && mv "$1/exit.tmp" "$1/exit"'
)


def new_job_id(now: float | None = None) -> str:
    stamp = format(int(now if now is not None else time.time()), "x")
    return f"job-{stamp}-{secrets.token_hex(2)}"


def validate_job_id(job_id: str) -> str:
    """id 会被拼进 shell 脚本和 SFTP 路径，所以只做白名单校验、从不转义。"""
    if not JOB_ID_RE.fullmatch(job_id or ""):
        raise ValueError(f"job_id 形态非法：{job_id!r}（应形如 job-<base36>-<4位hex>）")
    return job_id


def _job_dir(job_id: str) -> str:
    return f"$HOME/{JOBS_DIRNAME}/{validate_job_id(job_id)}"


def build_start_script(job_id: str, command: str, directory: str, retention_days: int, max_concurrent: int) -> str:
    j = _job_dir(job_id)
    root = f"$HOME/{JOBS_DIRNAME}"
    dir_file = f"  printf '%s\\n' {shlex.quote(directory)} > \"$J/dir\"\n" if directory else ""
    return (
        f'J="{j}"\n'
        f'R="{root}"\n'
        "BUSY=0\n"
        # 清扫与计数一趟循环：没有 exit/killed 标记的算"在跑或失联"；已结束且过保留期的整组删掉
        'for d in "$R"/*/; do\n'
        '  [ -d "$d" ] || continue\n'
        '  id=${d%/}; id=${id##*/}\n'
        '  case "$id" in job-*) ;; *) continue;; esac\n'
        '  if [ ! -f "$d/exit" ] && [ ! -f "$d/killed" ]; then\n'
        "    BUSY=$((BUSY+1))\n"
        f'  elif find "$d" -maxdepth 1 -type f \\( -name exit -o -name killed \\) -mtime +{int(retention_days)} | grep -q .; then\n'
        '    rm -rf -- "$d"\n'
        "  fi\n"
        "done\n"
        f'if [ "$BUSY" -ge {int(max_concurrent)} ]; then\n'
        '  echo "BUSY $BUSY"\n'
        "else\n"
        '  mkdir -p "$J" || echo "CANNOT_CREATE $J"\n'
        f"  printf '%s\\n' {shlex.quote(command)} > \"$J/cmd\"\n"
        f"{dir_file}"
        '  date +%s > "$J/started"\n'
        '  S=""; command -v setsid >/dev/null 2>&1 && S=setsid\n'
        f'  nohup $S sh -c {shlex.quote(_WRAPPER)} _ "$J" {shlex.quote(directory)} > "$J/out" 2>&1 < /dev/null &\n'
        '  i=0; while [ ! -s "$J/pid" ] && [ "$i" -lt 30 ]; do sleep 0.1 2>/dev/null || sleep 1; i=$((i+1)); done\n'
        '  if [ -s "$J/pid" ]; then echo "STARTED $(cat "$J/pid")"; else echo "NOPID"; fi\n'
        "fi"
    )


def build_state_script(job_id: str) -> str:
    return (
        _STATE_FN + "\n"
        + f'J="{_job_dir(job_id)}"; ID={validate_job_id(job_id)}\n'
        + 'if [ ! -d "$J" ]; then echo "state=missing"; else\n'
        '  job_state "$J" "$ID"\n'
        '  now=$(date +%s)\n'
        '  st=$(cat "$J/started" 2>/dev/null || echo "$now")\n'
        '  size=$(wc -c < "$J/out" 2>/dev/null | tr -d " "); size=${size:-0}\n'
        '  echo "state=$state"\n'
        '  echo "code=$code"\n'
        '  echo "pid=$pid"\n'
        '  echo "started=$st"\n'
        '  echo "now=$now"\n'
        '  echo "out_bytes=$size"\n'
        '  echo "command=$(head -c 200 "$J/cmd" 2>/dev/null | head -n 1)"\n'
        "fi"
    )


def build_kill_script(job_id: str) -> str:
    return (
        _STATE_FN + "\n"
        + _KILL_TREE_FN + "\n"
        + f'J="{_job_dir(job_id)}"; ID={validate_job_id(job_id)}\n'
        + 'if [ ! -d "$J" ]; then echo "result=missing"; else\n'
        '  job_state "$J" "$ID"\n'
        '  if [ "$state" != running ]; then\n'
        '    echo "result=not_running"\n'
        '    echo "state=$state"\n'
        '    if [ -n "$code" ]; then echo "code=$code"; fi\n'
        "  else\n"
        '    kill -s TERM -- "-$pid" 2>/dev/null; kill_tree "$pid" TERM\n'
        '    i=0; while kill -0 "$pid" 2>/dev/null && [ "$i" -lt 5 ]; do sleep 1; i=$((i+1)); done\n'
        '    if kill -0 "$pid" 2>/dev/null; then\n'
        '      kill -s KILL -- "-$pid" 2>/dev/null; kill_tree "$pid" KILL\n'
        '      echo "result=sigkill"\n'
        "    else\n"
        '      echo "result=terminated"\n'
        "    fi\n"
        '    touch "$J/killed"\n'
        "  fi\n"
        "fi"
    )


def build_list_script(limit: int) -> str:
    return (
        _STATE_FN + "\n"
        + f'R="$HOME/{JOBS_DIRNAME}"\n'
        + 'if [ ! -d "$R" ]; then echo "(none)"; else\n'
        "  n=0\n"
        '  for ID in $(ls -1t "$R" 2>/dev/null); do\n'
        '    case "$ID" in job-*) ;; *) continue;; esac\n'
        f'    n=$((n+1)); if [ "$n" -gt {max(1, int(limit))} ]; then break; fi\n'
        '    J="$R/$ID"; job_state "$J" "$ID"\n'
        '    echo "$ID|$state|$code|$(cat "$J/started" 2>/dev/null)"\n'
        "  done\n"
        '  if [ "$n" -eq 0 ]; then echo "(none)"; fi\n'
        "fi"
    )


def parse_kv(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        key, sep, val = line.partition("=")
        if sep and key:
            out[key] = val
    return out


def parse_start(text: str) -> dict:
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("STARTED "):
            pid = line.split(" ", 1)[1].strip()
            return {"result": "started", "pid": int(pid) if pid.isdigit() else None}
        if line.startswith("BUSY "):
            busy = line.split(" ", 1)[1].strip()
            return {"result": "busy", "busy": int(busy) if busy.isdigit() else None}
        if line == "NOPID":
            return {"result": "nopid"}
    return {"result": "unknown"}


def parse_list(text: str) -> list[dict]:
    jobs: list[dict] = []
    for line in text.splitlines():
        parts = line.split("|")
        if len(parts) != 4 or not JOB_ID_RE.fullmatch(parts[0]):
            continue
        jobs.append(
            {
                "job_id": parts[0],
                "state": parts[1] or "unknown",
                "exit_code": int(parts[2]) if parts[2].isdigit() else None,
                "started": int(parts[3]) if parts[3].isdigit() else None,
            }
        )
    return jobs
