# /// script
# requires-python = ">=3.11"
# ///
"""stdio 冒烟测试：拉起 ssh_mcp.py，走一遍 initialize / tools/list / list_hosts。

    uv run smoke_stdio.py
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent


def send(proc, msg: dict) -> None:
    proc.stdin.write((json.dumps(msg, ensure_ascii=False) + "\n").encode("utf-8"))
    proc.stdin.flush()


def read_until(proc, want_id: int, timeout: float = 25.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        line = proc.stdout.readline()
        if not line:
            time.sleep(0.05)
            continue
        try:
            msg = json.loads(line.decode("utf-8", "replace").strip())
        except json.JSONDecodeError:
            continue
        if msg.get("id") == want_id:
            return msg
    raise TimeoutError(f"等 id={want_id} 超时")


def main() -> int:
    # 子进程必须经 uv 起，才能拿到 ssh_mcp.py 的 PEP 723 内联依赖
    child = ["uv", "run", "--quiet", str(HERE / "ssh_mcp.py"), "serve"]
    proc = subprocess.Popen(
        child,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=str(HERE),
    )
    failures: list[str] = []
    try:
        t0 = time.monotonic()
        send(
            proc,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "smoke", "version": "0"},
                },
            },
        )
        init = read_until(proc, 1)
        server_info = init.get("result", {}).get("serverInfo", {})
        print(f"initialize {time.monotonic() - t0:.2f}s  server={server_info.get('name')!r}")
        if server_info.get("name") != "ssh-mcp":
            failures.append("serverInfo.name 不是 ssh-mcp")

        send(proc, {"jsonrpc": "2.0", "method": "notifications/initialized"})

        t1 = time.monotonic()
        send(proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        tools = read_until(proc, 2).get("result", {}).get("tools", [])
        names = sorted(t["name"] for t in tools)
        print(f"tools/list  {time.monotonic() - t1:.2f}s  -> {names}")
        for expect in ("audit_tail", "exec", "list_hosts", "session_reset"):
            if expect not in names:
                failures.append(f"缺工具 {expect}")

        send(proc, {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "list_hosts", "arguments": {}}})
        res = read_until(proc, 3).get("result", {})
        text = "".join(c.get("text", "") for c in res.get("content", []) if c.get("type") == "text")
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            failures.append(f"list_hosts 返回不是 JSON：{text[:200]}")
        else:
            hosts = payload.get("hosts", [])
            print(f"list_hosts -> {len(hosts)} 台，allowlist {len(payload.get('ro_allowlist', []))} 条")
            blob = json.dumps(payload, ensure_ascii=False)
            if "password" in blob.lower():
                failures.append("list_hosts 输出里出现了 password 字段")
            for h in hosts:
                print(f"   {h['alias']:<8} mode={h.get('effective_mode'):<12} {h.get('mode_reason', '')}")
    finally:
        proc.stdin.close()
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        err = proc.stderr.read().decode("utf-8", "replace").strip()
        if err:
            print("--- stderr ---")
            print(err)

    if failures:
        print("\n失败：")
        for f in failures:
            print("  -", f)
        return 1
    print("\n全部通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
