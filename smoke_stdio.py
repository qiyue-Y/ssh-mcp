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

# list_hosts 该露的是「这台怎么配」，不是密钥本身。
# 注意别用 blob 里搜字符串的写法判泄露：auth 的值就是 "password"（认证方式名），会假红。
SECRET_FIELDS = {"password", "passphrase", "token", "secret", "private_key", "key_path", "elevate_password"}


def find_secret_fields(node, path="") -> list[str]:
    bad: list[str] = []
    if isinstance(node, dict):
        for key, value in node.items():
            if str(key).lower() in SECRET_FIELDS:
                bad.append(f"{path}.{key}")
            bad += find_secret_fields(value, f"{path}.{key}")
    elif isinstance(node, list):
        for index, value in enumerate(node):
            bad += find_secret_fields(value, f"{path}[{index}]")
    return bad


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
        for expect in ("audit_tail", "exec", "get_file", "job_kill", "job_list", "job_status",
                       "list_hosts", "pin_hostkey", "put_file", "read_output", "session_reset", "xfer_stat"):
            if expect not in names:
                failures.append(f"缺工具 {expect}")
        # 解除权限控制后仍要在 schema 里：越清单的开关、探测指纹的确认位、续传与覆盖开关
        schemas = {t["name"]: t.get("inputSchema", {}).get("properties", {}) for t in tools}
        for p in ("force", "elevate", "detach"):
            if p not in schemas.get("exec", {}):
                failures.append(f"exec 缺 {p} 参数")
        for p in ("offset", "max_bytes"):
            if p not in schemas.get("job_status", {}):
                failures.append(f"job_status 缺 {p} 参数")
        if "trust" not in schemas.get("pin_hostkey", {}):
            failures.append("pin_hostkey 缺 trust 参数")
        for name, params in (("put_file", ("overwrite", "force", "elevate", "restart", "mode")),
                             ("get_file", ("overwrite", "elevate", "restart", "local"))):
            for p in params:
                if p not in schemas.get(name, {}):
                    failures.append(f"{name} 缺 {p} 参数")
        for name in ("grant", "revoke"):
            if name in names:
                failures.append(f"权限控制已解除，不该再有 {name}")

        send(proc, {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "list_hosts", "arguments": {}}})
        res = read_until(proc, 3).get("result", {})
        text = "".join(c.get("text", "") for c in res.get("content", []) if c.get("type") == "text")
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            failures.append(f"list_hosts 返回不是 JSON：{text[:200]}")
        else:
            hosts = payload.get("hosts", [])
            print(f"list_hosts -> {len(hosts)} 台，killlist {len(payload.get('killlist', []))} 条（仅 root 主机）")
            leaked = find_secret_fields(payload)
            if leaked:
                failures.append(f"list_hosts 输出了密钥字段：{', '.join(leaked)}")
            for h in hosts:
                print(
                    f"   {h['alias']:<8} {'root' if h['privileged'] else 'user':<5} guard={h['guard']:<8} "
                    f"pin={h['pin_source'] or '未固定':<10} {h['purpose']}"
                )
            if "rw_allowed" in text or "effective_mode" in text:
                failures.append("list_hosts 还在输出已废弃的权限字段")
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
