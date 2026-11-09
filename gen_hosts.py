# /// script
# requires-python = ">=3.11"
# ///
"""gen_hosts.py —— 命令行薄壳：扫描本机 ~/.ssh，可选并入主机清单。

日常维护请用图形界面 `uv run hosts_gui.py`；这个脚本留给无界面环境或批处理。
扫描与写入逻辑都在 `hostreg.py`，这里只负责打印与参数解析。

用法：
    uv run gen_hosts.py            # 只列出候选，不写任何文件
    uv run gen_hosts.py --merge    # 把可导入的候选并入凭据文件（先自动备份）
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import hostreg as R


def main() -> int:
    ap = argparse.ArgumentParser(prog="gen_hosts.py", description="从本机 ~/.ssh 生成 ssh-mcp 主机候选（password 留空给人填）")
    ap.add_argument("--merge", action="store_true", help="把可导入的候选并入凭据文件（先备份；JSON 坏了拒跑）")
    ap.add_argument("--hosts", default="", help="凭据文件路径；默认取 SSHMCP_HOSTS 或脚本目录")
    args = ap.parse_args()

    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, OSError):
            pass

    reg = R.Registry(Path(args.hosts).expanduser() if args.hosts else None)
    if not reg.writable:
        print(f"凭据文件 {reg.path}：{reg.error}——先修好再跑。")
        return 1

    connected, hashed = R.read_known_hosts()
    config = R.read_ssh_config()
    hashed_note = f"（另有 {hashed} 条 hashed 记录反查不出主机名）" if hashed else ""
    print(f"扫描 ~/.ssh：known_hosts {len(connected)} 台{hashed_note}；ssh config {len(config)} 条")
    print(f"凭据文件 {reg.path}：现有 {len(reg.aliases())} 台")

    candidates = R.build_candidates(reg.raw, connected, config)
    if not candidates:
        print("没有扫描到任何主机。")
        return 0

    importable = [c for c in candidates if c.importable]
    print(f"\n候选 {len(candidates)} 台，其中可导入 {len(importable)} 台：")
    for cand in candidates:
        if cand.importable:
            needs = "、".join(cand.notes) or "无"
            print(f"  + {cand.alias:<16} {cand.entry['address']}:{cand.entry['port']:<6} 待补：{needs}")
        else:
            print(f"  - {cand.alias:<16} {cand.entry['address']}:{cand.entry['port']:<6} 跳过：{'；'.join(cand.reasons)}")

    if not args.merge:
        print("\n只列出，没有写任何文件。要并入就加 --merge，或用界面：uv run hosts_gui.py")
        return 0
    if not importable:
        print("\n没有可导入的新主机。")
        return 0

    added = []
    for cand in importable:
        reg.upsert(cand.alias, cand.entry, keep_password_if_empty=False)
        added.append(cand.alias)
    backup = reg.save()
    print(f"\n已并入 {len(added)} 台：{'、'.join(added)}")
    print(f"原文件备份为 {backup}。" if backup else "（原来没有凭据文件，本次新建）")
    print("接着补 password（username 为空的那几台也要补），或用界面逐台编辑。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
