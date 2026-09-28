# ssh-mcp

常驻 SSH 会话的 MCP 服务。替代 `E:\Ilovestudy\env\passkey\ssh-key.ps1`（那个继续保留，两者并存）。

设计规格见工作区的 `ssh-mcp-SPEC.md`。

## 它解决什么

| 之前（plink -batch） | 现在 |
|---|---|
| 每条命令重新握手认证 | 连接池 + keepalive，复用同一 transport |
| Agent 不知道该拦什么，靠试 | `list_hosts` 直接把白名单/黑名单/当前 mode 回给 Agent |
| 密码出现在本机进程命令行（`-pw`） | 密码只在服务进程内存里 |
| 没有权限分层 | ro 白名单 / rw 黑名单 / 人工 grant 三层 |
| 无留痕 | 每条命令（含被拒）落 JSONL 审计 |

## 装

```powershell
# 自检（配置、凭据、依赖、审计目录可写）
uv run --quiet E:\Ilovestudy\MyWork\mcp\ssh-mcp\ssh_mcp.py doctor
```

离线策略测试（裸 python 即可，不需要 paramiko）：

```powershell
python test_ssh_policy.py
```

连接拒绝与授权路径的用例要真导入 paramiko，必须用 `uv run`，且**不能写成 `uv run python xxx.py`** —— 那种写法不读文件头的 PEP 723 deps，会拿到本机 site-packages 里缺 `cryptography` 的 paramiko 而报 ModuleNotFoundError：

```powershell
uv run --quiet test_connect_refusals.py
```

## 配

1. `copy ssh_mcp_hosts.example.json ssh_mcp_hosts.json`，填真实凭据。**这个文件我不读不写**，`hostKey` 缺失会直接拒连。
2. `policy.json` 的 `hosts` 键集合 = 可连白名单。凭据里有但这里没列的主机连不上（两处都要点头）。
3. Qoder 里加 MCP（或手工写进 MCP 配置）：

```json
"ssh-mcp": {
  "command": "uv",
  "args": ["run", "--quiet", "E:\\Ilovestudy\\MyWork\\mcp\\ssh-mcp\\ssh_mcp.py"],
  "env": { "SSHMCP_HOME": "E:\\Ilovestudy\\MyWork\\mcp\\ssh-mcp" }
}
```

加完 `/mcp reload`。

## 权限模型速查

| 账号 | 无 `rw_allowed` | `rw_allowed: true` |
|---|---|---|
| 非特权 | 永远 ro | 长期 rw（黑名单仍生效） |
| `root` | 永远 ro | 默认 ro，需未过期 grant |

`privileged` 由 `username == "root"` 推导，不可手工覆盖。`sudo` 在 rw 黑名单里，MCP 这条路上不会自动提权。

## 工具

- `list_hosts()` —— 主机、约束、`effective_mode`、grant 到期时间、限额。不含密码。
- `exec(host, command, cwd?, idle_timeout?, max_duration?)` —— 离散命令。被拒不建立连接，返回 `reason` + 下一步建议。
- `session_reset(host)` —— 丢连接与 cwd 重来。
- `audit_tail(host?, limit?)` —— 回看最近审计（含被拒）。

**没有** 交互 shell / PTY / 按键透传，这是故意的：netcatty 那套长会话死在 `terminal_execute` 全部挂起上。

## CLI（人在终端敲）

```powershell
uv run --quiet ssh_mcp.py list                       # 看当前 mode 与 grant
uv run --quiet ssh_mcp.py grant 100 --scope host --for 30m --why "装 nginx"
uv run --quiet ssh_mcp.py grant 100 --scope cmd --cmd "apt install nginx" --uses 1
uv run --quiet ssh_mcp.py revoke 100 --all
```

`grant` 会弹一个 Windows 原生模态框，列出主机/scope/时长/理由，**必须有人点「确定」**；取消或 120s 超时都不落盘。
（别指望 `stdin.isatty()`：实测 Agent 的 Bash 里它返回 True，Git Bash 经 conpty 伪装成终端，那道校验拦不住自批。）

## 超时

- `idle_timeout_s`（默认 30）：**无新输出**才触发。下载有进度条会不断重置，不会被误杀。
- `max_duration_s`（默认 300）：硬兜底。
- 超时只关 channel 不关连接，后续命令照常。
- 静默长任务（编译、`tail -f`）M1 只能撞 max_duration；`detach` + `job_log` 在 M2。

## 已知边界

1. `policy.json` 是**护栏不是沙箱**。真边界是远端账号权限 —— 长期 rw 的主机请用非特权、无 sudo 账号。
2. `grants.json` 与凭据同属当前用户，Agent 用文件工具理论上能直接改它。原生确认框挡的是「Agent 自己跑 grant」这条正路，不挡「蓄意绕过」。要硬边界就得把 grants.json 放到另一个 Windows 用户下，或全部改用非 root 账号。
3. cmd grant 对包管理器类命令（`apt`/`pip`/`npm`/`docker`/`systemctl`）≈放行任意执行，这类命中会打 `broad_grant` 标记，只标注不改行为。
4. 引号内的 `>` `<` 已通过掩码排除；但 `grep a>b`（未加引号）仍会被判为重定向 —— 宁可错杀。
5. 密码解密后常驻服务进程内存。长期方案是全量转私钥认证。
