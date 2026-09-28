# ssh-mcp 待处理问题

给不在本会话里的 Agent 看的。追加式，新条目往顶部加。每条写清：症状、最小复现、影响面、已排除项、临时规避。

判定口径：凭据/认证/指纹类问题**不要记在这里**，那是用户的事（提醒他改 `ssh_mcp_hosts.json`，该文件不读不写）。这里只收 ssh-mcp 自身的缺陷与已知边界。

---

## 2026-09-28 · 静默长任务仍会被 max_duration 砍断（P1，未修）

- **症状**：`idle_timeout_s=30` 只在「无新输出」时触发，`max_duration_s=300` 是硬兜底。`configure`、大依赖编译这类**长时间一行都不输出**的命令会在 300 秒被切断，`timed_out: "duration"`，此时命令其实还在远端跑。
- **最小复现**：`exec(host="100", command="sleep 400", max_duration=5)` → `exit_code=-1`、`timed_out="duration"`。真实场景是 `cmake --build` / `pip install torch`。
- **影响面**：任何预期超过 5 分钟的构建类任务，MCP 这条路目前走不通。
- **已排除**：不是收流逻辑问题 —— 被砍时**已收到的部分仍在 `output/`**，可 `read_output` 捞回，这条已实测并有用例。
- **临时规避**：调用方显式传更大的 `max_duration`（上限受 `policy.max_duration_s` 夹住，见 `execute()` 里的 `min(...)`），或者自己 `nohup ... &` 后分次查日志。
- **正解**：原计划的 M2 `detach` + `job_log`（提交即返回 job_id，之后轮询状态 + 拉日志）。落盘层已经就位，`job_log` 可直接复用 `output_store`。

## 2026-09-28 · root 账号的 grant 解锁路径没有真机证据（P1）

- **症状**：`grant` 只有对 `username == "root"` 且 `rw_allowed: true` 的主机才有意义。`resolve_mode`（ssh_mcp.py:204）在长期 rw 时直接 return，压根不读 grant。
- **实测**：在 100（非 root + `rw_allowed: true`）上签发了 cmd grant `g-17a6d988` 并执行被授权命令，结果是**放行但条子空转** —— 审计里 `grant_id=null`、`grants.json` 的 `uses_left` 仍是 1。
- **最小复现**：`grant 100 --scope cmd --cmd "touch /tmp/x" --uses 1` → 弹窗确认 → `exec(100, "touch /tmp/x")` → 看返回的 `decision.grant_id`。
- **已排除**：不是 grant 存储/消费的 bug（离线 `GrantUnlock` 4 例覆盖了 root+host grant 解锁、过期不解锁、cmd scope 消费计数，全绿）。是**缺真机验证**。
- **卡在哪**：唯一配置的 root 主机是 `admin`（pve2），但它在 `policy.json` 白名单里而凭据文件缺条目 → `list_hosts` 报 `unreachable`。`new8`（10.81.2.48 / dell）同样缺凭据。**要补的是凭据，不是代码** —— 提示用户往 `ssh_mcp_hosts.json` 里加这两条。
- **临时规避**：需要 root 权限的操作交给用户自己跑，别指望 MCP 这条路提权（`sudo` 本来就在 rw 黑名单里，是故意的）。

## 2026-09-28 · 裸 `mount` 被错杀（P2，只报备）

- **症状**：黑名单条目是 program 级（`mount`、`umount`），匹配只看 program 名，不看有无参数。于是 `mount`（无参 = 纯打印挂载表，只读操作）也被拒。
- **最小复现**：`exec(host="100", command="du -xh --max-depth=1 / | sort -hr; mount")` → 整条 `deny:mount`。本会话真实踩过一次，代价是多一轮往返。
- **临时规避**：看挂载表用 `df -h` / `lsblk`（都在 ro 白名单，已实测放行）。
- **要不要修**：可以加「program 是 mount 且 args 为空 → 放行」的特例，但这会给黑名单开一类「按参数决定危险性」的先例，而 `mount` 的改状态形态太多（`-a`、`-o remount`、设备路径…）列不全。当前按 README「宁可错杀」保持原样。

## 2026-09-28 · 静态分析地板：8 种等价写法看不见危险段（P2，设计边界）

- **形态**：`python -c "os.system('rm -rf /')"`、`perl -e system(...)`、`awk BEGIN{system(...)}`、`find / -delete`、`$(echo rm) -rf /`、`R=/; rm -rf $R`、`export R=/; rm -rf $R`、`(reboot)`。
- **为什么拦不住**：判定发生在**发给远端 shell 之前**，这些写法要么把危险段藏进别的语言字符串、要么运行期才算值，静态切片里根本没有 `rm`/`reboot` 这个 token。与「包装器剥壳」「不空格分号」不同 —— 那两类危险段仍以 shell 词法摆在字符串里，所以能修。
- **已排除**：不是漏匹配。`test_rw_blacklist_known_gaps` 逐条钉着这 8 个形态，防止将来有人误以为已防住。
- **真边界**：远端账号权限。长期 rw 的主机请用非特权、无 sudo 账号（README 已知边界 1）。

## 2026-09-28 · 明文与落盘的敏感面（P2，已接受的代价）

- 口令解密后常驻服务进程内存；`output/<id>.out.log` 是**原文落盘不脱敏**（构建日志里可能出现 `--password=`、`Authorization:`、带 token 的镜像源 URL），保留 7 天 / ≤200 run / ≤500MB。
- `grants.json` 与凭据同属当前用户 → Agent 用文件工具理论上能直接改它；原生模态框挡的是「Agent 敲 grant 命令」这条正路。
- 未修的原因：真要硬边界得把 grants/output 放到另一个 Windows 用户下，或全量转私钥认证。README 已知边界 2、5 已写明。
- **提醒用户**：本机若跑了文件同步/分享类工具（QuickFilesSharing 等），别让同步范围覆盖 `output/` 与 `audit/`。

---

## 已修但值得记住形状的两类（勿回退）

1. **收流竞态三兄弟**（都靠真机暴露，离线逐行喂数据照不到）：`exit_status_ready()` 单独为真就 break 会丢尾巴且仍报 `exit_code=0`；首块超预算时 `_head` 真值判断让内联整段变空；尾窗恰好是一条完整行时行对齐把整窗当半行丢掉（真机 chunk 序列 `[32768,32768,32768,10590,14]`）。回归用例：`test_live_chunk_sequence_keeps_the_tail`、`test_single_chunk_larger_than_budget_keeps_both_ends`、`test_empty_chunk_does_not_evict_the_tail`。
2. **策略绕过四类**：根目录写法变体（`rm -rf /*`）、权限位八进制（`chmod 0777 /`）、前缀包装器（`nohup rm -rf /`）、不空格的 `;` `|` `&` 不分段（最后这条会让 **ro 模式直接失守**：`df -h;touch /tmp/x` 曾被放行）。
