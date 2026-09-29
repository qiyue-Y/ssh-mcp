# ssh-mcp 待处理问题

给不在本会话里的 Agent 看的。追加式，新条目往顶部加。每条写清：症状、最小复现、影响面、已排除项、临时规避。

判定口径：凭据/认证/指纹类问题**不要记在这里**，那是用户的事（提醒他改 `ssh_mcp_hosts.json`，该文件不读不写）。这里只收 ssh-mcp 自身的缺陷与已知边界。

---

## 2026-09-29 · 权限控制解除，只留 killlist（决策记录）

- **变更**：`ssh_policy.py`(566) → `ssh_guard.py`(~315)。ro 白名单 / rw 黑名单 / grant / CLI `grant`+`revoke` / Windows 确认框全部移除。`exec` 新增 `force`，`max_duration` 不再被服务端夹制，新增 `pin_hostkey` 工具（探测不发凭据，落盘要 `trust=true`，写本机 `hostkeys.json`）。可连主机从「policy.json + 凭据文件双白名单」改为「凭据文件里有这条即可」。
- **查清单的主机**：`username == "root"` 恒查，非 root 由 `policy.json` 的 `guarded_hosts` 点名（当前点名：`66`）。
- **理由（用户判定）**：命令过滤挡不住蓄意绕行的 AI，却给每条正常命令加一轮往返。保留的清单定位是**挡手滑**。
- **随变更消失的旧条目**：裸 `mount` 被错杀（P2）、`policy.json` 与凭据双写造成的 `new8`/`admin` 缺条目摩擦、grant 对非 root 主机空转。
- **仍未修的**：见下面两条 P1。

## 2026-09-29 · `username == "root"` 这条判定分支没有真机证据（P2，从 P1 降级）

- **症状**：killlist 的生效条件之一是 `cred.privileged`（`username == "root"`），而配置里唯一的 root 主机 `admin`（pve2）在凭据文件中缺条目，`new8`（10.81.2.48/dell）同样缺。
- **已排除**：不是整条链路没验。**「命中 → 拒且不建立连接 → `force=true` 送到远端 → 审计记 `rule:"forced"`」在 100 上真机跑通了** —— 办法是把 100 临时加进 `guarded_hosts`（它是非 root 的 `qy`，走的是同一个 `G.applies` 谓词的另一半）。硬证据：`userdel mcp-selftest-absent` 不带 force 返回 `{blocked:true, rule:"deny:userdel"}` 且 `POOL.connected("100")` 为假；带 force 后远端真执行、返回 `exit_code=6`（用户不存在）。验完已把 100 从 `guarded_hosts` 里撤掉，撤掉后同一条命令不再被拦（exit 6）。
- **残留风险**：只差 `privileged` 那半行的真机确认。离线侧 `KilllistWiring` 有 5 例 + `test_ssh_guard.py::GuardScope` 4 例钉着两种触发条件与 `list_hosts` 的归属显示。
- **最小复现**：补上 root 凭据后 `exec(host="admin", command="mkfs.ext4 /dev/sda1")` 应 `{blocked:true, reason:"killlisted"}`，带 `force=true` 应执行且审计记 `rule:"forced"`。
- **要补的是凭据，不是代码。**

## 2026-09-29 · `pin_hostkey` 的两步确认靠约定，不靠强制（P1）

- **症状**：`hostkeys.json` 与凭据同属当前用户，Agent 用文件工具理论上能直接写它；`trust=true` 也只是个参数，服务端无法知道用户是否真的核对过。
- **已排除的假防护**：原 `grant` 那套 `stdin.isatty()` + 原生模态框已被实测证明挡不住 Agent（Git Bash 经 conpty 伪装成终端，`isatty()` 返回 True），随权限控制一起删了。别再照着它设计新守卫。
- **缓解手段（已实测）**：探测阶段只做密钥交换，不发送用户名与密码，所以即便对端是冒充的机器，密码也不会漏 —— 这条有 `test_probe_works_without_any_valid_credential` 钉着（把 `Transport.auth_password`/`auth_publickey` 钉成会抛，指纹照样拿得到）。
- **残留风险**：TOFU 首次信任仍可能被中间人骗走。硬边界要么把 `hostkeys.json` 放到另一个 Windows 用户下，要么凭据文件里逐台手工钉 `hostKey`（那里钉过的，工具**拒绝覆盖**，`writable:false`）。
- **约定**：AI 必须把 `pinned` 与 `fingerprint` 两个值并报给用户，得到确认后才带 `trust=true`。

## 2026-09-28 · 静默长任务仍会被默认 300s 砍断（P1，本次已放开但没改默认）

- **症状**：`idle_timeout_s=30` 只在「无新输出」时触发，`max_duration_s=300` 是缺省硬兜底。`configure`、大依赖编译这类**长时间一行都不输出**的命令默认 300 秒被切断，`timed_out: "duration"`，此时命令其实还在远端跑。
- **本次变化**：服务端那句 `min(传入值, policy.max_duration_s)` 的夹制已删，调用方传多大用多大（真机实测 `max_duration=1` 会在 1s 被切、`sleep 3` 报 `duration` 不再误报 `idle`）。所以 `cmake --build` 这类现在**传个大 max_duration 就能跑完**，不用再自己 `nohup`。
- **最小复现**：`exec(host="100", command="sleep 400", max_duration=5)` → `exit_code=-1`、`timed_out="duration"`。不传 `max_duration` 时是 300s。
- **影响面**：不知道要传大时长的调用方仍会撞上默认 300s 被切。
- **正解**：要么把 `defaults.max_duration_s` 提到 1800，要么实现原计划的 M2 `detach` + `job_log`（落盘层已就位，`job_log` 可直接复用 `output_store`）。本次没动默认值。

## 2026-09-28 · 明文与落盘的敏感面（P2，已接受的代价）

- 口令解密后常驻服务进程内存；`output/<id>.out.log` 是**原文落盘不脱敏**（构建日志里可能出现 `--password=`、`Authorization:`、带 token 的镜像源 URL），保留 7 天 / ≤200 run / ≤500MB。
- `hostkeys.json` 取代了 `grants.json` 的位置，同样与凭据同属当前用户（见上面 P1 条目）。
- 未修的原因：真要硬边界得把这些文件放到另一个 Windows 用户下，或全量转私钥认证。README 已知边界 2、5 已写明。
- **提醒用户**：本机若跑了文件同步/分享类工具（QuickFilesSharing 等），别让同步范围覆盖 `output/` 与 `audit/`。

---

## 已修但值得记住形状的两类（勿回退）

1. **收流竞态三兄弟**（都靠真机暴露，离线逐行喂数据照不到）：`exit_status_ready()` 单独为真就 break 会丢尾巴且仍报 `exit_code=0`；首块超预算时 `_head` 真值判断让内联整段变空；尾窗恰好是一条完整行时行对齐把整窗当半行丢掉（真机 chunk 序列 `[32768,32768,32768,10590,14]`）。回归用例：`test_live_chunk_sequence_keeps_the_tail`、`test_single_chunk_larger_than_budget_keeps_both_ends`、`test_empty_chunk_does_not_evict_the_tail`。
2. **策略绕过三类**（killlist 仍防）：根目录写法变体（`rm -rf /*`）、权限位八进制（`chmod 0777 /`）、不空格的 `;` `|` `&` 不分段。第四类「前缀包装器剥壳」（`nohup rm -rf /`）是 2026-09-29 **主动删掉**的 —— 它属于「防蓄意绕过」那半边，代价是每条 `nice -n 10 make` 都可能被误杀。`DeliberatelyNotCaught` 用例把它和其他 8 种形态一起钉着，别当成漏匹配。

## 本次实测顺手修掉的两处（记录形状）

- **`timed_out` 误报种类**：`wait = min(idle, 剩余时长)` 之后统一把 `socket.timeout` 记成 `idle`，于是传 `max_duration=1` 得到的也是 `idle`，调用方会以为自己的时长没生效。改成按「这一轮谁定的 wait」报 `duration`/`idle`（`_drain`）。别用 `monotonic() >= deadline` 判 —— 边界上会抖，真机第一次就是这么漏的。
- **`read_output` 的 `grep` 是子串匹配不是正则**：`pattern="^199999$"` 命中 0 行。行为没改（改正则会让现有肌肉记忆失效），只把工具描述和 README 写清了。
