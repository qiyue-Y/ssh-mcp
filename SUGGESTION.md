# ssh-mcp 优化建议

给不在本会话里的 Agent 看的。追加式，新条目往顶部加。

## 这个文件收什么

收**可改可不改的优化建议** —— 不修也照常好用，修了更顺手的那类。和 `ISSUES.md` 是两回事，按「现在会不会咬人」判：

| | `ISSUES.md` | `SUGGESTION.md`（本文件） |
|---|---|---|
| 收什么 | 缺陷、错误行为、已知边界 | 优化建议、体验与设计上的改进空间 |
| 判据 | 现在就会咬人，或已实测到行为不对 | 现在跑得好好的，只是能更好 |
| 处理默认值 | 在本项目里发现就当场修完再汇报 | **用户没点头就不动代码**，只登记 |

一条既像缺陷又像建议时（例如某个行为没错但反直觉），记进 `ISSUES.md`，把改进想法写在它那一条的「正解」里，不要两边各记一份。

## 写入规则

**Agent 只能提议；必须经用户同意才落到这个文件。**

使用 ssh-mcp 的过程中发现可优化的地方，先回报三点就好 —— 现状与痛点、建议做法、预期收益（有代价一并说）。用户点头之后才写条目；没点头不写，也不要顺手改代码。

每条写清：日期、现状与痛点、建议做法、预期收益、代价与风险、涉及的文件与行号（若已定位）、有没有实测支撑。没实测过的猜想照实标「未实测」，别写成结论。

---

## 条目

### 2026-10-13 · `get_file` 读 `st_size <= 0` 的文件拿不到内容（P2，提权路径反倒能读）

**已实现（2026-10-14，ab160ef）**：pull 按「长度未知」读到 EOF、bytes/chunks 报实际落盘量、total_limit 按已写字节判、st_size=0 不续传；get_file 对 st_size=0 跳过二次 md5（`md5_check: skipped_st_size_0`）、FIFO 直接拒（会挂住等写者）。真机：/proc/cpuinfo 由 0 字节 → 48142 字节 verified；/sys 的 bytes 虚报 → 实际值（18）。

- **现状与痛点**：`ssh_xfer.py:132` 用 `sftp.stat(remote).st_size` 规划要搬多少字节，`ssh_xfer.py:84`（`_write_blocks` 里）的写循环条件是 `while sent < total`。`/proc/*` 这类伪文件的 `st_size` 是 **0**，于是 `total = size - base = 0`，循环一次都不进，**落盘 0 字节**。随后 `ssh_mcp.py:1039-1044` 比对两侧 md5：远端算的是真实内容哈希、本地是空文件哈希 → 报 `md5_match: false`。所以这不是"静默产出错数据"（我一开始这么判断，读了校验环节才推翻），而是**永远抓不到、且报错原因指向错方向**。
- **`/sys` 不在受害面里（2026-10-14 补测）**：`/sys/class/net/lo/address`、`/sys/kernel/vmcoreinfo` 的 `st_size` 实测是 **4096** 不是 0；读到内容尾遇 EOF 会提前停，实测落盘 18 字节、`md5_match:true`，能读。只是同一次返回里 `bytes:4096`、`chunks:1` 是按 stat **虚报**的（实际 18 字节）——同属"拿 st_size 当真相"这一个根因。
- **反差值得单独记**：`elevate=true` 路径先把远端内容 `cat` 进一个暂存文件（`ssh_mcp.py:1005-1014`），暂存的是普通文件、有真实大小，于是**提权读得到、普通账号读不到**。使用者很容易误判成权限不足而不是实现缺陷。
- **另一处同形问题**：`ssh_xfer.py:160-164` 的 `_remote_size` 在 `IOError` 时也返回 0 —— 同一个 `0` 同时表示"真的是空文件"和"大小取不到"，两种语义压在一个值上。
- **建议做法**：`total` 允许为 `None` 表示长度未知，此时改流式读到 EOF（`block = src.read(chunk); if not block: break`）；`total_limit` 仍按已写字节判定，不放松上限。`_remote_size` 的失败与零值分开返回（`None` vs `0`）。
- **预期收益**：`/proc` 这类 `st_size=0` 的可读文件一次拿到；失败时的信息从"md5 不符"变成直接说清原因。（FIFO 未测：两条路径都可能要等写者，先不承诺）
- **代价与风险**：长度未知就失去了"按 size 判完整"的参照，**续传语义需要另定**——建议对 `size<=0` 一律不续传、整篇重读，避免把"上次读到 0 字节"当成有效续传点。改动集中在 `pull`，不影响 `push`。
- **涉及文件**：`ssh_xfer.py:132`（stat）、`ssh_xfer.py:84`（写循环）、`ssh_xfer.py:160-164`（`_remote_size`）；调用侧 `ssh_mcp.py:1005-1014`（提权暂存）、`ssh_mcp.py:1039-1044`（md5 比对）。
- **实测支撑**：**已真机复现**。`get_file(host="100", remote="/proc/cpuinfo")` 返回 `bytes:0`、`chunks:0`、`md5_local:d41d8cd9…`（即空文件的 MD5）、`md5_remote:b162153b…`、`md5_match:false`。
- **顺带撞出的第二个问题**：失败时给的 hint 是「md5 不符，part 已保留：重调同一参数从缺口续传」——但这里**没有缺口可续**，重调只会再来一次 0 字节。对这类文件，续传提示本身就是误导，应改说"该远端路径无固定大小，建议直接执行 `cat`（或走 elevate 路径）"。

### 2026-10-11 · M2 `detach` / `job_log` 接口草案（参考实现已逐行核过，可直接照抄形状）

**已实现（2026-10-14，ab160ef）**：`exec(detach=true)` + `job_status`（状态与增量输出合并、offset/offset_next 游标）+ `job_kill` + `job_list`；状态存远端 `~/.sshmcp-jobs/`；按本草案的取舍落地——status/output 合并成一个、本地二级缓存不做、elevate 的 detach 不做、out 合并流。真机：75 秒任务跨过 60 秒客户端上限正常取回。失联任务的回收：`job_kill` 对 `lost` 补写 killed 标记（见 README「后台任务」）。

下面「`max_duration` 放开后仍不够」那条的落地稿。参考对象是 `classfang/ssh-mcp-server` 的 job 实现，我把它源码读完了，**下列细节都在代码里核实存在，不是文档转述**：`src/utils/remote-jobs.ts:7-22`（目录布局）、`:40-47`（存活状态机与 PID 复用防护）、`:50-60`（wrapper 与原子写 exit）、`src/tools/jobs.ts:43/66/100/118`（四个 `registerTool`）。

**为什么必须做（不是优化项）**：从 Agent 侧发起调用时，客户端层约 60 秒会自行中断，`max_duration` 传多大都救不回来——本次 `npm i -g @deepseek-ai/dsh` 实测 3 次丢失结果（远端进程全程存活）。唯一出路是把"发起"和"取结果"拆成两次**都很快**的调用。

**远端布局**（照抄，路径前缀换成我们自己的）：`$HOME/.ssh-mcp-jobs/<job_id>/`，内含 `cmd` 命令原文、`dir` 工作目录、`out` **stdout+stderr 合并**、`pid`、`started`、`exit`、`killed`。

- 关键取舍：**状态存远端文件系统，而不是存服务进程内存**。这样 MCP 服务重启、SSH 断连、Agent 换会话之后仍能接着轮询。对照案例：`tufantunc` 的 session 是进程内 Map（`src/ssh/session-manager.ts:31`），服务一死全丢；`bvisible` 更糟，session 超时即置 ERROR 态、后续命令全拒（`src/session-manager.js:118-131` 超时抛错、`:220` 置 ERROR、`:161` 门禁）。**这是三家唯一的分水岭，选错就白做。**
- `exit` 用 `.tmp` + `mv` **原子发布**（`:54`），读侧永远不会看到半个退出码。
- `pid` 存的是 wrapper shell 自己（`echo $$ > pid`），配合 `setsid` 时它同时是进程组 id，杀整棵树有依据。

**存活状态机**（`:40-47`，四态，判定顺序固定）：有 `exit` → `exited`(带码) ＞ 有 `killed` → `killed` ＞ `kill -0` 成立**且** `job_is_ours` → `running` ＞ 否则 `lost`。
`job_is_ours` 读 `/proc/$pid/cmdline`（无 procfs 退回 `ps -o args=`）并 grep job id ——**这是防 PID 复用的关键**：`kill -0` 只证明"有进程占着这个 pid"，不证明"还是我们那个进程"。我们自己的代码若做判活必须带上这一条。

**工具形状**（四个，`exec` 加一个参数即可）：

- `exec(..., detach=true)` → 立即返回 `job_id`（一次 RTT，毫秒级）
- `job_status(job_id)` → `{state, exit_code?, started, out_bytes}`
- `job_output(job_id, offset, tail_bytes, max_bytes)` → 增量读 `out`，返回新内容与新的 `offset`。**`offset` 游标是省上下文的命门**：Agent 每次只取"上次之后"的那段，不必反复重读全文，也不必用 `grep` 猜进度。建议直接复用现成的 `output_store.py` 做本地二级缓存。
- `job_kill(job_id)` → 打 `killed` 标记 + 按进程组杀，杀前必须过 `job_is_ours`
- （可选）`job_list(limit)` → 便于回收与孤儿任务发现；保留期照抄 7 天

**两个他们踩过的兼容性约束，值得我们同步**（`:17-18` 注释写得很直白）：job 脚本必须是**纯 POSIX sh**、**不得含 `exit`**、**不得用 heredoc**——因为 shell 传输模式下这些片段会被粘进一个活的交互 shell，`exit` 会直接杀掉会话。我们目前是 paramiko 单命令 exec，暂时碰不到，但若将来加 shell/交互模式，这条会立刻咬人。

**预期收益**：长任务不再受客户端硬上限牵连；判活从"Agent 手写 shell 技巧"变成工具语义，顺带消掉我本次实测到的两个判活假阴性（普通用户 `kill -0` 探 root 进程返回 EPERM 却看似"已退出"；`pgrep -f` 命中自身命令行导致轮询永不退出）。
**代价与风险**：① 在远端 `$HOME` 下写文件，需要事先在文档写明路径与清理策略（保留 7 天后自删）；② 四个新工具会抬高 `tools/list` 体积，建议与下条的精简模式一起做；③ `out` 合并 stdout/stderr 后无法分离错误流，若要区分得改成两个文件；④ 需要有 job 数量上限，否则 job 泄漏。
**涉及文件**：新增逻辑接在 `ssh_mcp.py:648`（`execute`）旁；落盘复用 `output_store.py`；`policy.json` 加 `job_retention_days` 与 `job_max_concurrent`。
**实测支撑**：参考实现有（逐行核过）；我方尚未实现，收益部分是推断——其中"客户端 60 秒硬上限"有实测（25s/55s 通过、70s 以上丢结果），"offset 省上下文"是设计推论，**未实测**。

### 2026-10-11 · `max_duration` 放开后仍不够：客户端侧有独立的调用硬上限，`detach` 是唯一解（给既有 P1 条目补论据）

**已落地（2026-10-14，ab160ef）**：detach 已实现，长任务改走它。60 秒数字另有 8 个历史样本复核（客户端报错时刻 − 审计 intent 时刻 = 60.4–60.9s）；默认 `max_duration_s` 300s 未动。

- **现状与痛点**：`ISSUES.md` 那条「静默长任务仍会被默认 300s 砍断」的正解写了「传个大 `max_duration` 就能跑完」。本次在 10.81.2.100 上实测到一个**服务端管不到的新事实**：从 Agent 侧发起调用时，MCP 客户端层自身约 60 秒就会中断调用，返回 `MCP tool invocation did not complete`，此时 `max_duration=900` 也没用。实测样本：远端跑 25s、55s 的命令能正常拿到结果；70s、120s、320s 的那几次全部丢结果（`npm i -g @deepseek-ai/dsh`、40×8s 轮询循环各撞一次），而远端进程照常在跑。
- **建议做法**：把 M2 的 `detach` 优先级提上来，语义按「调用必须短」设计：`exec(detach=true)` 立刻返回 `job_id`，配 `job_status(job_id)` / `job_output(job_id, offset, tail_bytes, max_bytes)` / `job_kill(job_id)`。这样任何一次调用都远在 60 秒以内，长任务的完成与否由轮询判断，不再依赖"服务端超时够大"。
- **预期收益**：一次性解决三类问题——长任务结果丢失、判活要靠手写 shell 轮询、以及 `idle_timeout` 按输出判活带来的误杀。
- **外部设计参照**（本次实测取的样本）：`classfang/ssh-mcp-server` v1.10.0 只有 10 个工具，其中 `job-start / job-status / job-kill / job-list` 就是这套语义，且 `job-status` 的入参是 `jobId, offset, tailBytes, maxBytes`（分页 + 单次响应字节上限），`read-file` 也用 `offset, length`。可直接抄它的接口形状，落盘层复用现成的 `output_store`。
- **代价与风险**：新增 4 个工具会抬高 `tools/list` 的上下文占用；job 需要生命周期与并发上限（否则 job 泄漏）。
- **涉及文件**：`ssh_mcp.py:648`（`execute`）、`ssh_mcp.py:676`（`idle_s`）、`policy.json:3`、`ssh_guard.py:59`。
- **实测支撑**：有（上述 5 个时长样本 + 远端进程存活确认）。

### 2026-10-11 · 缺判活原语，导致 Agent 手写轮询时踩到 `kill -0` 的权限假阴性

**按方案 A 落地（2026-10-14）**：不新增工具，README 新增「判活」一节把规矩写死（跨用户判活带 elevate、`pgrep -x` 取 PID 且与 kill 分两条、长任务改 detach 轮询）。detach 也吃掉了本条的长任务那半边。

- **现状与痛点**：工具没有"等进程结束/等文件出现"的语义，Agent 只能自己拼 shell。实测两个坑：① 用 qy 执行 `kill -0 <root 的 PID>` 判活返回 **EPERM**，看起来像"进程已退出"，据此误判了一次 apt 已结束（其实还在下载并持有 dpkg 锁）；② `pgrep -f '<模式>'` 会匹配到**承载这条 pgrep 自己的 `bash -c` 命令行**，导致轮询循环永不退出并虚报存活。
- **建议做法**：给 `exec` 加 `wait_pid=<pid>` / `wait_file=<path>` 语义（内部用 `/proc` 判活并按 `idle_timeout` 心跳输出），或在 README「判活」一节写死：跨用户判活必须带 `elevate`，且 `pgrep -f` 的模式不得与自身命令行重合。
- **预期收益**：消掉两类静默误判——这两类都不是报错，是**返回了错误的结论**，比报错更贵。
- **代价与风险**：`wait_*` 若做成阻塞调用会重新撞上 60 秒上限，必须做成"查一次就返回"的非阻塞探针。
- **涉及文件**：`ssh_mcp.py:648` 附近；文档 `README.md:147`。
- **实测支撑**：有（两条都在 100 上复现过）。

### 2026-10-11 · `list_hosts` 没有精简模式，`exec` 原样回显整条命令

**已实现（2026-10-14）**：`list_hosts(brief=true)` 去掉每台的 limits 与全量 killlist；exec 回显超 200 字符截尾（标注"全文见 audit_tail"，审计里始终是全文）。第 3 条「输出默认只给摘要」不做——头+尾内联是报错可读性的地基（有实测理由）。

- **现状与痛点**：`list_hosts` 每台机器都重复一整块 `limits` 与 `inline_output` 说明，加上全量 killlist，单次约 2.5KB；本次为查一个 `auth` 字段调了 3 次。`exec` 的响应把调用方发过去的命令**逐字回显**，本次约 25 条命令平均 700 字符，光回显约 17KB。粗估这轮调用返回的字节里 40–55% 是信封与回声，不是信息（量级估算，非精确计量）。
- **建议做法**：`list_hosts(brief=true)` 或 `fields=` 只回别名/地址/auth/pin_source；把 `limits` 挪到单独工具或只在首次返回。`exec` 加 `echo_command`（默认 `false`，或超过 N 字符时截断）。stdout 超阈值时默认只回摘要 + `output_id`——`read_output` 已经存在，缺的是让它成为默认路径。
- **预期收益**：长会话里 Agent 的上下文占用显著下降，同样任务能塞进更多轮次。
- **代价与风险**：不回显命令会让"哪条命令产生了这个输出"的审计需要另找来源（`audit_tail` 可以承担，要一并写明）。
- **涉及文件**：`ssh_mcp.py:785-788`（limits/inline_output 载荷）、`ssh_mcp.py:806`。
- **实测支撑**：有（字节数是实测相加，比例是估算）。

### 2026-10-11 · 凭据从 password 切到 key 后，`elevate_password_from: "password"` 的语义要写明

**已实现（2026-10-14）**：README 提权一节写明 `auth` 与 `elevate_password_from` 是两个独立字段，key 登录下后者照常有效（口令只喂 `sudo -S` 的 stdin）。

- **现状与痛点**：100 改仅密钥登录后，`auth` 变成 `"key"`，但 `elevate` 仍靠登录口令工作（实测 `ran_as: root` 正常）。`list_hosts` 里 `elevate_password_from: "password"` 字面上像"仍用密码认证"，容易让人误判凭据配置没改过来——本次就因此多绕了一轮排查。
- **建议做法**：在 README 或 `list_hosts` 输出里把两者区分清楚：登录认证方式（`auth`）与提权口令来源（`elevate_password_from`）是两个独立字段，后者在前者为 `key` 时依旧有效，因为口令只喂给 `sudo -S` 的 channel stdin。
- **预期收益**：减少把"仍能提权"误读成"密码登录还开着"的判断。
- **代价与风险**：无。顺带一条外部对照支持这个设计：`bvisible/mcp-ssh-manager` 的 `ssh_execute_sudo` 把 `password` 做成**工具入参**，也就是提权口令会流经模型上下文；`ssh-mcp` 用服务端 stdin 注入而不进命令行/history/审计的形状更好，值得在文档里明确点出这个差别。
- **实测支撑**：有。
