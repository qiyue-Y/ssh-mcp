# ssh-mcp 待处理问题

给不在本会话里的 Agent 看的。追加式，新条目往顶部加。每条写清：症状、最小复现、影响面、已排除项、临时规避。

判定口径：凭据/认证/指纹类问题**不要记在这里**，那是用户的事（提醒他改 `ssh_mcp_hosts.json`，该文件不读不写）。这里只收 ssh-mcp 自身的缺陷与已知边界。

纯优化建议（不修也照常好用、修了更顺手的那类）**也不要记在这里**，走 `SUGGESTION.md`，且必须经用户同意才写。判据是「现在会不会咬人」：会咬人的进本文件，不会咬人的进 `SUGGESTION.md`。

---

## 2026-10-14 · `cd ~` 被引号裹成字面量、光一个 `cd` 静默无效果（已修，回归用例钉着）

- **症状**：`exec(host, command="cd ~")` 报 `cd: ~: 没有那个文件或目录`（100 实测，exit 1）。根因：探活串用 `shlex.quote(cd_target)` 把 `~` 裹成 `'~'`，远端 shell 不再展开；`cd ~/xxx` 与 `cwd="~/xxx"` 参数同病。另一处：光一个 `cd`（不带参数）此前不匹配 cd-only 分支，跑完静默无效果。
- **修法**：新增 `_cd_expr()`（`ssh_mcp.py`），`~` / `~user` 与第一个 `/` 之前的头留在引号外、其余照旧引号保护，前缀与探活两处都换用它；`_cd_only_segment` 接受单 token 的 `cd`，按回 home 处理。
- **真机复验（100）**：`cd ~` → `cwd_after=/home/qy`；`cd ~/no-such-xyz` 报错里是展开后的 `/home/qy/no-such-xyz`；带空格目录 `cd '/tmp/sshmcp cd dir'` 记住，下一条 `pwd` 命中。离线 +2 例：`test_cd_expr_keeps_tilde_out_of_the_quotes`、`test_cd_probe_forms`。
- **语义备忘**：只有「单发一条 cd」或 `cwd` 参数改服务端记忆；`cd X && cmd` 复合形态只影响本条（与真 shell 的持久目录不同）。

## 2026-09-29 · 权限控制解除，只留 killlist（决策记录）

- **变更**：`ssh_policy.py`(566) → `ssh_guard.py`(~315)。ro 白名单 / rw 黑名单 / grant / CLI `grant`+`revoke` / Windows 确认框全部移除。`exec` 新增 `force`，`max_duration` 不再被服务端夹制，新增 `pin_hostkey` 工具（探测不发凭据，落盘要 `trust=true`，写本机 `hostkeys.json`）。可连主机从「policy.json + 凭据文件双白名单」改为「凭据文件里有这条即可」。
- **查清单的主机**：`username == "root"` 恒查，非 root 由 `policy.json` 的 `guarded_hosts` 点名（当前点名：`66`）。
- **提权（同日追加）**：`exec(..., elevate=true)` 把单条命令包成 `sudo -S -p '' --user <elevate_user> -- sh -c '<含 cd 前缀的整段>'`，口令写进 channel stdin。能力位在凭据文件（`elevate` / `elevate_user` / `elevate_password`，后两者可省，口令默认复用登录口令）。**提权命令一律查 killlist**，不看 `guarded_hosts`。
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
- **2026-10-14 更新**：M2 detach 已实现（ab160ef，`exec(detach=true)` + `job_status`/`job_kill`/`job_list`）——长任务改走 detach，不再受单次调用时长限制；默认 `max_duration_s` 仍 300s（短任务不受影响，未动）。

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

## 2026-09-28 · 没有文件传输工具（**已修**，见下一条；dd 变通仅作历史）

- **原症状**：需要把远端文件搬回本机（或反向）时，六个工具里没有任何传输能力；`exec` 的输出单文件落盘上限 `max_output_bytes`（8MB），一次 exec 最多带回 8MB。
- **现状**：`get_file` / `put_file` / `xfer_stat` 已补上（见下面「文件传输通道」那条）。**搬文件照那条走，不要再照着下面的 dd 变通做** —— 它留在这是为了记录当时的实测形状，不是现行做法。
- **当时的变通（真机实测，128MB / 18 块全量 md5 与远端一致）**：远端 `dd if=FILE bs=8000000 skip=N count=1 status=none` 逐块输出，本地把 `output/<run_id>.out.log` 按顺序 `cat >>` 拼回目标文件。要点：
  1. 落盘是**原始字节**（`open("wb")`），二进制安全，不需要 base64；
  2. 每块 ≤ 8388608 字节，且命令除数据外不能有别的 stdout（dd 加 `status=none`）；
  3. 输出按 run 轮转（默认 200 run / 500MB），每块收到后尽快拼走；每块会有一段二进制乱码内联回显（头 4KB+尾 4KB），属预期；
  4. 分块之间彼此独立，可并行发多条 exec（各开独立 channel）。
- **影响面（当时）**：搬 100MB 量级可行但笨重（≈18 次 exec），大目录同步不建议走这条路。

## 2026-09-29 · 文件传输通道（新增，附三个实测踩出来的坑）

新增 `put_file` / `get_file` / `xfer_stat`（分片断点续传 + 双向 md5 + root 两段式）。三个坑都是真机抓的，别改回去：

1. **pipelined 异步写会让 part 状态漂移**。第一版只在收尾 flush，超时中断时实测 part 是 12MB，下次再看成了 60MB —— 已入队的写在异常后还会继续落服务端，续传点建立在假状态上。改成**每片 flush**，吞吐反而从 5.9 涨到 10.1 MB/s（与 `sftp.put` 持平）。回归用例：`test_every_chunk_is_flushed`。
2. **普通 `sftp.rename` 不能覆盖已存在的目标**：100 实测回 `Failure`，`posix_rename` 才成功。所以 `overwrite=true` 必须走 `posix_rename`。
3. **`paramiko 5.0` 没有 `SCPClient`**（`hasattr` 实测 False），scp 路线要引第三方依赖；同时 `SFTPClient.get_version()` 也没了。别照旧文章写 scp 兜底。

另外三条设计约束（都有实测支撑，写在 README）：暂存不能放 `/tmp`（100 的 `/tmp` 是 tmpfs 15.2G，4GB 上限会吃内存）；传输目标必须走 `ssh_guard.check_write_target`（否则 SFTP 是清单的绕过口，缺口已实测）；远端 md5 用 `md5sum` 而不是读回来算（0.12s vs 18s / 200MB）。

4. **提交后又抓到两个命名/作废缺陷**（已修，回归用例钉着）：
   - `restart=true` 在 `elevate` 路径上是**空操作** —— 它删的是非提权那条 part 名（`<目标>.sshmcp-part`），而提权走 `~/.sshmcp-xfer/<名>.sshmcp-part`，于是 3MB 的旧暂存被当"已传部分"静默复用。修法是让提权路径也调 `X.part_path_for()`（命名只有一处来源），并把删除挪到 part 解析之后。真机分别验了两条分支：默认续传 `resumed_from=7340096` 保留已传片；带 restart `resumed_from=0` 从头传，两者最终 md5 都等于原文。
   - part 比新源文件还大（源被重新生成过）时，旧前缀不对应任何有效状态却会被当已传部分 → `push`/`pull` 现在遇到 `base > size` 一律作废从头传。用例：`test_stale_part_larger_than_source_is_discarded`、`test_stale_local_part_larger_than_remote_is_discarded`。

## 2026-09-29 · 传输没有跨调用取消，也没有目录批量（P2，按用户决定不做）

- **症状**：中断的传输只能由"用同一组参数再调一次"续传，无法取消别人发起的那次；目录要靠调用方自己 `exec tar czf` 再传归档。
- **根因**：v1 不设 job id（`xfer_timeout_s` 到点自己停，part 留在原地）。用户明确"v1 只做单文件"。
- **最小复现**：`put_file` 超时返回 `aborted` + `part`，再调一次走 `resumed_from`；想推掉别人的传输只能 `restart=true` 从头传。
- **要不要修**：真要取消/进度得加 job 表和一个 `xfer_cancel(job_id)`，那是另一套状态机。等有并发传大文件的实际痛点再说。
- **未验部分**：66 的传输路径没在真机跑过（真机限定 100）。

## 2026-09-29 · 提权口令错时会挂到 idle 超时（已修，勿回退）

- **症状**：`elevate=true` 而口令不对时，命令阻塞 21s 才回来，且报的是 `timed_out: "idle"`、`exit_code: -1` —— 看起来像网络/空闲问题，其实是认证失败。
- **根因**：`sudo -S` 认证失败后会**回头再读一次 stdin** 重试。我们只喂了一遍口令又没关 stdin，于是它一直等下一次输入。
- **修法**：喂完口令立刻 `chan.shutdown_write()`，sudo 读到 EOF 即放弃。修后同一场景 **2.5s** 返回 `exit_code: 1`、`timed_out: null`、stderr 是 `sudo: Authentication failed, try again.`。
- **代价**：提权命令自己的标准输入被关掉（`sh -c 'read x'` 会立刻拿到 EOF）。本服务没有交互输入能力，本来也喂不进东西，所以换得值。有 NOPASSWD 时多喂的那行口令会落进命令自己的 stdin —— 记在这里，别当新 bug。
- **回归用例**：`Elevate.test_channel_gets_password_on_stdin_not_in_command` 断言 `stdin_closed`；口令只走 stdin 不进命令串由 `test_sudo_wrap_keeps_the_password_out_of_argv` 钉住（`shlex.split` 逐位解析回原命令，防引号拼漏）。
