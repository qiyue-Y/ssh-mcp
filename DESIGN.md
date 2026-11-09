# ssh-mcp 下一阶段设计参考

写下这份文档的时间：2026-11-09。它记录「AI 通过 SSH 控制远程主机」这个场景下，本项目下一阶段的设计取舍。具体任务拆解见 `todo.md`。

## 设计原则

1. **准入由用户维护，不由模型判定。** 哪台主机、什么账号、能不能提权、能不能传文件，由凭据文件决定；服务只负责执行与留痕。
2. **安全目标从「防绕过」改成「可回滚」。** 不追求拦住蓄意绕行的 AI，追求高后果动作慢一点、事后能查、改坏了能退回去。
3. **审计不要求人逐条看。** 只把 blocked / forced / 失败 / 敏感写这类异常推到人眼前，正常命令不打扰人。
4. **不做隐藏状态。** 每条命令尽量无状态、可重放；需要环境就用显式初始化片段，不靠持久 shell。

---

## 一、身份与策略：准入 + 回滚

### 1.1 用户维护的准入面

现状已经基本正确：凭据文件决定「哪台机器、什么账号、能不能提权」，热加载，AI 不读不写。建议只补两个字段，不再加命令级策略：

| 字段 | 作用 | 理由 |
|---|---|---|
| `disabled: true` | 临时停用一台主机 | 吊销权限不用删凭据，改完即生效 |
| `critical: true` | 这台永远查 killlist | 把 `policy.json` 的 `guarded_hosts` 并回一个文件，少一处双写 |
| `xfer: false`（可选） | 这台只能执行、不能传文件 | 生产库这类主机常需要 |

`elevate` 保持现状：按主机开总开关、按命令显式 `elevate=true`，审计能看到 `ran_as=root`。不做默认提权，否则审计里分不清哪些命令是 root 跑的。

不建议加：命令白名单、角色、审批、配额。MCP 形态下没人逐条看，判定只会拖慢；而且命令过滤挡不住蓄意绕行。有时候必须让 AI 拿到更高权限来维持效率，这是有意的取舍。

### 1.2 killlist 升级为「不可逆动作清单」

当前 25 条存在几个盲区：

- `systemctl reboot` / `systemctl poweroff` 不会命中 `reboot` 条目 —— 规则要求程序在**段首**，这里程序是 `systemctl`，`reboot` 只是参数。
- `telinit 0/6`、`init 0/6` 不在清单。
- `.bashrc`、`.ssh/rc`、`/etc/profile.d` 不在 8 条敏感写目标里（`ssh_guard.py` 的 `SENSITIVE_WRITE_TARGETS`）。
- 数据删除（`rm -rf /data/foo`）不在清单 —— 这也不应该靠清单解决，得靠备份/快照。

建议按五类补，而不是继续加单词：

| 类别 | 补什么 |
|---|---|
| 电源/启动 | `systemctl` + `reboot`/`poweroff`/`halt`/`kexec`、`telinit 0/6`、`init 0/6`、`shutdown -r/-h` |
| 磁盘 | `mkfs.*`、`wipefs`、`parted`/`sgdisk` 破坏性用法、`dd of=/dev/*`、`lvremove`/`vgremove`/`pvremove`、`mdadm --zero-superblock`、`cryptsetup luksFormat`、`zpool destroy`/`zfs destroy` |
| 登录 | `sshd_config`、`authorized_keys`、`sudoers`、`shadow`、`fstab`、`grub`、`initramfs`、`iptables -F`/`nft flush`/`ufw disable`、禁用 sshd、`userdel` 登录账号 |
| 数据 | 数据根目录的 `rm -rf`、`find -delete`、`shred`、数据库 `DROP`/`FLUSHALL`、`docker system prune --volumes`、`kubectl delete pvc/namespace` |
| 虚拟化 | `virsh undefine --remove-all-storage` |

匹配方式用多 token 组合（现有规则支持「程序在段首、其余 token 任意位置」），例如 `systemctl` + `reboot|poweroff|halt|kexec`、`dd` + `of=/dev/`，比加一堆单词准。

**2026-11-09 已实现**：清单 25→72 条，覆盖上述五类；`exec`/`put_file` 的 `force_reason` 已写入审计；`rm`/`cp`/`mv`/`install`/`ln`/`sed`/`truncate` 就地改写敏感文件也纳入了检查。

**边界**：清单不可能穷尽，它挡的是「手滑 + 高后果」，不是「蓄意」。`force=true` 仍然一步过，保持效率。

### 1.3 比清单更有效的是「可回滚设施」

1. **敏感文件写前自动备份**：`put_file` 覆盖敏感路径、exec 的重定向/tee 命中敏感目标时，先 `cp -a` 到 `~/.sshmcp-backups/<时间戳>/`，备份失败就拒绝执行；返回值带 `backup` 路径并写审计。
2. **`force` 带 `force_reason`**：不弹审批、不加往返，只要求越过清单时留一句为什么。审计摘要里能直接看到「谁在什么时候、为什么强制删了 `authorized_keys`」。
3. **审计只推异常**：`audit_tail(only_risky=true)` 只回 blocked / forced / 失败 / 敏感写。用户很难审计全量日志，就只让这 1% 浮出来。
4. 数据删除类的回滚靠主机快照/备份，不靠清单；如果某几台有保护目录，可以在凭据里加 `protected_paths`，命中才要求 `force`。

---

## 二、持久 shell：不做

| 需求 | 持久 shell 能做吗 | 现有替代 | 结论 |
|---|---|---|---|
| conda/venv、环境变量 | 能 | 每条命令 `source`，或加 `shell_init`/`login_shell` | 不需要 |
| cwd 保持 | 能 | 服务端 cwd 记忆 + 显式 `cwd` | 不需要 |
| `top`/`vim`/`less` 等 TTY 程序 | 能 | AI 用 `ps`/`journalctl`/非交互参数；人用真终端 | 不需要 |
| `sudo -i`/`su` | 能，但危险 | `exec(elevate=true)` 单条提权 | 不要 |
| 长任务 | 能 | `detach` + job | 不需要 |
| 连续调试手感 | 能 | 人用 ssh/mosh/tmux | 不需要 |

它对回滚的伤害，不只是「命令做错了」，而是**这个能力本身是一扇单向门**：

1. **特权状态会隐身**：`sudo -i` 或 `su` 之后，后续每条命令都以 root 跑，但审计里没有 `elevate=true`。事后看日志，无法区分「这条是 qy 跑的」还是「root 跑的」。
2. **状态不可重放**：环境变量、别名、函数、cwd、后台作业都留在那个 shell 里；拿审计在一台新机器上重放，结果不会一样。
3. **清理边界不清**：shell 里起的后台进程会跟着会话走，杀 shell 可能连带杀掉无关工作，也可能留下孤儿。
4. **输出归属不可靠**：提示符、ANSI 转义、交错输出会让「这条命令的退出码」和「这段输出属于谁」变得模糊。
5. **交互提示会挂住**：口令错时 sudo 回头重试、挂到 idle 超时的老问题会在持久 shell 里重新出现。
6. **回滚只能杀会话**：shell 状态没有「撤销」，只能整条杀掉。

结论：**不加 PTY、不加持久 shell**。真要解决环境初始化，加两个低成本选项：

- `exec(login_shell=true)`：用 `bash -lc` 跑，读 profile；
- 凭据里 `shell_init`：每条命令前 source 一段固定片段（如 conda 激活），可审计、可复现。

每条命令多几毫秒启动，换来「命令之间没有隐藏状态」，这个交换是赚的。人需要交互调试时，用真终端，不要把 MCP 做成半个终端。

---

## 三、数据与批量 + 并发控制

### 3.1 数据与批量

- 给 `put_file`/`get_file` 加 `recursive=true`，不新增工具；逐文件续传、保留 mode、默认跳过 symlink、空目录也建；不做 `rsync --delete` 式同步（那是真正的不可逆）。
- 递归传输有两个安全点必须一起做：**每一层目标文件都要过 `check_write_target`**（不能只查根目录），远端 symlink 先 `lstat` 再决定，防止通过软链写到 `authorized_keys`。
- 批量执行暂不加 `exec_many`。MCP 客户端本身可以并行发多个 `exec`，先把并发正确性修好；以后真需要，再按 `purpose` 标签批量。

### 3.2 并发控制

读代码确认的现状（2026-11-09）：

- `Pool._locks` 只定义、从未调用。
- `Pool.client()` 是 check-then-create 无锁：并发首连会建两条连接，后写覆盖前者，前一条泄漏。
- `run_command` 失败时直接 `POOL.close(alias)`，会把别人正在用的连接一起关掉；`session_reset` 同样能掐断在途命令。
- `OS.prune` 在每次 exec 里跑，无锁且 `f.stat()` 没有容错；两个并发 exec 同时清理，可能抛 `FileNotFoundError`，把一次正常执行打失败。
- cwd 的读-改-写无锁；并发 `cd` 与 `exec` 会串味（最后写入者赢）。
- 同一远端路径并发 `put` 会复用同一个 part 名，续传点互相踩。

修复方向：

1. `Pool._guard` 保护连接表/cwd 表；`client()` 的建连与 `close()` 走 per-host 生命周期锁；
2. 每台主机一个活跃调用计数：`session_reset` 在有人用时不强杀，返回 `busy`；失败不再直接关共享连接；
3. per-target 传输锁（`host + remote path`），同路径串行；
4. `prune` 串行化，并给 `stat`/`unlink` 加容错；
5. cwd 语义写清：并发调用请显式传 `cwd`；单独 `cd` 只保证「改记忆」这一步原子，不保证两条并发命令的先后。

**2026-11-09 已实现**：`Pool` 的建连/关闭/重置加锁、活跃计数、`run_command` 失败不再关共享连接、`session_reset` 在途返回 busy、传输同目标条带锁、`prune` 串行化与 stat/unlink 容错。并发上限（每台最多几条 channel）本次未做，`sshd` 的 `MaxSessions` 是天然上限，等有实际压力再加。

---

## 四、下一步顺序

| 优先级 | 做什么 | 理由 |
|---|---|---|
| **P0** | 并发控制 | 唯一现在就会导致「执行结果错 / 连接被误杀 / prune 报错」的问题，先修正确性 |
| **P0** | killlist 补五类 + `force` 带 `reason` | 成本低，直接提高不可逆动作的拦截面和可追溯性 |
| **P1** | 敏感写前自动备份 + `audit_tail(only_risky=true)` | 让「回滚」和「审计」真正可用，而不是靠人翻日志 |
| **P1** | `login_shell` / `shell_init` | 替代持久 shell，解决环境初始化 |
| **P1** | 目录传输 `recursive=true`（含逐文件清单校验） | 数据与批量，等前三项稳定后做 |
| **P2** | `critical`/`disabled`/`xfer` 字段、`protected_paths`、批量 exec、快照钩子 | 按实际需要再加 |

明确不做：PTY/持久 shell、命令白名单/审批/配额、`rsync --delete` 式同步。

这个顺序把「正确性」放在「能力」前面：并发是现在就会出错的，清单和备份是回滚的底座，目录传输是增量。
