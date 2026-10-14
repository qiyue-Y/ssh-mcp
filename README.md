# ssh-mcp

常驻 SSH 会话的 MCP 服务。替代 `E:\Ilovestudy\env\passkey\ssh-key.ps1` —— 2026-09-28 起用户已规定**所有 SSH 一律走本服务**，那个脚本退为应急与手工使用。

已知未修的问题与边界集中在 **`ISSUES.md`**（追加式，供未参与原会话的 Agent 接手）；排查出缺陷时先往那里记一条，再来改代码。

可改可不改的**优化建议**记在 **`SUGGESTION.md`**，和 `ISSUES.md` 分开：前者现在不咬人、只是能更好，后者是实测到的缺陷与边界。Agent 发现建议只能先口头提议，**经用户同意才写入**，没点头不改代码。

## 2026-09-29：权限控制已解除

原来那套「ro 白名单 / rw 黑名单 / 人工 grant」三层判定整条移除。理由（用户判定）：命令过滤挡不住蓄意绕行的 AI，却给每一条正常命令都加了一轮往返和一个假红点 —— 效率代价全额支付，安全收益接近零。

服务现在只做三件事：**保持 SSH 连接**、**返回日志**、**注入密码**。

唯一保留的拦截是一张 25 条的**自杀清单**（`policy.json` 的 `killlist`）：**`username == "root"` 的主机恒查**，非 root 主机要在 `policy.json` 的 `guarded_hosts` 里点名才查。命中后 `exec(force=true)` 一步就过。它的定位是「挡手滑的 AI」，不是「挡蓄意的 AI」：毁盘、把 ssh 关掉、把自己锁在门外这三类形态。

`ssh_policy.py`(566 行) → `ssh_guard.py`(~315 行)。删掉的 300 行全是反绕过机制（包装器剥壳、`sh -c` 递归复检、curl/wget 专项、解释器特判）。`grants.json`、CLI `grant`/`revoke`、Windows 原生确认框一并移除。

## 它解决什么

| 之前（plink -batch） | 现在 |
|---|---|
| 每条命令重新握手认证 | 连接池 + keepalive，复用同一 transport |
| 密码出现在本机进程命令行（`-pw`） | 密码只在服务进程内存里 |
| 输出大到看不下，Agent 只能猜 | 全文落本机 `output/`，`read_output` 按行号回捞 |
| 无留痕 | 每条命令落 JSONL 审计，force 越过清单也记一笔 |
| 新主机要在两个文件各点一次头 | 可连 = 凭据文件里有这条（`policy.json` 不再列主机） |

## 装

```powershell
# 自检（配置、凭据、指纹、依赖、审计与日志目录可写）
uv run --quiet E:\Ilovestudy\MyWork\mcp\ssh-mcp\ssh_mcp.py doctor
```

清单判定的离线用例（裸 python 即可，不需要 paramiko；21 例，含等价写法与「设计上不再防」的形态）：

```powershell
python test_ssh_guard.py
```

全文日志与回捞的离线用例（同样裸 python，不碰网络；24 例）：

```powershell
python test_output_store.py
```

前置检查、指纹固定与执行接线的用例要真导入 paramiko，必须用 `uv run`，且**不能写成 `uv run python xxx.py`** —— 那种写法不读文件头的 PEP 723 deps，会拿到本机 site-packages 里缺 `cryptography` 的 paramiko 而报 ModuleNotFoundError：

```powershell
uv run --quiet test_connect_refusals.py
```

stdio 冒烟（拉起服务、走 initialize / tools/list / list_hosts，并检查返回值不含密钥字段）：

```powershell
uv run --quiet smoke_stdio.py
```

## 配

1. `copy ssh_mcp_hosts.example.json ssh_mcp_hosts.json`，填真实凭据。**这个文件我不读不写**，是红线。
   可用字段：`address` `port` `username` `auth`（`password`/`key`）`password` `key_path` `hostKey` `purpose`，外加提权三项 `elevate` `elevate_user` `elevate_password`（见「提权」节）。
   旧字段 `rw_allowed` 已从模型里删掉；凭据文件里残留它会被静默忽略，不用你去清理（有用例钉着这个兼容行为）。
   `auth: "key"` 时 `key_path` 可省略，缺省按 `~/.ssh/{id_ed25519,id_rsa,id_ecdsa,id_dsa}` 顺序找。**带 passphrase 的文件私钥不支持**，此时改为问 ssh-agent 并取它的第一把 key（只取一把：逐把试认证会连着打远端的失败次数）。Windows 的 `ssh-agent` 服务默认是 Stopped/Disabled，要先 `Set-Service ssh-agent -StartupType Manual` 起服务再 `ssh-add`。
2. `policy.json` 现在只剩三样：`defaults`（超时与输出上限）、`killlist`（25 条自杀清单）、`guarded_hosts`（非 root 主机里哪些也要查清单）。
3. Qoder 里加 MCP（或手工写进 MCP 配置）：

```json
"ssh-mcp": {
  "command": "uv",
  "args": ["run", "--quiet", "E:\\Ilovestudy\\MyWork\\mcp\\ssh-mcp\\ssh_mcp.py"],
  "env": { "SSHMCP_HOME": "E:\\Ilovestudy\\MyWork\\mcp\\ssh-mcp" }
}
```

加完 `/mcp reload`。

## 指纹与 pin_hostkey

`hostKey` 是**唯一还在拦你的东西**，而它拦的不是 AI，是中间人 —— 探测阶段不发送用户名与密码，所以密码永远不会交给一台没验证过的机器。未钉指纹的主机一律拒连。

新主机不必再去手抄指纹了：`pin_hostkey(host)` 探测实际指纹（只做到密钥交换），落盘要显式 `trust=true`，写进本机 `hostkeys.json`。约定流程是 **探测 → 把 `pinned` 与 `fingerprint` 两个值并报给用户 → 用户核对 → 再带 `trust=true` 调用**。

两条边界：
- 凭据文件里已钉过 `hostKey` 且与实际不符 → 工具**拒绝覆盖**（返回 `writable: false`），那必须是主机重装或真中间人，由人自己改凭据文件。
- `hostkeys.json` 只给凭据文件没钉的主机兜底；凭据里钉过就以凭据为准（`list_hosts` 的 `pin_source` 会告诉你是哪边）。

## 提权（elevate）

本服务**不开 PTY**，所以 `sudo su`、`sudo -i`、`su -` 这类要交互终端读口令的形态一律失败：

```
$ sudo su
sudo: interactive authentication is required
sudo: A terminal is required to authenticate      # 退出码 1
```

提权走的是**单条命令**形态：`exec(host, command, elevate=true)`，服务端把它包成

```sh
sudo -S -p '' --user root -- sh -c '<原命令，含 cd 前缀>'
```

`-S` 从 stdin 读口令，`-p ''` 把提示置空（否则 `[sudo] password for qy:` 会污染 stderr）。**口令由服务端写进 channel 的 stdin**，所以它不出现在命令串里 —— 不进远端 `argv`（`ps` 看不到）、不进本机审计、不进远端 shell history。真机硬证据：拿 100 跑 `id -u; id -un`，不提权得 `qy/1000`，提权得 `0/root`；再对审计文件、`output/*.log` 全文、返回值、`list_hosts` 四处搜口令，全部为否。

凭据文件里的三个字段（那文件只有你能写）：

| 字段 | 作用 |
|---|---|
| `elevate: true` | 能力位。没打开时 `elevate=true` 直接返回 `elevate_not_configured` |
| `elevate_password` | **留空即复用登录口令**（`password`）。sudo 校验的本来就是登录用户自己的口令，所以 Ubuntu 这类机器通常什么都不用填 |
| `elevate_user` | 提权目标，默认 `root` |

两条配套行为：

- **提权命令一律查 killlist**，无视主机是否在 `guarded_hosts` 里。命中照样可以 `force=true` 越过，审计记 `rule:"forced"` + `elevated:true`。
- `cd` 的探活也跟着走提权 —— `cd /root` 用主账号验会假失败（实测 `exit_code: 1`，`权限不够`），验不过就不该把 cwd 记进去。

口令错时不会挂死：喂完口令服务端立即 `shutdown_write()`，sudo 重试读到 EOF 就放弃。实测错口令 **2.5s** 返回 `exit_code: 1` + `sudo: Authentication failed`；不关 stdin 时它会阻塞到 idle 超时（实测 21s 才带着假的 `timed_out:"idle"` 回来）。

副作用要清楚：关掉 stdin 意味着**提权命令自己读不到标准输入**（`sh -c 'read x'` 这类会立刻拿到 EOF）。本服务没有交互输入能力，本来也喂不进东西。另外远端得装了 `sudo` 且该用户在 sudoers 里；有 NOPASSWD 时我们多喂的那行口令会落到命令自己的 stdin。

## 拦截边界（Agent 必读）

`exec(host, command, cwd?, idle_timeout?, max_duration?, force?, elevate?)` 对任何命令一律放行，只在**受保护主机**上查下面这三类形态。受保护 = `username == "root"`，或别名被 `policy.json` 的 `guarded_hosts` 点名（非 root 也挡一手手滑，比如跑共享业务的 `66`），或本次调用带 `elevate=true`（一旦落到 root，破坏面和 root 账号同级，不因登录账号是 `qy` 而免检）。没点名的非 root 主机（当前是 `100`）零拦截。

| 类别 | 条目 |
|---|---|
| 毁盘 | `rm` 递归删一级目录（`/`、`/etc`、`/var`…）、`mkfs*`、`wipefs`、`dd of=/dev/`、`fdisk /dev/`、`parted` |
| 断电 | `shutdown` `reboot` `halt` `poweroff` `init 0/6` |
| 锁死自己 | `systemctl stop/disable sshd|ssh`、`systemctl stop firewalld`、`iptables -F/-X`、`nft flush`、`ufw disable`、`userdel` `groupdel` `passwd`、覆写 `authorized_keys`/`sshd_config`/`sudoers`/`fstab`/`shadow`/`passwd` |

判定发生在**发给远端 shell 之前**，所以「看着不像但等价」的写法要自己归一，做三件事：

- **路径归一**：`//`、`/./`、尾部斜杠、`/*` 折叠回规范形态；`rm` 那条按归一后的**路径深度 ≤1** 判，所以 `rm -rf /*` 和 `rm -rf /` 同一命中，而 `rm -rf /tmp/build` 不受影响。
- **权限位等价**：数字 token 按整数值比，`chmod 0777 /` 等于 `chmod 777 /`。
- **引号外的 `;` `|` `&` 补空格再切段**：`uptime;rm -rf /` 是两条命令，不分段就只能看见 `uptime`。`2>&1` / `&>` 里的 `&` 不算分隔符。

命中时返回 `{blocked: true, reason: "killlisted", rule, hint}`，hint 就一句「带 force=true 重发」。执行过的 force 命令在审计里记 `rule: "forced"`。

**设计上不再防的形态**（钉在 `test_ssh_guard.py` 的 `DeliberatelyNotCaught` 里，别当成已防住）：`nohup rm -rf /`、`env FOO=1 reboot`、`timeout 5 mkfs /dev/sda`、`bash -c 'rm -rf /'`、`python -c "os.system('reboot')"`、`$(echo rm) -rf /`、`R=/; rm -rf $R`、`vi /etc/ssh/sshd_config`、`sed -i ... /etc/sudoers`。真边界是远端账号权限。

## 工具

- `list_hosts()` —— 主机、`pin_source`、是否查清单、限额。不含密码。
- `exec(host, command, cwd?, idle_timeout?, max_duration?, force?, elevate?, detach?)` —— 离散命令。`cwd` 由服务端按主机记忆：单发一条 `cd <目录>`（或光一个 `cd` 回 home）验活成功后写入，后续命令自动从该目录开始；`cd X && cmd` 复合形态只影响本条。被拦下时不建立连接。`elevate=true` 以 root 跑这一条（凭据里得先给这台开 `elevate`）。`detach=true` 丢后台跑并立刻返回 `job_id`（见「后台任务」一节）。
- `pin_hostkey(host, trust?)` —— 探测主机指纹；`trust=true` 才写 `hostkeys.json`。
- `put_file(host, local, remote, overwrite?, force?, elevate?, restart?, mode?)` —— 本机 → 远端，分片续传 + md5。
- `get_file(host, remote, local?, overwrite?, elevate?, restart?)` —— 远端 → 本机，落 `defaults.xfer_dir`。
- `xfer_stat(host, remote)` —— 远端 size/mode/uid/mtime，传前判断该不该传（省一次 `ls -l` 文本解析）。
- `job_status(host, job_id, offset?, max_bytes?)` —— 读后台任务的状态与输出增量（`offset_next` 供下次只取新增）。
- `job_kill(host, job_id)` —— 停后台任务：进程组 SIGTERM→5 秒后 SIGKILL，带队里子进程树，杀前核对 `job_is_ours`。
- `job_list(host, limit?)` —— 列最近的后台任务（running/exited/killed/lost），找孤儿用。
- `session_reset(host)` —— 丢连接与 cwd 重来。
- `audit_tail(host?, limit?)` —— 回看最近审计（含被拦的）。
- `read_output(output_id, stream?, mode?, start?, end?, pattern?, limit?)` —— 按 `exec` 返回的 `output_id` 回捞全文。`mode`：`head`/`tail` 按行边界取，`grep` 返回**带行号**的命中（`pattern` 是**子串**匹配，不是正则），`lines` 取 `[start,end]` 行；单次上限 16KB。

**没有** 交互 shell / PTY / 按键透传，这是故意的：netcatty 那套长会话死在 `terminal_execute` 全部挂起上。

## 文件传输

走 SFTP。选型是被实测逼出来的，不是试出来的：

| 路线 | 结论 |
|---|---|
| scp | **出局** —— paramiko 5.0 已删 `SCPClient`（实测 `hasattr(paramiko, "SCPClient")` 为 False），要走得引第三方依赖 |
| `base64` 过 `exec` | 只解决上传；下载方向实测取 100KB 就 `truncated=true`，50MB 膨胀到 6990 万字节压根回不来 |
| `cat > file` 喂 channel stdin（不依赖 sftp-server） | 实测 5 MB/s，比 SFTP 慢 76%，下载方向同样无解 —— **不做这第二条路**，远端没 sftp-server 就明确报错 |
| SFTP | 100 上实测握手 13ms，整文件 `put`/`get` 双向 md5 一致 |

### 分片续传

`put`/`get` 没有 offset 参数（实测签名 `put(localpath, remotepath, callback, confirm)`），续传只能自己用 `sftp.file()` + `seek` 拼。**关键写法实测**（同一个 24MB）：

| 写法 | 吞吐 |
|---|---|
| 整块一次 `write` | 2.8 MB/s |
| 8MB 分片 | 4.0 MB/s |
| 非 pipelined 1MB 分片 | 5.2 MB/s |
| pipelined、只在收尾 flush | 5.9 MB/s |
| **pipelined + 每片 flush** | **10.1 MB/s**（与 `sftp.put` 持平） |

每片 flush 不是代价，是**正确性要求**：pipelined 写是异步入队的，中途抛异常或提前关通道时，已入队的写还会继续落服务端。真机抓到过这一幕 —— 超时中断时 part 是 12MB，下次再看成了 60MB，续传点建立在漂移的状态上。逐片 flush 之后 part 的字节数才是确定的。

续传语义按**片**而不是按字节：part 路径由目标固定（`<目标>.sshmcp-part`，不带随机后缀，这是「下次能接着传」的前提）；恢复时把末尾不足一片的部分截掉，从该片整片重写；片内不连续由最终的整文件 md5 兜底。想丢掉 part 从头传带 `restart=true`。

真机验证（100，60MB 随机数据）：3 秒超时掐断 → part 留 16 片 → 续传 `resumed_from=16777216`、实传 44MB、`md5_local == md5_remote == 原文`、part 消失。下载方向同样（`resumed_from=22020096`，续传 16.9 MB/s）。

### 校验

传完在**两端各算一次整文件 md5**，不符就不 rename、不删 part、返回 `verified: false` 加续传提示。远端 md5 用 `md5sum`（实测 0.12s / 200MB），而不是把文件读回来算 —— 后者按 11 MB/s 要 18s。

### 传输不能成为清单的绕过口

这是文件通道最要紧的一条。`ssh_guard` 只看命令字符串，SFTP 的写不经过它。100 上实测过缺口：

```
exec  echo key >> /home/qy/.ssh/authorized_keys  ->  blocked, rule="deny:写入敏感文件 ..."
SFTP  open(同一路径, "a")                        ->  成功
```

所以 `put_file` 的 `remote` 必须过 `ssh_guard.check_write_target()`（复用同一份 `SENSITIVE_WRITE_TARGETS`，不复制规则），在**受保护主机**上生效（root 恒查 / `guarded_hosts` 点名 / 本次带 `elevate`）。命中返回和 `exec` 同形的 `{blocked, rule, hint}`，`force=true` 可越过。已验证：点名状态下写 `authorized_keys` 被拦；带 `force` 越过清单后仍被覆盖保护挡住，文件尺寸 101→101，一个字节都没写出去。

### 落到 root 独占路径

SFTP 以登录用户身份写 `/root`、`/etc` 实测都是 `Permission denied`，sudo 又给不了 SFTP，所以 `elevate=true` 走两段式：

- 上传：SFTP 到 `~/.sshmcp-xfer/<名>.part` → `exec(elevate)` 跑 `install -m <mode> <part> <目标> && rm part`
- 下载：`exec(elevate)` 把源 `cat` 到 `~/.sshmcp-xfer/<名>.in.part` → SFTP 取回 → 删暂存

暂存**不放 `/tmp`**：100 的 `/tmp` 是 tmpfs（15.2G，机器 30G 内存），按 4GB 上限算，一个临时文件就吃掉 4GB 内存。`~/.sshmcp-xfer` 落在 ext4（实测可用 849G）。

覆盖保护独立于清单：同名文件已存在时默认拒（`remote_exists` / `local_exists`），要覆盖显式 `overwrite=true`。注意普通 `sftp.rename` 在目标已存在时回 `Failure`（100 实测），所以覆盖走 `posix_rename`。

### 本机落盘目录

`get_file` 的默认位置按三级解析，改哪级都是热加载：

1. 环境变量 `SSHMCP_XFER`
2. `policy.json` 的 `defaults.xfer_dir` ← 本机已设为 **`D:\temporaryfile\download`**
3. 都没有 → 系统真实下载目录（Windows 读注册表 `User Shell Folders` 的 `{374DE290-123F-4565-9164-39C4925E467B}`，因为下载目录可能被重定向到别的盘；本机该值是 `C:\Users\qiyue\Downloads`）

预算：`max_transfer_bytes` 4GB、`xfer_chunk_bytes` 1MB、`xfer_timeout_s` 1800。`doctor` 会实测目录可写并对比空闲（`D:` 现余 255.6GB），空闲装不下一个上限文件时会提示。

**远端文件的原文会落到你硬盘**，和 `output/` 一样不脱敏。开发过程中我自己演示过反面教材：提权 `cat /etc/shadow` 之后那行内容整段躺在 `output/*.log` 里，是按 `output_id` 逐个对审计才清干净的。建议判断类需求只读结论（`stat`、`grep -c`），别整读口令/私钥文件。

### 传输的已知边界

1. 依赖远端有 sftp-server（100 实测有）。没有就报错，不做 base64 兜底。
2. 4GB @ 实测 10 MB/s 单向约 7 分钟，1800s 够用；但**跨调用没有 job id**，中断只能靠「用同一组参数再调一次」续传，无法取消别人发起的传输。
3. 只传单文件（v1 明确排除目录批量）；要传目录自己 `exec tar czf` 再传归档。
4. 分片 1MB，续传粒度到不了字节；末尾不足一片一律重传。
5. 66 的传输没验过（真机限定在 100）。它的清单保护由 `guarded_hosts` 点名提供，传输目标检查同样生效。
6. **`st_size` 不可信的两类都已处理**：`/proc` 这类报 0 的伪文件按「长度未知」读到 EOF 取回（不做远端二次读取的 md5 校验——这类文件两次读取可能天然不同）；`/sys` 这类 stat 报 4096 而实际更短的，`bytes`/`chunks` 报**实际落盘量**。FIFO 直接拒（按 EOF 读会挂住等写者）。

**输出默认只回头尾两截。** `exec` 内联是 stdout 头 4KB + 省略标记 + 尾 4KB（stderr 是 1KB/2KB），全文写进本机 `output/<output_id>.{out,err}.log`；`truncated: true` 时返回值里带 `read_full` 提示怎么用 `read_output`。留尾部是重点 —— `make`/`pip`/`apt` 的失败原因就在最后几行，早先「留头弃尾」会把报错整块丢掉。

## 后台任务（detach）

`exec(..., detach=true)` 把命令丢到远端后台跑，立刻返回 `job_id`；配 `job_status` / `job_kill` / `job_list` 使用。**这是绕开「客户端 60 秒调用硬上限」的唯一出路**——实测任何单次 MCP 调用超过约 60 秒必报 `MCP tool invocation did not complete`（8 次报错与审计 intent 的时间差实测 60.4–60.9s），`max_duration` 传多大都没用。

- 状态存**远端** `~/.sshmcp-jobs/<job_id>/`：`cmd` 命令原文、`dir` 工作目录、`out`（stdout+stderr 合并）、`pid`、`started`、`exit`、`killed`。MCP 服务重启、SSH 断连、Agent 换会话都能接着轮询（要点：状态不存服务进程内存）。
- 判活必须过 `job_is_ours`：`/proc/<pid>/cmdline`（无 procfs 退 `ps -o args=`）里有这个 job id 才算 running —— `kill -0` 只证明「有进程占着这个 pid」，防 PID 复用误判/误杀。
- `job_kill` 先对进程组 SIGTERM，5 秒不退再 SIGKILL，另有子进程树兜底（setsid 不可用的主机）；杀前同样过 `job_is_ours`。
- `job_status` 给 `offset` 就只回新增部分（返回 `offset_next` 供下次接着取），不给就回最后 `max_bytes` 字节。输出只在远端 `out` 文件，不占本机 `output/` 配额。
- 保留 7 天（按结束标记的 mtime 判，job-start 时顺手清）+ 并发上限 8，都可改 `policy.json` 的 `defaults.job_retention_days` / `job_max_concurrent`；超限时 `exec(detach=true)` 返回 `too_many_jobs`。
- 审计：起/杀各记一条（`job_started` / `job_killed`，带 job_id）；`job_status` / `job_list` 是纯读，不审计。
- **v1 明确排除**：elevate 的 detach（口令注入与 setsid 的组合没验过，会返回 `elevate_detach_unsupported`）；`out` 合并 stdout/stderr 不分离。
- 脚本一律 POSIX sh、不含顶层 `exit`、不用 heredoc —— 为将来可能的 shell/交互通道留的（片段会被粘进活 shell，`exit` 会直接杀掉会话）。

## 全文日志与轮转

落**本机**不落远端：rw 主机也没必要在人家盘上堆调试垃圾，写远端文件本身还可能踩到只读挂载。

- 单文件上限取 `policy.defaults.max_output_bytes`（现 8MB），超出即停止写入并在 `output.<stream>.overflow` 里标记
- 轮转预算：`7 天` 且 `≤200 个 run` 且 `≤500MB`，任一命中就删整组；每次 `exec` 前顺手清一次（无定时器、无后台线程）
- 以上预算可用环境变量覆盖：`SSHMCP_OUTPUT`（目录）、`SSHMCP_OUTPUT_KEEP_RUNS`、`SSHMCP_OUTPUT_KEEP_BYTES`、`SSHMCP_OUTPUT_KEEP_DAYS`
- **全文是原文落盘，不做脱敏。** 构建日志里可能出现 `--password=`、`Authorization:`、带 token 的镜像源 URL。`output/` 已进 `.gitignore`，但如果你在本机跑了文件同步/分享工具，别让它覆盖这个目录 —— 这是这套设计换来的代价，换掉的收益是「Agent 能拿到结论而不用吞 80KB 日志」。
- 日志目录与审计目录写不了就**拒绝执行**（fail closed），不会静默降级成「只有内存里那份」。

## 超时

- `idle_timeout_s`（默认 30）：**无新输出**才触发。下载有进度条会不断重置，不会被误杀。
- `max_duration_s`（默认 300）：缺省值。**调用方传的 `max_duration` 不再被夹制**，传多大用多大 —— 长构建（`cmake`、`pip install torch`）靠这个跑完，M2 的 `detach` 因此不再紧迫。
- 两种超时各归各的：`wait=min(idle,剩余时长)`，谁定的这一轮就报谁，所以传 `max_duration=1` 会得到 `timed_out: "duration"` 而不是 `idle`（真机实测修过一次误报）。
- 超时只关 channel 不关连接，后续命令照常。
- 超时被打断时，**已经收到的输出仍在 `output/` 里**，可以 `read_output` 捞回来看跑到哪一步了。

## CLI（人在终端敲）

```powershell
uv run --quiet ssh_mcp.py doctor    # 配置/凭据/指纹/依赖/两个目录可写
uv run --quiet ssh_mcp.py list      # 主机、guard 是否生效、pin 来源、当前 cwd
```

`grant`/`revoke` 与 Windows 原生确认框随权限控制一起删掉了。（留着也没意义：实测 Agent 的 Bash 里 `stdin.isatty()` 返回 True，Git Bash 经 conpty 伪装成终端，那道校验本来就拦不住自批。）

## 已知边界

1. **服务端不再做任何权限判断**（除受保护主机的 killlist，而 force=true 一步就过）。同一台机器上「读一眼」和「`rm -rf`」的代价完全相同，唯一的地板是远端账号权限。`66` 原先靠 `rw_allowed: false` 被锁成只读，现在没有那层了 —— 它靠 `guarded_hosts` 点名换来的是「挡手滑」，不是「挡越权」。
2. `hostkeys.json` 与凭据同属当前用户，Agent 用文件工具理论上能直接改它。`pin_hostkey` 的两步（探测 → `trust=true`）靠的是**约定和向用户回报**，不是强制。要硬边界就得把这个文件放到另一个 Windows 用户下，或全部改用非 root 账号。
3. 静态分析有地板，见上面「设计上不再防的形态」。包装器与解释器的反绕过机制是主动删掉的，不是漏了。
4. 引号内的 `>` `<` 已通过掩码排除；但 `grep a>b`（未加引号）里的 `>` 仍会被当成重定向目标去看一眼 —— 只有撞上那张敏感文件名单才拦，日常不会误杀。
5. 密码解密后常驻服务进程内存。长期方案是全量转私钥认证。
6. `username == "root"` 这一条判定分支没有真机证据：唯一配置的 root 主机 `admin`（pve2）在凭据文件里没条目，而真机测试只允许在 100 上跑。**「命中 → 拒且不建连 → force 送到远端 → 审计记 forced」整条链路已在 100 上用 `guarded_hosts` 点名真机验过**（`userdel` 不存在用户返回 exit 6，证明确实执行了），root 分支与非 root 点名分支在代码里是同一个 `G.applies` 谓词，只差那半行。要补的是 `admin` 的凭据，不是代码。
7. 原先被错杀的只读用法现在都能跑了：裸 `mount`（只是打印挂载表）、`fdisk -l`、`docker system prune -af`、`kubectl delete`、`crontab -r`、`history -c`、`sudo`。
