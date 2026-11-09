# ssh-mcp

常驻 SSH 会话的 MCP 服务。替代 `E:\Ilovestudy\env\passkey\ssh-key.ps1` —— 2026-09-28 起用户已规定**所有 SSH 一律走本服务**，那个脚本退为应急与手工使用。

已知未修的问题与边界集中在 **`ISSUES.md`**（追加式，供未参与原会话的 Agent 接手）；排查出缺陷时先往那里记一条，再来改代码。

可改可不改的**优化建议**记在 **`SUGGESTION.md`**，和 `ISSUES.md` 分开：前者现在不咬人、只是能更好，后者是实测到的缺陷与边界。Agent 发现建议只能先口头提议，**经用户同意才写入**，没点头不改代码。

## 2026-09-29：权限控制已解除

原来那套「ro 白名单 / rw 黑名单 / 人工 grant」三层判定整条移除。理由（用户判定）：命令过滤挡不住蓄意绕行的 AI，却给每一条正常命令都加了一轮往返和一个假红点 —— 效率代价全额支付，安全收益接近零。

服务现在只做三件事：**保持 SSH 连接**、**返回日志**、**注入密码**。

唯一保留的拦截是一张 72 条的**不可逆动作清单**（`policy.json` 的 `killlist`）：**`username == "root"` 的主机恒查**，非 root 主机要在 `policy.json` 的 `guarded_hosts` 里点名才查。命中后 `exec(force=true)` 一步就过，可用 `force_reason` 留一句为什么。它的定位是「挡手滑的 AI」，不是「挡蓄意的 AI」：毁盘、关机/断电、删数据、把 ssh 关掉、把自己锁在门外这五类形态。

`ssh_policy.py`(566 行) → `ssh_guard.py`(~390 行)。删掉的 300 行全是反绕过机制（包装器剥壳、`sh -c` 递归复检、curl/wget 专项、解释器特判）。`grants.json`、CLI `grant`/`revoke`、Windows 原生确认框一并移除。

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

清单判定的离线用例（裸 python 即可，不需要 paramiko；含等价写法与「设计上不再防」的形态）：

```powershell
python test_ssh_guard.py
```

主机清单读写的离线用例（原子写、备份轮转、字段校验、保留注释键、扫描导入）：

```powershell
python test_hostreg.py
```

全文日志与回捞的离线用例（同样裸 python，不碰网络；24 例）：

```powershell
python test_output_store.py
```

审计留痕的离线用例（call/result/error、轮转、14 天保留、output_id→host；11 例）：

```powershell
python test_audit.py
```

前置检查、指纹固定、执行接线与并发用例要真导入 paramiko，必须用 `uv run`，且**不能写成 `uv run python xxx.py`** —— 那种写法不读文件头的 PEP 723 deps，会拿到本机 site-packages 里缺 `cryptography` 的 paramiko 而报 ModuleNotFoundError：

```powershell
uv run --quiet test_connect_refusals.py
```

stdio 冒烟（拉起服务、走 initialize / tools/list / list_hosts，并检查返回值不含密钥字段）：

```powershell
uv run --quiet smoke_stdio.py
```

## 配

1. `copy ssh_mcp_hosts.example.json ssh_mcp_hosts.json`，填真实凭据；或者直接用界面维护：`uv run hosts_gui.py`。**这个文件我不读不写**，是红线。
   可用字段：`address` `port` `username` `auth`（`password`/`key`）`password` `key_path` `hostKey` `purpose`，提权三项 `elevate` `elevate_user` `elevate_password`（见「提权」节），环境初始化字段 `shell_init`（见「环境初始化」节），以及能力位 `disabled` `critical` `xfer`（见下一条）。
   旧字段 `rw_allowed` 已从模型里删掉；凭据文件里残留它会被静默忽略，不用你去清理（有用例钉着这个兼容行为）。
   `auth: "key"` 时 `key_path` 可省略，缺省按 `~/.ssh/{id_ed25519,id_rsa,id_ecdsa,id_dsa}` 顺序找。**带 passphrase 的文件私钥不支持**，此时改为问 ssh-agent 并取它的第一把 key（只取一把：逐把试认证会连着打远端的失败次数）。Windows 的 `ssh-agent` 服务默认是 Stopped/Disabled，要先 `Set-Service ssh-agent -StartupType Manual` 起服务再 `ssh-add`。
2. `policy.json` 现在只剩三样：`defaults`（超时、输出上限与传输预算）、`killlist`（72 条不可逆动作清单）、`guarded_hosts`（非 root 主机里哪些也要查清单）。
   凭据里每台还能带三个能力位（都由你自己维护，界面里是复选框）：

   | 字段 | 作用 |
   |---|---|
   | `disabled: true` | 临时停用这台：所有工具在**建立连接前**就拒（`reason: host_disabled`），不用删条目 |
   | `critical: true` | 这台**永远查 killlist**，等价于把别名写进 `guarded_hosts`（`list_hosts` 显示 `guard_reason: "critical 标记"`） |
   | `xfer: false` | 只执行、**禁止传文件**：`put_file`/`get_file` 直接拒（`reason: xfer_disabled`）；`xfer_stat` 只读元数据仍可用 |

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

## 主机配置界面（hosts_gui.py）

```powershell
uv run hosts_gui.py
```

tkinter 窗口，专门维护主机清单——**不经过 MCP，AI 碰不到**（凭据文件仍然只有你能改）：

- 左侧列表 + 右侧表单，增 / 改 / 复制 / 删除 / 停用主机；保存前自动备份 `<文件名>.bak-<时间戳>`（留最近 10 份），写入是原子的（临时文件 + `os.replace`），正在跑的服务不会读到半截 JSON。
- **密码框留空＝沿用原口令**，打开时不回填明文；只有填了才覆盖。
- **探测指纹**：只做密钥交换、不发送任何凭据，显示出指纹让你核对，确认后填入 `hostKey`，点保存才落盘。与已钉指纹不符时拒绝覆盖。
- **测试连接**：只跑固定探针（`/etc/os-release` 前两行 + `uname -m`），不是第二个终端。
- **从 known_hosts / ssh config 导入**：列出本机 ssh 过的主机，勾选后并入，已在清单里的地址自动排除。
- 能力位复选框：`disabled`（停用）、`critical`（恒查清单）、`xfer`（允许传文件）、`elevate`（允许提权）。

界面逻辑都下沉在 `hostreg.py`（纯 stdlib、可离线测）；窗口只做绑定。无界面环境仍可用命令行：

```powershell
uv run gen_hosts.py            # 只列出候选，不写文件
uv run gen_hosts.py --merge    # 把可导入的候选并入清单（先备份）
```

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

三条配套行为：

- **提权命令一律查 killlist**，无视主机是否在 `guarded_hosts` 里。命中照样可以 `force=true` 越过，审计记 `rule:"forced"` + `elevated:true`。
- `cd` 的探活也跟着走提权 —— `cd /root` 用主账号验会假失败（实测 `exit_code: 1`，`权限不够`），验不过就不该把 cwd 记进去。
- `auth`（登录认证方式）与 `elevate_password_from`（提权口令来源）是**两个独立字段**：主机改成仅密钥登录后 `auth` 变 `"key"`，而 `elevate_password_from` 仍可以是 `"password"` —— 口令只喂给 `sudo -S` 的 channel stdin，与怎么登录无关（100 实测：key 登录下提权照常 `ran_as: root`）。

口令错时不会挂死：喂完口令服务端立即 `shutdown_write()`，sudo 重试读到 EOF 就放弃。实测错口令 **2.5s** 返回 `exit_code: 1` + `sudo: Authentication failed`；不关 stdin 时它会阻塞到 idle 超时（实测 21s 才带着假的 `timed_out:"idle"` 回来）。

副作用要清楚：关掉 stdin 意味着**提权命令自己读不到标准输入**（`sh -c 'read x'` 这类会立刻拿到 EOF）。本服务没有交互输入能力，本来也喂不进东西。另外远端得装了 `sudo` 且该用户在 sudoers 里；有 NOPASSWD 时我们多喂的那行口令会落到命令自己的 stdin。

## 拦截边界（Agent 必读）

`exec(host, command, cwd?, idle_timeout?, max_duration?, force?, elevate?, detach?, force_reason?, login_shell?)` 对任何命令一律放行，只在**受保护主机**上查下面这五类形态。受保护 = `username == "root"`，或凭据里标了 `critical: true`，或别名被 `policy.json` 的 `guarded_hosts` 点名（非 root 也挡一手手滑，比如跑共享业务的 `66`），或本次调用带 `elevate=true`（一旦落到 root，破坏面和 root 账号同级，不因登录账号是 `qy` 而免检）。没点名的非 root 主机（当前是 `100`）零拦截。

| 类别 | 条目 |
|---|---|
| 毁盘 | `rm` 递归删一级目录（`/`、`/etc`、`/var`…）、`mkfs*`、`wipefs`、`dd of=/dev/`、`fdisk /dev/`、`parted`、`sgdisk` 破坏性子命令、`blkdiscard`、`lvremove`/`vgremove`/`pvremove`、`mdadm --zero-superblock/--create`、`cryptsetup luksFormat/luksErase/erase`、`zpool destroy`/`zfs destroy`、`btrfs subvolume delete` |
| 断电 | `shutdown` `reboot` `halt` `poweroff` `init 0/6` `telinit 0/6` `systemctl reboot/poweroff/halt/kexec/soft-reboot` |
| 锁死自己 | `systemctl stop/disable/mask sshd|ssh`、`systemctl stop/disable networking`、`systemctl stop firewalld`、`iptables -F/-X/-P … DROP`、`nft flush`、`ufw disable`、`userdel` `groupdel` `passwd` `chpasswd` `usermod -L`、覆写 `authorized_keys`/`sshd_config`/`sudoers`/`fstab`/`shadow`/`passwd` |
| 删数据/资源 | `find -delete`、`shred`、`truncate /dev/`、`dropdb`、`mysqladmin drop`、`redis-cli flushall/flushdb`、`docker system prune`、`docker volume prune/rm`、`kubectl delete pvc/namespace/ns`、`virsh undefine --remove-all-storage`、`virsh vol-delete` |
| 就地改敏感文件 | `rm`/`cp`/`mv`/`install`/`ln`/`sed`/`truncate` 的操作数命中 `authorized_keys`/`sshd_config`/`sudoers`/`fstab`/`shadow`/`passwd` |

判定发生在**发给远端 shell 之前**，所以「看着不像但等价」的写法要自己归一，做三件事：

- **路径归一**：`//`、`/./`、尾部斜杠、`/*` 折叠回规范形态；`rm` 那条按归一后的**路径深度 ≤1** 判，所以 `rm -rf /*` 和 `rm -rf /` 同一命中，而 `rm -rf /tmp/build` 不受影响。
- **权限位等价**：数字 token 按整数值比，`chmod 0777 /` 等于 `chmod 777 /`。
- **引号外的 `;` `|` `&` 补空格再切段**：`uptime;rm -rf /` 是两条命令，不分段就只能看见 `uptime`。`2>&1` / `&>` 里的 `&` 不算分隔符。

命中时返回 `{blocked: true, reason: "killlisted", rule, hint}`，hint 会说明带 `force=true` + `force_reason` 重发。执行过的 force 命令在审计里记 `rule: "forced"` 和 `force_reason`（最多 500 字）。

**设计上不再防的形态**（钉在 `test_ssh_guard.py` 的 `DeliberatelyNotCaught` 里，别当成已防住）：`nohup rm -rf /`、`env FOO=1 reboot`、`timeout 5 mkfs /dev/sda`、`bash -c 'rm -rf /'`、`python -c "os.system('reboot')"`、`$(echo rm) -rf /`、`R=/; rm -rf $R`、`vi /etc/ssh/sshd_config`、`chmod 000 /etc/ssh/sshd_config`、`sudo rm -rf /`。真边界是远端账号权限。

## 工具

- `list_hosts(brief?)` —— 主机、`pin_source`、是否查清单、限额。`brief=true` 只回短字段（不带每台的 limits 与全量 killlist），省上下文。不含密码。
- `exec(host, command, cwd?, idle_timeout?, max_duration?, force?, elevate?, detach?, force_reason?, login_shell?)` —— 离散命令。`cwd` 由服务端按主机记忆：单发一条 `cd <目录>`（或光一个 `cd` 回 home）验活成功后写入，后续命令自动从该目录开始；`cd X && cmd` 复合形态只影响本条。被拦下时不建立连接。`elevate=true` 以 root 跑这一条（凭据里得先给这台开 `elevate`）。`detach=true` 丢后台跑并立刻返回 `job_id`（见「后台任务」一节）。`force_reason` 是 `force=true` 时写进审计的一句原因。`login_shell=true` 用 `bash -lc` 跑这一条（见「环境初始化」）。
- `pin_hostkey(host, trust?)` —— 探测主机指纹；`trust=true` 才写 `hostkeys.json`。
- `put_file(host, local, remote, overwrite?, force?, elevate?, restart?, mode?, force_reason?, recursive?)` —— 本机 → 远端，分片续传 + md5。`recursive=true` 传整棵目录（见「目录传输」）。
- `get_file(host, remote, local?, overwrite?, elevate?, restart?, recursive?)` —— 远端 → 本机，落 `defaults.xfer_dir`。`recursive=true` 拉整棵目录。
- `xfer_stat(host, remote)` —— 远端 size/mode/uid/mtime，传前判断该不该传（省一次 `ls -l` 文本解析）。
- `job_status(host, job_id, offset?, max_bytes?)` —— 读后台任务的状态与输出增量（`offset_next` 供下次只取新增）。
- `job_kill(host, job_id)` —— 停后台任务：进程组 SIGTERM→5 秒后 SIGKILL，带队里子进程树，杀前核对 `job_is_ours`。
- `job_list(host, limit?)` —— 列最近的后台任务（running/exited/killed/lost），找孤儿用。
- `session_reset(host)` —— 丢连接与 cwd 重来。若有命令在途则返回 `{reset:false, reason:"active_commands", active:N}`，不强杀在途命令。
- `audit_tail(host?, limit?, only_risky?)` —— 回看最近审计（含被拦的）。所有工具调用都留 `call`/`result` 记录，可用 `call_id` 串联。`only_risky=true` 只回被拦、强制越过、失败、异常与敏感写备份，正常成功的命令不出现。
- `read_output(output_id, stream?, mode?, start?, end?, pattern?, limit?)` —— 按 `exec` 返回的 `output_id` 回捞全文。`mode`：`head`/`tail` 按行边界取，`grep` 返回**带行号**的命中（`pattern` 是**子串**匹配，不是正则），`lines` 取 `[start,end]` 行；单次上限 16KB。

**没有** 交互 shell / PTY / 按键透传，这是故意的：netcatty 那套长会话死在 `terminal_execute` 全部挂起上。

**并发**：同一台主机的首次连接只建一条；命令可以并行执行。`cwd` 是 per-host 的共享记忆，并发时最后写入者赢 —— 要确定性就显式传 `cwd=`。同一传输目标会串行（防止两个调用复用同一个 part），不同目标并行。`session_reset` 遇到在途命令会返回 busy，不强杀。

## 敏感文件写前备份

改 `authorized_keys`、`sshd_config`、`sudoers`、`fstab`、`shadow`、`passwd` 这类文件前，服务端先把现有内容备份到远端 `~/.sshmcp-backups/<时间戳>-<短id>/`，文件名带序号前缀（`00-authorized_keys`）。

- 覆盖对象是**这条命令会写到的文件**：写重定向、`tee`、`rm`/`cp`/`mv`/`install`/`ln`/`sed`/`truncate` 的操作数；`put_file` 覆盖已存在的敏感目标也走同一条路。
- **备份失败就不执行**：返回 `{blocked:true, reason:"backup_failed"}`，原文件保持不动。目标文件本来不存在不算失败（没有旧内容可备）。
- 返回值带 `backup` 路径，审计记 `event:"backup"`（成功）或 `backup_failed`（失败），可用来恢复：`cp -a ~/.sshmcp-backups/<目录>/00-authorized_keys /root/.ssh/authorized_keys`。
- 备份目录不会自动清理（它不是调试垃圾，而是回滚依据）；空间不够时自己删旧目录。

## 环境初始化（login_shell / shell_init）

本服务**不开持久 shell**（原因见 `DESIGN.md`：隐藏状态不可重放、特权状态会隐身、回滚只能杀会话）。需要"先激活环境再跑命令"时，用这两个显式开关，不要把 MCP 做成半个终端：

| 形态 | 用法 | 适用 |
|---|---|---|
| 登录 shell | `exec(host, "python -V", login_shell=true)` | 需要 profile 里的 PATH / 环境变量；会在命令外包一层 `bash -lc` |
| 固定初始化片段 | 凭据里写 `"shell_init": "~/miniconda3/etc/profile.d/conda.sh"` | conda / venv / 自定义 PATH，每条 exec 都先 source 它 |

- `shell_init` 只在**用户命令**前生效；备份、md5、job 脚本这类内部命令不 source，避免初始化输出污染判断。
- 初始化片段失败时命令不执行，返回 `exit_code: 97` 且 stderr 有 `[sshmcp] shell_init 失败`，不会和用户命令的退出码混在一起。
- 顺序是 `cd <cwd>` → `source <shell_init>` → 你的命令；`login_shell` 再整体套 `bash -lc`。
- 两者都不改变"每条命令独立"的语义：没有隐藏状态，审计可以原样重放。

```json
"example-conda": {
  "address": "10.0.0.16",
  "username": "deploy",
  "password": "<填口令>",
  "hostKey": "SHA256:<服务器指纹>",
  "shell_init": "/opt/miniconda3/etc/profile.d/conda.sh",
  "purpose": "每条命令前 source conda，省得调用方自己拼 source &&"
}
```

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

（上表是早期 24MB 环境的相对比较；2026-10-14 的 256MiB 同场复测见「单条请求尺寸」一节，条件与数字都不同，别混用。）

每片 flush 不是代价，是**正确性要求**：pipelined 写是异步入队的，中途抛异常或提前关通道时，已入队的写还会继续落服务端。真机抓到过这一幕 —— 超时中断时 part 是 12MB，下次再看成了 60MB，续传点建立在漂移的状态上。逐片 flush 之后 part 的字节数才是确定的。

续传语义按**片**而不是按字节：part 路径由目标固定（`<目标>.sshmcp-part`，不带随机后缀，这是「下次能接着传」的前提）；恢复时把末尾不足一片的部分截掉，从该片整片重写；片内不连续由最终的整文件 md5 兜底。想丢掉 part 从头传带 `restart=true`。

真机验证（100，60MB 随机数据）：3 秒超时掐断 → part 留 16 片 → 续传 `resumed_from=16777216`、实传 44MB、`md5_local == md5_remote == 原文`、part 消失。下载方向同样（`resumed_from=22020096`，续传 16.9 MB/s）。

### 单条请求尺寸

paramiko 默认把数据切成 32KB 的 SFTP 请求（`SFTPFile.MAX_REQUEST_SIZE`）。`ssh_xfer.py` 在打开的句柄上实例级放大到 **128KB**（`REQUEST_SIZE`），上传下载两个方向都生效。2026-10-14 同场对照（256MiB → 100:/tmp，服务端 btime→mtime 计时）：

| 对照 | 结果 |
|---|---|
| 128KB 请求 vs 32KB | 16 对同场配对里 15 对更快，中位 +5%（~7.9 → ~8.3 MiB/s）；64KB 与 128KB 无差别 |
| 服务端红线（实测） | 单条 262144B 请求会让 sftp-server 退出、SFTP 通道当场死；255KB 可过——128KB 留余量 |

参照系（同场对照）：拥塞时段 OpenSSH scp ~10.0 MiB/s（`-O` 旧协议 ~10.5）、paramiko ~8，双路并行聚合≈单流；深夜空闲时段 scp 上传可到 ~90 MiB/s，而 paramiko 上传卡在 ~21 MiB/s——链路上限随时段差一个数量级（估时按当时实测），paramiko 另有自己的客户端上限，和请求尺寸无关（32K/64K/128K 空闲时段实测无差）。

### 下载预取

`get_file` 对**全新下载**也调用 `prefetch`（此前只有续传时预取，全新下载走同步逐块读）。2026-10-14 实测（256MiB，同一时段）：全新下载 4.5 → **36.7 MiB/s**（8 倍），快过同场 scp 的下载（~18）。`prefetch` 显式传 `st_size`，避免 paramiko 内部再次 stat（其对着伪文件会挂，见 paramiko #562；`st_size<=0` 的文件不走预取，按读到 EOF 处理）。

### 校验

传完在**两端各算一次整文件 md5**，不符就不 rename、不删 part、返回 `verified: false` 加续传提示。远端 md5 用 `md5sum`（实测 0.12s / 200MB），而不是把文件读回来算 —— 后者按 11 MB/s 要 18s。

### 目录传输（recursive=true）

`put_file(..., recursive=true)` / `get_file(..., recursive=true)` 传整棵目录，不新增工具：

- **逐文件**走上面同一套分片续传 + 两端 md5；中断后重调同一参数，已完成的文件跳过、未完成的从缺口续传。
- 空目录也会建（上传逐个 `mkdir`，下载按远端目录树补建）。
- **符号链接与 FIFO/设备文件一律跳过**：不跟随链接目标（可能是 `/etc`），也不给 FIFO 读内容（会挂住等写者）。返回值里给 `skipped_symlink_count` 与前 20 个名字。
- **每个目标文件都过敏感路径清单**（不只看根目录）：目录里混进 `authorized_keys` 会被单文件拦下，其余照传；`force=true` 才放行。覆盖已存在的敏感文件前同样先备份（与单文件 put 一致），备份路径进 `backups` 列表。
- 默认不覆盖已存在的文件（`overwrite=true` 才覆盖），**不做 `rsync --delete`**：远端多余文件不动，删除永远是显式操作。
- 预算是整次调用的：文件数 ≤ `defaults.xfer_max_files`（默认 2000）、总字节 ≤ `max_transfer_bytes`、总时长 ≤ `xfer_timeout_s`。任一项超了会在开始前拒（文件数/总量）或中途 `aborted`（时长）。
- v1 与 `elevate` 互斥：目录里逐文件的暂存命名与提权路径会互相干扰，明确拒绝并提示先 `tar`。

真机验证（100，`/tmp`）：含子目录与空目录的树，上传 2 文件 / 3 目录、下载回来两个文件 md5 均与原文一致、空目录按原样重建。

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
- 失联任务（机器重启、进程被 `kill -9` 后不留下退出标记）不会卡住池子：`job_list` 里显示为 `lost`，`job_kill` 对它补写 `killed` 标记完成**回收**（返回 `reaped: true`）——不再占并发名额，7 天后随其它结束任务一起被清。
- 审计：起/杀各记一条（`job_started` / `job_killed`，带 job_id）；`job_status` / `job_list` 也记 `call`/`result` 元数据（任务列表与输出正文不复制进审计）。
- **v1 明确排除**：elevate 的 detach（口令注入与 setsid 的组合没验过，会返回 `elevate_detach_unsupported`）；`out` 合并 stdout/stderr 不分离。
- 脚本一律 POSIX sh、不含顶层 `exit`、不用 heredoc —— 为将来可能的 shell/交互通道留的（片段会被粘进活 shell，`exit` 会直接杀掉会话）。

## 审计与追溯

每个 MCP 工具调用写两条元数据：入口 `call`（工具名、参数、host、`call_id`），出口 `result` 或 `error`（ok、`duration_ms`、结果摘要；异常带类型、消息与调用栈）。工具内部原有的 `intent` / `executed` / `blocked` / `transferred` / `job_started` 等记录会自动带上同一个 `call_id`，一次调用前后的线索可以直接串起来。

- **审计只放元数据和引用**：命令原文、退出码、`output_id`、传输字节数与 md5 进审计；stdout/stderr/文件内容不复制进审计，它们留在 `output/` 与传输目标里，按引用回查。
- 审计文件按天轮转：`audit/ssh-mcp.jsonl` → `audit/ssh-mcp.YYYYMMDD.jsonl`，保留 **14 天**（`SSHMCP_AUDIT_KEEP_DAYS`），路径可用 `SSHMCP_AUDIT` 覆盖。
- `audit_tail(host?, limit?, only_risky?)` 会按时间倒序读当前文件与轮转文件；排障时先按 host/时间找到 `call_id`，再看这次调用的 `call`、工具内部记录与最终 `result`/`error`。正常命令太多时用 `only_risky=true`，只看被拦、强制越过、失败、异常和敏感写备份。
- `read_output` 本身没有 host 参数：服务端用内存里的 `output_id → host` 表补 host；服务重启后表为空时会回扫审计文件里同 `output_id` 的 `executed` 记录，所以按主机过滤也能看到回捞动作。
- 审计写入失败时：`exec` 的 `intent` 仍是 fail closed（写不进就不执行）；包装层的 `call`/`result` 是尽力而为，只往 stderr 报错，不影响只读工具。

## 全文日志与轮转

落**本机**不落远端：rw 主机也没必要在人家盘上堆调试垃圾，写远端文件本身还可能踩到只读挂载。

- 单文件上限取 `policy.defaults.max_output_bytes`（现 8MB），超出即停止写入并在 `output.<stream>.overflow` 里标记
- 轮转预算：`14 天` 且 `≤200 个 run` 且 `≤500MB`，任一命中就删整组；每次 `exec` 前顺手清一次（无定时器、无后台线程）
- 以上预算可用环境变量覆盖：`SSHMCP_OUTPUT`（目录）、`SSHMCP_OUTPUT_KEEP_RUNS`、`SSHMCP_OUTPUT_KEEP_BYTES`、`SSHMCP_OUTPUT_KEEP_DAYS`
- **全文是原文落盘，不做脱敏。** 构建日志里可能出现 `--password=`、`Authorization:`、带 token 的镜像源 URL。`output/` 已进 `.gitignore`，但如果你在本机跑了文件同步/分享工具，别让它覆盖这个目录 —— 这是这套设计换来的代价，换掉的收益是「Agent 能拿到结论而不用吞 80KB 日志」。
- 日志目录与审计目录写不了就**拒绝执行**（fail closed），不会静默降级成「只有内存里那份」。

## 超时

- `idle_timeout_s`（默认 30）：**无新输出**才触发。下载有进度条会不断重置，不会被误杀。
- `max_duration_s`（默认 300）：缺省值。**调用方传的 `max_duration` 不再被夹制**，传多大用多大。注意它管不了单次调用的客户端硬上限（约 60 秒，见「后台任务」）——长构建（`cmake`、`pip install torch`）要等完得走 `exec(detach=true)`。
- 两种超时各归各的：`wait=min(idle,剩余时长)`，谁定的这一轮就报谁，所以传 `max_duration=1` 会得到 `timed_out: "duration"` 而不是 `idle`（真机实测修过一次误报）。
- 超时只关 channel 不关连接，后续命令照常。
- 超时被打断时，**已经收到的输出仍在 `output/` 里**，可以 `read_output` 捞回来看跑到哪一步了。

## 判活（探进程 / 看文件出没）

没有"等进程结束 / 等文件出现"的工具，这类等待要自己写**秒级**短查询（单次调用远小于 60 秒）。规矩别用错——下面两条都是实测踩出来的假阴性：

- **跨用户判活必须带 `elevate=true`**：`kill -0 <root 的 pid>` 用普通账号跑返回 EPERM，rc 与"进程不存在"同为 1，看起来像已经退出（实测据此误判过一次 apt 还在跑）。
- **`pgrep` 别用 `-f` 匹配长模式**：模式串就写在承载它的那条 `bash -c` 命令行里，永远命中自己（实测轮询循环永不退出）。用 `pgrep -x <comm>`（comm 截 15 字符）按进程名取 PID，并把"取 PID"和"kill"分成两条调用——`pkill -f` 加同一行里的裸词 grep 会把自己杀掉，症状是 `exit_code:-1`、零输出。
- **长任务优先 `exec(detach=true)` + `job_status` 轮询**：判活在服务端做（任务状态机 running/exited/killed/lost），不用手写轮询。

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
4. 引号内的 `>` `<` 已通过掩码排除；`grep a>b`（未加引号）里的 `>` 仍会被当成**写**重定向看一眼 —— 只有撞上那张敏感文件名单才拦，日常不会误杀。`<` / `<<` / `<<<` 不算写（读重定向与 heredoc 不落文件，2026-10-14 起不收进写目标——此前 `wc -l < 密钥文件` 这类只读会被误拦）。
5. 密码解密后常驻服务进程内存。长期方案是全量转私钥认证。
6. `username == "root"` 这一条判定分支没有真机证据：唯一配置的 root 主机 `admin`（pve2）在凭据文件里没条目，而真机测试只允许在 100 上跑。**「命中 → 拒且不建连 → force 送到远端 → 审计记 forced」整条链路已在 100 上用 `guarded_hosts` 点名真机验过**（`userdel` 不存在用户返回 exit 6，证明确实执行了），root 分支与非 root 点名分支在代码里是同一个 `G.applies` 谓词，只差那半行。要补的是 `admin` 的凭据，不是代码。
7. 原先被错杀的只读用法现在都能跑了：裸 `mount`（只是打印挂载表）、`fdisk -l`、`docker system prune -af`、`kubectl delete`、`crontab -r`、`history -c`、`sudo`。
