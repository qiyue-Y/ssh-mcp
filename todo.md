# ssh-mcp 优化任务清单

本文件是 `DESIGN.md` 的执行版。每条都写清：现状、目标、范围、验收、风险/回退。完成一项就把「状态」改成「已完成」，并补一句实测证据。

状态标记：`待办` / `进行中` / `已完成` / `暂缓`

---

## P0-1 并发控制

**状态：已完成（2026-11-09）**

**实测证据**
- 离线：`test_connect_refusals.py` 69 例全绿（新增 6 例并发：首连只建一条、死连接替换、失败不关共享连接、在途 reset busy、同目标传输串行、并发 prune 不抛异常）。
- 真机 100：5 条并发 `exec` 全部 `exit_code=0`；`POOL._clients` 始终为 1；5 条 `sleep 2` 墙钟 4.01s（串行会 ≥10s），确认真并行；在途 `session_reset` 返回 `{reset:false, reason:"active_commands", active:1}`；命令结束后 reset 返回 `{reset:true, cwd:"~"}`、连接数为 0。
- 并发上限（每台最多几条 channel）本次未做，按 `DESIGN.md` 留到有实际压力再加。

**现状**
- `Pool._locks` 只定义、从未调用；`Pool.client()` 的 check-then-create 无锁，并发首连会建两条连接并泄漏一条。
- `run_command` 失败时直接 `POOL.close(alias)`，会关掉别的调用正在用的连接；`session_reset` 同样能掐断在途命令。
- `OS.prune` 每次 exec 都跑，无锁且 `f.stat()` 无容错，并发时可能抛 `FileNotFoundError` 把正常执行打失败。
- cwd 的读-改-写无锁，并发 `cd` 与 `exec` 会串味。
- 同一远端路径并发 `put` 会复用同一个 part 名，续传点互相踩。

**目标**
- 连接创建/关闭线程安全，不再误杀在途连接。
- 在同主机并发场景下，不再出现「一条命令失败导致另一条被掐断」。
- 同一传输目标串行；不同目标可并行。
- `session_reset` 在有人用时不强杀，返回明确原因。
- `prune` 并发安全、文件消失不报错。

**范围**
- `ssh_mcp.py`：`Pool`、`run_command`、`_tool_session_reset`、`_tool_put_file`、`_tool_get_file`、`_tool_xfer_stat`、`_tool_job_status`。
- `output_store.py`：`prune`。
- `test_connect_refusals.py`：新增并发用例。
- 不改 `policy.json`，不新增工具，不改 MCP schema。

**验收**
- 单元用例：10 线程同时首连只建一条连接；失败重试不关共享连接；`session_reset` 在途时返回 `busy`、结束后能正常 reset；同 key 传输锁串行；并发 prune 不抛异常。
- 全量离线与 paramiko 用例通过：`test_ssh_guard.py`、`test_output_store.py`、`test_audit.py`、`test_connect_refusals.py`、`test_ssh_jobs.py`、`test_ssh_xfer.py`、`smoke_stdio.py`。
- 真机（100）：并发 5 条 `exec` 全部 `exit_code=0`；在途命令期间 `session_reset` 返回 `busy`。

**风险 / 回退**
- 风险：`client()` 在建连期间持有 per-host 锁，同主机的其它调用会等待；这是有意的，避免重复握手。
- 风险：传输锁按目标串行，长传输会让同目标第二次传输等待；不同目标不受影响。
- 回退：改动集中在 `Pool` 与几个调用点的 `try/finally`，可单独 revert，不影响传输协议与 job 状态机。

---

## P0-2 killlist 升级为「不可逆动作清单」

**状态：已完成（2026-11-09）**

**实测证据**
- `policy.json` 从 25 条扩到 72 条，覆盖电源/启动、磁盘、登录、数据、虚拟化五类。
- `ssh_guard.py` 新增就地改敏感文件检查：`rm`/`cp`/`mv`/`install`/`ln`/`sed`/`truncate` 的操作数命中 `authorized_keys`/`sshd_config`/`sudoers` 等即拦。
- `test_ssh_guard.py` 33 例全绿（新增 6 组命中 + 1 组不误杀对照）；`test_connect_refusals.py` 71 例全绿（新增 exec / put_file 的 `force_reason` 审计用例）。
- 真机 100（临时把 100 当 guarded 主机，只用 `/tmp` 下的临时 `authorized_keys`）：`rm` 被 `deny:敏感文件被就地改写` 拦下、文件仍在；带 `force_reason` 后执行成功、文件删除，审计 intent/executed 两条都带理由。
- `passwd` 仍保持拦截：无 PTY 时它本来也无法完成，且改口令难回滚；不误杀对照用 `systemctl status/restart`、`docker ps`、`kubectl delete pod` 等。
- 未覆盖并已写进 README：`chmod 000`、`vi`、`sudo` 包装器这类形态（静态切片看不见）。

**现状**
- 25 条清单按「程序在段首」匹配；`systemctl reboot/poweroff`、`telinit 0/6` 等不命中。
- 敏感写目标只有 8 条，`.bashrc`、`.ssh/rc`、`/etc/profile.d` 不在内。
- `force=true` 一步过，审计只记 `rule="forced"`，没有理由字段。

**目标**
- 覆盖电源/启动、磁盘、登录、数据、虚拟化五类高后果动作。
- 用多 token 组合匹配（如 `systemctl` + `reboot|poweroff|halt|kexec`），不靠堆单词。
- `exec` / 传输的 `force` 增加可选 `force_reason`，审计记录；不增加审批往返。

**范围**
- `policy.json`：扩展 `killlist`。
- `ssh_guard.py`：必要的匹配辅助（若现有多 token 前缀规则够用则不改逻辑）。
- `ssh_mcp.py`：`exec` / `put_file` 的 `force` 旁增加 `force_reason` 字段并写入审计；MCP schema 增加可选参数。
- `README.md`：清单边界与 `force_reason` 用法。
- `test_ssh_guard.py`：每类至少一条命中 + 一条不误杀。

**验收**
- `systemctl reboot`、`systemctl poweroff`、`telinit 0`、`dd of=/dev/sda`、`rm -rf /`、写 `authorized_keys`/`sudoers` 均命中。
- 普通 `systemctl status`、`systemctl restart nginx`、`docker ps`、`kubectl delete pod` 不误杀；最终以用例钉住。
- `force=true, force_reason="..."` 审计里有 `force_reason`；不带理由仍可执行，审计里为 null。

**风险 / 回退**
- 风险：清单扩大可能误杀正常运维命令；每条新增都要有「不误杀」用例。
- 回退：`policy.json` 是热加载的，删掉条目即可恢复；代码侧只多一个可选参数。

---

## P1-1 敏感写前自动备份 + 审计只推异常

**状态：已完成（2026-11-09）**

**实测证据**
- `ssh_guard.sensitive_write_targets()` 覆盖写重定向、`tee`、`rm`/`cp`/`mv`/`install`/`ln`/`sed -i`/`truncate`；`cat`、`cp` 的源、无 `-i` 的 `sed`、`sed -n` 脚本都不误报；`mv` 两个敏感路径都会列出来。
- `exec` 与 `put_file` 都会在写入前备份到远端 `~/.sshmcp-backups/<时间戳>-<短id>/`；备份失败返回 `{blocked:true, reason:"backup_failed"}`，原文件不动；返回值和审计带 `backup` 路径。
- `audit_tail(only_risky=true)` 只回 blocked / forced / 失败 / 异常 / 备份；正常成功命令不出现。
- 离线：`test_connect_refusals.py` 77 例全绿（新增 5 条备份 + 1 条 only_risky）；`test_ssh_guard.py` 35 例全绿（新增 2 条写目标清单用例）。
- 真机 100（只用 `/tmp` 临时 `authorized_keys`）：`exec rm` 后备份文件 `00-authorized_keys` 存在；`put_file` 覆盖前备份内容为 `old`，覆盖成功；临时文件与备份目录已清理。

**现状**
- 改 `sshd_config`、`authorized_keys` 这类文件改坏了不可回滚；审计全文原样落盘，用户不会逐条看。

**目标**
- exec 的重定向/tee、`put_file` 覆盖命中敏感目标时，先备份到 `~/.sshmcp-backups/<时间戳>/`，备份失败则拒绝执行；返回值与审计带 `backup` 路径。
- `audit_tail` 增加 `only_risky=true`，只回 blocked / forced / 失败 / 敏感写。

**范围**
- `ssh_mcp.py`：敏感写路径、备份命令、`audit_tail`。
- `ssh_guard.py`：复用 `SENSITIVE_WRITE_TARGETS`。
- `README.md`、`test_connect_refusals.py`、`test_audit.py`。

**验收**
- 覆盖 `sshd_config`：先出现备份文件，再写入；备份失败时命令被拒。
- `audit_tail(only_risky=true)` 不返回普通成功命令，只返回异常与强制项。
- 备份路径在 Windows 本机可读回，能直接用于恢复。

**风险 / 回退**
- 风险：备份命令插入会改变命令串，需保证只对「写敏感目标」生效，且不破坏 `&&`/`;` 语义。
- 回退：备份是附加步骤，可用配置关闭；`only_risky` 是可选参数，不影响旧调用。

---

## P1-2 `login_shell` / `shell_init`

**状态：已完成（2026-11-09）**

**实测证据**
- `exec(login_shell=true)` → 实际下发 `bash -lc '<cd 前缀 + 命令>'`；默认为空时不改变任何既有命令串。
- 凭据字段 `shell_init`（也接受 `shellInit`）：顺序为 `cd <cwd> && { . <init>; } || { echo '[sshmcp] shell_init 失败' >&2; exit 97; }; <命令>`；失败返回 97，不与用户命令退出码混淆。
- `shell_init` 只在用户命令前生效，备份 / md5 / job 脚本等内部命令不 source。
- detach 路径同样支持：`bash -lc` 与 shell_init 在交给远端 job wrapper 之前就拼好；审计与回显仍记用户原话。
- 离线：`test_connect_refusals.py` 83 例全绿（新增 5 条 bootstrapping 用例），`smoke_stdio` 断言 `exec` schema 含 `login_shell`。
- 真机 100（`/tmp` 下临时 env.sh，验完清理）：不配 `shell_init` 时 `echo $SSHMCP_PROBE` 得 `empty`，配上后得 `hello`；指向不存在的片段时 `exit_code=97`、stderr 同时有 bash 的缺文件报错与 `[sshmcp] shell_init 失败`、stdout 为空（命令没执行）；`login_shell=true` 下 `echo $0` 得 `bash`。

**现状**
- 每条命令独立执行，conda/venv/export 需要调用方自己拼 `source ... && ...`。

**目标**
- `exec(login_shell=true)` 用 `bash -lc` 跑，读 profile。
- 凭据文件可选 `shell_init`，每条命令前 source 固定片段；两者互斥或按明确优先级。
- 不引入持久 shell/PTY。

**范围**
- `ssh_mcp.py`：`exec` 参数、命令包装、MCP schema。
- `ssh_mcp_hosts.example.json` / `README.md`：字段说明。
- `test_connect_refusals.py`：命令串形状用例（不连真机）。

**验收**
- `login_shell=true` 时命令串带 `bash -lc`；默认路径不变。
- `shell_init` 出现在每条命令前缀里，且只出现一次。
- 失败时 stderr 能看出是初始化片段还是原命令。

**风险 / 回退**
- 风险：`bash -lc` 会读 profile，可能引入交互输出或慢启动；默认关闭。
- 回退：两个都是可选参数/字段，不填即旧行为。

---

## P1-3 目录传输 `recursive=true`

**状态：已完成（2026-11-09）**

**实测证据**
- `put_file(recursive=true)` / `get_file(recursive=true)`：逐文件走同一套分片续传 + 两端 md5；空目录逐个建；软链与 FIFO/设备文件跳过并计数。
- 每个目标文件单独过 `G.check_write_target`（不只看根目录），命中者进 `blocked` 列表、其余照传；`force=true` 才放行。
- 预算：`defaults.xfer_max_files`（默认 2000）与总字节超限在开始前拒；总时长用 `xfer_timeout_s`，中途超时 `aborted` 并保留已传部分。
- v1 与 `elevate` 互斥，明确返回 `elevate_recursive_unsupported`；不做 `rsync --delete`。
- 离线：`test_connect_refusals.py` 90 例全绿（新增 7 条目录用例，覆盖空目录、软链、逐目标清单、覆盖前备份、文件数上限、远端非目录）。
- 真机 100（`/tmp`）：含空目录的树上传 2 文件 / 3 目录，`find` 确认远端空目录存在；下载回来两个文件 md5 与原文一致、空目录重建；目录覆盖 `authorized_keys` 时先产生备份（备份内容 `oldkey`、目标变为 `newkey`）。远端临时目录与备份目录均已清理。Windows 本机建软链需要特权，软链跳过路径只有离线用例覆盖（未做真机验证）。

**现状（原）**
- `put_file`/`get_file` 只传单文件，目录要靠调用方自己 `tar`。

**目标**
- `put_file`/`get_file` 增加 `recursive=true`，不新增工具。
- 逐文件续传、保留 mode、默认跳过 symlink、空目录也建；不做 `rsync --delete` 式同步。
- 每个目标文件都过 `check_write_target`；远端 symlink `lstat` 后拒绝或跳过。

**范围**
- `ssh_mcp.py`：`put_file`/`get_file` 的目录分支。
- `ssh_xfer.py`：必要的遍历/续传辅助。
- `test_ssh_xfer.py` / `test_connect_refusals.py`：目录遍历、软链、逐文件清单校验。
- `README.md`：递归传输边界。

**验收**
- 传一棵含子目录、空目录、symlink 的树：文件内容 md5 一致，空目录存在，symlink 按策略处理。
- 目录内出现 `authorized_keys` 时被清单拦下（除非 force）。
- 中断后重调能从缺口续传，不从头重传。

**风险 / 回退**
- 风险：目录遍历可能很慢、文件很多；需要文件数/总字节上限与单次调用超时。
- 回退：`recursive` 是可选参数，默认关闭。

---

## P2-1 主机能力字段 `critical` / `disabled` / `xfer`

**状态：已完成（2026-11-09）**

**实测证据**
- `disabled: true`：`exec` 在 `_preflight` 就返回 `{blocked, reason:"host_disabled"}`，不建连（用例断言 `POOL.connected` 为假）。
- `critical: true`：非 root 主机也查 killlist；`list_hosts` 的 `guard_reason` 显示「critical 标记」，`force=true` 仍可越过。
- `xfer: false`：`put_file`/`get_file` 返回 `xfer_disabled`；`xfer_stat` 只读元数据仍可用（未拦）。
- 三个字段不填时行为与旧版完全一致（用例钉住默认值）。
- 离线：`test_ssh_guard.py` 36 例、`test_connect_refusals.py` 95 例全绿。

**目标**
- 凭据文件增加 `critical: true`（永远查清单）、`disabled: true`（临时停用）、可选 `xfer: false`（禁传文件）。
- `critical` 与 `policy.json` 的 `guarded_hosts` 合并，减少双文件维护。

**范围**：`ssh_mcp.py` 的凭据模型、`list_hosts` 输出、`ssh_guard.applies` 的可选 critical 参数、README、用例。

**验收**：`disabled` 主机的 `exec` 在建立连接前被拒；`critical` 主机即使非 root 也查清单；`xfer=false` 时 `put_file`/`get_file` 直接拒。

**风险/回退**：字段都是可选的，不填即旧行为；`guarded_hosts` 保留兼容。

---

## P2-1b 主机清单可视化编辑（hosts_gui.py）

**状态：已完成（2026-11-09）**

**交付**
- `hostreg.py`：凭据文件的唯一写入口——读取/校验/原子写/保存前备份（留最近 10 份）/保留 `_` 注释与未知字段/扫描 known_hosts 与 ssh config 出候选。
- `ssh_probe.py`：指纹探测、私钥加载、一次性连测，从 `ssh_mcp.py` 抽出，GUI 不再反向依赖服务模块；探测仍只做密钥交换、不发凭据。
- `hosts_gui.py`：tkinter 窗口——列表 + 表单、增改复制删、停用开关、探测指纹并确认、测试连接、从 known_hosts/ssh config 勾选导入；密码留空即不改、不回填明文。
- `gen_hosts.py`：退成 `hostreg` 的薄壳 CLI（默认只列候选，`--merge` 才写）。
- `ssh_mcp.py`：只读凭据不变；探测相关函数改为从 `ssh_probe` 引入，`test_connect_refusals` 的 mock 点仍有效。

**验证**
- `test_hostreg.py` 18 例全绿（原子写、备份轮转、坏 JSON 拒写、password 留空保留、未知字段保留、扫描与去重）。
- 原有 95 + 36 例、冒烟测试全绿（抽取后无回归）。
- `hosts_gui.py --selftest` 能构造窗口并自动关闭；用演示数据实际打开截图核对过布局（标记列、表单、状态栏无裁切）。
- 真机未做写操作验证：GUI 保存路径由 `test_hostreg.py` 的临时文件用例覆盖，未对真实 `ssh_mcp_hosts.json` 做写测试。

**边界**
- GUI 不是 MCP 工具，AI 碰不到凭据文件；服务进程仍然只读。
- 不做命令执行、日志、批量运维。
- 「测试连接」只跑固定探针，不开放任意命令输入。

---

## P2-2 批量执行（按 purpose 标签）

**状态：待办 / 暂缓**

**目标**
- 在多主机场景下按 `purpose` 标签批量执行同一命令，返回每台结果与失败汇总。
- 仅在 P0/P1 稳定、确有实际需求后再做；不先新增 `exec_many` 工具。

**验收**：3 台主机并发执行，单台失败不影响其它台；汇总里能看出哪台失败、退出码与 output_id。

**风险/回退**：工具面会增大；如果 MCP 客户端本身能并行发多个 `exec`，优先不新增工具。

---

## P2-3 主机级快照钩子

**状态：待办 / 暂缓**

**目标**
- 凭据里可选 `pre_change_hook`（如 `zfs snapshot`、`virsh snapshot-create-as`），只在 `force` 或高危写前调用；失败则拒绝。
- 不做默认；依赖具体主机能力。

**验收**：配置了钩子的主机在高危写前产生快照；钩子失败时命令被拒并留审计。

**风险/回退**：钩子是用户自己写的命令，需自行保证幂等与清理；不配置即旧行为。

---

## 明确不做

- PTY / 持久 shell / 交互式会话。
- 命令白名单、角色、审批流、配额。
- `rsync --delete` 式目录同步。
