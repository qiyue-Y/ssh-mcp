# /// script
# requires-python = ">=3.11"
# dependencies = ["paramiko>=3.4"]
# ///
"""hosts_gui.py —— ssh-mcp 主机清单的可视化编辑窗口（用户本人运行）。

    uv run hosts_gui.py            # 打开窗口
    uv run hosts_gui.py --selftest # 只验证窗口能构造：建好后自动关（给自动化用）

这不是 MCP 工具：AI 碰不到它，凭据文件仍然只有你本人能改。
窗口只做「维护主机清单」——增删改、停用、指纹、连测、从 ~/.ssh 导入；
不做命令执行、日志查看、批量运维。

密码框留空 ＝ 沿用原口令（打开时不回填明文，避免出现在截图里）。
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import tkinter as tk
from pathlib import Path
from tkinter import messagebox, ttk

import hostreg as R
import ssh_probe as P

AUTH_LABELS = {"password": "口令", "key": "私钥"}


def _flags(entry: dict) -> str:
    marks = []
    if entry.get("disabled"):
        marks.append("停用")
    if entry.get("critical"):
        marks.append("查清单")
    if entry.get("xfer") is False:
        marks.append("禁传")
    if entry.get("elevate"):
        marks.append("提权")
    return " ".join(marks)


class App:
    def __init__(self, root: tk.Tk, registry: R.Registry):
        self.root = root
        self.reg = registry
        self.current: str | None = None  # 正在编辑的条目；None 表示新建

        root.title(f"ssh-mcp 主机清单 — {self.reg.path}")
        root.geometry("1180x720")
        root.minsize(960, 600)

        self._build()
        self.refresh_list()
        if self.reg.error:
            self.set_status(f"！{self.reg.error}", error=True)

    # ---------------------------------------------------------------- 界面搭建
    def _build(self) -> None:
        outer = ttk.Frame(self.root, padding=12)
        outer.pack(fill="both", expand=True)

        panes = ttk.PanedWindow(outer, orient="horizontal")
        panes.pack(fill="both", expand=True)

        left = ttk.Frame(panes, padding=(0, 0, 10, 0))
        right = ttk.Frame(panes, padding=(10, 0, 0, 0))
        panes.add(left, weight=2)
        panes.add(right, weight=3)

        self.tree = ttk.Treeview(left, columns=("alias", "address", "user", "flags"), show="headings", height=18)
        for col, title, width in (("alias", "别名", 90), ("address", "地址", 130),
                                  ("user", "用户", 75), ("flags", "标记", 115)):
            self.tree.heading(col, text=title)
            self.tree.column(col, width=width, minwidth=60, stretch=True, anchor="w")
        xscroll = ttk.Scrollbar(left, orient="horizontal", command=self.tree.xview)
        self.tree.configure(xscrollcommand=xscroll.set)
        xscroll.pack(side="bottom", fill="x")
        self.tree.pack(fill="both", expand=True)
        self.tree.bind("<<TreeviewSelect>>", self._on_select)

        bar = ttk.Frame(left)
        bar.pack(fill="x", pady=(8, 0))
        ttk.Button(bar, text="新建", command=self.new_host).pack(side="left")
        ttk.Button(bar, text="复制", command=self.copy_host).pack(side="left", padx=4)
        ttk.Button(bar, text="删除", command=self.delete_host).pack(side="left")
        ttk.Button(bar, text="停用/启用", command=self.toggle_disabled).pack(side="left", padx=4)

        ttk.Button(left, text="从 known_hosts / ssh config 导入…", command=self.open_import).pack(fill="x", pady=(8, 0))

        self._build_form(right)

        self.status = ttk.Label(outer, text="", foreground="#444", wraplength=980, justify="left")
        self.status.pack(fill="x", pady=(10, 0))

    def _build_form(self, parent: ttk.Frame) -> None:
        head = ttk.Frame(parent)
        head.pack(fill="x")
        self.form_title = ttk.Label(head, text="新建主机", font=("", 11, "bold"))
        self.form_title.pack(side="left")

        body = ttk.Frame(parent)
        body.pack(fill="both", expand=True, pady=(8, 0))
        body.columnconfigure(1, weight=1)

        self.vars: dict[str, tk.Variable] = {}
        row = 0

        def text_row(label: str, key: str, show: str = "") -> ttk.Entry:
            nonlocal row
            ttk.Label(body, text=label).grid(row=row, column=0, sticky="w", pady=3)
            var = tk.StringVar()
            entry = ttk.Entry(body, textvariable=var, show=show)
            entry.grid(row=row, column=1, sticky="ew", padx=(8, 0), pady=3)
            self.vars[key] = var
            row += 1
            return entry

        self.alias_entry = text_row("别名 *", "alias")
        text_row("地址 *", "address")
        text_row("端口", "port")
        text_row("用户名", "username")

        ttk.Label(body, text="认证方式").grid(row=row, column=0, sticky="w", pady=3)
        auth_box = ttk.Frame(body)
        auth_box.grid(row=row, column=1, sticky="w", padx=(8, 0), pady=3)
        self.vars["auth"] = tk.StringVar(value="password")
        for value, label in AUTH_LABELS.items():
            ttk.Radiobutton(auth_box, text=label, value=value, variable=self.vars["auth"]).pack(side="left", padx=(0, 12))
        row += 1

        self.pw_entry = text_row("口令", "password", show="•")
        self.pw_hint = ttk.Label(body, text="", foreground="#666")
        self.pw_hint.grid(row=row - 1, column=2, sticky="w", padx=(8, 0))
        text_row("私钥路径（auth=key 时可留空）", "key_path")
        text_row("主机指纹 hostKey", "hostKey")
        text_row("初始化片段 shell_init（可选）", "shell_init")

        ttk.Label(body, text="备注 purpose").grid(row=row, column=0, sticky="nw", pady=3)
        purpose = tk.Text(body, height=3, wrap="word")
        purpose.grid(row=row, column=1, sticky="ew", padx=(8, 0), pady=3)
        self.purpose_text = purpose
        row += 1

        flags = ttk.LabelFrame(body, text="能力位", padding=8)
        flags.grid(row=row, column=0, columnspan=2, sticky="ew", pady=(8, 0))
        for idx, (key, label) in enumerate((
            ("disabled", "停用（建连前拒）"),
            ("critical", "恒查清单（非 root 也查）"),
            ("xfer", "允许传文件（取消勾选＝禁传）"),
            ("elevate", "允许提权 elevate"),
        )):
            # xfer 是"允许"语义，默认勾上；其余能力位默认关
            var = tk.BooleanVar(value=key == "xfer")
            ttk.Checkbutton(flags, text=label, variable=var).grid(
                row=idx // 2, column=idx % 2, sticky="w", padx=(0, 24), pady=2)
            self.vars[key] = var
        row += 1

        elev = ttk.Frame(body)
        elev.grid(row=row, column=0, columnspan=2, sticky="ew", pady=(6, 0))
        ttk.Label(elev, text="提权用户").pack(side="left")
        self.vars["elevate_user"] = tk.StringVar(value="root")
        ttk.Entry(elev, textvariable=self.vars["elevate_user"], width=14).pack(side="left", padx=(6, 16))
        ttk.Label(elev, text="提权口令（默认复用登录口令）").pack(side="left")
        self.vars["elevate_password"] = tk.StringVar()
        ttk.Entry(elev, textvariable=self.vars["elevate_password"], show="•", width=18).pack(side="left", padx=(6, 0))
        row += 1

        actions = ttk.Frame(parent)
        actions.pack(fill="x", pady=(12, 0))
        ttk.Button(actions, text="保存", command=self.save_host).pack(side="left")
        ttk.Button(actions, text="探测指纹", command=self.probe).pack(side="left", padx=6)
        ttk.Button(actions, text="测试连接", command=self.test_connection).pack(side="left")
        ttk.Button(actions, text="重新载入", command=self.reload).pack(side="right")

    # ---------------------------------------------------------------- 数据 <-> 表单
    def _form_entry(self) -> dict:
        purpose = self.purpose_text.get("1.0", "end").strip()
        return {
            "address": self.vars["address"].get().strip(),
            "port": self.vars["port"].get().strip() or "22",
            "username": self.vars["username"].get().strip(),
            "auth": self.vars["auth"].get(),
            "password": self.vars["password"].get(),
            "key_path": self.vars["key_path"].get().strip(),
            "hostKey": self.vars["hostKey"].get().strip(),
            "purpose": purpose,
            "shell_init": self.vars["shell_init"].get().strip(),
            "disabled": bool(self.vars["disabled"].get()),
            "critical": bool(self.vars["critical"].get()),
            "xfer": bool(self.vars["xfer"].get()),
            "elevate": bool(self.vars["elevate"].get()),
            "elevate_user": self.vars["elevate_user"].get().strip() or "root",
            "elevate_password": self.vars["elevate_password"].get(),
        }

    def _fill_form(self, alias: str | None, entry: dict) -> None:
        self.current = alias
        self.form_title.configure(text=f"编辑 {alias}" if alias else "新建主机")
        self.vars["alias"].set(alias or "")
        self.alias_entry.configure(state="disabled" if alias else "normal")
        self.vars["address"].set(str(entry.get("address") or ""))
        self.vars["port"].set(str(entry.get("port") or 22))
        self.vars["username"].set(str(entry.get("username") or ""))
        self.vars["auth"].set(str(entry.get("auth") or "password"))
        self.vars["password"].set("")  # 永不回填明文
        self.vars["elevate_password"].set("")
        self.vars["key_path"].set(str(entry.get("key_path") or ""))
        self.vars["hostKey"].set(str(entry.get("hostKey") or ""))
        self.vars["shell_init"].set(str(entry.get("shell_init") or ""))
        self.vars["disabled"].set(bool(entry.get("disabled")))
        self.vars["critical"].set(bool(entry.get("critical")))
        self.vars["xfer"].set(entry.get("xfer") is not False)
        self.vars["elevate"].set(bool(entry.get("elevate")))
        self.vars["elevate_user"].set(str(entry.get("elevate_user") or "root"))
        self.purpose_text.delete("1.0", "end")
        self.purpose_text.insert("1.0", str(entry.get("purpose") or ""))
        if alias:
            has_pw = bool(entry.get("password"))
            tip = "留空＝沿用原口令" if has_pw else "当前没有口令，建议填写"
            self.pw_hint.configure(text=tip)
        else:
            self.pw_hint.configure(text="新主机需要填写")

    # ---------------------------------------------------------------- 列表操作
    def refresh_list(self, select: str | None = None) -> None:
        self.tree.delete(*self.tree.get_children())
        for alias, entry in sorted(self.reg.entries().items()):
            self.tree.insert("", "end", iid=alias, values=(
                alias, f"{entry.get('address', '')}:{entry.get('port', 22)}",
                entry.get("username", ""), _flags(entry)))
        if select and select in self.tree.get_children():
            self.tree.selection_set(select)
            self.tree.see(select)

    def _on_select(self, _event=None) -> None:
        picked = self.tree.selection()
        if not picked:
            return
        alias = picked[0]
        self._fill_form(alias, self.reg.get(alias))

    def new_host(self) -> None:
        self._fill_form(None, {})
        self.tree.selection_remove(*self.tree.selection())

    def copy_host(self) -> None:
        picked = self.tree.selection()
        if not picked:
            self.set_status("先在左边选一台再复制")
            return
        entry = dict(self.reg.get(picked[0]))
        entry["purpose"] = f"复制自 {picked[0]}"
        self._fill_form(None, entry)
        self.vars["password"].set("")
        self.pw_hint.configure(text="复制不会带上原口令，请填写（或认证方式改私钥）")

    def delete_host(self) -> None:
        picked = self.tree.selection()
        if not picked:
            self.set_status("先在左边选一台再删除")
            return
        alias = picked[0]
        if not messagebox.askyesno("确认删除", f"从清单里删除 {alias}？\n（保存后生效，会先自动备份原文件）"):
            return
        self.reg.remove(alias)
        self._persist(f"已删除 {alias}")

    def toggle_disabled(self) -> None:
        picked = self.tree.selection()
        if not picked:
            self.set_status("先在左边选一台")
            return
        alias = picked[0]
        entry = self.reg.get(alias)
        self.reg.set_flag(alias, "disabled", not bool(entry.get("disabled")))
        self._persist(f"{alias} 已{'停用' if not entry.get('disabled') else '启用'}")

    def reload(self) -> None:
        self.reg.reload()
        self.refresh_list(self.current)
        if self.reg.error:
            self.set_status(f"！{self.reg.error}", error=True)
        else:
            self.set_status("已重新载入")

    # ---------------------------------------------------------------- 保存
    def save_host(self) -> None:
        alias = (self.current or self.vars["alias"].get().strip())
        if not alias:
            self.set_status("别名不能为空", error=True)
            return
        entry = self._form_entry()
        errors, warnings = R.validate(alias, entry, self.reg.aliases(), is_new=self.current is None)
        if errors:
            self.set_status("保存不了：" + "；".join(errors), error=True)
            return
        self.reg.upsert(alias, entry)
        self._persist(f"已保存 {alias}" + (f"（提示：{'；'.join(warnings)}）" if warnings else ""), select=alias)

    def _persist(self, message: str, select: str | None = None) -> None:
        try:
            backup = self.reg.save()
        except (R.HostregError, OSError) as exc:
            self.set_status(f"保存失败：{exc}", error=True)
            return
        self.refresh_list(select)
        suffix = f"，原文件备份为 {backup}" if backup else ""
        self.set_status(message + suffix)
        if select:
            self._fill_form(select, self.reg.get(select))

    # ---------------------------------------------------------------- 探测 / 连测
    def _form_cred(self) -> P.ProbeCred:
        entry = self._form_entry()
        password = entry["password"]
        if not password and self.current:
            password = str(self.reg.get(self.current).get("password") or "")
        try:
            port = int(entry["port"])
        except ValueError:
            port = 22
        return P.ProbeCred(
            address=entry["address"], port=port, username=entry["username"],
            auth=entry["auth"], password=password, key_path=entry["key_path"],
        )

    def probe(self) -> None:
        cred = self._form_cred()
        if not cred.address:
            self.set_status("先填地址", error=True)
            return
        alias = self.current or self.vars["alias"].get().strip() or cred.address
        self.set_status(f"正在探测 {cred.address}:{cred.port} 的指纹（不发送任何凭据）…")
        self._run_async(lambda: P.probe_hostkey(cred.address, cred.port),
                        lambda out, err: self._on_probe(alias, cred, out, err))

    def _on_probe(self, alias: str, cred: P.ProbeCred, out, err) -> None:
        if err is not None:
            self.set_status(f"探测失败：{type(err).__name__}: {err}", error=True)
            return
        fingerprint, key_type = out
        pinned = self.vars["hostKey"].get().strip()
        lines = [f"主机：{alias}（{cred.address}:{cred.port}）",
                 f"算法：{key_type}",
                 f"实际指纹：{fingerprint}",
                 f"当前固定：{pinned or '（空）'}"]
        if pinned and pinned != fingerprint:
            messagebox.showerror("指纹不符", "\n".join(lines) + "\n\n与已固定的指纹不一致，拒绝覆盖。\n"
                                            "这可能是主机重装，也可能是中间人——由你自己判断后手改。")
            self.set_status("指纹不符，未做任何修改", error=True)
            return
        if pinned == fingerprint:
            self.set_status("指纹与已固定的一致")
            return
        if messagebox.askyesno("确认固定指纹", "\n".join(lines) + "\n\n核对无误后填入 hostKey；点『保存』才写入清单。"):
            self.vars["hostKey"].set(fingerprint)
            self.set_status("已填入 hostKey，记得点保存")

    def test_connection(self) -> None:
        cred = self._form_cred()
        if not cred.address:
            self.set_status("先填地址", error=True)
            return
        pin = self.vars["hostKey"].get().strip()
        if not pin:
            self.set_status("hostKey 为空：先点『探测指纹』并确认，再连测", error=True)
            return
        self.set_status(f"正在连接 {cred.address}:{cred.port}…")
        self._run_async(lambda: P.test_connection(cred, pin),
                        lambda out, err: self._on_test(out, err))

    def _on_test(self, out, err) -> None:
        if err is not None:
            self.set_status(f"连测失败：{type(err).__name__}: {err}", error=True)
            return
        if not out.get("ok"):
            self.set_status(f"连测失败：{out.get('error')}", error=True)
            return
        self.set_status(f"连测成功（{out.get('elapsed_ms')}ms）：{out.get('os') or '未知系统'} / "
                        f"{out.get('arch') or '未知架构'} / {out.get('server') or ''}")

    def _run_async(self, work, done) -> None:
        """把阻塞的探测/连接放到线程，结果回主线程处理（tkinter 不能跨线程操作控件）。"""
        def runner() -> None:
            try:
                out, err = work(), None
            except Exception as exc:  # noqa: BLE001 - 网络错误形态太多，交给界面显示
                out, err = None, exc
            self.root.after(0, lambda: done(out, err))

        threading.Thread(target=runner, daemon=True).start()

    # ---------------------------------------------------------------- 导入
    def open_import(self) -> None:
        connected, hashed = R.read_known_hosts()
        config = R.read_ssh_config()
        candidates = [c for c in R.build_candidates(self.reg.raw, connected, config) if c.importable]
        if not candidates:
            messagebox.showinfo("没有可导入的主机",
                                f"扫描了 known_hosts（{len(connected)} 台）与 ssh config（{len(config)} 条），"
                                "没有新的可导入主机。")
            return
        win = tk.Toplevel(self.root)
        win.title("从 known_hosts / ssh config 导入")
        win.geometry("720x420")
        win.transient(self.root)
        ttk.Label(win, padding=10, wraplength=690,
                  text=(f"共 {len(candidates)} 台候选；已在清单里的不会出现。\n"
                        "按住 Ctrl / Shift 多选。导入后 password 仍需逐台补（或改用私钥）。"
                        + (f"\n另有 {hashed} 条 known_hosts 记录是 hashed 形式，反查不出主机名。" if hashed else ""))
        ).pack(fill="x")
        box = tk.Listbox(win, selectmode="extended", font=("Consolas", 10))
        box.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        for cand in candidates:
            note = "；".join(cand.notes[:2])
            box.insert("end", f"{cand.alias:<16} {cand.entry['address']}:{cand.entry['port']:<6} "
                              f"{cand.entry['username'] or '(缺用户)':<12} {note}")
            box.selection_set("end")

        def do_import() -> None:
            picked = [candidates[i] for i in box.curselection()]
            if not picked:
                return
            added, skipped = [], []
            for cand in picked:
                if cand.alias in self.reg.aliases():
                    skipped.append(cand.alias)
                    continue
                self.reg.upsert(cand.alias, cand.entry, keep_password_if_empty=False)
                added.append(cand.alias)
            win.destroy()
            if not added:
                self.set_status("没有新增（别名都已存在）")
                return
            self._persist(f"导入 {len(added)} 台：{'、'.join(added)}" +
                          (f"；跳过 {len(skipped)} 台重名" if skipped else ""), select=added[0])

        btns = ttk.Frame(win, padding=(10, 0, 10, 10))
        btns.pack(fill="x")
        ttk.Button(btns, text="导入选中", command=do_import).pack(side="left")
        ttk.Button(btns, text="取消", command=win.destroy).pack(side="right")

    # ---------------------------------------------------------------- 状态栏
    def set_status(self, text: str, error: bool = False) -> None:
        self.status.configure(text=text, foreground="#B00020" if error else "#333")


def main(argv: list[str]) -> int:
    selftest = "--selftest" in argv
    if selftest:
        # 自检不碰真实凭据：指到一个临时文件
        tmp = Path(tempfile.mkdtemp(prefix="hosts-gui-selftest-")) / "hosts.json"
        tmp.write_text(json.dumps({"100": {"address": "10.0.0.1", "username": "u", "auth": "password",
                                           "password": "x", "hostKey": "SHA256:AAA"}}, ensure_ascii=False),
                       encoding="utf-8")
        os.environ["SSHMCP_HOSTS"] = str(tmp)

    root = tk.Tk()
    app = App(root, R.Registry())
    if selftest:
        root.after(500, root.destroy)
    else:
        app.set_status(f"清单文件：{app.reg.path}（保存前会自动备份）")
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
