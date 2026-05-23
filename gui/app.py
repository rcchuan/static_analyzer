"""
Main GUI Application - Static Code Analyzer
Built with tkinter for cross-platform compatibility and PyInstaller packaging
"""
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import os
import sys

# Ensure project root in path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analysis.engine import AnalysisEngine, detect_language
from core.ir import Language, AnalysisIssue
from gui.widgets import (IssueTreeView, CodeViewer, CFGViewer,
                          StatusBar, ToolbarButton, SliceDialog)


THEME = {
    "bg_dark": "#1e1e2e",
    "bg_mid": "#2a2a3e",
    "bg_light": "#313145",
    "accent": "#7c6af7",
    "accent2": "#50c8a0",
    "text": "#cdd6f4",
    "text_dim": "#6c7086",
    "error": "#f38ba8",
    "warning": "#fab387",
    "info": "#89dceb",
    "success": "#a6e3a1",
    "border": "#45475a",
    "selection": "#3d3d5c",
}

LANGUAGES = ["自动检测", "Python", "C", "C++", "Java"]
LANG_MAP = {
    "Python": Language.PYTHON,
    "C": Language.C,
    "C++": Language.CPP,
    "Java": Language.JAVA,
}


class StaticAnalyzerApp:
    def __init__(self):
        self.engine = AnalysisEngine()
        self.current_result = None
        self.root = tk.Tk()
        self._setup_window()
        self._setup_styles()
        self._build_ui()

    def _setup_window(self):
        self.root.title("🔍 MultiLang Static Code Analyzer v1.0")
        self.root.geometry("1400x900")
        self.root.minsize(1100, 700)
        self.root.configure(bg=THEME["bg_dark"])
        # Center window
        self.root.update_idletasks()
        x = (self.root.winfo_screenwidth() - 1400) // 2
        y = (self.root.winfo_screenheight() - 900) // 2
        self.root.geometry(f"1400x900+{x}+{y}")

    def _setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')

        style.configure(".", background=THEME["bg_dark"], foreground=THEME["text"],
                        fieldbackground=THEME["bg_mid"], bordercolor=THEME["border"],
                        troughcolor=THEME["bg_mid"], selectbackground=THEME["accent"],
                        selectforeground="white", font=("Consolas", 10))

        style.configure("TNotebook", background=THEME["bg_dark"], borderwidth=0)
        style.configure("TNotebook.Tab", background=THEME["bg_mid"],
                        foreground=THEME["text_dim"], padding=[16, 8],
                        font=("Segoe UI", 10, "bold"))
        style.map("TNotebook.Tab",
                  background=[("selected", THEME["bg_light"])],
                  foreground=[("selected", THEME["text"])])

        style.configure("Treeview", background=THEME["bg_mid"],
                        foreground=THEME["text"], fieldbackground=THEME["bg_mid"],
                        rowheight=26, font=("Consolas", 9))
        style.configure("Treeview.Heading", background=THEME["bg_light"],
                        foreground=THEME["text"], font=("Segoe UI", 9, "bold"))
        style.map("Treeview", background=[("selected", THEME["selection"])],
                  foreground=[("selected", THEME["text"])])

        style.configure("TCombobox", fieldbackground=THEME["bg_mid"],
                        background=THEME["bg_mid"], foreground=THEME["text"])

        style.configure("Vertical.TScrollbar", background=THEME["bg_mid"],
                        troughcolor=THEME["bg_dark"], arrowcolor=THEME["text_dim"])
        style.configure("Horizontal.TScrollbar", background=THEME["bg_mid"],
                        troughcolor=THEME["bg_dark"], arrowcolor=THEME["text_dim"])

        style.configure("TProgressbar", troughcolor=THEME["bg_mid"],
                        background=THEME["accent"])

    def _build_ui(self):
        # ─── Toolbar ───────────────────────────────────────────────
        toolbar = tk.Frame(self.root, bg=THEME["bg_mid"], height=52, pady=6)
        toolbar.pack(fill=tk.X, side=tk.TOP)
        toolbar.pack_propagate(False)

        tk.Label(toolbar, text="⬡ StaticAnalyzer",
                 bg=THEME["bg_mid"], fg=THEME["accent"],
                 font=("Segoe UI", 14, "bold")).pack(side=tk.LEFT, padx=16)

        sep = tk.Frame(toolbar, bg=THEME["border"], width=1)
        sep.pack(side=tk.LEFT, fill=tk.Y, padx=8, pady=4)

        self._make_toolbar_btn(toolbar, "📂 打开文件", self._open_file)
        self._make_toolbar_btn(toolbar, "▶ 开始分析", self._run_analysis, accent=True)
        self._make_toolbar_btn(toolbar, "🔪 程序切片", self._show_slice_dialog)
        self._make_toolbar_btn(toolbar, "💾 导出报告", self._export_report)
        self._make_toolbar_btn(toolbar, "🗑 清空", self._clear_all)

        sep2 = tk.Frame(toolbar, bg=THEME["border"], width=1)
        sep2.pack(side=tk.LEFT, fill=tk.Y, padx=8, pady=4)

        tk.Label(toolbar, text="语言:", bg=THEME["bg_mid"],
                 fg=THEME["text_dim"], font=("Segoe UI", 9)).pack(side=tk.LEFT, padx=(0, 4))
        self.lang_var = tk.StringVar(value="自动检测")
        lang_combo = ttk.Combobox(toolbar, textvariable=self.lang_var,
                                   values=LANGUAGES, width=10, state="readonly")
        lang_combo.pack(side=tk.LEFT)

        # Right side: stats labels
        self.stat_frame = tk.Frame(toolbar, bg=THEME["bg_mid"])
        self.stat_frame.pack(side=tk.RIGHT, padx=16)
        self.stat_labels = {}
        for key, color, emoji in [("errors", THEME["error"], "🔴"),
                                    ("warnings", THEME["warning"], "🟡"),
                                    ("security", THEME["info"], "🛡")]:
            lbl = tk.Label(self.stat_frame, text=f"{emoji} 0",
                           bg=THEME["bg_mid"], fg=color,
                           font=("Segoe UI", 10, "bold"))
            lbl.pack(side=tk.LEFT, padx=8)
            self.stat_labels[key] = lbl

        # ─── Main paned layout ────────────────────────────────────
        main_pane = tk.PanedWindow(self.root, orient=tk.HORIZONTAL,
                                    bg=THEME["border"], sashwidth=4,
                                    sashrelief=tk.FLAT)
        main_pane.pack(fill=tk.BOTH, expand=True)

        # ─── Left: Code editor ────────────────────────────────────
        left_frame = tk.Frame(main_pane, bg=THEME["bg_dark"])
        main_pane.add(left_frame, minsize=400)

        code_header = tk.Frame(left_frame, bg=THEME["bg_light"], height=32)
        code_header.pack(fill=tk.X)
        code_header.pack_propagate(False)
        tk.Label(code_header, text="📝 源代码编辑器",
                 bg=THEME["bg_light"], fg=THEME["text"],
                 font=("Segoe UI", 9, "bold")).pack(side=tk.LEFT, padx=12, pady=6)
        self.file_label = tk.Label(code_header, text="未打开文件",
                                    bg=THEME["bg_light"], fg=THEME["text_dim"],
                                    font=("Consolas", 8))
        self.file_label.pack(side=tk.RIGHT, padx=12, pady=6)

        self.code_viewer = CodeViewer(left_frame, THEME)
        self.code_viewer.pack(fill=tk.BOTH, expand=True)

        # ─── Right: Analysis results ───────────────────────────────
        right_pane = tk.PanedWindow(main_pane, orient=tk.VERTICAL,
                                     bg=THEME["border"], sashwidth=4,
                                     sashrelief=tk.FLAT)
        main_pane.add(right_pane, minsize=550)

        # Top right: notebook with tabs
        nb_frame = tk.Frame(right_pane, bg=THEME["bg_dark"])
        right_pane.add(nb_frame, minsize=300)

        self.notebook = ttk.Notebook(nb_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)

        # Tab 1: Issues
        issues_frame = tk.Frame(self.notebook, bg=THEME["bg_dark"])
        self.notebook.add(issues_frame, text="⚠ 问题列表")
        self._build_issues_tab(issues_frame)

        # Tab 2: CFG
        cfg_frame = tk.Frame(self.notebook, bg=THEME["bg_dark"])
        self.notebook.add(cfg_frame, text="🔀 控制流图")
        self.cfg_viewer = CFGViewer(cfg_frame, THEME)
        self.cfg_viewer.pack(fill=tk.BOTH, expand=True)

        # Tab 3: Fix Report
        fix_frame = tk.Frame(self.notebook, bg=THEME["bg_dark"])
        self.notebook.add(fix_frame, text="🛠 修复方案")
        self._build_fix_tab(fix_frame)

        # Tab 4: Taint Flow
        taint_frame = tk.Frame(self.notebook, bg=THEME["bg_dark"])
        self.notebook.add(taint_frame, text="☣ 污点分析")
        self._build_taint_tab(taint_frame)

        # Bottom right: detail panel
        detail_frame = tk.Frame(right_pane, bg=THEME["bg_mid"])
        right_pane.add(detail_frame, minsize=160)

        tk.Label(detail_frame, text="📋 问题详情",
                 bg=THEME["bg_mid"], fg=THEME["text"],
                 font=("Segoe UI", 9, "bold")).pack(anchor=tk.W, padx=12, pady=(8, 2))

        self.detail_text = scrolledtext.ScrolledText(
            detail_frame, bg=THEME["bg_mid"], fg=THEME["text"],
            font=("Consolas", 9), wrap=tk.WORD, height=8,
            relief=tk.FLAT, insertbackground=THEME["text"],
            selectbackground=THEME["selection"])
        self.detail_text.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 8))
        self.detail_text.config(state=tk.DISABLED)

        # ─── Status bar ───────────────────────────────────────────
        self.status_bar = StatusBar(self.root, THEME)
        self.status_bar.pack(fill=tk.X, side=tk.BOTTOM)

        # ─── Progress bar ─────────────────────────────────────────
        self.progress = ttk.Progressbar(self.root, mode='indeterminate',
                                         style="TProgressbar")

    def _make_toolbar_btn(self, parent, text, command, accent=False):
        bg = THEME["accent"] if accent else THEME["bg_light"]
        fg = "white" if accent else THEME["text"]
        btn = tk.Button(parent, text=text, command=command,
                        bg=bg, fg=fg, font=("Segoe UI", 9, "bold"),
                        relief=tk.FLAT, padx=12, pady=4,
                        activebackground=THEME["accent2"],
                        activeforeground="white", cursor="hand2",
                        borderwidth=0)
        btn.pack(side=tk.LEFT, padx=3, pady=6)
        return btn

    def _build_issues_tab(self, parent):
        # Filter bar
        filter_frame = tk.Frame(parent, bg=THEME["bg_dark"])
        filter_frame.pack(fill=tk.X, padx=4, pady=4)

        tk.Label(filter_frame, text="筛选:", bg=THEME["bg_dark"],
                 fg=THEME["text_dim"], font=("Segoe UI", 8)).pack(side=tk.LEFT, padx=4)

        self.filter_vars = {}
        for label, key, color in [("🔴 错误", "ERROR", THEME["error"]),
                                    ("🟡 警告", "WARNING", THEME["warning"]),
                                    ("🔵 提示", "INFO", THEME["info"])]:
            var = tk.BooleanVar(value=True)
            cb = tk.Checkbutton(filter_frame, text=label, variable=var,
                                bg=THEME["bg_dark"], fg=color,
                                selectcolor=THEME["bg_mid"],
                                activebackground=THEME["bg_dark"],
                                activeforeground=color,
                                font=("Segoe UI", 8),
                                command=self._apply_filter)
            cb.pack(side=tk.LEFT, padx=4)
            self.filter_vars[key] = var

        # Search
        tk.Label(filter_frame, text="搜索:", bg=THEME["bg_dark"],
                 fg=THEME["text_dim"], font=("Segoe UI", 8)).pack(side=tk.LEFT, padx=(12, 2))
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *a: self._apply_filter())
        search_entry = tk.Entry(filter_frame, textvariable=self.search_var,
                                bg=THEME["bg_mid"], fg=THEME["text"],
                                insertbackground=THEME["text"],
                                relief=tk.FLAT, font=("Consolas", 9), width=20)
        search_entry.pack(side=tk.LEFT, padx=4)

        # Issue tree
        self.issue_tree = IssueTreeView(parent, THEME)
        self.issue_tree.pack(fill=tk.BOTH, expand=True, padx=4, pady=(0, 4))
        self.issue_tree.bind_selection(self._on_issue_select)

    def _build_fix_tab(self, parent):
        self.fix_text = scrolledtext.ScrolledText(
            parent, bg=THEME["bg_dark"], fg=THEME["text"],
            font=("Consolas", 9), wrap=tk.WORD, relief=tk.FLAT,
            insertbackground=THEME["text"],
            selectbackground=THEME["selection"])
        self.fix_text.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        self.fix_text.config(state=tk.DISABLED)

    def _build_taint_tab(self, parent):
        self.taint_text = scrolledtext.ScrolledText(
            parent, bg=THEME["bg_dark"], fg=THEME["text"],
            font=("Consolas", 9), wrap=tk.WORD, relief=tk.FLAT,
            insertbackground=THEME["text"],
            selectbackground=THEME["selection"])
        self.taint_text.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

        self.taint_text.tag_configure("source", foreground=THEME["warning"])
        self.taint_text.tag_configure("sink", foreground=THEME["error"])
        self.taint_text.tag_configure("header", foreground=THEME["accent"],
                                       font=("Consolas", 10, "bold"))
        self.taint_text.config(state=tk.DISABLED)

    # ─── Actions ──────────────────────────────────────────────────

    def _open_file(self):
        path = filedialog.askopenfilename(
            title="打开源代码文件",
            filetypes=[
                ("源代码文件", "*.py *.c *.cpp *.cc *.h *.java"),
                ("Python", "*.py"), ("C/C++", "*.c *.cpp *.cc *.h"),
                ("Java", "*.java"), ("All", "*.*")
            ])
        if not path:
            return
        try:
            with open(path, 'r', encoding='utf-8', errors='replace') as f:
                code = f.read()
            self.code_viewer.set_code(code)
            self.file_label.config(text=os.path.basename(path))
            # Auto-detect language
            lang = detect_language(code, path)
            for k, v in LANG_MAP.items():
                if v == lang:
                    self.lang_var.set(k)
                    break
            self.status_bar.set(f"已打开: {path}", "success")
        except Exception as e:
            messagebox.showerror("错误", f"无法读取文件:\n{e}")

    def _run_analysis(self):
        code = self.code_viewer.get_code()
        if not code.strip():
            messagebox.showwarning("提示", "请先输入或打开源代码文件。")
            return

        lang_name = self.lang_var.get()
        language = LANG_MAP.get(lang_name) if lang_name != "自动检测" else None

        self.status_bar.set("正在分析...", "info")
        self.progress.pack(fill=tk.X, side=tk.BOTTOM, before=self.status_bar)
        self.progress.start(10)
        self._clear_results()

        def run():
            try:
                result = self.engine.analyze(code, language=language)
                self.root.after(0, lambda: self._display_results(result))
            except Exception as e:
                self.root.after(0, lambda: self._show_error(str(e)))

        threading.Thread(target=run, daemon=True).start()

    def _display_results(self, result):
        self.progress.stop()
        self.progress.pack_forget()
        self.current_result = result

        # Update stats
        stats = result.stats
        self.stat_labels["errors"].config(text=f"🔴 {stats.get('errors', 0)}")
        self.stat_labels["warnings"].config(text=f"🟡 {stats.get('warnings', 0)}")
        self.stat_labels["security"].config(text=f"🛡 {stats.get('security', 0)}")

        # Populate issue tree
        self.issue_tree.load_issues(result.issues)
        self._apply_filter()

        # Highlight code
        self.code_viewer.clear_highlights()
        for issue in result.issues:
            sev = issue.severity.value if issue.severity else "INFO"
            self.code_viewer.highlight_line(issue.line, sev)

        # CFG
        self.cfg_viewer.draw_cfg(result.cfg_blocks, result.cfg_edges)

        # Fix report
        self._update_fix_text(result.fix_report)

        # Taint summary
        self._update_taint_tab(result)

        lang = result.language.value
        total = stats.get('total_issues', 0)
        self.status_bar.set(
            f"✅ 分析完成 [{lang}] — 共 {total} 个问题 | "
            f"{stats.get('lines', 0)} 行 | {stats.get('cfg_blocks', 0)} 个基本块",
            "success")

    def _update_fix_text(self, text: str):
        self.fix_text.config(state=tk.NORMAL)
        self.fix_text.delete("1.0", tk.END)
        self.fix_text.insert("1.0", text)
        # Color coding
        self.fix_text.tag_configure("red", foreground=THEME["error"])
        self.fix_text.tag_configure("yellow", foreground=THEME["warning"])
        self.fix_text.tag_configure("green", foreground=THEME["success"])
        self.fix_text.tag_configure("blue", foreground=THEME["info"])
        self.fix_text.tag_configure("bold_accent", foreground=THEME["accent"],
                                     font=("Consolas", 10, "bold"))
        self.fix_text.config(state=tk.DISABLED)

    def _update_taint_tab(self, result):
        self.taint_text.config(state=tk.NORMAL)
        self.taint_text.delete("1.0", tk.END)

        taint_issues = [i for i in result.issues
                        if i.category and "污点" in i.category.value or
                        "注入" in (i.category.value if i.category else "")]

        self.taint_text.insert(tk.END, "═══ 污点分析报告 ═══\n\n", "header")

        if not taint_issues:
            self.taint_text.insert(tk.END, "✅ 未检测到污点流漏洞\n")
        else:
            for issue in taint_issues:
                self.taint_text.insert(tk.END, f"⚠ {issue.title}\n", "sink")
                self.taint_text.insert(tk.END, f"  行: {issue.line}\n")
                self.taint_text.insert(tk.END, f"  {issue.description}\n")
                self.taint_text.insert(tk.END, f"  CWE: {issue.cwe_id}\n", "source")
                self.taint_text.insert(tk.END, f"  修复: {issue.fix_suggestion}\n\n")

        self.taint_text.insert(tk.END, "\n═══ 污点传播规则 ═══\n\n", "header")
        self.taint_text.insert(tk.END,
            "Source（污点源）:\n"
            "  C/C++: scanf, gets, fgets, getenv, argv, recv\n"
            "  Java:  getParameter, getHeader, readLine, getCookies\n"
            "  Python: input(), request.GET/POST/args, sys.argv\n\n",
            "source")
        self.taint_text.insert(tk.END,
            "Sink（危险点）:\n"
            "  命令注入: system(), exec(), subprocess, Runtime.exec()\n"
            "  SQL注入:  execute(), query(), cursor.execute()\n"
            "  XSS:      innerHTML, document.write(), eval()\n"
            "  路径遍历: open(), fopen(), FileInputStream\n"
            "  格式字符串: printf(), sprintf(), String.format()\n",
            "sink")
        self.taint_text.config(state=tk.DISABLED)

    def _on_issue_select(self, issue: AnalysisIssue):
        if issue is None:
            return
        # Jump to line in code viewer
        self.code_viewer.jump_to_line(issue.line)
        # Show detail
        self.detail_text.config(state=tk.NORMAL)
        self.detail_text.delete("1.0", tk.END)
        sev = issue.severity.value if issue.severity else "INFO"
        cat = issue.category.value if issue.category else ""
        detail = (
            f"标题: {issue.title}\n"
            f"严重性: {sev}  |  类别: {cat}\n"
            f"位置: 第 {issue.line} 行\n"
            f"{'─'*50}\n"
            f"CWE编号: {issue.cwe_id}\n"
            f"CWE名称: {issue.cwe_name}\n"
            f"{'─'*50}\n"
            f"描述:\n  {issue.description}\n"
            f"{'─'*50}\n"
            f"问题代码:\n  {issue.code_snippet}\n"
            f"{'─'*50}\n"
            f"修复建议:\n  {issue.fix_suggestion}\n"
        )
        self.detail_text.insert("1.0", detail)
        self.detail_text.config(state=tk.DISABLED)

    def _apply_filter(self):
        if not self.current_result:
            return
        search = self.search_var.get().lower()
        active_sevs = {k for k, v in self.filter_vars.items() if v.get()}
        filtered = [
            i for i in self.current_result.issues
            if (i.severity.value if i.severity else "INFO") in active_sevs
            and (not search or search in i.title.lower()
                 or search in i.description.lower()
                 or search in str(i.line))
        ]
        self.issue_tree.load_issues(filtered)

    def _show_slice_dialog(self):
        if not self.current_result:
            messagebox.showinfo("提示", "请先运行分析。")
            return
        dlg = SliceDialog(self.root, THEME)
        self.root.wait_window(dlg.dialog)
        if dlg.result:
            line, var = dlg.result
            slice_output = self.engine.slice(self.current_result, line, var)
            self._show_text_window("程序切片结果", slice_output)

    def _show_text_window(self, title: str, text: str):
        win = tk.Toplevel(self.root)
        win.title(title)
        win.geometry("700x500")
        win.configure(bg=THEME["bg_dark"])
        txt = scrolledtext.ScrolledText(win, bg=THEME["bg_dark"], fg=THEME["text"],
                                         font=("Consolas", 10), wrap=tk.WORD, relief=tk.FLAT)
        txt.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)
        txt.insert("1.0", text)
        txt.config(state=tk.DISABLED)

    def _export_report(self):
        if not self.current_result:
            messagebox.showinfo("提示", "请先运行分析。")
            return
        path = filedialog.asksaveasfilename(
            title="导出分析报告",
            defaultextension=".txt",
            filetypes=[("文本报告", "*.txt"), ("All", "*.*")])
        if not path:
            return
        try:
            with open(path, 'w', encoding='utf-8') as f:
                f.write(self.current_result.fix_report)
            self.status_bar.set(f"报告已导出: {path}", "success")
        except Exception as e:
            messagebox.showerror("错误", str(e))

    def _clear_all(self):
        self.code_viewer.set_code("")
        self._clear_results()
        self.file_label.config(text="未打开文件")
        self.status_bar.set("就绪", "info")

    def _clear_results(self):
        self.issue_tree.clear()
        self.cfg_viewer.clear()
        for lbl in self.stat_labels.values():
            text = lbl.cget("text")
            emoji = text[0] if text else ""
            lbl.config(text=f"{emoji} 0")
        self.fix_text.config(state=tk.NORMAL)
        self.fix_text.delete("1.0", tk.END)
        self.fix_text.config(state=tk.DISABLED)
        self.taint_text.config(state=tk.NORMAL)
        self.taint_text.delete("1.0", tk.END)
        self.taint_text.config(state=tk.DISABLED)
        self.detail_text.config(state=tk.NORMAL)
        self.detail_text.delete("1.0", tk.END)
        self.detail_text.config(state=tk.DISABLED)
        self.current_result = None

    def _show_error(self, msg: str):
        self.progress.stop()
        self.progress.pack_forget()
        self.status_bar.set(f"❌ 错误: {msg}", "error")
        messagebox.showerror("分析错误", msg)

    def run(self):
        self.root.mainloop()
