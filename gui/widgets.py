"""
Custom GUI Widgets for Static Analyzer
"""
import sys
import tkinter as tk
from tkinter import ttk, scrolledtext
from typing import List, Optional, Callable, Dict, Tuple
import math
from core.ir import AnalysisIssue


# 平台判断，用于区分滚轮事件绑定方式
IS_WINDOWS = sys.platform == "win32"
IS_MAC     = sys.platform == "darwin"
IS_LINUX   = sys.platform.startswith("linux")


class CodeViewer(tk.Frame):
    """Syntax-highlighted code editor with line numbers"""

    def __init__(self, parent, theme: Dict):
        super().__init__(parent, bg=theme["bg_dark"])
        self.theme = theme
        self._build()

    def _build(self):
        self.text_frame = tk.Frame(self, bg=self.theme["bg_dark"])
        self.text_frame.pack(fill=tk.BOTH, expand=True)

        # Line numbers
        self.line_nums = tk.Text(
            self.text_frame, width=5, bg=self.theme["bg_mid"],
            fg=self.theme["text_dim"], font=("Consolas", 10),
            relief=tk.FLAT, state=tk.DISABLED, selectbackground=self.theme["bg_mid"])
        self.line_nums.pack(side=tk.LEFT, fill=tk.Y)

        # Code area
        self.code_text = scrolledtext.ScrolledText(
            self.text_frame, bg=self.theme["bg_dark"], fg=self.theme["text"],
            font=("Consolas", 10), wrap=tk.NONE, relief=tk.FLAT,
            insertbackground=self.theme["text"],
            selectbackground=self.theme["selection"],
            undo=True, tabs=("4c",))
        self.code_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Highlight tags
        self.code_text.tag_configure("error_line",
                                      background="#3d1a1a", foreground=self.theme["error"])
        self.code_text.tag_configure("warning_line",
                                      background="#3d2e1a", foreground=self.theme["warning"])
        self.code_text.tag_configure("info_line",
                                      background="#1a2a3d", foreground=self.theme["info"])
        self.code_text.tag_configure("current_line",
                                      background=self.theme["selection"])

        self.code_text.bind('<KeyRelease>', self._update_line_nums)
        self.code_text.bind('<MouseWheel>', self._sync_scroll)
        self.code_text.bind('<Button-4>', self._sync_scroll)
        self.code_text.bind('<Button-5>', self._sync_scroll)

    def set_code(self, code: str):
        self.code_text.config(state=tk.NORMAL)
        self.code_text.delete("1.0", tk.END)
        self.code_text.insert("1.0", code)
        self._update_line_nums()

    def get_code(self) -> str:
        return self.code_text.get("1.0", tk.END)

    def highlight_line(self, lineno: int, severity: str):
        tag = {"ERROR": "error_line", "WARNING": "warning_line"}.get(severity, "info_line")
        try:
            self.code_text.tag_add(tag, f"{lineno}.0", f"{lineno}.end")
        except Exception:
            pass

    def clear_highlights(self):
        for tag in ("error_line", "warning_line", "info_line", "current_line"):
            self.code_text.tag_remove(tag, "1.0", tk.END)

    def jump_to_line(self, lineno: int):
        try:
            self.code_text.tag_remove("current_line", "1.0", tk.END)
            self.code_text.tag_add("current_line", f"{lineno}.0", f"{lineno}.end")
            self.code_text.see(f"{lineno}.0")
            self.code_text.mark_set(tk.INSERT, f"{lineno}.0")
        except Exception:
            pass

    def _update_line_nums(self, event=None):
        self.line_nums.config(state=tk.NORMAL)
        self.line_nums.delete("1.0", tk.END)
        lines = self.code_text.get("1.0", tk.END).count('\n')
        nums = "\n".join(str(i) for i in range(1, lines + 2))
        self.line_nums.insert("1.0", nums)
        self.line_nums.config(state=tk.DISABLED)

    def _sync_scroll(self, event=None):
        self.line_nums.yview_moveto(self.code_text.yview()[0])


class IssueTreeView(tk.Frame):
    """Treeview widget for displaying analysis issues"""

    SEV_ICONS = {"ERROR": "🔴", "WARNING": "🟡", "INFO": "🔵"}
    COLS = [
        ("line",     "行",     60),
        ("severity", "严重性", 80),
        ("category", "类别",   100),
        ("title",    "问题标题", 280),
        ("cwe",      "CWE",   100),
        ("snippet",  "代码片段", 200),
    ]

    def __init__(self, parent, theme: Dict):
        super().__init__(parent, bg=theme["bg_dark"])
        self.theme = theme
        self._issues: List[AnalysisIssue] = []
        self._select_cb: Optional[Callable] = None
        self._build()

    def _build(self):
        cols = [c[0] for c in self.COLS]
        self.tree = ttk.Treeview(self, columns=cols, show="headings",
                                  selectmode="browse")

        for col_id, col_name, width in self.COLS:
            self.tree.heading(col_id, text=col_name,
                               command=lambda c=col_id: self._sort(c))
            self.tree.column(col_id, width=width, minwidth=40)

        # Tags for row colors
        self.tree.tag_configure("ERROR",   foreground=self.theme["error"])
        self.tree.tag_configure("WARNING", foreground=self.theme["warning"])
        self.tree.tag_configure("INFO",    foreground=self.theme["info"])

        vsb = ttk.Scrollbar(self, orient=tk.VERTICAL,   command=self.tree.yview)
        hsb = ttk.Scrollbar(self, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        self.tree.bind("<<TreeviewSelect>>", self._on_select)

    def load_issues(self, issues: List[AnalysisIssue]):
        self._issues = issues
        for item in self.tree.get_children():
            self.tree.delete(item)

        for issue in issues:
            sev = issue.severity.value if issue.severity else "INFO"
            cat = issue.category.value if issue.category else ""
            icon = self.SEV_ICONS.get(sev, "🔵")
            self.tree.insert("", tk.END,
                              values=(
                                  issue.line,
                                  f"{icon} {sev}",
                                  cat,
                                  issue.title,
                                  issue.cwe_id,
                                  issue.code_snippet[:40] if issue.code_snippet else ""
                              ),
                              tags=(sev,))

    def clear(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        self._issues = []

    def bind_selection(self, callback: Callable):
        self._select_cb = callback

    def _on_select(self, event=None):
        sel = self.tree.selection()
        if not sel or not self._select_cb:
            return
        idx = self.tree.index(sel[0])
        if 0 <= idx < len(self._issues):
            self._select_cb(self._issues[idx])

    def _sort(self, col: str):
        data = [(self.tree.set(k, col), k) for k in self.tree.get_children("")]
        try:
            data.sort(key=lambda x: int(x[0]))
        except ValueError:
            data.sort()
        for i, (_, k) in enumerate(data):
            self.tree.move(k, "", i)


class StatusBar(tk.Frame):
    def __init__(self, parent, theme: Dict):
        super().__init__(parent, bg=theme["bg_mid"], height=24)
        self.pack_propagate(False)
        self.theme = theme
        self.label = tk.Label(
            self, text="就绪 | 欢迎使用 MultiLang 静态代码分析器",
            bg=theme["bg_mid"], fg=theme["text_dim"],
            font=("Segoe UI", 8), anchor=tk.W)
        self.label.pack(side=tk.LEFT, padx=12, fill=tk.X, expand=True)

    def set(self, text: str, status: str = "info"):
        colors = {
            "success": self.theme["success"],
            "error":   self.theme["error"],
            "info":    self.theme["text_dim"],
            "warning": self.theme["warning"],
        }
        self.label.config(text=text, fg=colors.get(status, self.theme["text_dim"]))


class ToolbarButton(tk.Button):
    def __init__(self, parent, text, command, theme, accent=False):
        bg = theme["accent"] if accent else theme["bg_light"]
        super().__init__(
            parent, text=text, command=command,
            bg=bg, fg="white" if accent else theme["text"],
            font=("Segoe UI", 9, "bold"),
            relief=tk.FLAT, padx=12, pady=4,
            activebackground=theme["accent2"],
            activeforeground="white",
            cursor="hand2", borderwidth=0)


