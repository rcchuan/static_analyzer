"""
Custom GUI Widgets for Static Analyzer
"""
import sys
import tkinter as tk
from tkinter import ttk, scrolledtext
from typing import List, Optional, Callable, Dict, Tuple
import math

from core.ir import AnalysisIssue, BasicBlock, CFGEdge

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


class CFGViewer(tk.Frame):
    """Canvas-based CFG visualization with pan & scroll"""

    NODE_W, NODE_H = 140, 40
    H_GAP,  V_GAP  = 60,  60

    def __init__(self, parent, theme: Dict):
        super().__init__(parent, bg=theme["bg_dark"])
        self.theme = theme
        self._build()
        self.blocks:    List[BasicBlock]           = []
        self.edges:     List[CFGEdge]              = []
        self.positions: Dict[int, Tuple[int, int]] = {}
        self._drag_start = None

    def _build(self):
        self.canvas = tk.Canvas(self, bg=self.theme["bg_dark"],
                                highlightthickness=0)
        vbar = ttk.Scrollbar(self, orient=tk.VERTICAL,   command=self.canvas.yview)
        hbar = ttk.Scrollbar(self, orient=tk.HORIZONTAL, command=self.canvas.xview)
        self.canvas.configure(yscrollcommand=vbar.set, xscrollcommand=hbar.set)

        # 布局：滚动条贴边，画布填满剩余空间
        hbar.pack(side=tk.BOTTOM, fill=tk.X)
        vbar.pack(side=tk.RIGHT,  fill=tk.Y)
        self.canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # ── 垂直滚动（鼠标滚轮）──────────────────────────────────────
        self.canvas.bind("<MouseWheel>", self._on_wheel)   # Windows / Mac
        if IS_LINUX:
            self.canvas.bind("<Button-4>", self._on_wheel) # Linux 向上
            self.canvas.bind("<Button-5>", self._on_wheel) # Linux 向下

        # ── 水平滚动（Shift + 滚轮）──────────────────────────────────
        # Windows / Mac：Shift+MouseWheel
        self.canvas.bind("<Shift-MouseWheel>", self._on_hwheel)
        if IS_LINUX:
            # Linux 上水平滚动设备用 Button-6 / Button-7，
            # 但部分发行版不支持，用 try 包裹避免崩溃
            try:
                self.canvas.bind("<Button-6>", self._on_hwheel)
                self.canvas.bind("<Button-7>", self._on_hwheel)
            except tk.TclError:
                pass  # 该平台不支持，忽略

        # ── 左键拖拽平移 ─────────────────────────────────────────────
        self.canvas.bind("<ButtonPress-1>",   self._on_drag_start)
        self.canvas.bind("<B1-Motion>",       self._on_drag)
        self.canvas.bind("<ButtonRelease-1>", self._on_drag_end)

    # ── 绘制 ────────────────────────────────────────────────────────

    def draw_cfg(self, blocks: List[BasicBlock], edges: List[CFGEdge]):
        self.canvas.delete("all")
        if not blocks:
            self.canvas.create_text(
                300, 200, text="暂无控制流图数据",
                fill=self.theme["text_dim"], font=("Segoe UI", 12))
            return

        self.blocks    = blocks[:30]   # 限制节点数，避免卡顿
        self.edges     = edges
        self.positions = self._layout()

        # 先画边，再画节点（节点压在边上方）
        for edge in edges:
            if edge.src.id in self.positions and edge.dst.id in self.positions:
                self._draw_edge(edge)
        for bb in self.blocks:
            if bb.id in self.positions:
                self._draw_node(bb)

        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def _layout(self) -> Dict[int, Tuple[int, int]]:
        """BFS 分层布局，返回 {block_id: (x, y)}"""
        positions: Dict[int, Tuple[int, int]] = {}
        if not self.blocks:
            return positions

        visited: set = set()
        layers:  List[List[BasicBlock]] = []
        queue = [self.blocks[0]]
        visited.add(self.blocks[0].id)

        while queue:
            layer: List[BasicBlock] = []
            next_q: List[BasicBlock] = []
            for bb in queue:
                layer.append(bb)
                for succ in bb.successors:
                    if succ.id not in visited and \
                            any(b.id == succ.id for b in self.blocks):
                        visited.add(succ.id)
                        next_q.append(succ)
            layers.append(layer)
            queue = next_q

        # 未被 BFS 访问到的块（孤立块/死代码）单独成层
        for bb in self.blocks:
            if bb.id not in visited:
                layers.append([bb])

        x_start, y_start = 80, 60
        first_layer_w = len(layers[0]) * (self.NODE_W + self.H_GAP) - self.H_GAP

        for layer_i, layer in enumerate(layers):
            y = y_start + layer_i * (self.NODE_H + self.V_GAP)
            layer_w = len(layer) * (self.NODE_W + self.H_GAP) - self.H_GAP
            # 居中对齐：以第一层宽度为基准
            x_offset = x_start + max(0, (first_layer_w - layer_w) // 2)
            for node_i, bb in enumerate(layer):
                x = x_offset + node_i * (self.NODE_W + self.H_GAP)
                positions[bb.id] = (x, y)

        return positions

    def _draw_node(self, bb: BasicBlock):
        x,  y  = self.positions[bb.id]
        x2, y2 = x + self.NODE_W, y + self.NODE_H

        # ── 节点配色（fill/outline/text_color 均独立设置）───────────
        # 深色填充 + 亮色描边，保证文字在任何背景上都清晰可读
        if "ENTRY" in bb.label:
            fill       = "#1a4a2a"               # 深绿
            outline    = self.theme["success"]    # 亮绿描边
            text_color = "#ffffff"
        elif "EXIT" in bb.label:
            fill       = "#4a1a1a"               # 深红
            outline    = self.theme["error"]      # 亮红描边
            text_color = "#ffffff"
        elif "loop" in bb.label:
            fill       = "#1a2a4a"               # 深蓝
            outline    = self.theme["info"]       # 亮蓝描边
            text_color = self.theme["text"]
        elif "dead" in bb.label:
            fill       = "#2a1a2a"               # 深紫灰
            outline    = self.theme["text_dim"]   # 暗描边
            text_color = self.theme["text_dim"]
        else:
            fill       = self.theme["bg_light"]
            outline    = self.theme["accent"]
            text_color = self.theme["text"]

        # 阴影
        self.canvas.create_rectangle(
            x+3, y+3, x2+3, y2+3, fill="#111122", outline="")
        # 主矩形
        self.canvas.create_rectangle(
            x, y, x2, y2, fill=fill, outline=outline, width=2)

        # 节点标签（最多两行：标签 + 代码预览）
        label = bb.label or f"BB{bb.id}"
        if bb.instructions:
            first       = bb.instructions[0]
            preview     = (first.value or first.node_type.name)[:16]
            node_text   = f"{label}\n{preview}"
        else:
            node_text   = label

        self.canvas.create_text(
            x + self.NODE_W // 2, y + self.NODE_H // 2,
            text=node_text, fill=text_color,
            font=("Consolas", 8), justify=tk.CENTER)

        # 右上角指令数量徽章
        if bb.instructions:
            bx, by = x2 - 2, y - 2
            self.canvas.create_oval(
                bx-10, by-10, bx+10, by+10,
                fill=self.theme["accent"], outline="")
            self.canvas.create_text(
                bx, by, text=str(len(bb.instructions)),
                fill="white", font=("Segoe UI", 7, "bold"))

    def _draw_edge(self, edge: CFGEdge):
        sx, sy = self.positions.get(edge.src.id, (0, 0))
        dx, dy = self.positions.get(edge.dst.id, (0, 0))
        # 从源节点底部中心出发，到目标节点顶部中心
        sx += self.NODE_W // 2;  sy += self.NODE_H
        dx += self.NODE_W // 2

        color = {
            "true":      self.theme["success"],
            "false":     self.theme["error"],
            "exception": self.theme["warning"],
            "back":      self.theme["info"],
            "":          self.theme["text_dim"],
        }.get(edge.label, self.theme["text_dim"])

        if edge.label == "back":
            # 回边：左侧曲线，避免与正向边重叠
            cx = sx - 80
            cy = (sy + dy) // 2
            self.canvas.create_line(
                sx, sy, cx, cy, dx, dy,
                fill=color, width=1, smooth=True, dash=(4, 3))
        else:
            self.canvas.create_line(
                sx, sy, dx, dy,
                fill=color, width=1, arrow=tk.LAST)

        if edge.label:
            mx, my = (sx + dx) // 2, (sy + dy) // 2
            self.canvas.create_text(
                mx + 8, my, text=edge.label,
                fill=color, font=("Segoe UI", 7))

    def clear(self):
        self.canvas.delete("all")

    # ── 滚动事件处理 ─────────────────────────────────────────────────

    def _on_wheel(self, event):
        """垂直滚动：Windows/Mac 用 event.delta，Linux 用 event.num"""
        if IS_LINUX:
            self.canvas.yview_scroll(-2 if event.num == 4 else 2, "units")
        else:
            self.canvas.yview_scroll(-2 if event.delta > 0 else 2, "units")

    def _on_hwheel(self, event):
        """水平滚动：Shift+滚轮（Windows/Mac）或 Button-6/7（Linux）"""
        if IS_LINUX:
            self.canvas.xview_scroll(-2 if event.num == 6 else 2, "units")
        else:
            self.canvas.xview_scroll(-2 if event.delta > 0 else 2, "units")

    # ── 拖拽平移事件处理 ─────────────────────────────────────────────

    def _on_drag_start(self, event):
        """记录拖拽起点，并将光标改为"移动"样式"""
        self._drag_start = (event.x, event.y)
        self.canvas.config(cursor="fleur")

    def _on_drag(self, event):
        """每帧根据相对位移滚动画布，并更新起点（保证线性平移）"""
        if self._drag_start is None:
            return
        dx = event.x - self._drag_start[0]
        dy = event.y - self._drag_start[1]
        # 负号：鼠标向右 → 视图向左滚（内容向右移）
        self.canvas.xview_scroll(int(-dx / 2), "units")
        self.canvas.yview_scroll(int(-dy / 2), "units")
        # 关键：每帧更新起点，确保是"增量"而非"累积"位移
        self._drag_start = (event.x, event.y)

    def _on_drag_end(self, event):
        """松开鼠标，重置状态"""
        self._drag_start = None
        self.canvas.config(cursor="")


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


