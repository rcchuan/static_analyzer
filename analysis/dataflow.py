"""
Data Flow Analysis Engine
- Uninitialized Variable Detection
- Dead Assignment Detection
"""
import re
from typing import Set, List
from core.ir import IRNode, NodeType, AnalysisIssue, AnalysisResult, Language


class DataFlowAnalyzer:
    def __init__(self, language: Language = Language.PYTHON):
        self.language = language

    def analyze(self, result: AnalysisResult) -> AnalysisResult:
        if not result.ir_root:
            return result
        self._detect_issues(result)
        return result

    def _detect_issues(self, result: AnalysisResult):
        lines = result.source_lines
        self._detect_uninitialized(result, lines)
        self._detect_dead_assignments(result, lines)

    def _detect_uninitialized(self, result: AnalysisResult, lines: List[str]):
        """Detect variables used before definition by walking the IR tree."""
        defined_vars: Set[str] = set()
        # Collect all parameter names first
        for node in self._walk(result.ir_root):
            if node.node_type == NodeType.PARAM_DECL and node.value:
                defined_vars.add(node.value)

        for node in self._walk(result.ir_root):
            used = self._get_used_vars(node)
            defined = self._get_defined_vars(node)
            for v in used:
                if (v not in defined_vars and
                        not v.startswith('__') and
                        not self._is_builtin(v) and
                        len(v) > 1):
                    snippet = lines[node.line - 1] if 0 < node.line <= len(lines) else ""
                    result.add_issue(AnalysisIssue(
                        title="可能使用未初始化变量",
                        description=f"变量 '{v}' 在第 {node.line} 行可能未初始化就被使用",
                        line=node.line,
                        severity=AnalysisIssue.Severity.WARNING,
                        category=AnalysisIssue.Category.UNINITIALIZED,
                        cwe_id="CWE-457",
                        cwe_name="Use of Uninitialized Variable",
                        fix_suggestion=f"在使用 '{v}' 之前，请先对其进行初始化赋值。",
                        code_snippet=snippet.strip(),
                        language=self.language
                    ))
            defined_vars |= defined

    def _detect_dead_assignments(self, result: AnalysisResult, lines: List[str]):
        """Detect dead local variable assignments — a variable assigned but
        never read afterwards within its function scope.

        Uses IR tree walking to find assignments, then checks whether the
        variable name appears in subsequent IR nodes of the same function.
        """
        import re as _re

        # ── Collect all variable names read in the entire IR tree ──────────
        all_used: Set[str] = set()
        for node in self._walk(result.ir_root):
            all_used |= self._get_used_vars(node)

        # Supplement with raw-text identifier scan of entire source
        _raw_src = '\n'.join(lines)
        _ident_pat = _re.compile('[a-zA-Z_][a-zA-Z0-9_]*')
        all_used |= set(_ident_pat.findall(_raw_src))

        # C/C++ type keywords
        TYPE_KEYWORDS = {
            'int', 'long', 'short', 'char', 'float', 'double', 'bool', 'void',
            'unsigned', 'signed', 'auto', 'const', 'static', 'extern', 'volatile',
            'register', 'inline', 'virtual', 'explicit', 'mutable', 'constexpr',
            'String', 'var', 'size_t', 'ssize_t', 'ptrdiff_t',
            'HANDLE', 'DWORD', 'BOOL', 'LPVOID', 'LPCSTR', 'LPSTR', 'LPARAM', 'WPARAM',
            'pPCB', 'pList', 'PCB', 'CRITICAL_SECTION', 'WINAPI',
            'typedef', 'struct', 'enum', 'union', 'namespace', 'class',
        }

        # Compute brace depth per line for global scope filtering
        brace_depth_per_line: List[int] = []
        depth = 0
        for raw_line in lines:
            s = _re.sub(r'//.*$', '', raw_line)
            s = _re.sub(r'"[^"]*"', '', s)
            brace_depth_per_line.append(depth)
            depth += s.count('{') - s.count('}')
            if depth < 0:
                depth = 0

        # ── Find functions and scan their assignments ──────────────────────
        for func_node in self._walk(result.ir_root):
            if func_node.node_type != NodeType.FUNCTION:
                continue

            # Collect all assignments within this function
            assign_nodes = [
                n for n in self._walk(func_node)
                if n.node_type == NodeType.ASSIGN and n.value
            ]

            for i, instr in enumerate(assign_nodes):
                line_idx = instr.line - 1
                if line_idx < 0 or line_idx >= len(lines):
                    continue
                raw_snippet = lines[line_idx].strip()

                # Skip global-scope
                if line_idx < len(brace_depth_per_line):
                    if brace_depth_per_line[line_idx] == 0:
                        continue

                # Skip field writes
                lhs = raw_snippet.split('=')[0].strip() if '=' in raw_snippet else raw_snippet
                if 'this.' in lhs or 'self.' in lhs or '->' in lhs or '.' in lhs or '[' in lhs:
                    continue

                # Skip function calls
                eq_pos = raw_snippet.find('=')
                paren_pos = raw_snippet.find('(')
                if paren_pos != -1 and (eq_pos == -1 or paren_pos < eq_pos):
                    continue

                # Extract var name
                s = _re.sub(r'//.*$', '', raw_snippet).strip()
                s = _re.sub(r'/\*.*?\*/', '', s).strip()
                if '=' not in s:
                    continue
                lhs_tokens = s.split('=')[0].strip().split()
                if not lhs_tokens:
                    continue
                var = lhs_tokens[-1].lstrip('*&')
                if not _re.match(r'^[a-zA-Z_]\w*$', var):
                    continue
                if var in TYPE_KEYWORDS:
                    continue
                if var in ('extern', 'static', 'volatile', 'register', 'inline'):
                    continue
                if var.isupper() and len(var) > 1:
                    continue
                if len(var) <= 1:
                    continue
                # Pointer typedef: starts with p + uppercase
                if len(var) > 1 and var[0] == 'p' and var[1].isupper():
                    continue

                # Skip if used anywhere
                if var in all_used:
                    continue

                # Check subsequent instructions in same function
                if any(var in self._get_used_vars(later)
                       for later in assign_nodes[i + 1:]):
                    continue

                result.add_issue(AnalysisIssue(
                    title="无效赋值（死代码）",
                    description=(
                        f"局部变量 '{var}' 在第 {instr.line} 行被赋值，"
                        f"但在此后整个函数作用域内从未被读取"
                    ),
                    line=instr.line,
                    severity=AnalysisIssue.Severity.WARNING,
                    category=AnalysisIssue.Category.DEAD_CODE,
                    cwe_id="CWE-563",
                    cwe_name="Assignment to Variable without Use",
                    fix_suggestion=(
                        f"移除对 '{var}' 的无效赋值，"
                        f"或在后续逻辑中使用该变量。"
                    ),
                    code_snippet=raw_snippet,
                    language=self.language
                ))

    def _get_defined_vars(self, node: IRNode) -> Set[str]:
        if node.node_type in (NodeType.ASSIGN, NodeType.VAR_DECL) and node.value:
            v = node.value.split('=')[0].strip().split(',')[0].strip()
            parts = v.split()
            name = parts[-1] if parts else v
            name = re.sub(r'[^a-zA-Z0-9_]', '', name)
            if name:
                return {name}
        if node.node_type == NodeType.PARAM_DECL and node.value:
            return {node.value}
        return set()

    def _get_used_vars(self, node: IRNode) -> Set[str]:
        used = set()
        if node.node_type == NodeType.IDENTIFIER and node.value:
            used.add(node.value)
        elif node.node_type == NodeType.ASSIGN and node.value:
            if '=' in node.value:
                rhs = node.value.split('=', 1)[1]
                used |= set(re.findall(r'\b([a-zA-Z_]\w*)\b', rhs))
        elif node.node_type == NodeType.CALL and node.value:
            pass
        for child in node.children:
            used |= self._get_used_vars(child)
        return {v for v in used if not self._is_builtin(v) and len(v) > 1}

    def _is_builtin(self, name: str) -> bool:
        builtins = {
            'print', 'input', 'len', 'range', 'str', 'int', 'float', 'list',
            'dict', 'set', 'tuple', 'bool', 'None', 'True', 'False', 'self',
            'cls', 'super', 'type', 'isinstance', 'hasattr', 'getattr',
            'open', 'close', 'read', 'write', 'append', 'System', 'Math',
            'null', 'nullptr', 'this', 'new', 'delete', 'sizeof',
            'printf', 'scanf', 'malloc', 'free', 'cout', 'cin', 'endl',
        }
        return name in builtins

    def _walk(self, node: IRNode):
        if node is None:
            return
        yield node
        for child in node.children:
            yield from self._walk(child)
