"""
Data Flow Analysis Engine
- Reaching Definitions Analysis
- Liveness Analysis
- Dead Code Detection
"""
import re
from typing import Set, Dict, List, Tuple, Optional
from core.ir import IRNode, NodeType, BasicBlock, AnalysisIssue, AnalysisResult, Language


class DataFlowAnalyzer:
    def __init__(self, language: Language = Language.PYTHON):
        self.language = language

    def analyze(self, result: AnalysisResult) -> AnalysisResult:
        if not result.cfg_blocks:
            return result
        self._compute_gen_kill(result.cfg_blocks)
        self._reaching_definitions(result)
        self._liveness_analysis(result)
        self._detect_issues(result)
        return result

    def _compute_gen_kill(self, blocks: List[BasicBlock]):
        for bb in blocks:
            defined_before = set()
            for instr in bb.instructions:
                defined = self._get_defined_vars(instr)
                used = self._get_used_vars(instr)
                # gen: vars used before being defined in this block
                for v in used:
                    if v not in defined_before:
                        bb.gen.add(v)
                for v in defined:
                    bb.kill.add(v)
                    defined_before.add(v)

    def _reaching_definitions(self, result: AnalysisResult):
        blocks = result.cfg_blocks
        if not blocks:
            return
        # Initialize
        for bb in blocks:
            bb.in_set = set()
            bb.out_set = set(bb.gen)

        changed = True
        iterations = 0
        while changed and iterations < 100:
            changed = False
            iterations += 1
            for bb in blocks:
                new_in: Set[str] = set()
                for pred in bb.predecessors:
                    new_in |= pred.out_set
                new_out = bb.gen | (new_in - bb.kill)
                if new_in != bb.in_set or new_out != bb.out_set:
                    bb.in_set = new_in
                    bb.out_set = new_out
                    changed = True

    def _liveness_analysis(self, result: AnalysisResult):
        blocks = result.cfg_blocks
        if not blocks:
            return
        for bb in blocks:
            bb.live_in = set()
            bb.live_out = set()

        changed = True
        iterations = 0
        while changed and iterations < 100:
            changed = False
            iterations += 1
            for bb in reversed(blocks):
                new_live_out: Set[str] = set()
                for succ in bb.successors:
                    new_live_out |= succ.live_in
                new_live_in = bb.gen | (new_live_out - bb.kill)
                if new_live_in != bb.live_in or new_live_out != bb.live_out:
                    bb.live_in = new_live_in
                    bb.live_out = new_live_out
                    changed = True

    def _detect_issues(self, result: AnalysisResult):
        lines = result.source_lines
        self._detect_uninitialized(result, lines)
        self._detect_dead_assignments(result, lines)
        self._detect_dead_code_blocks(result, lines)
        self._detect_infinite_loops(result, lines)

    def _detect_uninitialized(self, result: AnalysisResult, lines: List[str]):
        """Detect variables used before definition"""
        defined_vars: Set[str] = set()
        # Collect all parameter names first
        if result.ir_root:
            for node in self._walk(result.ir_root):
                if node.node_type == NodeType.PARAM_DECL and node.value:
                    defined_vars.add(node.value)

        for bb in result.cfg_blocks:
            for instr in bb.instructions:
                used = self._get_used_vars(instr)
                defined = self._get_defined_vars(instr)
                for v in used:
                    if (v not in defined_vars and
                            v not in bb.in_set and
                            not v.startswith('__') and
                            not self._is_builtin(v) and
                            len(v) > 1):
                        snippet = lines[instr.line - 1] if 0 < instr.line <= len(lines) else ""
                        result.add_issue(AnalysisIssue(
                            title="可能使用未初始化变量",
                            description=f"变量 '{v}' 在第 {instr.line} 行可能未初始化就被使用",
                            line=instr.line,
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
        """Detect truly dead local variable assignments.

        Conservative rules (prefer false negatives over false positives)
        ---------------------------------------------------------------
        * SKIP global variables: lines at brace_depth==0 are global scope.
        * SKIP field writes: this.x, self.x, ptr->x, obj.x, arr[i].
        * SKIP assignments where RHS reads from a struct/pointer field.
        * SKIP type-keyword-only "variables" (pList, pPCB, extern, const…).
        * SKIP function-call statements misidentified as assignments.
        * SKIP variables used anywhere in ALL blocks (whole-function scope).
        * SKIP ALL_CAPS and Title-case names (likely globals/constants).
        * SKIP single-char names used as loop counters etc.
        """
        import re as _re

        # C/C++ type keywords and storage-class specifiers that are NOT var names
        TYPE_KEYWORDS = {
            'int','long','short','char','float','double','bool','void',
            'unsigned','signed','auto','const','static','extern','volatile',
            'register','inline','virtual','explicit','mutable','constexpr',
            'String','var','size_t','ssize_t','ptrdiff_t',
            # Windows / POSIX typedefs that start with p or are uppercase
            'HANDLE','DWORD','BOOL','LPVOID','LPCSTR','LPSTR','LPARAM','WPARAM',
            'pPCB','pList','PCB','CRITICAL_SECTION','WINAPI',
            # storage class
            'typedef','struct','enum','union','namespace','class',
        }

        def is_type_keyword(name: str) -> bool:
            if name in TYPE_KEYWORDS:
                return True
            # Pointer typedefs: starts with p + uppercase  e.g. pPCB pList
            if len(name) > 1 and name[0] == 'p' and name[1].isupper():
                return True
            # ALL_CAPS usually macros/globals
            if name.isupper() and len(name) > 1:
                return True
            return False

        def is_field_write(raw: str) -> bool:
            """True for this.x, self.x, ptr->x, obj.x, arr[i] on LHS."""
            s = raw.strip()
            lhs = s.split('=')[0].strip() if '=' in s else s
            return ('this.' in lhs or 'self.' in lhs
                    or '->' in lhs or '.' in lhs or '[' in lhs)

        def is_function_call(raw: str) -> bool:
            """Detect lines that are pure function calls, not assignments."""
            s = raw.strip()
            # No '=' at all, or = is inside () — it's a call
            eq_pos = s.find('=')
            paren_pos = s.find('(')
            if paren_pos != -1 and (eq_pos == -1 or paren_pos < eq_pos):
                return True
            return False

        def extract_var_name(raw: str) -> str:
            """
            Extract the actual variable name from an assignment/declaration.
            Handles:
              int x = 0          -> x
              pPCB ptr = NULL    -> ptr
              const int X = 30   -> X
              exiting = false    -> exiting
            Returns '' if extraction fails or result is a type keyword.
            """
            s = raw.strip()
            # Remove inline comments
            s = _re.sub(r'//.*$', '', s).strip()
            s = _re.sub(r'/\*.*?\*/', '', s).strip()
            if '=' not in s:
                return ''
            lhs = s.split('=')[0].strip()
            # lhs may be: "int x", "pPCB ptr", "const int X", "exiting"
            tokens = lhs.split()
            if not tokens:
                return ''
            var = tokens[-1]   # last token is always the variable name
            # Strip pointer stars and reference ampersands
            var = var.lstrip('*&')
            # Validate: must be a valid identifier
            if not _re.match(r'^[a-zA-Z_]\w*$', var):
                return ''
            # Must not be a type keyword
            if is_type_keyword(var):
                return ''
            # Must not be a storage specifier
            if var in ('extern', 'static', 'volatile', 'register', 'inline'):
                return ''
            return var

        # ── Compute brace depth per line to identify global vs local scope ──
        brace_depth_per_line: List[int] = []
        depth = 0
        for raw_line in lines:
            s = _re.sub(r'//.*$', '', raw_line)
            s = _re.sub(r'"[^"]*"', '', s)   # remove string contents
            brace_depth_per_line.append(depth)
            depth += s.count('{') - s.count('}')
            if depth < 0:
                depth = 0

        # ── Collect ALL variable names read anywhere in all blocks ──────────
        all_used: Set[str] = set()
        for bb in result.cfg_blocks:
            for instr in bb.instructions:
                all_used |= self._get_used_vars(instr)
            all_used |= bb.live_in | bb.live_out | bb.gen

        # Supplement with raw-text identifier scan of entire source.
        # This captures cross-function usage that the simplified IR cannot
        # model, preventing false 'dead assignment' reports for vars used
        # in other functions (e.g. freePCB, newPcb, hSchedule, exiting).
        # Extract all identifiers from raw source text
        import re as _re2
        _raw_src = '\n'.join(lines)
        _ident_pat = _re2.compile('[a-zA-Z_][a-zA-Z0-9_]*')
        all_used |= set(_ident_pat.findall(_raw_src))

        # ── Scan instructions and report only clear dead local assigns ───────
        for bb in result.cfg_blocks:
            for i, instr in enumerate(bb.instructions):
                if instr.node_type != NodeType.ASSIGN or not instr.value:
                    continue

                line_idx = instr.line - 1
                if line_idx < 0 or line_idx >= len(lines):
                    continue
                raw_snippet = lines[line_idx].strip()

                # Skip global-scope lines (brace_depth == 0 at that line)
                if line_idx < len(brace_depth_per_line):
                    if brace_depth_per_line[line_idx] == 0:
                        continue

                # Skip field writes
                if is_field_write(raw_snippet):
                    continue

                # Skip if RHS reads from struct field (ptr->x or obj.x)
                rhs = raw_snippet.split('=', 1)[1].strip() if '=' in raw_snippet else ''
                if '->' in rhs or ('.' in rhs and not rhs.startswith('"')):
                    continue

                # Skip pure function calls
                if is_function_call(raw_snippet):
                    continue

                # Extract real variable name
                var = extract_var_name(raw_snippet)
                if not var or len(var) <= 1:
                    continue

                # Skip if used anywhere in all blocks
                if var in all_used:
                    continue

                # Skip live_out of this block
                if var in bb.live_out:
                    continue

                # Skip if used in any subsequent instruction in same block
                if any(var in self._get_used_vars(later)
                       for later in bb.instructions[i + 1:]):
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

    def _detect_dead_code_blocks(self, result: AnalysisResult, lines: List[str]):
        """Detect unreachable basic blocks.

        False-positive guards
        ---------------------
        * Skip blocks whose label is 'dead_code': these are synthetic CFG nodes
          created by CFGBuilder immediately after a RETURN/BREAK statement.
          If they contain only structural tokens (braces, preprocessor lines,
          closing delimiters) they are NOT real dead code — they are artefacts
          of the parser seeing '}' after 'return'.
        * Only report a block if it contains at least one real statement, i.e.
          an IRNode whose node_type is not UNKNOWN and whose value is not a
          bare brace or preprocessor directive.
        """
        import re as _re

        # Tokens that are pure structural delimiters, not real statements
        STRUCTURAL = _re.compile(r'^[\{\}#\s]*$')

        def has_real_statements(bb) -> bool:
            """True only if the block contains at least one genuine statement."""
            from core.ir import NodeType as NT
            for instr in bb.instructions:
                if instr.node_type == NT.UNKNOWN:
                    # UNKNOWN nodes from brace/preprocessor lines are not real
                    val = (instr.value or "").strip()
                    if STRUCTURAL.match(val) or val.startswith('#'):
                        continue
                    # UNKNOWN with real content (e.g. an expression) counts
                    if len(val) > 2:
                        return True
                else:
                    # Any typed node (ASSIGN, CALL, RETURN, …) is real
                    return True
            return False

        reachable = set()
        if result.cfg_blocks:
            stack = [result.cfg_blocks[0]]
            while stack:
                bb = stack.pop()
                if bb.id in reachable:
                    continue
                reachable.add(bb.id)
                for succ in bb.successors:
                    stack.append(succ)

        for bb in result.cfg_blocks:
            skip_labels = ("EXIT", "ENTRY", "dead_code")
            truly_disconnected = (len(bb.predecessors) == 0
                                  and bb.id not in reachable)
            if truly_disconnected \
                    and bb.instructions \
                    and bb.label not in skip_labels \
                    and not any(sl in bb.label for sl in skip_labels) \
                    and has_real_statements(bb):
                first_instr = bb.instructions[0]
                snippet = lines[first_instr.line - 1] if 0 < first_instr.line <= len(lines) else ""
                result.add_issue(AnalysisIssue(
                    title="不可达代码（死代码）",
                    description=f"代码块从第 {first_instr.line} 行开始永远不会被执行",
                    line=first_instr.line,
                    severity=AnalysisIssue.Severity.WARNING,
                    category=AnalysisIssue.Category.DEAD_CODE,
                    cwe_id="CWE-561",
                    cwe_name="Dead Code",
                    fix_suggestion="删除不可达代码，或修正控制流逻辑使其可达。",
                    code_snippet=snippet.strip(),
                    language=self.language
                ))

    def _detect_infinite_loops(self, result: AnalysisResult, lines: List[str]):
        """Detect loops with no exit condition"""
        for bb in result.cfg_blocks:
            if 'loop_header' in bb.label:
                has_exit = any(e.label == "false" for e in result.cfg_edges if e.src == bb)
                has_break_in_body = False
                for body_bb in result.cfg_blocks:
                    if 'loop_body' in body_bb.label:
                        for instr in body_bb.instructions:
                            if instr.node_type == NodeType.BREAK:
                                has_break_in_body = True
                if not has_exit and not has_break_in_body and bb.instructions:
                    first = bb.instructions[0] if bb.instructions else None
                    line = first.line if first else 0
                    snippet = lines[line - 1] if 0 < line <= len(lines) else ""
                    result.add_issue(AnalysisIssue(
                        title="潜在无限循环",
                        description=f"在第 {line} 行附近的循环可能没有退出条件",
                        line=line,
                        severity=AnalysisIssue.Severity.WARNING,
                        category=AnalysisIssue.Category.CODE_SMELL,
                        cwe_id="CWE-835",
                        cwe_name="Loop with Unreachable Exit Condition",
                        fix_suggestion="确保循环中包含有效的退出条件或 break 语句。",
                        code_snippet=snippet.strip(),
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
            # right side variables
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
        yield node
        for child in node.children:
            yield from self._walk(child)
