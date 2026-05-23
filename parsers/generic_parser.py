"""
Generic regex-based parser for C, C++, Java
Produces IR nodes via pattern matching (no external dependencies)
"""
import re
from typing import List, Optional
from core.ir import IRNode, NodeType, Language, AnalysisIssue, AnalysisResult


class GenericParser:
    """Regex/heuristic-based parser for C, C++, Java"""

    def __init__(self, language: Language):
        self.language = language
        self.issues: List[AnalysisIssue] = []

    def parse(self, code: str) -> AnalysisResult:
        result = AnalysisResult(language=self.language)
        lines = code.splitlines()
        result.source_lines = lines
        self.issues = []

        ir_root = IRNode(NodeType.PROGRAM, line=0)

        # Two-pass parse:
        # Pass 1: build a flat list of (lineno, stripped, IRNode)
        # Pass 2: use brace depth to assign statements to their enclosing function
        self._build_tree(lines, ir_root)

        self._check_braces(code, result)
        self._check_parens(lines, result)
        self._check_strings(lines, result)
        self._check_semicolons(lines, result)

        result.ir_root = ir_root
        result.issues = self.issues
        return result

    # ──────────────────────────────────────────────────────────────────
    def _build_tree(self, lines: List[str], ir_root: IRNode):
        """
        Walk source lines while tracking brace depth.
        Top-level function declarations become FUNCTION IRNodes;
        statements inside them become children of the nearest function.
        Top-level non-function lines (e.g. #include, global vars) become
        children of ir_root with depth 0.
        """
        # Stack of (IRNode, open_brace_depth_when_entered)
        # We start with the program root at depth 0
        scope_stack: List[IRNode] = [ir_root]   # current container
        brace_depth = 0
        # brace depth at which each scope was entered
        scope_depth_stack: List[int] = [0]

        for i, raw_line in enumerate(lines, 1):
            stripped = raw_line.strip()

            # ── skip blank / comment lines ────────────────────────────
            if not stripped \
                    or stripped.startswith('//') \
                    or stripped.startswith('*') \
                    or stripped.startswith('/*'):
                # Still count braces in comments? No — comments are skipped.
                continue

            # ── strip inline comment for brace counting ───────────────
            code_part = re.sub(r'//.*$', '', stripped)
            code_part = re.sub(r'/\*.*?\*/', '', code_part)

            # ── skip pure brace lines (don't add to IR) ───────────────
            is_pure_brace = re.match(r'^[{}\s]+$', code_part.strip())

            # ── count braces on this line ─────────────────────────────
            open_count  = code_part.count('{')
            close_count = code_part.count('}')

            # ── pop scopes closed by '}' BEFORE processing the line ───
            # (closing braces at the start reduce depth first)
            for _ in range(close_count):
                brace_depth -= 1
                if brace_depth < 0:
                    brace_depth = 0
                # Pop scope if we've returned to the depth it was opened at
                if len(scope_stack) > 1 and brace_depth < scope_depth_stack[-1]:
                    scope_stack.pop()
                    scope_depth_stack.pop()

            if is_pure_brace:
                # Pure brace line: open braces push depth, already handled closes
                brace_depth += open_count
                continue

            # ── parse the line into an IRNode ─────────────────────────
            node = self._parse_line(stripped, i)

            # ── attach to current scope ───────────────────────────────
            current_scope = scope_stack[-1]
            current_scope.add_child(node)

            # ── if this line opens a new scope (function/class), push ─
            if open_count > 0:
                brace_depth += open_count
                if node.node_type == NodeType.FUNCTION:
                    scope_stack.append(node)
                    scope_depth_stack.append(brace_depth)

    # ──────────────────────────────────────────────────────────────────
    def _parse_line(self, line: str, lineno: int) -> IRNode:
        # Preprocessor
        if line.startswith('#'):
            return IRNode(NodeType.UNKNOWN, value=line[:60], line=lineno)

        # Function declaration (has parentheses, not ending with ;)
        if re.search(r'\b\w[\w\s\*<>]*\s+\w+\s*\([^)]*\)\s*(\{|$)', line) \
                and not line.endswith(';') \
                and not re.match(r'\s*(if|while|for|switch)\b', line):
            m = re.search(r'(\w+)\s*\(', line)
            name = m.group(1) if m else ""
            return IRNode(NodeType.FUNCTION, value=name, line=lineno)

        # Control flow
        if re.match(r'if\s*\(',          line): return IRNode(NodeType.IF,       line=lineno)
        if re.match(r'else\s*(if\s*\()?' ,line): return IRNode(NodeType.ELSE,    line=lineno)
        if re.match(r'while\s*\(',       line): return IRNode(NodeType.WHILE,    line=lineno)
        if re.match(r'for\s*\(',         line): return IRNode(NodeType.FOR,      line=lineno)
        if re.match(r'return\b',         line): return IRNode(NodeType.RETURN,   line=lineno)
        if re.match(r'try\s*\{',         line): return IRNode(NodeType.TRY,      line=lineno)
        if re.match(r'catch\s*\(',       line): return IRNode(NodeType.CATCH,    line=lineno)
        if re.match(r'(throw|throws)\b', line): return IRNode(NodeType.THROW,    line=lineno)
        if re.match(r'break\b',          line): return IRNode(NodeType.BREAK,    line=lineno)
        if re.match(r'continue\b',       line): return IRNode(NodeType.CONTINUE, line=lineno)

        # Variable declaration
        if re.match(r'(int|long|float|double|char|bool|String|var|auto'
                    r'|void\s*\*|unsigned|signed|size_t|uint\w+|int\w+)\s+', line):
            m = re.search(r'\b(\w+)\s*[=;\[]', line)
            return IRNode(NodeType.VAR_DECL, value=m.group(1) if m else "", line=lineno)

        # Assignment
        if re.search(r'\w\s*([+\-*/%&|^]|<<|>>)?=\s*\S', line) \
                and not re.match(r'(if|while|for)\b', line):
            m = re.match(r'(\w+)\s*', line)
            return IRNode(NodeType.ASSIGN, value=m.group(1) if m else "", line=lineno)

        # Function call
        m = re.match(r'(\w[\w.]*)\s*\(', line)
        if m:
            return IRNode(NodeType.CALL, value=m.group(1), line=lineno)

        return IRNode(NodeType.UNKNOWN, value=line[:50], line=lineno)

    # ──────────────────────────────────────────────────────────────────
    def _check_braces(self, code: str, result: AnalysisResult):
        depth = 0
        for i, ch in enumerate(code):
            if ch == '{':
                depth += 1
            elif ch == '}':
                depth -= 1
            if depth < 0:
                line = code[:i].count('\n') + 1
                self.issues.append(AnalysisIssue(
                    title="括号不匹配", description="检测到多余的 '}'",
                    line=line, severity=AnalysisIssue.Severity.ERROR,
                    category=AnalysisIssue.Category.SYNTAX,
                    cwe_id="CWE-691", cwe_name="Insufficient Control Flow Management",
                    fix_suggestion="检查并匹配所有花括号 '{}'。",
                    language=self.language))
                depth = 0
        if depth != 0:
            self.issues.append(AnalysisIssue(
                title="括号不匹配",
                description=f"花括号未闭合，缺少 {depth} 个 '}}'",
                line=len(result.source_lines),
                severity=AnalysisIssue.Severity.ERROR,
                category=AnalysisIssue.Category.SYNTAX,
                cwe_id="CWE-691", cwe_name="Insufficient Control Flow Management",
                fix_suggestion="在文件末尾添加缺失的 '}'。",
                language=self.language))

    # ──────────────────────────────────────────────────────────────────
    def _check_parens(self, lines: List[str], result: AnalysisResult):
        """
        Detect unmatched parentheses ( ) in C / C++ / Java source.

        Algorithm
        ---------
        * Per-line: strip string literals so parens inside "..." are ignored.
        * Track cumulative paren depth across lines (multi-line expressions).
        * When depth goes negative  -> extra ')' on this line -> ERROR.
        * When a statement boundary (line ending with ';') is reached while
          depth > 0  -> unclosed '(' -> ERROR, report on the opening line.
        * All issues go to self.issues (merged into result.issues by parse()).
        """
        import re as _re

        def count_parens(s: str) -> tuple:
            """Return (open, close) ignoring parens inside string literals."""
            # Remove string contents (keep the quotes as placeholders)
            cleaned = _re.sub(r'"(?:[^"\\]|\\.)*"', lambda m: '""', s)
            cleaned = _re.sub(r"'(?:[^'\\]|\\.)*'", lambda m: "''", cleaned)
            # Remove comments
            cleaned = _re.sub(r'//.*$', '', cleaned)
            cleaned = _re.sub(r'/\*.*?\*/', '', cleaned)
            return cleaned.count('('), cleaned.count(')')

        in_block_comment = False
        paren_depth  = 0
        open_line    = None   # line where current unclosed '(' first appeared

        for lineno, raw_line in enumerate(lines, 1):
            stripped = raw_line.strip()

            # Block comment tracking
            if in_block_comment:
                if '*/' in stripped:
                    in_block_comment = False
                continue
            if stripped.startswith('/*') and '*/' not in stripped:
                in_block_comment = True
                continue

            # Skip blank / comment / pure-brace lines
            if (not stripped
                    or stripped.startswith('//')
                    or stripped.startswith('*')
                    or _re.match(r'^[{}\s]*$', stripped)):
                continue

            opens, closes = count_parens(stripped)
            prev_depth = paren_depth

            # Extra ')' before tracking opens
            if prev_depth + opens - closes < 0:
                self.issues.append(AnalysisIssue(
                    title="圆括号不匹配",
                    description=f"第 {lineno} 行存在多余的 ')'",
                    line=lineno,
                    severity=AnalysisIssue.Severity.ERROR,
                    category=AnalysisIssue.Category.SYNTAX,
                    cwe_id="CWE-691",
                    cwe_name="Insufficient Control Flow Management",
                    fix_suggestion="删除多余的 ')' 或补充对应的 '('。",
                    code_snippet=stripped,
                    language=self.language,
                ))
                paren_depth = 0
                open_line   = None
                continue

            paren_depth += opens - closes

            # Record where an unclosed '(' first appeared
            if prev_depth == 0 and paren_depth > 0:
                open_line = lineno

            # Check for statement boundary: line ends with ';' after comment strip
            code_end = _re.sub(r'//.*$', '', stripped).strip()
            code_end = _re.sub(r'/\*.*?\*/', '', code_end).strip()

            if code_end.endswith(';') and paren_depth > 0:
                # Unclosed paren at end of statement
                report_line   = open_line if open_line else lineno
                snippet       = lines[report_line - 1].strip() if report_line <= len(lines) else stripped
                missing       = paren_depth
                fixed_snippet = snippet.rstrip(';').rstrip() + ')' * missing + ';'
                self.issues.append(AnalysisIssue(
                    title="圆括号不匹配",
                    description=(
                        f"第 {report_line} 行的表达式缺少 {missing} 个 ')'，"
                        f"在第 {lineno} 行语句结束时仍未闭合"
                    ),
                    line=report_line,
                    severity=AnalysisIssue.Severity.ERROR,
                    category=AnalysisIssue.Category.SYNTAX,
                    cwe_id="CWE-691",
                    cwe_name="Insufficient Control Flow Management",
                    fix_suggestion=f"补充缺失的 ')': `{fixed_snippet}`",
                    code_snippet=snippet,
                    language=self.language,
                ))
                paren_depth = 0
                open_line   = None

            elif code_end.endswith(';'):
                # Normal statement end — reset depth
                paren_depth = 0
                open_line   = None

    # ──────────────────────────────────────────────────────────────────
    def _check_strings(self, lines, result):
        # Detect unclosed string literals (odd unescaped double-quotes per line).
        # Applies to C, C++, Java where strings open and close on the same line.
        import re as _re

        def count_dquotes(s):
            # Count double-quotes not preceded by backslash
            count = 0
            i = 0
            while i < len(s):
                if s[i] == '\\' and i + 1 < len(s):
                    i += 2      # skip escaped char
                    continue
                if s[i] == '"':
                    count += 1
                i += 1
            return count

        in_block_comment = False

        for lineno, raw_line in enumerate(lines, 1):
            stripped = raw_line.strip()

            # Track block comments
            if in_block_comment:
                if '*/' in stripped:
                    in_block_comment = False
                continue
            if stripped.startswith('/*') and '*/' not in stripped:
                in_block_comment = True
                continue

            # Skip blank / comment lines
            if not stripped or stripped.startswith('//') or stripped.startswith('*'):
                continue

            # Strip trailing // comment (only when outside a string literal)
            code_part = stripped
            q = 0
            for ci, ch in enumerate(stripped):
                if ch == '"' and (ci == 0 or stripped[ci - 1] != '\\'):
                    q += 1
                if (ch == '/' and ci + 1 < len(stripped)
                        and stripped[ci + 1] == '/'
                        and q % 2 == 0):
                    code_part = stripped[:ci].strip()
                    break

            # Remove fully-enclosed inline block comments
            code_part = _re.sub(r'/\*[^*]*\*+(?:[^/*][^*]*\*+)*/', '', code_part).strip()
            if not code_part:
                continue

            n = count_dquotes(code_part)
            if n % 2 == 1:
                # Odd number of quotes -> unclosed string
                desc = "第 " + str(lineno) + " 行的字符串字面量缺少配对的双引号"
                fix  = ("检查并补全第 " + str(lineno) + " 行缺失的双引号。"
                        + " 当前行: " + stripped)
                self.issues.append(AnalysisIssue(
                    title="字符串字面量未闭合",
                    description=desc,
                    line=lineno,
                    severity=AnalysisIssue.Severity.ERROR,
                    category=AnalysisIssue.Category.SYNTAX,
                    cwe_id="CWE-691",
                    cwe_name="Insufficient Control Flow Management",
                    fix_suggestion=fix,
                    code_snippet=stripped,
                    language=self.language,
                ))


    # ──────────────────────────────────────────────────────────────────
    @staticmethod
    def _strip_line_comments(s: str) -> str:
        s = re.sub(r'/\*[^*]*\*+(?:[^/*][^*]*\*+)*/', '', s)
        s = re.sub(r'//.*$', '', s)
        return s.strip()

    @staticmethod
    def _next_code_line(lines: List[str], current_idx: int) -> str:
        for j in range(current_idx + 1, len(lines)):
            s = lines[j].strip()
            if s and not s.startswith('//') and not s.startswith('*'):
                return s
        return ''

    def _check_semicolons(self, lines: List[str], result: AnalysisResult):
        if self.language == Language.PYTHON:
            return

        SKIP_RE = re.compile(
            r"""^(
                \#
              | //
              | /\*
              | \*
              | @\w
              | (public|private|protected|static|final
                 |abstract|synchronized|native
                 |volatile|transient|default|interface
                 |enum)\s*(\{|$)
              | (class|struct|union|namespace)\s+\w
              | (if|else(\s+if)?|for|while|do|switch
                 |try|catch|finally|case|default)\b
              | \}
              | \{
            )""", re.VERBOSE)

        OK_ENDS = (';', '{', '}', ',', '\\', ':', '*/', '//')

        in_block_comment = False
        paren_depth = 0

        for idx, raw_line in enumerate(lines):
            lineno = idx + 1
            stripped = raw_line.strip()

            if in_block_comment:
                if '*/' in stripped:
                    in_block_comment = False
                continue
            if '/*' in stripped and '*/' not in stripped and stripped.startswith('/*'):
                in_block_comment = True
                continue

            if not stripped:
                continue

            code_part = self._strip_line_comments(stripped)
            if not code_part:
                continue

            if SKIP_RE.match(stripped):
                paren_depth += code_part.count('(') - code_part.count(')')
                if paren_depth < 0:
                    paren_depth = 0
                continue

            if code_part.startswith('.'):
                paren_depth += code_part.count('(') - code_part.count(')')
                if paren_depth < 0:
                    paren_depth = 0
                continue

            delta = code_part.count('(') - code_part.count(')')
            paren_depth += delta
            if paren_depth > 0:
                continue
            if paren_depth < 0:
                paren_depth = 0

            if any(code_part.endswith(e) for e in OK_ENDS):
                continue

            next_line = self._next_code_line(lines, idx)
            if next_line.startswith('.'):
                continue

            # Skip method/function DEFINITION signature lines:
            # A declaration like 'public void foo(int x)' where the NEXT
            # code line is '{' is a function body opener, NOT a statement
            # needing a semicolon. Only abstract method DECLARATIONS (in
            # interfaces/abstract classes) end with ';'.
            if code_part.endswith(')') and next_line.startswith('{'):
                continue
            # Also skip lines that are clearly method signatures:
            # they have () and contain access modifiers / return types
            if (code_part.endswith(')')
                    and re.search(
                        r'\b(?:public|protected|private|static|void|'
                        r'int|double|float|bool|char|String|long|short|'
                        r'HANDLE|DWORD|VOID|WINAPI|virtual|override|'
                        r'inline|explicit|operator)\b',
                        code_part)):
                # Only report if we're sure it's a statement (not a signature)
                # Signatures: contain '(' with identifier before it
                # Statements: assignments, calls as standalone expressions
                # Heuristic: if line has a return-type keyword at start → signature
                if re.match(
                    r'\s*(?:public|protected|private|static|virtual|'
                    r'inline|explicit|override|\w+\s+)?'
                    r'(?:void|int|double|float|bool|char|String|long|short|'
                    r'HANDLE|DWORD|WINAPI|\w+)\s+\w+\s*\(',
                    code_part):
                    continue

            is_statement = (
                bool(re.search(r'\w\s*(\+\+|--)$', code_part))
                or bool(re.match(r'(\+\+|--)\s*\w', code_part))
                or bool(re.search(r'\w\s*([+\-*/%&|^]|<<|>>)?=\s*\S', code_part))
                or code_part.endswith(')')
                or (('<<' in code_part or '>>' in code_part)
                    and bool(re.search(r'\b(cout|cerr|clog|cin)\b', code_part)))
                or bool(re.match(
                    r'(return|break|continue|throw'
                    r'|delete(\s*\[\])?|free'
                    r'|System\.out\.(print|println|printf|format)'
                    r'|printf|scanf|fprintf|snprintf|sprintf|puts|gets|fgets|fputs'
                    r'|int|long|short|char|float|double|bool|void\s*\*'
                    r'|unsigned|signed|String|var|auto'
                    r'|size_t|ssize_t|ptrdiff_t'
                    r'|uint8_t|uint16_t|uint32_t|uint64_t'
                    r'|int8_t|int16_t|int32_t|int64_t)\b',
                    code_part))
            )

            if is_statement:
                self.issues.append(AnalysisIssue(
                    title="缺少分号",
                    description="语句末尾缺少分号 ';'",
                    line=lineno,
                    col=len(raw_line.rstrip()),
                    severity=AnalysisIssue.Severity.ERROR,
                    category=AnalysisIssue.Category.SYNTAX,
                    cwe_id="CWE-691",
                    cwe_name="Insufficient Control Flow Management",
                    fix_suggestion=f"在该行末尾添加分号: `{code_part};`",
                    code_snippet=stripped,
                    language=self.language,
                ))
