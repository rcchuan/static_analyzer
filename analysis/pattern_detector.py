"""
Pattern-based detector for code smells and security issues
Language-specific regex patterns
"""
import re
from typing import List
from core.ir import AnalysisIssue, AnalysisResult, Language


class PatternDetector:
    def __init__(self, language: Language):
        self.language = language

    def detect(self, result: AnalysisResult) -> AnalysisResult:
        lines = result.source_lines
        code = "\n".join(lines)

        if self.language in (Language.C, Language.CPP):
            self._detect_c_cpp(lines, result)
        if self.language == Language.JAVA:
            self._detect_java(lines, result)
        if self.language == Language.PYTHON:
            self._detect_python(lines, result)

        # Common patterns for all languages
        self._detect_common(lines, result)
        return result

    def _detect_c_cpp(self, lines: List[str], result: AnalysisResult):
        for i, line in enumerate(lines, 1):
            s = line.strip()

            # Integer overflow
            if re.search(r'\b(int|short)\s+\w+\s*=\s*\d{8,}', line):
                result.add_issue(AnalysisIssue(
                    title="潜在整数溢出",
                    description="使用 int 存储超出范围的值，可能导致整数溢出",
                    line=i, severity=AnalysisIssue.Severity.WARNING,
                    category=AnalysisIssue.Category.SECURITY,
                    cwe_id="CWE-190", cwe_name="Integer Overflow or Wraparound",
                    fix_suggestion="使用 long long 或无符号类型，并检查运算前后的值范围。",
                    code_snippet=s, language=self.language))

            # Double free potential
            if re.search(r'\bfree\s*\(\s*\w+\s*\)', line):
                result.add_issue(AnalysisIssue(
                    title="内存释放风险",
                    description="调用 free() 后应将指针设置为 NULL 防止悬空指针",
                    line=i, severity=AnalysisIssue.Severity.WARNING,
                    category=AnalysisIssue.Category.SECURITY,
                    cwe_id="CWE-415", cwe_name="Double Free",
                    fix_suggestion="调用 free(ptr) 后立即执行 ptr = NULL。",
                    code_snippet=s, language=self.language))

            # memcpy without bounds check
            if re.search(r'\bmemcpy\s*\(', line):
                result.add_issue(AnalysisIssue(
                    title="memcpy 潜在缓冲区溢出",
                    description="memcpy 调用未见边界检查，可能导致缓冲区溢出",
                    line=i, severity=AnalysisIssue.Severity.WARNING,
                    category=AnalysisIssue.Category.SECURITY,
                    cwe_id="CWE-125", cwe_name="Out-of-bounds Read",
                    fix_suggestion="在调用 memcpy 前验证 size 参数不超过目标缓冲区大小。",
                    code_snippet=s, language=self.language))

            # Use after free pattern
            if re.search(r'\bdelete\b.*\bdelete\b', line):
                result.add_issue(AnalysisIssue(
                    title="可能的双重释放",
                    description="同一行出现多次 delete，可能导致双重释放",
                    line=i, severity=AnalysisIssue.Severity.ERROR,
                    category=AnalysisIssue.Category.SECURITY,
                    cwe_id="CWE-415", cwe_name="Double Free",
                    fix_suggestion="确保每个对象只被 delete 一次，删除后将指针设为 nullptr。",
                    code_snippet=s, language=self.language))

    def _detect_java(self, lines: List[str], result: AnalysisResult):
        in_catch = False
        for i, line in enumerate(lines, 1):
            s = line.strip()

            # Empty catch block
            if re.match(r'catch\s*\(', s):
                in_catch = True
            if in_catch and s == '}':
                in_catch = False
            if in_catch and s == '' or (in_catch and re.match(r'catch\s*\(', s)):
                result.add_issue(AnalysisIssue(
                    title="空 catch 块（异常吞噬）",
                    description="捕获异常后未做任何处理，错误被静默忽略",
                    line=i, severity=AnalysisIssue.Severity.WARNING,
                    category=AnalysisIssue.Category.CODE_SMELL,
                    cwe_id="CWE-390", cwe_name="Detection of Error Condition Without Action",
                    fix_suggestion="在 catch 块中至少记录异常日志，或向上抛出异常。",
                    code_snippet=s, language=self.language))
                in_catch = False

            # String comparison with == instead of .equals()
            if re.search(r'\bString\b.*==', line) and 'equals' not in line:
                result.add_issue(AnalysisIssue(
                    title="字符串比较错误",
                    description="使用 == 比较字符串对象，应使用 .equals() 方法",
                    line=i, severity=AnalysisIssue.Severity.WARNING,
                    category=AnalysisIssue.Category.CODE_SMELL,
                    cwe_id="CWE-597", cwe_name="Use of Wrong Operator in String Comparison",
                    fix_suggestion="将 str1 == str2 改为 str1.equals(str2) 或 Objects.equals(str1, str2)。",
                    code_snippet=s, language=self.language))

            # System.exit in library/method
            if 'System.exit(' in line:
                result.add_issue(AnalysisIssue(
                    title="不当使用 System.exit()",
                    description="在非 main 方法中调用 System.exit() 会导致整个JVM退出",
                    line=i, severity=AnalysisIssue.Severity.WARNING,
                    category=AnalysisIssue.Category.CODE_SMELL,
                    cwe_id="CWE-382", cwe_name="J2EE Bad Practices: Use of System.exit()",
                    fix_suggestion="抛出适当的异常代替 System.exit()，让调用者决定如何处理。",
                    code_snippet=s, language=self.language))

            # printStackTrace without logger
            if 'printStackTrace()' in line:
                result.add_issue(AnalysisIssue(
                    title="使用 printStackTrace() 代替日志框架",
                    description="printStackTrace() 输出到标准错误流，生产环境应使用日志框架",
                    line=i, severity=AnalysisIssue.Severity.INFO,
                    category=AnalysisIssue.Category.CODE_SMELL,
                    cwe_id="CWE-200", cwe_name="Exposure of Sensitive Information",
                    fix_suggestion="使用 logger.error(\"...\", e) 代替 e.printStackTrace()。",
                    code_snippet=s, language=self.language))

    def _detect_python(self, lines: List[str], result: AnalysisResult):
        for i, line in enumerate(lines, 1):
            s = line.strip()

            # eval() usage
            if re.search(r'\beval\s*\(', line):
                result.add_issue(AnalysisIssue(
                    title="危险的 eval() 使用",
                    description="eval() 可执行任意代码，极易导致代码注入漏洞",
                    line=i, severity=AnalysisIssue.Severity.ERROR,
                    category=AnalysisIssue.Category.SECURITY,
                    cwe_id="CWE-95", cwe_name="Improper Neutralization of Directives in Dynamically Evaluated Code",
                    fix_suggestion="避免使用 eval()。如需解析数据，使用 json.loads() 或 ast.literal_eval()。",
                    code_snippet=s, language=self.language))

            # exec() usage
            if re.search(r'\bexec\s*\(', line):
                result.add_issue(AnalysisIssue(
                    title="危险的 exec() 使用",
                    description="exec() 执行动态代码，存在代码注入风险",
                    line=i, severity=AnalysisIssue.Severity.ERROR,
                    category=AnalysisIssue.Category.SECURITY,
                    cwe_id="CWE-78", cwe_name="OS Command Injection",
                    fix_suggestion="避免 exec()，重构代码逻辑或使用安全的替代方案。",
                    code_snippet=s, language=self.language))

            # Bare except
            if re.match(r'except\s*:', s) or re.match(r'except\s+Exception\s*:', s):
                result.add_issue(AnalysisIssue(
                    title="过于宽泛的异常捕获",
                    description="裸 except: 或 except Exception: 会捕获所有异常，掩盖真实错误",
                    line=i, severity=AnalysisIssue.Severity.WARNING,
                    category=AnalysisIssue.Category.CODE_SMELL,
                    cwe_id="CWE-390", cwe_name="Detection of Error Condition Without Action",
                    fix_suggestion="捕获具体的异常类型，如 except ValueError, TypeError:",
                    code_snippet=s, language=self.language))

            # assert for security checks
            if re.match(r'\bassert\b', s) and ('password' in s.lower() or 'auth' in s.lower()):
                result.add_issue(AnalysisIssue(
                    title="使用 assert 进行安全检查",
                    description="assert 在优化模式(-O)下会被禁用，不能用于安全校验",
                    line=i, severity=AnalysisIssue.Severity.ERROR,
                    category=AnalysisIssue.Category.SECURITY,
                    cwe_id="CWE-617", cwe_name="Reachable Assertion",
                    fix_suggestion="使用显式的 if 条件和异常抛出代替 assert 进行安全检查。",
                    code_snippet=s, language=self.language))

            # mutable default argument
            if re.match(r'def\s+\w+\s*\(.*=\s*[\[\{]', line):
                result.add_issue(AnalysisIssue(
                    title="可变默认参数（代码坏味道）",
                    description="使用可变对象（list/dict）作为默认参数，会在函数调用间共享状态",
                    line=i, severity=AnalysisIssue.Severity.WARNING,
                    category=AnalysisIssue.Category.CODE_SMELL,
                    cwe_id="CWE-1188", cwe_name="Insecure Default Initialization of Resource",
                    fix_suggestion="将默认值改为 None，并在函数体内初始化: `if param is None: param = []`",
                    code_snippet=s, language=self.language))

    def _detect_common(self, lines: List[str], result: AnalysisResult):
        """Common patterns across all languages"""
        long_method_start = None
        func_line_count = 0

        # Track main() body for magic-number exemption
        _in_main_func = False
        _main_brace_depth = 0
        _cur_brace_depth = 0

        for i, line in enumerate(lines, 1):
            # Update brace depth tracking for main() exemption
            _s = re.sub(r'//.*$', '', line)
            _cur_brace_depth += _s.count('{') - _s.count('}')
            if _cur_brace_depth < 0: _cur_brace_depth = 0
            if re.search(r'\bmain\s*\(', line) and '{' in _s:
                _in_main_func = True
                _main_brace_depth = _cur_brace_depth - 1
            if _in_main_func and _cur_brace_depth <= _main_brace_depth:
                _in_main_func = False
            s = line.strip()

            # Magic numbers — only flag bare numeric literals in EXPRESSION context.
            # Explicitly skip:
            #   - Constant definitions:  const int X = 30;  /  final int X = 30;
            #   - Macro definitions:     #define X 30
            #   - Array size that IS a named constant reference
            #   - Version strings, CWE references, comment-only lines
            _is_const_defn = bool(re.search(
                r'\b(?:const|final|constexpr|#define|static\s+final)\b', line))
            _is_comment_only = s.startswith('//') or s.startswith('*') or s.startswith('#')
            # Exempt literals inside main() — test/demo code, low-value noise
            _in_main_body = _in_main_func
            _has_magic = bool(re.search(
                r'(?<!["\'a-zA-Z_])\b(?!0\b|1\b|2\b|3\b|4\b|-1\b)\d{2,}\b(?!["\'a-zA-Z_.])',
                line))
            _in_expression = bool(re.search(
                r'(?:Sleep|sleep|usleep|malloc|calloc|\[\d|=\s*\d|\(\d|,\s*\d)',
                line))
            if (_has_magic and _in_expression
                    and not _is_const_defn and not _is_comment_only
                    and not _in_main_body
                    and not re.search(r'CWE|version|Version|\d\.\d|0x[0-9a-fA-F]', line)):
                result.add_issue(AnalysisIssue(
                    title="魔术数字（代码坏味道）",
                    description=f"代码中存在未命名的数字常量，降低可读性",
                    line=i, severity=AnalysisIssue.Severity.INFO,
                    category=AnalysisIssue.Category.CODE_SMELL,
                    cwe_id="CWE-1078", cwe_name="Inappropriate Source Code Style or Formatting",
                    fix_suggestion="将魔术数字提取为有意义的命名常量（const/final/CAPS_NAME）。",
                    code_snippet=s, language=self.language))

            # TODO/FIXME/HACK comments
            if re.search(r'\b(TODO|FIXME|HACK|XXX|BUG|TEMP)\b', line, re.IGNORECASE):
                result.add_issue(AnalysisIssue(
                    title=f"未完成代码标记",
                    description=f"发现待处理标记，表明存在未完成或临时代码",
                    line=i, severity=AnalysisIssue.Severity.INFO,
                    category=AnalysisIssue.Category.CODE_SMELL,
                    cwe_id="CWE-1078", cwe_name="Inappropriate Source Code Style or Formatting",
                    fix_suggestion="处理并移除 TODO/FIXME 标记，不要将临时代码提交到生产环境。",
                    code_snippet=s, language=self.language))

        # Check for very long functions (> 50 lines)
        # Use brace-depth tracking for accurate function body boundaries
        func_open_re = re.compile(
            r'\b(?:def|void|int|double|float|char|bool|long|short|unsigned|'
            r'String|auto|HANDLE|DWORD|WINAPI|\w+)\s+'
            r'(\w+)\s*\([^)]*\)\s*(?:const\s*)?\{?\s*$'
        )
        in_func_name  = None
        in_func_start = None
        brace_depth   = 0
        func_brace_at_open = 0
        i = 0
        while i < len(lines):
            line = lines[i]
            stripped = line.strip()
            code = re.sub(r'//.*$', '', stripped)
            opens  = code.count('{')
            closes = code.count('}')

            if in_func_name is None:
                m = func_open_re.match(stripped)
                if m:
                    # Check next non-blank line for '{' if not on this line
                    has_open = '{' in code
                    if not has_open and i + 1 < len(lines):
                        nxt = lines[i+1].strip()
                        has_open = nxt.startswith('{')
                    if has_open:
                        in_func_name  = m.group(1)
                        in_func_start = i + 1
                        func_brace_at_open = brace_depth

            brace_depth += opens - closes
            if brace_depth < 0:
                brace_depth = 0

            if in_func_name is not None:
                # Function ends when depth returns to where it was before the {
                if brace_depth <= func_brace_at_open and i > in_func_start:
                    length = i - in_func_start + 1
                    if length > 50:
                        start_line = in_func_start
                        result.add_issue(AnalysisIssue(
                            title="函数过长（代码坏味道）",
                            description=(
                                f"函数 '{in_func_name}' 约 {length} 行，"
                                f"超过建议的50行，违反单一职责原则"
                            ),
                            line=start_line,
                            severity=AnalysisIssue.Severity.INFO,
                            category=AnalysisIssue.Category.CODE_SMELL,
                            cwe_id="CWE-1121",
                            cwe_name="Excessive McCabe Cyclomatic Complexity",
                            fix_suggestion=(
                                f"将函数 '{in_func_name}' 拆分为多个职责单一的小函数，"
                                f"每个函数不超过50行。"
                            ),
                            code_snippet=lines[start_line-1].strip() if lines else "",
                            language=self.language))
                    in_func_name  = None
                    in_func_start = None
            i += 1
