"""
Taint Analysis Engine
Tracks data flow from sources (user input) to sinks (dangerous operations)
"""
import re
from typing import Dict, List, Set, Tuple
from core.ir import IRNode, NodeType, AnalysisIssue, AnalysisResult, Language


# Taint Sources by language
TAINT_SOURCES: Dict[str, Dict] = {
    "C": {
        "scanf": ("CWE-20", "Improper Input Validation"),
        "gets": ("CWE-120", "Buffer Copy without Checking Size"),
        "fgets": ("CWE-20", "Improper Input Validation"),
        "getenv": ("CWE-807", "Reliance on Untrusted Inputs"),
        "argv": ("CWE-20", "Improper Input Validation"),
        "read": ("CWE-20", "Improper Input Validation"),
        "recv": ("CWE-20", "Improper Input Validation"),
    },
    "C++": {
        "cin": ("CWE-20", "Improper Input Validation"),
        "getline": ("CWE-20", "Improper Input Validation"),
        "scanf": ("CWE-20", "Improper Input Validation"),
        "gets": ("CWE-120", "Buffer Copy without Checking Size"),
        "argv": ("CWE-20", "Improper Input Validation"),
    },
    "Java": {
        "getParameter": ("CWE-20", "Improper Input Validation"),
        "getHeader": ("CWE-20", "Improper Input Validation"),
        "getInputStream": ("CWE-20", "Improper Input Validation"),
        "readLine": ("CWE-20", "Improper Input Validation"),
        "nextLine": ("CWE-20", "Improper Input Validation"),
        "getQueryString": ("CWE-20", "Improper Input Validation"),
        "getCookies": ("CWE-20", "Improper Input Validation"),
        "getenv": ("CWE-807", "Reliance on Untrusted Inputs"),
    },
    "Python": {
        "input": ("CWE-20", "Improper Input Validation"),
        "request.GET": ("CWE-20", "Improper Input Validation"),
        "request.POST": ("CWE-20", "Improper Input Validation"),
        "request.args": ("CWE-20", "Improper Input Validation"),
        "request.form": ("CWE-20", "Improper Input Validation"),
        "os.environ": ("CWE-807", "Reliance on Untrusted Inputs"),
        "sys.argv": ("CWE-20", "Improper Input Validation"),
        "flask.request": ("CWE-20", "Improper Input Validation"),
    }
}

# Taint Sinks by category
TAINT_SINKS: Dict[str, Dict] = {
    "command_injection": {
        "functions": ["system", "exec", "popen", "subprocess.call", "subprocess.run",
                      "subprocess.Popen", "os.system", "os.popen", "os.execv",
                      "Runtime.exec", "ProcessBuilder", "ShellUtils"],
        "cwe_id": "CWE-78",
        "cwe_name": "OS Command Injection",
        "severity": "ERROR",
        "description": "不可信数据流入命令执行函数，可能导致OS命令注入",
        "fix": "使用参数化命令或白名单验证输入，避免直接将用户输入传入 shell 命令。"
    },
    "sql_injection": {
        "functions": ["execute", "query", "executeQuery", "executeUpdate",
                      "prepareStatement", "cursor.execute", "db.execute",
                      "connection.execute", "session.execute"],
        "cwe_id": "CWE-89",
        "cwe_name": "SQL Injection",
        "severity": "ERROR",
        "description": "不可信数据流入SQL执行函数，可能导致SQL注入",
        "fix": "使用参数化查询 (Prepared Statements) 代替字符串拼接构造SQL语句。"
    },
    "xss": {
        "functions": ["innerHTML", "document.write", "eval", "render_template_string",
                      "Markup", "jinja2.Template"],
        "cwe_id": "CWE-79",
        "cwe_name": "Cross-site Scripting (XSS)",
        "severity": "ERROR",
        "description": "不可信数据流入HTML输出函数，可能导致XSS攻击",
        "fix": "在输出前对用户输入进行HTML转义，使用安全的模板引擎。"
    },
    "path_traversal": {
        "functions": ["open", "fopen", "FileInputStream", "FileOutputStream",
                      "Path.of", "Paths.get", "os.path.join", "os.open"],
        "cwe_id": "CWE-22",
        "cwe_name": "Path Traversal",
        "severity": "ERROR",
        "description": "不可信数据用于文件路径构造，可能导致路径遍历攻击",
        "fix": "验证并规范化文件路径，使用白名单目录限制文件访问范围。"
    },
    "format_string": {
        "functions": ["printf", "sprintf", "fprintf", "snprintf", "syslog",
                      "String.format"],
        "cwe_id": "CWE-134",
        "cwe_name": "Use of Externally-Controlled Format String",
        "severity": "ERROR",
        "description": "不可信数据用作格式字符串，可能导致格式字符串漏洞",
        "fix": "永远不要将用户输入直接用作格式字符串，使用固定格式字符串如 printf(\"%s\", user_input)。"
    }
}


class TaintAnalyzer:
    def __init__(self, language: Language):
        self.language = language
        self.lang_key = language.value
        self.tainted_vars: Set[str] = set()
        self.taint_sources = TAINT_SOURCES.get(self.lang_key, {})

    def analyze(self, result: AnalysisResult) -> AnalysisResult:
        lines = result.source_lines
        code = "\n".join(lines)
        self.tainted_vars = set()

        self._detect_taint_sources(lines, result)
        self._detect_taint_sinks(lines, result)
        self._detect_buffer_overflow(lines, result)
        self._detect_null_pointer(lines, result)
        self._detect_resource_leak(lines, result)
        self._detect_hardcoded_secrets(lines, result)
        self._detect_weak_crypto(lines, result)
        return result

    def _detect_taint_sources(self, lines: List[str], result: AnalysisResult):
        for i, line in enumerate(lines, 1):
            for src, (cwe, name) in self.taint_sources.items():
                if src in line:
                    # Extract the variable being assigned tainted value
                    m = re.match(r'\s*(\w+)\s*=', line)
                    if m:
                        self.tainted_vars.add(m.group(1))

    def _detect_taint_sinks(self, lines: List[str], result: AnalysisResult):
        for i, line in enumerate(lines, 1):
            for category, sink_info in TAINT_SINKS.items():
                for func in sink_info["functions"]:
                    if func in line:
                        # Check if any tainted var is in arguments
                        is_tainted = False
                        for tainted_var in self.tainted_vars:
                            if tainted_var in line:
                                is_tainted = True
                                break

                        # Also detect direct source->sink in same expression
                        for src in self.taint_sources:
                            if src in line and func in line:
                                is_tainted = True
                                break

                        if is_tainted:
                            sev = (AnalysisIssue.Severity.ERROR
                                   if sink_info["severity"] == "ERROR"
                                   else AnalysisIssue.Severity.WARNING)
                            result.add_issue(AnalysisIssue(
                                title=f"污点漏洞: {sink_info['cwe_name']}",
                                description=sink_info["description"],
                                line=i,
                                severity=sev,
                                category=AnalysisIssue.Category.INJECTION,
                                cwe_id=sink_info["cwe_id"],
                                cwe_name=sink_info["cwe_name"],
                                fix_suggestion=sink_info["fix"],
                                code_snippet=line.strip(),
                                language=self.language
                            ))

    def _detect_buffer_overflow(self, lines: List[str], result: AnalysisResult):
        if self.language not in (Language.C, Language.CPP):
            return
        dangerous = {
            'gets': ("CWE-120", "Buffer Copy without Checking Size of Input",
                     "使用 fgets() 代替 gets()，并指定缓冲区大小。"),
            'strcpy': ("CWE-120", "Buffer Copy without Checking Size of Input",
                       "使用 strncpy() 代替 strcpy()，并验证目标缓冲区大小。"),
            'strcat': ("CWE-120", "Buffer Copy without Checking Size of Input",
                       "使用 strncat() 代替 strcat()，并检查缓冲区边界。"),
            'sprintf': ("CWE-120", "Buffer Copy without Checking Size of Input",
                        "使用 snprintf() 代替 sprintf()，并指定最大长度。"),
            'scanf': ("CWE-20", "Improper Input Validation",
                      "使用 scanf(\"%Ns\", buf) 形式限制输入长度，其中N为缓冲区大小减1。"),
        }
        for i, line in enumerate(lines, 1):
            for func, (cwe, name, fix) in dangerous.items():
                if re.search(r'\b' + func + r'\s*\(', line):
                    result.add_issue(AnalysisIssue(
                        title=f"危险函数使用: {func}()",
                        description=f"使用了不安全的函数 {func}()，可能导致缓冲区溢出",
                        line=i,
                        severity=AnalysisIssue.Severity.ERROR,
                        category=AnalysisIssue.Category.SECURITY,
                        cwe_id=cwe, cwe_name=name,
                        fix_suggestion=fix,
                        code_snippet=line.strip(),
                        language=self.language
                    ))

    def _detect_null_pointer(self, lines: List[str], result: AnalysisResult):
        """Detect potential null pointer dereferences"""
        if self.language in (Language.C, Language.CPP):
            # malloc without null check
            malloc_vars = set()
            for i, line in enumerate(lines, 1):
                m = re.search(r'(\w+)\s*=\s*(?:malloc|calloc|realloc)\s*\(', line)
                if m:
                    malloc_vars.add((m.group(1), i))
                for var, malloc_line in malloc_vars:
                    if var in line and f'{var} ==' not in line and f'== {var}' not in line:
                        if f'{var}->' in line or f'*{var}' in line or f'{var}[' in line:
                            result.add_issue(AnalysisIssue(
                                title="潜在空指针解引用",
                                description=f"指针 '{var}' 在第 {malloc_line} 行分配后未检查是否为NULL即被使用",
                                line=i,
                                severity=AnalysisIssue.Severity.WARNING,
                                category=AnalysisIssue.Category.NULL_PTR,
                                cwe_id="CWE-476",
                                cwe_name="NULL Pointer Dereference",
                                fix_suggestion=f"在使用 '{var}' 之前，检查 `if ({var} == NULL) {{ /* 处理错误 */ }}`",
                                code_snippet=line.strip(),
                                language=self.language
                            ))

        if self.language == Language.JAVA:
            for i, line in enumerate(lines, 1):
                if '.equals(' in line or '.length()' in line or '.size()' in line:
                    m = re.match(r'\s*(\w+)\.(?:equals|length|size|get|charAt)', line)
                    if m:
                        var = m.group(1)
                        if var not in ('this', 'self') and not var[0].isupper():
                            result.add_issue(AnalysisIssue(
                                title="潜在空指针异常 (NPE)",
                                description=f"对象 '{var}' 在调用方法前未检查是否为null",
                                line=i,
                                severity=AnalysisIssue.Severity.WARNING,
                                category=AnalysisIssue.Category.NULL_PTR,
                                cwe_id="CWE-476",
                                cwe_name="NULL Pointer Dereference",
                                fix_suggestion=f"在调用 '{var}' 的方法前，添加 `if ({var} != null)` 检查，或使用 Optional。",
                                code_snippet=line.strip(),
                                language=self.language
                            ))

    def _detect_resource_leak(self, lines: List[str], result: AnalysisResult):
        """Detect unclosed resources"""
        code = "\n".join(lines)
        if self.language == Language.PYTHON:
            # open() without context manager or close()
            for i, line in enumerate(lines, 1):
                if re.search(r'\bopen\s*\(', line) and 'with ' not in line:
                    m = re.match(r'\s*(\w+)\s*=\s*open', line)
                    if m:
                        var = m.group(1)
                        has_close = any(f'{var}.close()' in l for l in lines[i:])
                        has_with = False
                        if not has_close and not has_with:
                            result.add_issue(AnalysisIssue(
                                title="资源未关闭（文件泄漏）",
                                description=f"文件 '{var}' 打开后可能没有被正确关闭",
                                line=i,
                                severity=AnalysisIssue.Severity.WARNING,
                                category=AnalysisIssue.Category.RESOURCE,
                                cwe_id="CWE-772",
                                cwe_name="Missing Release of Resource after Effective Lifetime",
                                fix_suggestion=f"使用 `with open(...) as {var}:` 语法确保文件自动关闭。",
                                code_snippet=line.strip(),
                                language=self.language
                            ))

        if self.language in (Language.C, Language.CPP):
            fopen_vars = set()
            for i, line in enumerate(lines, 1):
                m = re.search(r'(\w+)\s*=\s*fopen\s*\(', line)
                if m:
                    fopen_vars.add(m.group(1))
            for var in fopen_vars:
                if f'fclose({var})' not in code:
                    result.add_issue(AnalysisIssue(
                        title="文件资源未关闭",
                        description=f"文件指针 '{var}' 通过 fopen() 打开，但未调用 fclose() 关闭",
                        line=1,
                        severity=AnalysisIssue.Severity.WARNING,
                        category=AnalysisIssue.Category.RESOURCE,
                        cwe_id="CWE-775",
                        cwe_name="Missing Release of File Descriptor or Handle after Effective Lifetime",
                        fix_suggestion=f"在所有退出路径上调用 `fclose({var})`，使用 goto cleanup 模式或 RAII。",
                        language=self.language
                    ))

    def _detect_hardcoded_secrets(self, lines: List[str], result: AnalysisResult):
        """Detect hardcoded passwords, API keys, secrets"""
        patterns = [
            (r'(?i)(password|passwd|pwd)\s*=\s*["\'][^"\']{3,}["\']', "硬编码密码"),
            (r'(?i)(api[_-]?key|apikey)\s*=\s*["\'][^"\']{8,}["\']', "硬编码API密钥"),
            (r'(?i)(secret[_-]?key|secret)\s*=\s*["\'][^"\']{8,}["\']', "硬编码密钥"),
            (r'(?i)(token)\s*=\s*["\'][^"\']{10,}["\']', "硬编码Token"),
            (r'(?i)(private[_-]?key)\s*=\s*["\'][^"\']{10,}["\']', "硬编码私钥"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, title in patterns:
                if re.search(pattern, line):
                    result.add_issue(AnalysisIssue(
                        title=f"安全风险: {title}",
                        description=f"在源代码中发现疑似硬编码的敏感凭证",
                        line=i,
                        severity=AnalysisIssue.Severity.ERROR,
                        category=AnalysisIssue.Category.SECURITY,
                        cwe_id="CWE-798",
                        cwe_name="Use of Hard-coded Credentials",
                        fix_suggestion="将敏感凭证移至环境变量或加密配置文件中，切勿在代码中硬编码。",
                        code_snippet=re.sub(r'=\s*["\'].*["\']', '= "***"', line.strip()),
                        language=self.language
                    ))

    def _detect_weak_crypto(self, lines: List[str], result: AnalysisResult):
        """Detect use of weak cryptographic algorithms"""
        weak_algos = {
            'MD5': ("CWE-327", "Use of a Broken or Risky Cryptographic Algorithm",
                    "使用 SHA-256 或 SHA-3 代替 MD5，MD5 已被证明不安全。"),
            'SHA1': ("CWE-327", "Use of a Broken or Risky Cryptographic Algorithm",
                     "使用 SHA-256 或 SHA-3 代替 SHA-1，SHA-1 已被弃用。"),
            'SHA-1': ("CWE-327", "Use of a Broken or Risky Cryptographic Algorithm",
                      "使用 SHA-256 或 SHA-3 代替 SHA-1。"),
            'DES': ("CWE-327", "Use of a Broken or Risky Cryptographic Algorithm",
                    "使用 AES-256 代替 DES，DES 密钥长度不足。"),
            'RC4': ("CWE-327", "Use of a Broken or Risky Cryptographic Algorithm",
                    "使用 AES-GCM 代替 RC4，RC4 存在严重安全漏洞。"),
            'Random()': ("CWE-330", "Use of Insufficiently Random Values",
                         "在安全场景中使用 SecureRandom (Java) 或 secrets 模块 (Python)。"),
            'Math.random': ("CWE-330", "Use of Insufficiently Random Values",
                            "在安全场景中使用 crypto.getRandomValues() 代替 Math.random()。"),
        }
        for i, line in enumerate(lines, 1):
            for algo, (cwe, name, fix) in weak_algos.items():
                if algo in line:
                    result.add_issue(AnalysisIssue(
                        title=f"弱加密算法: {algo}",
                        description=f"使用了已知不安全的加密算法 {algo}",
                        line=i,
                        severity=AnalysisIssue.Severity.WARNING,
                        category=AnalysisIssue.Category.SECURITY,
                        cwe_id=cwe, cwe_name=name,
                        fix_suggestion=fix,
                        code_snippet=line.strip(),
                        language=self.language
                    ))
