"""
Intermediate Representation (IR) Layer
Unified AST representation for C/C++, Java, Python analysis
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import List, Optional, Dict, Any, Set


class NodeType(Enum):
    PROGRAM = auto(); FUNCTION = auto(); BLOCK = auto()
    IF = auto(); ELSE = auto(); WHILE = auto(); FOR = auto()
    FOREACH = auto(); RETURN = auto(); BREAK = auto()
    CONTINUE = auto(); TRY = auto(); CATCH = auto()
    FINALLY = auto(); THROW = auto()
    VAR_DECL = auto(); PARAM_DECL = auto(); CLASS_DECL = auto()
    IMPORT = auto(); ASSIGN = auto(); BINARY_OP = auto()
    UNARY_OP = auto(); CALL = auto(); MEMBER_ACCESS = auto()
    ARRAY_ACCESS = auto(); CAST = auto(); TERNARY = auto()
    IDENTIFIER = auto(); LITERAL = auto(); STRING_LITERAL = auto()
    NULL = auto(); EXPR_STMT = auto(); PRINT = auto(); UNKNOWN = auto()


class Language(Enum):
    C = "C"; CPP = "C++"; JAVA = "Java"; PYTHON = "Python"; UNKNOWN = "Unknown"


@dataclass
class IRNode:
    node_type: NodeType
    value: Optional[str] = None
    line: int = 0
    col: int = 0
    children: List['IRNode'] = field(default_factory=list)
    parent: Optional['IRNode'] = field(default=None, repr=False)
    metadata: Dict[str, Any] = field(default_factory=dict)
    taint: bool = False
    taint_sources: Set[str] = field(default_factory=set)
    reaching_defs: Set[str] = field(default_factory=set)
    live_vars: Set[str] = field(default_factory=set)

    def add_child(self, child: 'IRNode') -> 'IRNode':
        child.parent = self
        self.children.append(child)
        return child

    def __repr__(self):
        return f"IRNode({self.node_type.name}, val={self.value!r}, line={self.line})"


@dataclass
class AnalysisIssue:
    class Severity(Enum):
        ERROR = "ERROR"; WARNING = "WARNING"; INFO = "INFO"

    class Category(Enum):
        SYNTAX = "语法错误"; SECURITY = "安全漏洞"; CODE_SMELL = "代码坏味道"
        DATA_FLOW = "数据流缺陷"; TAINT = "污点漏洞"; DEAD_CODE = "死代码"
        RESOURCE = "资源问题"; NULL_PTR = "空指针风险"
        UNINITIALIZED = "未初始化变量"; INJECTION = "注入漏洞"

    title: str
    description: str
    line: int
    col: int = 0
    severity: Any = None
    category: Any = None
    cwe_id: str = ""
    cwe_name: str = ""
    fix_suggestion: str = ""
    code_snippet: str = ""
    language: Any = None

    def __post_init__(self):
        if self.severity is None:
            self.severity = AnalysisIssue.Severity.WARNING
        if self.category is None:
            self.category = AnalysisIssue.Category.CODE_SMELL
        if self.language is None:
            self.language = Language.UNKNOWN


@dataclass
class AnalysisResult:
    language: Language
    issues: List[AnalysisIssue] = field(default_factory=list)
    ir_root: Optional[IRNode] = None
    fix_report: str = ""
    stats: Dict[str, int] = field(default_factory=dict)
    source_lines: List[str] = field(default_factory=list)

    def add_issue(self, issue: AnalysisIssue):
        self.issues.append(issue)

    @property
    def errors(self):
        return [i for i in self.issues if i.severity == AnalysisIssue.Severity.ERROR]

    @property
    def warnings(self):
        return [i for i in self.issues if i.severity == AnalysisIssue.Severity.WARNING]

    @property
    def security_issues(self):
        return [i for i in self.issues if i.category in (
            AnalysisIssue.Category.SECURITY, AnalysisIssue.Category.TAINT,
            AnalysisIssue.Category.INJECTION)]
