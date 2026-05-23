"""
Main Analysis Engine - orchestrates all analysis passes
"""
import re
from typing import Optional
from core.ir import Language, AnalysisResult
from parsers.python_parser import PythonParser
from parsers.generic_parser import GenericParser
from analysis.cfg_builder import CFGBuilder
from analysis.dataflow import DataFlowAnalyzer
from analysis.taint_analyzer import TaintAnalyzer
from analysis.pattern_detector import PatternDetector
from analysis.fix_generator import FixGenerator
from analysis.java_detector import detect_java_issues
from analysis.cpp_detector import detect_cpp_issues


def detect_language(code: str, filename: str = "") -> Language:
    """
    Detect language from filename extension first, then from code heuristics.

    Key fixes vs original:
    - #include regex now allows dots: <stdio.h>, <string.h>, <vector>, etc.
    - C/C++ #include is checked BEFORE Python heuristics, so C code is never
      mistakenly fed to the Python ast.parse() and falsely reported as a
      syntax error.
    - Python detection uses stricter patterns to avoid false positives on C code
      that happens to contain a colon (e.g. "case 0:" or "if (...) {").
    - Scoring system breaks ties when multiple weak signals are present.
    """
    fname = filename.lower()

    # ── 1. File extension — authoritative, always wins ──────────────────────
    if fname.endswith('.py'):
        return Language.PYTHON
    if fname.endswith('.java'):
        return Language.JAVA
    if fname.endswith(('.cpp', '.cc', '.cxx', '.hpp', '.hxx')):
        return Language.CPP
    if fname.endswith(('.c', '.h')):
        return Language.C

    # ── 2. Strong single-match signals — one hit is enough ──────────────────
    # Java: public class Foo  /  import java.util.*
    if re.search(r'\bpublic\s+class\b|\bimport\s+java\.', code):
        return Language.JAVA

    # C / C++: #include <header>  or  #include "header"
    # Fix: original used [a-z_]+ which excluded the dot in "stdio.h"
    # Correct pattern allows letters, digits, underscores, dots, slashes
    if re.search(r'#include\s*[<"][a-zA-Z0-9_./ ]+[>"]', code):
        # Distinguish C++ from C by C++-specific tokens
        if re.search(r'\b(cout|cin|cerr|clog|std::|namespace\s+\w|'
                     r'template\s*<|::\s*\w|#include\s*<(iostream|vector|'
                     r'string|map|set|algorithm|memory|thread|mutex|'
                     r'functional|utility|tuple|array|deque|list|stack|'
                     r'queue|unordered_map|unordered_set)>)', code):
            return Language.CPP
        return Language.C

    # ── 3. Scoring — accumulate weak signals, pick highest score ────────────
    scores = {Language.PYTHON: 0, Language.JAVA: 0,
              Language.C: 0,      Language.CPP: 0}

    # Python signals
    if re.search(r'^\s*def\s+\w+\s*\(', code, re.MULTILINE):
        scores[Language.PYTHON] += 3
    if re.search(r'^\s*import\s+\w+', code, re.MULTILINE):
        scores[Language.PYTHON] += 2
    if re.search(r'^\s*from\s+\w+\s+import\b', code, re.MULTILINE):
        scores[Language.PYTHON] += 3
    if re.search(r'^\s*class\s+\w+(\s*\(.*\))?\s*:', code, re.MULTILINE):
        scores[Language.PYTHON] += 2
    if re.search(r'\bprint\s*\(', code):
        scores[Language.PYTHON] += 1
    if re.search(r'\bself\b', code):
        scores[Language.PYTHON] += 2
    # Colon-ended lines that are NOT C-style (no { on same line)
    py_colons = re.findall(r'^\s*(if|elif|else|for|while|with|try|except|'
                           r'finally|def|class)\b[^{]*:\s*$',
                           code, re.MULTILINE)
    scores[Language.PYTHON] += min(len(py_colons), 4)

    # Java signals
    if re.search(r'\bpublic\s+(static\s+)?(void|int|String|boolean|'
                 r'double|float|long|char)\b', code):
        scores[Language.JAVA] += 3
    if re.search(r'\bSystem\.out\.print', code):
        scores[Language.JAVA] += 3
    if re.search(r'\bnew\s+[A-Z]\w+\s*\(', code):
        scores[Language.JAVA] += 2
    if re.search(r'@Override|@SuppressWarnings|@NotNull', code):
        scores[Language.JAVA] += 2
    if re.search(r'\bString\s+\w+\s*=', code):
        scores[Language.JAVA] += 1

    # C signals
    if re.search(r'\b(printf|scanf|malloc|free|fprintf|sprintf|'
                 r'strcpy|strncpy|strlen|memcpy|memset)\s*\(', code):
        scores[Language.C] += 3
    if re.search(r'\bint\s+main\s*\(', code):
        scores[Language.C] += 3
    if re.search(r'\b(int|char|float|double|void)\s*\*\s*\w+', code):
        scores[Language.C] += 1
    if re.search(r'\btypedef\s+struct\b', code):
        scores[Language.C] += 2

    # C++ signals
    if re.search(r'\bcout\b|\bcin\b|\bstd::', code):
        scores[Language.CPP] += 3
    if re.search(r'\bclass\s+\w+\s*(\{|:)', code):
        scores[Language.CPP] += 2
    if re.search(r'\btemplate\s*<', code):
        scores[Language.CPP] += 3
    if re.search(r'#include\s*<(iostream|vector|string|map|algorithm)>', code):
        scores[Language.CPP] += 3

    # C++ inherits all C signals
    scores[Language.CPP] += scores[Language.C] // 2

    best_lang = max(scores, key=lambda l: scores[l])
    best_score = scores[best_lang]

    # If no signal at all, default to Python
    return best_lang if best_score > 0 else Language.PYTHON


class AnalysisEngine:
    def __init__(self):
        self.cfg_builder = CFGBuilder()
        self.fix_gen = FixGenerator()

    def analyze(self, code: str, filename: str = "",
                language: Optional[Language] = None) -> AnalysisResult:
        """Run full analysis pipeline on source code"""
        if language is None:
            language = detect_language(code, filename)

        # Phase 1: Parse -> IR
        result = self._parse(code, language)

        # Phase 2: Build CFG
        result = self.cfg_builder.build(result)

        # Phase 3: Data Flow Analysis
        dfa = DataFlowAnalyzer(language)
        result = dfa.analyze(result)

        # Phase 4: Taint Analysis
        taint = TaintAnalyzer(language)
        result = taint.analyze(result)

        # Phase 5: Pattern Detection
        patterns = PatternDetector(language)
        result = patterns.detect(result)

        # Phase 5b: Language-specific advanced detection
        if language == Language.JAVA:
            result = detect_java_issues(result)
        elif language in (Language.CPP, Language.C):
            result = detect_cpp_issues(result)

        # Phase 6: Deduplicate issues by (line, title)
        seen = set()
        unique_issues = []
        for issue in result.issues:
            key = (issue.line, issue.title[:30])
            if key not in seen:
                seen.add(key)
                unique_issues.append(issue)
        result.issues = sorted(unique_issues, key=lambda x: x.line)

        # Phase 7: Generate fix report
        self.fix_gen.generate(result)

        # Stats
        result.stats = {
            "total_issues": len(result.issues),
            "errors": len(result.errors),
            "warnings": len(result.warnings),
            "security": len(result.security_issues),
            "cfg_blocks": len(result.cfg_blocks),
            "lines": len(result.source_lines),
        }
        return result

    def _parse(self, code: str, language: Language) -> AnalysisResult:
        if language == Language.PYTHON:
            parser = PythonParser()
        else:
            parser = GenericParser(language)
        return parser.parse(code)
