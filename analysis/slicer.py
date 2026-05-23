"""
Program Slicer - Static Backward Slicing
Given a criterion (line, variable), computes all statements the result depends on
"""
import re
from typing import Set, List, Dict, Tuple
from core.ir import IRNode, NodeType, BasicBlock, AnalysisResult


class ProgramSlicer:
    def backward_slice(self, result: AnalysisResult,
                       criterion_line: int, criterion_var: str) -> List[int]:
        """
        Compute backward slice from (criterion_line, criterion_var).
        Returns list of line numbers in the slice.
        """
        if not result.source_lines:
            return []
        lines = result.source_lines
        slice_lines: Set[int] = set()
        work_vars: Set[str] = {criterion_var}
        slice_lines.add(criterion_line)

        # Walk backwards through source lines
        for lineno in range(criterion_line - 1, 0, -1):
            if lineno < 1 or lineno > len(lines):
                continue
            line = lines[lineno - 1]
            stripped = line.strip()

            # Check if this line defines any variable in our work set
            defined = self._get_defined_var(stripped, lineno)
            used = self._get_used_vars(stripped)

            if defined and defined in work_vars:
                slice_lines.add(lineno)
                work_vars.discard(defined)
                work_vars |= used
                continue

            # Control dependencies: if/for/while that affect execution
            if self._is_control_stmt(stripped) and any(v in stripped for v in work_vars):
                slice_lines.add(lineno)
                work_vars |= used

        return sorted(slice_lines)

    def _get_defined_var(self, line: str, lineno: int) -> str:
        patterns = [
            r'^(\w+)\s*=(?!=)',             # x = ...
            r'^(\w+)\s*[+\-*/]=',           # x += ...
            r'^(?:int|float|str|bool|auto|var|long|double|char)\s+(\w+)',  # type decl
            r'^(\w+)\s*\+\+',               # x++
            r'^(\w+)\s*--',                 # x--
        ]
        for p in patterns:
            m = re.match(p, line)
            if m:
                return m.group(1)
        return ""

    def _get_used_vars(self, line: str) -> Set[str]:
        # Remove string literals
        cleaned = re.sub(r'"[^"]*"', '', line)
        cleaned = re.sub(r"'[^']*'", '', cleaned)
        # Extract identifiers
        tokens = re.findall(r'\b([a-zA-Z_]\w*)\b', cleaned)
        skip = {'if', 'else', 'for', 'while', 'return', 'int', 'float', 'str',
                'bool', 'True', 'False', 'None', 'null', 'new', 'this', 'self'}
        return {t for t in tokens if t not in skip and not t[0].isupper()}

    def _is_control_stmt(self, line: str) -> bool:
        return bool(re.match(r'\s*(if|else|elif|for|while|switch)\b', line))

    def format_slice(self, lines: List[str], slice_lines: List[int],
                     criterion_line: int, criterion_var: str) -> str:
        result = [f"=== 静态后向切片 ===",
                  f"切片准则: 第 {criterion_line} 行, 变量: '{criterion_var}'",
                  f"相关语句 ({len(slice_lines)} 条):", ""]
        for lineno in slice_lines:
            if 1 <= lineno <= len(lines):
                marker = " <<< [切片准则]" if lineno == criterion_line else ""
                result.append(f"  {lineno:4d} | {lines[lineno-1]}{marker}")
        return "\n".join(result)
