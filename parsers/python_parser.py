"""Python AST Parser -> IR"""
import ast
import re
from typing import List, Optional
from core.ir import IRNode, NodeType, Language, AnalysisIssue, AnalysisResult


class PythonParser:
    def __init__(self):
        self.issues: List[AnalysisIssue] = []
        self.language = Language.PYTHON

    def parse(self, code: str) -> AnalysisResult:
        result = AnalysisResult(language=self.language)
        result.source_lines = code.splitlines()
        self.issues = []
        try:
            tree = ast.parse(code)
            ir_root = self._convert_node(tree)
            result.ir_root = ir_root
            # Syntax check via compile
        except SyntaxError as e:
            issue = AnalysisIssue(
                title="语法错误", description=str(e), line=e.lineno or 0,
                severity=AnalysisIssue.Severity.ERROR,
                category=AnalysisIssue.Category.SYNTAX,
                cwe_id="CWE-691", cwe_name="Insufficient Control Flow Management",
                fix_suggestion="修复语法错误后重新分析。",
                language=self.language
            )
            self.issues.append(issue)
        result.issues = self.issues
        return result

    def _convert_node(self, node: ast.AST, parent: Optional[IRNode] = None) -> IRNode:
        ir = self._ast_to_ir(node)
        if parent:
            parent.add_child(ir)
        for child in ast.iter_child_nodes(node):
            self._convert_node(child, ir)
        return ir

    def _ast_to_ir(self, node: ast.AST) -> IRNode:
        line = getattr(node, 'lineno', 0)
        col = getattr(node, 'col_offset', 0)

        if isinstance(node, ast.Module):
            return IRNode(NodeType.PROGRAM, line=line, col=col)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return IRNode(NodeType.FUNCTION, value=node.name, line=line, col=col)
        elif isinstance(node, ast.ClassDef):
            return IRNode(NodeType.CLASS_DECL, value=node.name, line=line, col=col)
        elif isinstance(node, ast.If):
            return IRNode(NodeType.IF, line=line, col=col)
        elif isinstance(node, ast.While):
            return IRNode(NodeType.WHILE, line=line, col=col)
        elif isinstance(node, ast.For):
            return IRNode(NodeType.FOR, line=line, col=col)
        elif isinstance(node, ast.Return):
            return IRNode(NodeType.RETURN, line=line, col=col)
        elif isinstance(node, ast.Assign):
            targets = ", ".join(ast.unparse(t) for t in node.targets) if hasattr(ast, 'unparse') else ""
            return IRNode(NodeType.ASSIGN, value=targets, line=line, col=col)
        elif isinstance(node, ast.AugAssign):
            return IRNode(NodeType.ASSIGN, value=ast.unparse(node.target) if hasattr(ast, 'unparse') else "", line=line, col=col)
        elif isinstance(node, ast.AnnAssign):
            target = ast.unparse(node.target) if hasattr(ast, 'unparse') else ""
            return IRNode(NodeType.VAR_DECL, value=target, line=line, col=col)
        elif isinstance(node, ast.Call):
            func = ast.unparse(node.func) if hasattr(ast, 'unparse') else ""
            return IRNode(NodeType.CALL, value=func, line=line, col=col)
        elif isinstance(node, ast.Import):
            names = ", ".join(a.name for a in node.names)
            return IRNode(NodeType.IMPORT, value=names, line=line, col=col)
        elif isinstance(node, ast.ImportFrom):
            return IRNode(NodeType.IMPORT, value=node.module or "", line=line, col=col)
        elif isinstance(node, ast.Try):
            return IRNode(NodeType.TRY, line=line, col=col)
        elif isinstance(node, ast.ExceptHandler):
            return IRNode(NodeType.CATCH, line=line, col=col)
        elif isinstance(node, ast.Raise):
            return IRNode(NodeType.THROW, line=line, col=col)
        elif isinstance(node, ast.Name):
            return IRNode(NodeType.IDENTIFIER, value=node.id, line=line, col=col)
        elif isinstance(node, ast.Constant):
            return IRNode(NodeType.LITERAL, value=repr(node.value), line=line, col=col)
        elif isinstance(node, ast.Break):
            return IRNode(NodeType.BREAK, line=line, col=col)
        elif isinstance(node, ast.Continue):
            return IRNode(NodeType.CONTINUE, line=line, col=col)
        else:
            return IRNode(NodeType.UNKNOWN, value=type(node).__name__, line=line, col=col)
