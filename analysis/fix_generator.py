"""
Fix Report Generator
Aggregates all issues and produces a comprehensive fix report
"""
from typing import List
from core.ir import AnalysisResult, AnalysisIssue, Language


class FixGenerator:
    def generate(self, result: AnalysisResult) -> str:
        if not result.issues:
            return "✅ 未发现问题，代码质量良好！"

        lines = []
        lines.append(f"{'='*60}")
        lines.append(f"  静态代码分析 - 修复方案报告")
        lines.append(f"  语言: {result.language.value} | 共 {len(result.issues)} 个问题")
        lines.append(f"{'='*60}\n")

        # Summary
        errors = [i for i in result.issues if i.severity == AnalysisIssue.Severity.ERROR]
        warnings = [i for i in result.issues if i.severity == AnalysisIssue.Severity.WARNING]
        infos = [i for i in result.issues if i.severity == AnalysisIssue.Severity.INFO]

        lines.append("【问题摘要】")
        lines.append(f"  🔴 错误 (Error):   {len(errors)} 个")
        lines.append(f"  🟡 警告 (Warning): {len(warnings)} 个")
        lines.append(f"  🔵 提示 (Info):    {len(infos)} 个\n")

        # Group by category
        categories = {}
        for issue in result.issues:
            cat = issue.category.value if issue.category else "其他"
            if cat not in categories:
                categories[cat] = []
            categories[cat].append(issue)

        lines.append("【按类别分组的修复建议】\n")

        for cat, issues in sorted(categories.items()):
            lines.append(f"▶ {cat} ({len(issues)} 个问题)")
            lines.append("-" * 50)
            for idx, issue in enumerate(issues, 1):
                sev_icon = {"ERROR": "🔴", "WARNING": "🟡", "INFO": "🔵"}.get(
                    issue.severity.value if issue.severity else "INFO", "🔵")
                lines.append(f"\n  [{idx}] {sev_icon} {issue.title}")
                lines.append(f"      位置: 第 {issue.line} 行")
                if issue.cwe_id:
                    lines.append(f"      CWE: {issue.cwe_id} - {issue.cwe_name}")
                lines.append(f"      描述: {issue.description}")
                if issue.code_snippet:
                    lines.append(f"      问题代码: `{issue.code_snippet}`")
                if issue.fix_suggestion:
                    lines.append(f"      ✅ 修复建议: {issue.fix_suggestion}")
            lines.append("")

        # Security-specific recommendations
        security_issues = result.security_issues
        if security_issues:
            lines.append("\n【安全加固建议】")
            lines.append("="*50)
            seen_cwes = set()
            for issue in security_issues:
                if issue.cwe_id and issue.cwe_id not in seen_cwes:
                    seen_cwes.add(issue.cwe_id)
                    lines.append(f"\n• {issue.cwe_id}: {issue.cwe_name}")
                    lines.append(f"  参考: https://cwe.mitre.org/data/definitions/{issue.cwe_id.replace('CWE-', '')}.html")

        lines.append("\n" + "="*60)
        lines.append("报告生成完毕。请优先处理🔴错误级别问题，再处理🟡警告。")
        lines.append("="*60)

        result.fix_report = "\n".join(lines)
        return result.fix_report
