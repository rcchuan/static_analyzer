"""
Java-specific advanced pattern detector
"""
import re
from typing import List, Dict, Set
from core.ir import AnalysisIssue, AnalysisResult, Language

OBJECT_METHODS = {
    'toString':  ['toSting','toStrng','toStrign','toStirng','tostring','tosString','tString','toString2'],
    'equals':    ['equal','Equals','eqauls','equlas','eqals'],
    'hashCode':  ['hashcode','HashCode','hascode','hashCde','hashCod'],
    'compareTo': ['compareto','CompareTo','comapreTo','comparTo'],
    'clone':     ['Clone','clon'],
    'finalize':  ['Finalize','finalise','finalizze'],
}
TYPO_MAP: Dict[str, str] = {}
for correct, typos in OBJECT_METHODS.items():
    for typo in typos:
        TYPO_MAP[typo] = correct


def detect_java_issues(result: AnalysisResult) -> AnalysisResult:
    lines = result.source_lines
    _check_method_name_typos(lines, result)
    _check_missing_override(lines, result)
    _check_multiple_mains(lines, result)
    _check_redundant_interface_modifiers(lines, result)
    _check_variable_naming_ambiguity(lines, result)
    _check_outdated_array_param(lines, result)
    _check_field_encapsulation(lines, result)
    return result


def _check_method_name_typos(lines, result):
    method_decl = re.compile(
        r'^\s*(?:public|protected|private)?\s*(?:static\s+)?'
        r'(?:\w[\w<>\[\]]*\s+)(\w+)\s*\(')
    for i, line in enumerate(lines, 1):
        m = method_decl.match(line)
        if not m: continue
        name = m.group(1)
        if name not in TYPO_MAP: continue
        correct = TYPO_MAP[name]
        result.issues.append(AnalysisIssue(
            title=f"方法名拼写错误导致覆盖失效: {name}() → 应为 {correct}()",
            description=(
                f"第 {i} 行的方法名 '{name}' 是 '{correct}' 的拼写错误，"
                f"导致该方法未能覆盖 Object.{correct}()。"
                f"若后续通过 System.out.println(obj)、字符串拼接等"
                f"隐式调用 {correct}() 的方式使用该对象，"
                f"将输出默认的对象地址（如 MyRectangle@1a2b3c）"
                f"而非预期内容，行为不符合预期。"
                f" 提示：在 {name}() 上添加 @Override 注解后，"
                f"编译器会立即报方法名不匹配错误，"
                f"这是发现并修正拼写问题的最快路径。"
            ),
            line=i,
            severity=AnalysisIssue.Severity.ERROR,
            category=AnalysisIssue.Category.CODE_SMELL,
            cwe_id="CWE-398",
            cwe_name="Inappropriate Source Code Style or Formatting",
            fix_suggestion=(
                f"1. 将方法名 '{name}' 改为 '{correct}'\n"
                f"2. 添加 @Override 注解让编译器验证覆盖是否正确：\n"
                f"   @Override\n"
                f"   public String {correct}() {{ ... }}"
            ),
            code_snippet=line.strip(),
            language=Language.JAVA,
        ))


def _check_missing_override(lines, result):
    CANDIDATES = set(OBJECT_METHODS.keys()) | {
        'calculateArea','getArea','draw','run','execute','compareTo','iterator','hasNext','next',
    } | set(TYPO_MAP.keys())   # also flag misspelled override methods
    method_re = re.compile(
        r'^\s*(?:public|protected)\s+(?:static\s+)?(?:\w[\w<>\[\]]*\s+)(\w+)\s*\(')
    for i, line in enumerate(lines, 1):
        m = method_re.match(line)
        if not m: continue
        name = m.group(1)
        if name not in CANDIDATES: continue
        has_override = False
        for j in range(i - 2, max(i - 4, -1), -1):
            prev = lines[j].strip() if j >= 0 else ''
            if not prev: continue
            if '@Override' in prev: has_override = True
            break
        if not has_override:
            # Typo methods (toSting etc.) get WARNING; normal override methods get INFO
            sev = (AnalysisIssue.Severity.WARNING if name in TYPO_MAP
                   else AnalysisIssue.Severity.INFO)
            result.issues.append(AnalysisIssue(
                title=f"缺少 @Override 注解: {name}()",
                description=(
                    f"第 {i} 行的 '{name}()' 覆盖了父类/接口方法，"
                    f"但缺少 @Override 注解。缺少注解时，"
                    f"方法名拼写错误编译器不会报错，导致覆盖静默失效。"
                ),
                line=i,
                severity=sev,
                category=AnalysisIssue.Category.CODE_SMELL,
                cwe_id="CWE-398",
                cwe_name="Inappropriate Source Code Style or Formatting",
                fix_suggestion=(
                    f"在方法声明前加上 @Override 注解：\n"
                    f"  @Override\n"
                    f"  {line.strip()}\n"
                    + (f"注意：该方法名 '{name}' 疑似 '{TYPO_MAP[name]}' 的拼写错误。"
                       f"加上 @Override 后编译器会立即因方法名不匹配而报错，"
                       f"这是发现并修正拼写问题的最高效路径。"
                       if name in TYPO_MAP else "")
                ),
                code_snippet=line.strip(),
                language=Language.JAVA,
            ))


def _check_multiple_mains(lines, result):
    """Report main() in business classes individually with class context."""
    main_re  = re.compile(r'public\s+static\s+void\s+main\s*\(')
    class_re = re.compile(r'public\s+(?:class|interface|enum)\s+(\w+)')
    current_class = "Unknown"
    for i, line in enumerate(lines, 1):
        cm = class_re.search(line)
        if cm: current_class = cm.group(1)
        if main_re.search(line):
            result.issues.append(AnalysisIssue(
                title=f"业务类 {current_class} 包含 main() 方法（违反单一职责原则）",
                description=(
                    f"类 '{current_class}' 第 {i} 行定义了 main() 方法。"
                    f"业务/实体类不应承担程序入口职责，违反单一职责原则（SRP）。"
                    f"main() 应集中到专门的入口类（如 Main 或 App）中。"
                ),
                line=i,
                severity=AnalysisIssue.Severity.INFO,
                category=AnalysisIssue.Category.CODE_SMELL,
                cwe_id="CWE-1061",
                cwe_name="Insufficient Encapsulation",
                fix_suggestion=(
                    f"（教学/实验代码中每类一个 main() 是常见做法，可忽略）\n"
                    f"生产代码建议从 '{current_class}' 中删除 main()，新建独立入口类：\n"
                    f"  public class Main {{\n"
                    f"      public static void main(String[] args) {{\n"
                    f"          System.out.println(new {current_class}(...).toString());\n"
                    f"      }}\n"
                    f"  }}"
                ),
                code_snippet=line.strip(),
                language=Language.JAVA,
            ))


def _check_redundant_interface_modifiers(lines, result):
    in_interface = False
    brace_depth = 0
    interface_brace_depth = 0
    for i, line in enumerate(lines, 1):
        s = line.strip()
        if re.search(r'\binterface\b', s):
            in_interface = True
            interface_brace_depth = brace_depth + s.count('{') - s.count('}')
        brace_depth += s.count('{') - s.count('}')
        if brace_depth < 0: brace_depth = 0
        if in_interface and brace_depth <= interface_brace_depth - 1:
            in_interface = False
        if not in_interface: continue
        if re.search(r'\bpublic\s+abstract\b', s) and '(' in s:
            simplified = re.sub(r'\bpublic\s+abstract\s+', '', s)
            result.issues.append(AnalysisIssue(
                title="接口方法冗余修饰符 public abstract",
                description=(
                    f"第 {i} 行的接口方法声明包含冗余的 'public abstract' 修饰符。"
                    f"接口中的方法默认就是 public 和 abstract，显式声明是多余的。"
                ),
                line=i,
                severity=AnalysisIssue.Severity.INFO,
                category=AnalysisIssue.Category.CODE_SMELL,
                cwe_id="CWE-398",
                cwe_name="Inappropriate Source Code Style or Formatting",
                fix_suggestion=f"去掉 'public abstract' 修饰符，接口方法应直接写签名：\n  {simplified}",
                code_snippet=s,
                language=Language.JAVA,
            ))


def _check_variable_naming_ambiguity(lines, result):
    MATH_CLASS_KEYWORDS = {
        'circle','rectangle','triangle','square','polygon','sphere','ellipse',
        'cylinder','cone','matrix','vector','point','line','segment','arc',
        'curve','shape','geometry','math','numeric','calc','formula',
    }
    ALWAYS_OK = {'x','y','z','i','j','k','n','m','r','w','h','a','b','c','e','f','g','p','q','t','u','v'}
    class_name = ''
    for line in lines:
        m = re.search(r'\bclass\s+(\w+)', line)
        if m: class_name = m.group(1).lower(); break
    if any(kw in class_name for kw in MATH_CLASS_KEYWORDS):
        return
    field_re = re.compile(r'^\s*(?:protected|private|public)?\s*(?:double|int|float|long)\s+([a-z])\s*;')
    ambiguous: Set[str] = set()
    for line in lines:
        m = field_re.match(line)
        if m and m.group(1) not in ALWAYS_OK: ambiguous.add(m.group(1))
    if not ambiguous: return
    for i, line in enumerate(lines, 1):
        m = field_re.match(line)
        if m and m.group(1) in ambiguous:
            fname = m.group(1)
            result.issues.append(AnalysisIssue(
                title=f"字段命名过于模糊: '{fname}'",
                description=f"第 {i} 行的字段 '{fname}' 使用单字母命名，在非数学场景下语义不清。",
                line=i, severity=AnalysisIssue.Severity.INFO,
                category=AnalysisIssue.Category.CODE_SMELL,
                cwe_id="CWE-398", cwe_name="Inappropriate Source Code Style or Formatting",
                fix_suggestion=f"将字段 '{fname}' 改为有描述性的名称，或确保类名已清晰表达数学含义。",
                code_snippet=line.strip(), language=Language.JAVA,
            ))


def _check_outdated_array_param(lines, result):
    """Detect C-style array param: String args[]  →  String[] args."""
    pattern   = re.compile(r'\b(\w+)\s+(\w+)\s*\[\s*\]\s*(?=[,)])')
    method_re = re.compile(r'\(.*\)')
    PRIMITIVE = {'int','char','byte','short','long','float','double','boolean'}
    for i, line in enumerate(lines, 1):
        if not method_re.search(line): continue
        m = pattern.search(line)
        if not m: continue
        type_name, param_name = m.group(1), m.group(2)
        if type_name in PRIMITIVE: continue
        result.issues.append(AnalysisIssue(
            title=f"过时的数组参数声明: {type_name} {param_name}[]",
            description=(
                f"第 {i} 行使用了 C 风格的数组参数声明 '{type_name} {param_name}[]'。"
                f"Java 推荐将 [] 紧跟类型名：'{type_name}[] {param_name}'，"
                f"前者是从 C 继承的过时写法，虽合法但不符合 Java 规范。"
            ),
            line=i, severity=AnalysisIssue.Severity.INFO,
            category=AnalysisIssue.Category.CODE_SMELL,
            cwe_id="CWE-398", cwe_name="Inappropriate Source Code Style or Formatting",
            fix_suggestion=(
                f"将 '{type_name} {param_name}[]' 改为 '{type_name}[] {param_name}'：\n"
                f"  public static void main({type_name}[] {param_name})"
            ),
            code_snippet=line.strip(), language=Language.JAVA,
        ))


def _check_field_encapsulation(lines, result):
    """Detect protected fields without getter/setter (CWE-766)."""
    field_re = re.compile(
        r'^\s*protected\s+(?!static|final|class|interface)'
        r'(?:double|int|float|long|short|char|boolean|String|\w+)\s+(\w+)\s*;'
    )
    fields = []
    for i, line in enumerate(lines, 1):
        m = field_re.match(line)
        if m: fields.append((i, m.group(1), line.strip()))
    if not fields: return
    code = "\n".join(lines)
    for lineno, fname, snippet in fields:
        getter = f"get{fname[0].upper()}{fname[1:]}"
        setter = f"set{fname[0].upper()}{fname[1:]}"
        if getter not in code and setter not in code:
            result.issues.append(AnalysisIssue(
                title=f"字段封装建议: '{fname}' 声明为 protected",
                description=(
                    f"第 {lineno} 行的字段 '{fname}' 声明为 protected。"
                    f"若该类设计为可继承的基类，protected 是合理的继承设计；"
                    f"若无继承需求，建议改为 private 并提供 getter/setter，"
                    f"以防止子类或同包类直接修改内部状态，增强封装性。"
                ),
                line=lineno, severity=AnalysisIssue.Severity.INFO,
                category=AnalysisIssue.Category.CODE_SMELL,
                cwe_id="CWE-1061", cwe_name="Insufficient Encapsulation",
                fix_suggestion=(
                    f"若无继承需求，将字段改为 private 并提供访问方法：\n"
                    f"  private double {fname};\n"
                    f"  public double {getter}() {{ return {fname}; }}\n"
                    f"  public void {setter}(double v) {{ this.{fname} = v; }}\n"
                    f"注意同步修改所有直接访问该字段的方法，"
                    f"将 this.{fname} 改为 this.{getter}() 等。"
                ),
                code_snippet=snippet, language=Language.JAVA,
            ))
