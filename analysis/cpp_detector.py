"""
C++ advanced pattern detector
Detects: include-before-guard, lock-with-sleep, nested locks deadlock risk,
         exit-while-locked, dangling pointer after terminate, naming conflicts,
         log typos in string literals, null-check after dereference, etc.
"""
import re
from typing import List, Tuple, Set, Dict
from core.ir import AnalysisIssue, AnalysisResult, Language


def detect_cpp_issues(result: AnalysisResult) -> AnalysisResult:
    lines = result.source_lines
    _check_include_before_guard(lines, result)
    _check_lock_with_sleep(lines, result)
    _check_nested_locks(lines, result)
    _check_exit_while_locked(lines, result)
    _check_null_check_after_deref(lines, result)
    _check_dangling_ptr_after_terminate(lines, result)
    _check_std_name_conflict(lines, result)
    _check_string_literal_typos(lines, result)
    _check_meaningless_else_if(lines, result)
    _check_buffer_naming_risk(lines, result)
    _check_variable_shadowing(lines, result)
    return result


# ── 1. #include before #ifndef guard ─────────────────────────────────────────
def _check_include_before_guard(lines: List[str], result: AnalysisResult):
    """
    Detect #include directives that appear BEFORE the #ifndef header guard.
    Correct order: #ifndef GUARD / #define GUARD / #include ...
    """
    first_include_line = None
    first_ifndef_line  = None

    for i, line in enumerate(lines, 1):
        s = line.strip()
        if s.startswith('#include') and first_include_line is None:
            first_include_line = i
        if s.startswith('#ifndef') and first_ifndef_line is None:
            first_ifndef_line = i
            break   # stop at first guard

    if (first_include_line is not None
            and first_ifndef_line is not None
            and first_include_line < first_ifndef_line):
        result.issues.append(AnalysisIssue(
            title="#include 位于 #ifndef 头文件保护之前（结构错误）",
            description=(
                f"第 {first_include_line} 行的 #include 出现在第 {first_ifndef_line} 行"
                f"的 #ifndef 保护宏之前。"
                f"当该头文件被多次包含时，#include 部分不受保护，"
                f"可能引发重复定义错误或编译错误。"
            ),
            line=first_include_line,
            severity=AnalysisIssue.Severity.ERROR,
            category=AnalysisIssue.Category.CODE_SMELL,
            cwe_id="CWE-1106",
            cwe_name="Insufficient Use of Symbolic Constants",
            fix_suggestion=(
                "将所有 #include 移到 #ifndef / #define 之后：\n"
                "  #ifndef HEADER_H\n"
                "  #define HEADER_H\n"
                "  #include <...>\n"
                "  ...\n"
                "  #endif"
            ),
            code_snippet=lines[first_include_line - 1].strip(),
            language=Language.CPP,
        ))


# ── 2. Lock held while sleeping (performance / liveness issue) ────────────────
def _check_lock_with_sleep(lines: List[str], result: AnalysisResult):
    """
    Detect Sleep() / sleep() / usleep() called while a critical section lock
    is held (i.e., EnterCriticalSection appears before Sleep with no
    LeaveCriticalSection in between).
    """
    lock_stack: List[Tuple[str, int]] = []  # (lock_name, lineno)
    lock_re  = re.compile(r'EnterCriticalSection\s*\(\s*&?(\w+)\s*\)')
    unlock_re = re.compile(r'LeaveCriticalSection\s*\(\s*&?(\w+)\s*\)')
    sleep_re  = re.compile(r'\bSleep\s*\(|usleep\s*\(|sleep\s*\(|std::this_thread::sleep')

    for i, line in enumerate(lines, 1):
        m = lock_re.search(line)
        if m:
            lock_stack.append((m.group(1), i))
        mu = unlock_re.search(line)
        if mu and lock_stack:
            # Pop matching lock
            lname = mu.group(1)
            lock_stack = [(n, l) for n, l in lock_stack if n != lname]
        if sleep_re.search(line) and lock_stack:
            held = ', '.join(f'{n}(L{l})' for n, l in lock_stack)
            result.issues.append(AnalysisIssue(
                title="持有锁期间调用 Sleep()（严重性能问题）",
                description=(
                    f"第 {i} 行在持有临界区锁 [{held}] 的情况下调用了 Sleep()。"
                    f"在整个睡眠期间锁不会释放，所有等待该锁的线程全部阻塞，"
                    f"系统实际退化为单线程串行执行，严重影响并发性能。"
                ),
                line=i,
                severity=AnalysisIssue.Severity.ERROR,
                category=AnalysisIssue.Category.SECURITY,
                cwe_id="CWE-833",
                cwe_name="Deadlock",
                fix_suggestion=(
                    "在调用 Sleep() 前先释放锁，Sleep 之后重新获取：\n"
                    "  LeaveCriticalSection(&lock);\n"
                    "  Sleep(1000);\n"
                    "  EnterCriticalSection(&lock);"
                ),
                code_snippet=line.strip(),
                language=Language.CPP,
            ))


# ── 3. Nested lock acquisition (deadlock risk) ────────────────────────────────
def _check_nested_locks(lines: List[str], result: AnalysisResult):
    """
    Detect nested EnterCriticalSection calls (holding lock A while acquiring
    lock B). Flag each inner acquisition with a deadlock-risk warning.
    """
    lock_re   = re.compile(r'EnterCriticalSection\s*\(\s*&?(\w+)\s*\)')
    unlock_re = re.compile(r'LeaveCriticalSection\s*\(\s*&?(\w+)\s*\)')
    held_locks: List[Tuple[str, int]] = []
    reported: Set[Tuple[str, str]] = set()

    for i, line in enumerate(lines, 1):
        mu = unlock_re.search(line)
        if mu:
            lname = mu.group(1)
            held_locks = [(n, l) for n, l in held_locks if n != lname]

        m = lock_re.search(line)
        if m:
            new_lock = m.group(1)
            if held_locks:
                outer_name, outer_line = held_locks[-1]
                key = (outer_name, new_lock)
                if key not in reported:
                    reported.add(key)
                    result.issues.append(AnalysisIssue(
                        title=f"嵌套加锁存在死锁风险: {outer_name} → {new_lock}",
                        description=(
                            f"第 {i} 行在持有锁 '{outer_name}'（获取于第 {outer_line} 行）"
                            f"的情况下又申请锁 '{new_lock}'。"
                            f"若其他代码路径以相反顺序申请这两把锁，将导致死锁。"
                        ),
                        line=i,
                        severity=AnalysisIssue.Severity.ERROR,
                        category=AnalysisIssue.Category.SECURITY,
                        cwe_id="CWE-833",
                        cwe_name="Deadlock",
                        fix_suggestion=(
                            f"统一所有代码路径的加锁顺序，确保始终先获取 '{outer_name}' "
                            f"再获取 '{new_lock}'。或重构代码减少嵌套锁的使用。"
                        ),
                        code_snippet=line.strip(),
                        language=Language.CPP,
                    ))
            held_locks.append((new_lock, i))


# ── 4. exit() while lock held ─────────────────────────────────────────────────
def _check_exit_while_locked(lines: List[str], result: AnalysisResult):
    """
    Detect exit() / abort() called while a critical section lock is held.
    exit() does not release CRITICAL_SECTIONs, causing resource leaks / deadlock.
    Reports EVERY occurrence, not just the first.
    """
    lock_re   = re.compile(r'EnterCriticalSection\s*\(\s*&?(\w+)\s*\)')
    unlock_re = re.compile(r'LeaveCriticalSection\s*\(\s*&?(\w+)\s*\)')
    exit_re   = re.compile(r'\bexit\s*\(|\babort\s*\(')
    held_locks: List[Tuple[str, int]] = []
    reported_lines: set = set()

    for i, line in enumerate(lines, 1):
        # Process unlocks first (they free locks before processing new enters)
        mu = unlock_re.search(line)
        if mu:
            lname = mu.group(1)
            held_locks = [(n, l) for n, l in held_locks if n != lname]

        m = lock_re.search(line)
        if m:
            held_locks.append((m.group(1), i))

        if exit_re.search(line) and held_locks and i not in reported_lines:
            reported_lines.add(i)
            held = ', '.join(f'{n}(L{l})' for n, l in held_locks)
            last_lock = held_locks[-1][0]
            result.issues.append(AnalysisIssue(
                title="持有锁时调用 exit()（资源泄漏 / 死锁）",
                description=(
                    f"第 {i} 行在持有临界区锁 [{held}] 时调用 exit()。"
                    f"exit() 不会自动释放 CRITICAL_SECTION，"
                    f"其他等待该锁的线程将永久阻塞，造成死锁或资源泄漏。"
                ),
                line=i,
                severity=AnalysisIssue.Severity.ERROR,
                category=AnalysisIssue.Category.RESOURCE,
                cwe_id="CWE-772",
                cwe_name="Missing Release of Resource after Effective Lifetime",
                fix_suggestion=(
                    f"在调用 exit() 前释放所有持有的锁：\n"
                    f"  LeaveCriticalSection(&{last_lock});\n"
                    f"  exit(0);"
                ),
                code_snippet=line.strip(),
                language=Language.CPP,
            ))


# ── 5. Null-check after dereference ──────────────────────────────────────────
def _check_null_check_after_deref(lines: List[str], result: AnalysisResult):
    """
    Detect ptr->member on line N BEFORE if(ptr!=NULL) on line M, same function.
    Resets state at function boundaries to prevent cross-function false positives.
    Clears ptr from tracking when null-check is seen, so deref inside if-body is safe.
    """
    deref_re    = re.compile(r'(\w+)\s*->\w+')
    null_re     = re.compile(r'if\s*\(\s*(\w+)\s*!=\s*NULL')
    func_sig_re = re.compile(
        r'^\s*(?:void|int|double|char|bool|HANDLE|DWORD|WINAPI|\w+\s*\*)\s+'
        r'(?!if|for|while|switch)(\w+)\s*\('
    )
    recent_derefs: Dict[str, int] = {}

    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if func_sig_re.match(stripped):
            recent_derefs.clear()

        mn = null_re.search(line)
        if mn:
            ptr = mn.group(1)
            if ptr and ptr in recent_derefs:
                deref_line = recent_derefs[ptr]
                if deref_line < i and (i - deref_line) <= 15:
                    result.issues.append(AnalysisIssue(
                        title=f"空指针检查位置错误: '{ptr}' 先解引用后检查",
                        description=(
                            f"第 {deref_line} 行已对指针 '{ptr}' 执行解引用"
                            f"（'{ptr}->' 操作），但空指针检查"
                            f" 'if ({ptr} != NULL)' 出现在第 {i} 行。"
                            f"若 '{ptr}' 为 NULL，程序在第 {deref_line} 行就已崩溃，"
                            f"第 {i} 行的检查完全无效。"
                        ),
                        line=deref_line,
                        severity=AnalysisIssue.Severity.ERROR,
                        category=AnalysisIssue.Category.NULL_PTR,
                        cwe_id="CWE-476",
                        cwe_name="NULL Pointer Dereference",
                        fix_suggestion=(
                            f"将空指针检查移至第一次使用 '{ptr}->' 之前：\n"
                            f"  if ({ptr} == NULL) return;  // 先检查\n"
                            f"  {ptr}->member = ...;        // 再使用"
                        ),
                        code_snippet=lines[deref_line - 1].strip(),
                        language=Language.CPP,
                    ))
            if ptr in recent_derefs:
                del recent_derefs[ptr]

        for m in deref_re.finditer(line):
            ptr = m.group(1)
            if ptr not in recent_derefs:
                recent_derefs[ptr] = i


# ── 6. Dangling pointer after TerminateThread / TerminateProcess ──────────────
def _check_dangling_ptr_after_terminate(lines: List[str], result: AnalysisResult):
    """
    Detect TerminateThread(ptr->hThis, ...) where ptr is NOT set to NULL
    within the next few lines (dangling pointer after termination).
    """
    term_re  = re.compile(r'TerminateThread\s*\(\s*(\w+)\s*->')
    null_assign = re.compile(r'(\w+)\s*=\s*NULL\s*;')

    for i, line in enumerate(lines, 1):
        m = term_re.search(line)
        if not m:
            continue
        ptr = m.group(1)
        # Look ahead up to 6 lines for ptr = NULL
        found_null = False
        for j in range(i, min(i + 6, len(lines))):
            mn = null_assign.search(lines[j])
            if mn and mn.group(1) == ptr:
                found_null = True
                break
            # Stop at function boundary or leave-critical
            if re.search(r'\breturn\b|LeaveCriticalSection', lines[j]):
                break
        if not found_null:
            result.issues.append(AnalysisIssue(
                title=f"TerminateThread 后指针 '{ptr}' 未置 NULL（悬空指针）",
                description=(
                    f"第 {i} 行调用 TerminateThread 终止线程后，"
                    f"指针 '{ptr}' 仍指向已被终止的线程所在的 PCB/对象，"
                    f"形成悬空指针。后续若再访问 '{ptr}' 将引发未定义行为或崩溃。"
                ),
                line=i,
                severity=AnalysisIssue.Severity.WARNING,
                category=AnalysisIssue.Category.NULL_PTR,
                cwe_id="CWE-416",
                cwe_name="Use After Free",
                fix_suggestion=(
                    f"在 TerminateThread 和 CloseHandle 之后立即将指针置为 NULL：\n"
                    f"  TerminateThread({ptr}->hThis, 0);\n"
                    f"  CloseHandle({ptr}->hThis);\n"
                    f"  {ptr} = NULL;  // 防止悬空指针"
                ),
                code_snippet=line.strip(),
                language=Language.CPP,
            ))


# ── 7. Variable name conflicts with std:: names ───────────────────────────────
def _check_std_name_conflict(lines: List[str], result: AnalysisResult):
    """
    Detect global variable declarations that shadow std:: names.
    Only fires when 'using namespace std;' is also present.
    """
    std_names = {
        'log':      'std::log (数学对数函数)',
        'count':    'std::count (算法函数)',
        'find':     'std::find (算法函数)',
        'sort':     'std::sort (算法函数)',
        'copy':     'std::copy (算法函数)',
        'fill':     'std::fill (算法函数)',
        'next':     'std::next (迭代器函数)',
        'prev':     'std::prev (迭代器函数)',
        'move':     'std::move (移动语义)',
        'swap':     'std::swap (交换函数)',
        'distance': 'std::distance',
        'time':     'std::time',
        'queue':    'std::queue',
        'list':     'std::list',
        'map':      'std::map',
        'set':      'std::set',
    }
    has_using_namespace_std = any(
        re.search(r'using\s+namespace\s+std', l) for l in lines
    )
    if not has_using_namespace_std:
        return

    global_decl_re = re.compile(
        r'^\s*(?:extern\s+)?(?:ofstream|ifstream|int|double|float|bool|char|'
        r'string|auto|volatile\s+\w+|\w+)\s+(\w+)\s*[;=({]'
    )
    for i, line in enumerate(lines, 1):
        m = global_decl_re.match(line)
        if not m:
            continue
        vname = m.group(1)
        if vname in std_names:
            _rename_map = {
                'log':      "'logFile' 或 'processLog'",
                'count':    "'pcbCount' 或 'itemCount'",
                'time':     "'timeSlice' 或 'duration'",
                'find':     "'findResult' 或 'searchResult'",
                'sort':     "'sortKey' 或 'sortFunc'",
                'copy':     "'copyBuf' 或 'dataCopy'",
                'next':     "'nextNode' 或 'nextPtr'",
                'prev':     "'prevNode' 或 'prevPtr'",
                'move':     "'moveTarget' 或 'moveOp'",
                'swap':     "'swapTemp' 或 'swapBuf'",
                'queue':    "'taskQueue' 或 'msgQueue'",
                'list':     "'nodeList' 或 'itemList'",
                'map':      "'dataMap' 或 'keyMap'",
                'set':      "'dataSet' 或 'flagSet'",
                'fill':     "'fillData' 或 'fillBuf'",
                'distance': "'distVal' 或 'distCount'",
            }
            _suggestion = _rename_map.get(vname, f"'{vname}Renamed' 或更具描述性的名称")
            result.issues.append(AnalysisIssue(
                title=f"变量名 '{vname}' 与 std::{vname} 命名冲突",
                description=(
                    f"第 {i} 行声明的变量 '{vname}' 与标准库中的 {std_names[vname]} 同名。"
                    f"在 'using namespace std;' 的作用域下，"
                    f"可能在某些编译器版本下引发编译错误或行为不明确。"
                ),
                line=i,
                severity=AnalysisIssue.Severity.WARNING,
                category=AnalysisIssue.Category.CODE_SMELL,
                cwe_id="CWE-1107",
                cwe_name="Insufficient Isolation of Symbolic Constants",
                fix_suggestion=(
                    f"将变量 '{vname}' 重命名以避免与 std::{vname} 冲突，例如：\n"
                    f"  '{vname}' → {_suggestion}\n"
                    f"或去掉 'using namespace std;' 改用显式前缀 std::。"
                ),
                code_snippet=line.strip(),
                language=Language.CPP,
            ))


# ── 8. Typos in string literals ───────────────────────────────────────────────
def _check_string_literal_typos(lines: List[str], result: AnalysisResult):
    """
    Detect common English word typos inside string literals.
    Pattern: look for quoted strings and check word list.
    """
    typo_words = {
        'scheduleed': 'scheduled',
        'sucessfully': 'successfully',
        'successfuly': 'successfully',
        'recieve':    'receive',
        'recieved':   'received',
        'occured':    'occurred',
        'occurance':  'occurrence',
        'seperate':   'separate',
        'acheive':    'achieve',
        'benifit':    'benefit',
        'definately': 'definitely',
        'accomodate': 'accommodate',
        'existance':  'existence',
        'persistance':'persistence',
        'usefull':    'useful',
        'allready':   'already',
        'writting':   'writing',
        'comming':    'coming',
        'begining':   'beginning',
        'runnning':   'running',
        'refered':    'referred',
        'aborded':    'aborted',
        'initalize':  'initialize',
        'interupt':   'interrupt',
        'proccess':   'process',
        'prcess':     'process',
        'exsit':      'exist',
        'termanate':  'terminate',
    }
    str_re = re.compile(r'"([^"]*)"')
    for i, line in enumerate(lines, 1):
        for m in str_re.finditer(line):
            content = m.group(1)
            for typo, correct in typo_words.items():
                if typo in content.lower():
                    result.issues.append(AnalysisIssue(
                        title=f"字符串字面量拼写错误: '{typo}'",
                        description=(
                            f"第 {i} 行的字符串中包含拼写错误 '{typo}'，"
                            f"正确拼写应为 '{correct}'。"
                            f"虽不影响运行，但输出日志或界面信息不专业。"
                        ),
                        line=i,
                        severity=AnalysisIssue.Severity.INFO,
                        category=AnalysisIssue.Category.CODE_SMELL,
                        cwe_id="CWE-1078",
                        cwe_name="Inappropriate Source Code Style or Formatting",
                        fix_suggestion=(
                            f"将字符串中的 '{typo}' 改为 '{correct}'。"
                        ),
                        code_snippet=line.strip(),
                        language=Language.CPP,
                    ))


# ── 9. Meaningless else-if on always-true condition ───────────────────────────
def _check_meaningless_else_if(lines: List[str], result: AnalysisResult):
    """
    Detect 'else if (globalPtr != NULL)' where the pointer is a global
    that is always non-NULL (initialized at program start).
    Pattern: else if (pXxx != NULL) followed by trivial reset operations.
    """
    else_if_re = re.compile(
        r'else\s+if\s*\(\s*(\w+)\s*!=\s*NULL\s*\)'
    )
    for i, line in enumerate(lines, 1):
        m = else_if_re.search(line)
        if not m:
            continue
        ptr = m.group(1)
        # Look at next few lines — if they just zero-out the struct, flag it
        body = ' '.join(lines[i:i+5]) if i < len(lines) else ''
        if re.search(r'=\s*NULL\s*;|=\s*0\s*;|pcbNum\s*=\s*0', body):
            result.issues.append(AnalysisIssue(
                title=f"无意义的 else if 条件: '{ptr} != NULL'",
                description=(
                    f"第 {i} 行的 'else if ({ptr} != NULL)' 条件对全局指针"
                    f" '{ptr}' 做非空检查，但该指针在程序启动时已初始化，"
                    f"永远不会为 NULL，因此此分支永远成立。"
                    f"内部仅对已经为空的队列重复清零，逻辑上完全无意义，"
                    f"且可能掩盖 CPU 空转问题（就绪队列为空时应等待而非空循环）。"
                ),
                line=i,
                severity=AnalysisIssue.Severity.WARNING,
                category=AnalysisIssue.Category.CODE_SMELL,
                cwe_id="CWE-561",
                cwe_name="Dead Code",
                fix_suggestion=(
                    f"删除此 else if 分支，或替换为有意义的等待逻辑：\n"
                    f"  else {{\n"
                    f"      Sleep(10);  // 就绪队列为空时短暂等待，避免CPU空转\n"
                    f"  }}"
                ),
                code_snippet=line.strip(),
                language=Language.CPP,
            ))




# ── 10. Buffer with poor scalability ─────────────────────────────────────────
def _check_buffer_naming_risk(lines, result):
    """Detect small char arrays built via index arithmetic — breaks for i>=10."""
    import re as _re
    from typing import Dict as _Dict
    small_buf_re   = _re.compile(r'char\s+(\w+)\s*\[(\d+)\]\s*=\s*"(\w*)"')
    index_assign_re = _re.compile(r'(\w+)\s*\[\d+\]\s*=\s*.+\+\s*i')
    buffers: _Dict[str, tuple] = {}
    for i, line in enumerate(lines, 1):
        m = small_buf_re.search(line)
        if m:
            bname, bsize, bval = m.group(1), int(m.group(2)), m.group(3)
            buffers[bname] = (bsize, i, bval)
    for i, line in enumerate(lines, 1):
        m = index_assign_re.search(line)
        if not m:
            continue
        bname = m.group(1)
        if bname in buffers:
            bsize, decl_line, bval = buffers[bname]
            result.issues.append(AnalysisIssue(
                title=f"缓冲区 '{bname}' 扩展性不足（潜在溢出）",
                description=(
                    f"第 {decl_line} 行声明的 '{bname}[{bsize}]' 通过下标赋值"
                    f"（第 {i} 行）构造名称字符串。"
                    f"当 i >= 10 时索引字符不再是单个数字，产生非预期字符；"
                    f"若循环范围扩大还可能越界。"
                ),
                line=decl_line,
                severity=AnalysisIssue.Severity.WARNING,
                category=AnalysisIssue.Category.SECURITY,
                cwe_id="CWE-120",
                cwe_name="Buffer Copy without Checking Size of Input",
                fix_suggestion=(
                    f"使用 snprintf 格式化生成名称，扩大缓冲区：\n"
                    f"  char {bname}[20];\n"
                    f"  snprintf({bname}, sizeof({bname}), \"p%02d\", i);"
                ),
                code_snippet=lines[decl_line - 1].strip(),
                language=Language.CPP,
            ))

# ── 11. Variable shadowing (CWE-1109) ────────────────────────────────────────
def _check_variable_shadowing(lines, result):
    """
    Detect local variable declarations that shadow an outer-scope variable
    of the same name within the same function.
    Handles both single-line (int f() {) and split-line (int f()\n{).
    """
    import re as _re

    decl_re = _re.compile(
        r'^\s*(?:char|int|long|short|float|double|bool|auto|'
        r'pPCB|pList|HANDLE|DWORD)\s+'
        r'(\w+)\s*(?:\[\d*\])?\s*[={;]'
    )
    sig_re = _re.compile(
        r'\b(?:void|int|double|char|HANDLE|DWORD|bool|WINAPI)\s+'
        r'(?!if|for|while|switch)(\w+)\s*\([^)]*\)\s*(?:const\s*)?$'
    )
    func_open_re = _re.compile(
        r'\b(?:void|int|double|char|HANDLE|DWORD|bool)\s+'
        r'(?!if|for|while|switch)(\w+)\s*\([^)]*\)\s*(?:const\s*)?\{'
    )

    func_scope_stack = []
    brace_depth = 0
    func_depth = -1
    prev_was_sig = False

    for i, raw_line in enumerate(lines, 1):
        stripped = raw_line.strip()
        code = _re.sub(r'//.*$', '', stripped)
        opens  = code.count('{')
        closes = code.count('}')

        fo = func_open_re.search(code)
        if fo:
            func_scope_stack = [{}]
            func_depth = brace_depth
            prev_was_sig = False
        elif sig_re.search(code) and '{' not in code and ';' not in code:
            prev_was_sig = True
        elif prev_was_sig and opens > 0 and closes == 0:
            func_scope_stack = [{}]
            func_depth = brace_depth
            prev_was_sig = False
        else:
            prev_was_sig = False

        brace_depth += opens - closes
        if brace_depth < 0:
            brace_depth = 0

        if func_depth >= 0:
            if opens > 0:
                for _ in range(opens):
                    func_scope_stack.append({})
            if closes > 0:
                for _ in range(min(closes, len(func_scope_stack) - 1)):
                    func_scope_stack.pop()
                if brace_depth <= func_depth:
                    func_scope_stack = []
                    func_depth = -1

        if not func_scope_stack:
            continue

        m = decl_re.match(stripped)
        if not m:
            continue
        var = m.group(1)
        if len(var) <= 1 or var in ('i','j','k','p','q','n','m'):
            continue

        for frame in func_scope_stack[:-1]:
            if var in frame:
                outer_line = frame[var]
                result.issues.append(AnalysisIssue(
                    title=f"变量遮蔽（Variable Shadowing）: '{var}'",
                    description=(
                        f"第 {i} 行在内层作用域重新声明了变量 '{var}'，"
                        f"遮蔽了第 {outer_line} 行在外层作用域的同名变量。"
                        f"内层的 '{var}' 使外层同名变量不可访问，容易引起逻辑混淆。"
                    ),
                    line=i,
                    severity=AnalysisIssue.Severity.WARNING,
                    category=AnalysisIssue.Category.CODE_SMELL,
                    cwe_id="CWE-1109",
                    cwe_name="Use of Same Variable for Multiple Purposes",
                    fix_suggestion=(
                        f"将内层变量 '{var}' 重命名，或复用外层的 '{var}'（删除内层声明）。"
                    ),
                    code_snippet=stripped,
                    language=Language.CPP,
                ))
                break

        if func_scope_stack:
            func_scope_stack[-1][var] = i
