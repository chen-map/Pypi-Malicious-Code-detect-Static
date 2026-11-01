# -*- coding: utf-8 -*-
"""AST 级调用目标解析(2026-10 词法天花板攻坚)

问题:Source/Sink 靠正则匹配代码文本——
    getattr(builtins, 'ev' + 'al')(payload)   → 正则看不到 eval
    e = eval; e(payload)                      → 正则看到的是 e
    globals()['ex' + 'ec'](cmd)               → 同上

解法:extractor 在 visit_Call 时解析调用目标,把**解析出的真实函数名**
写到节点属性 resolved_call。规则:
1. Name/Attribute 链   → 点名字符串(os.system / requests.get)
2. getattr(常量, 常量)  → 字符串拼接常量折叠 → os.system / builtins.eval
3. 别名追踪             → e = eval / system = os.system 之后的 e(x)
4. globals()['ex'+'ec'] → Subscript 常量下标折叠
正则回退保留(不可解析形态仍由词法层兜底)。
"""
import ast


# 污点引擎关注的可解析目标(与 taint_engine 的 SOURCE/SINK 类别对应)
RESOLVED_SINKS = {
    'eval': 'code_execution',
    'exec': 'code_execution',
    'compile': 'code_execution',
    'os.system': 'command_execution',
    'os.popen': 'command_execution',
    'subprocess.run': 'command_execution',
    'subprocess.Popen': 'command_execution',
    'subprocess.call': 'command_execution',
    'subprocess.check_call': 'command_execution',
    'subprocess.check_output': 'command_execution',
    'requests.post': 'data_exfiltration',
    'requests.put': 'data_exfiltration',
    'socket.send': 'data_exfiltration',
    'socket.sendall': 'data_exfiltration',
    'socket.sendto': 'data_exfiltration',
    # 2026-10 词法天花板:变量调用目标=动态分发。
    # 污点 BFS 过滤:只有真污点源可达时才产链(合法回调无链)。
    'dynamic_dispatch': 'code_execution',
    # 2026-11 摘要传播:调用"参数到达危险 sink"的函数 = 该调用本身是 sink。
    # 类别从节点的 taint_categories 属性取(由 builder 写入)。
    'summary_expansion': 'code_execution',
}

RESOLVED_SOURCES = {
    'os.environ.get': 'environment',
    'os.getenv': 'environment',
    'input': 'user_input',
    'requests.get': 'network_response',
    'requests.head': 'network_response',
    'urllib.request.urlopen': 'network_response',
    'urlopen': 'network_response',
    'socket.recv': 'socket_recv',
    'pickle.loads': 'deserialization',
    'marshal.loads': 'deserialization',
    'base64.b64decode': 'decoded_data',
}

# 可被别名追踪的内置危险函数
ALIASABLE = {'eval', 'exec', 'compile'} | {k for k in RESOLVED_SINKS}


def fold_const_string(node):
    """常量字符串求值: 'ev'+'al' → 'eval';None 表示不可折叠"""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = fold_const_string(node.left)
        right = fold_const_string(node.right)
        if left is not None and right is not None:
            return left + right
    return None


def resolve_call_target(func, aliases=None):
    """解析调用目标为点名字符串

    Args:
        func: ast.Call.func 表达式
        aliases: {变量名: 已解析目标} 别名表(None 表示不追踪别名)

    Returns:
        点名字符串('os.system' / 'eval' / 'requests.get'),不可解析返回 None
    """
    aliases = aliases or {}

    if isinstance(func, ast.Name):
        if func.id in aliases:
            return aliases[func.id]
        return func.id

    if isinstance(func, ast.Attribute):
        base = resolve_call_target(func.value, aliases)
        if base:
            return f"{base}.{func.attr}"
        return None

    if isinstance(func, ast.Call):
        # getattr(x, 'name' [, default]) 常量折叠
        # base 支持递归解析: getattr(builtins, ...) 的 base 是 Name('builtins')
        if isinstance(func.func, ast.Name) and func.func.id == 'getattr' \
                and len(func.args) >= 2:
            base = fold_const_string(func.args[0])
            if base is None and isinstance(func.args[0], (ast.Name, ast.Attribute)):
                base = resolve_call_target(func.args[0], aliases)
            attr = fold_const_string(func.args[1])
            if base is not None and attr is not None:
                if base in ('builtins',):
                    base = ''
                target = f"{base}.{attr}" if base else attr
                return aliases.get(target, target)
        # globals() / locals() 调用本身:作为 Subscript 下标的基座
        if isinstance(func.func, ast.Name) and func.func.id in ('globals', 'locals') \
                and not func.args:
            return func.func.id
    if isinstance(func, ast.Subscript):
        # globals()['ex' + 'ec'] 常量下标(基座可以是 globals() 调用)
        base = resolve_call_target(func.value, aliases)
        if base in ('globals', 'locals', 'builtins'):
            key = fold_const_string(func.slice)
            if key:
                target = key if base == 'builtins' else key
                return aliases.get(target, target)
    return None


def match_resolved_sink(resolved: str):
    """解析名 → sink 类别(精确/前缀),不匹配返回 None"""
    if not resolved:
        return None
    if resolved in RESOLVED_SINKS:
        return RESOLVED_SINKS[resolved]
    for prefix, cat in RESOLVED_SINKS.items():
        if resolved.startswith(prefix + '.'):
            return cat  # subprocess.run(**kwargs) 之类已覆盖;防御性前缀
    return None


def match_resolved_source(resolved: str):
    """解析名 → source 类别,不匹配返回 None"""
    if not resolved:
        return None
    return RESOLVED_SOURCES.get(resolved)
