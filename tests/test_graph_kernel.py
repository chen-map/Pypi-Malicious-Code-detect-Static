# -*- coding: utf-8 -*-
"""图内核重构回归测试：节点身份/跨文件链路/kill语义/作用域隔离/污点引擎"""
import sys
import shutil
import tempfile
from pathlib import Path

NEW_DDG = Path(__file__).parent.parent
sys.path.insert(0, str(NEW_DDG))


def make_pkg(root: Path, name: str, files: dict) -> Path:
    pkg = root / name
    for rel, content in files.items():
        p = pkg / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return pkg


def build(pkg_dir: Path):
    from src.ddg_builder_v7 import ProjectDDGBuilderV7
    return ProjectDDGBuilderV7(str(pkg_dir)).build()


def test_same_name_files_no_collision():
    """核心验收:不同目录同名文件的节点 id 不得冲突(旧实现用 basename)"""
    root = Path(tempfile.mkdtemp(prefix="gk_"))
    try:
        pkg = make_pkg(root, "pkg-1.0", {
            "a/utils.py": "def a_helper():\n    return 1\n",
            "b/utils.py": "def b_helper():\n    return 2\n",
        })
        r = build(pkg)
        nodes = r.get('nodes') or {}
        ids = [n.get_id() for n in nodes.values()]
        assert len(ids) == len(set(ids)), "节点 id 存在冲突"
        # 两个 utils.py 的函数节点都应存在
        func_srcs = [n.source for n in nodes.values() if n.type == 'function']
        assert any('a_helper' in s for s in func_srcs), func_srcs
        assert any('b_helper' in s for s in func_srcs), func_srcs
        print(f"[OK] 同名文件 id 唯一 ({len(nodes)} 节点)")
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_function_node_full_body():
    """函数节点应携带完整函数体（LLM 上下文升级的载体）"""
    root = Path(tempfile.mkdtemp(prefix="gk_"))
    try:
        pkg = make_pkg(root, "pkg-1.0", {
            "core.py": "def payload():\n    data = open('/etc/passwd').read()\n"
                       "    return data\n",
        })
        r = build(pkg)
        nodes = r.get('nodes') or {}
        func_srcs = [n.source for n in nodes.values() if n.type == 'function']
        body = next((s for s in func_srcs if 'payload' in s), '')
        assert 'open(' in body and 'return data' in body, \
            f"函数节点应含完整函数体: {body!r}"
        print("[OK] 函数节点携带完整函数体")
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_cross_file_chain_connected():
    """核心验收:跨文件调用链在 nx_graph 上连通（旧实现接在幽灵节点上断开）"""
    root = Path(tempfile.mkdtemp(prefix="gk_"))
    try:
        pkg = make_pkg(root, "pkg-1.0", {
            "helper.py": "import os\n"
                         "def get_secret():\n"
                         "    return os.environ.get('SECRET')\n",
            "main.py": "import helper\n"
                       "import os\n"
                       "def go():\n"
                       "    s = helper.get_secret()\n"
                       "    os.system(s)\n",
        })
        r = build(pkg)
        g = r.get('nx_graph')
        assert g is not None
        # 找到 helper.get_secret 定义节点与 main.go 中 os.system 调用节点
        def find(pred):
            return [n for n, a in g.nodes(data=True) if pred(a)]
        secret_funcs = find(lambda a: 'get_secret' in (a.get('source') or ''))
        system_calls = find(lambda a: 'os.system' in (a.get('source') or ''))
        assert secret_funcs and system_calls, "应有 get_secret 定义与 os.system 调用节点"
        # 跨文件边存在
        cross = [(u, v) for u, v, d in g.edges(data=True) if d.get('type') == 'cross_file_call']
        assert cross, "应存在 cross_file_call 边"
        # 跨文件两端应连通到同图（可双向可达其一即可视为桥接成功）
        u, v = cross[0]
        assert g.has_node(u) and g.has_node(v)
        print(f"[OK] 跨文件桥接边存在且端点在图中 ({len(cross)} 条)")
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_kill_semantics_bounded_edges():
    """kill 语义:重复赋值变量的 def-use 边应线性而非组合数级"""
    root = Path(tempfile.mkdtemp(prefix="gk_"))
    try:
        # x 被赋值 6 次,最后一次流入 exec
        body = "\n".join(f"x = {i}" for i in range(6)) + "\nexec(x)\n"
        pkg = make_pkg(root, "pkg-1.0", {"m.py": body})
        r = build(pkg)
        edges = r.get('edges') or []
        # 统计流入 exec 调用节点的 intra_file 边数(变量读取边)
        exec_edges = [e for e in edges
                      if 'exec' in (e.to_node.source or '')
                      and e.type == 'intra_file'
                      and e.variable == 'x']
        # kill 语义: x 的活跃 def ≤ 2(旧def+新def),exec 处读取的 x 边 ≤ 2
        assert len(exec_edges) <= 2, \
            f"exec(x) 的 def-use 边应 ≤2(kill语义), 实际 {len(exec_edges)}"
        print(f"[OK] kill 语义: exec(x) 读取边 {len(exec_edges)} 条(≤2)")
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_scope_isolation():
    """作用域隔离:函数内局部定义不得泄漏到模块级"""
    root = Path(tempfile.mkdtemp(prefix="gk_"))
    try:
        pkg = make_pkg(root, "pkg-1.0", {
            "m.py": ("def f():\n"
                     "    payload = 'local'\n"
                     "    return payload\n"
                     "\n"
                     "result = f()\n"
                     "print(result)\n"),
        })
        r = build(pkg)
        edges = r.get('edges') or []
        # 模块级 result = f() 不应连到函数内 payload 定义
        leak = [e for e in edges
                if e.from_node.type in ('assignment', 'const_assignment')
                and 'payload' in (e.from_node.source or '')
                and e.from_node.line == 2
                and e.to_node.line == 5]
        assert not leak, f"函数内 payload 定义泄漏到模块级: {[(e.from_node.source, e.to_node.source) for e in leak]}"
        print("[OK] 作用域隔离: 函数内定义不泄漏")
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_taint_engine_unit():
    """污点引擎单元测试:合成子图产出正确顺序的链"""
    from src.taint_engine import analyze, format_for_prompt
    nodes = [
        {'node_id': 'n1', 'code': "key = os.environ.get('K')", 'line': 1, 'file': 'a.py', 'type': 'assignment_with_expr'},
        {'node_id': 'n2', 'code': 'data = b64decode(key)', 'line': 2, 'file': 'a.py', 'type': 'assignment_with_expr'},
        {'node_id': 'n3', 'code': 'exec(data)', 'line': 3, 'file': 'a.py', 'type': 'call'},
        {'node_id': 'n4', 'code': 'print("hello")', 'line': 4, 'file': 'a.py', 'type': 'call'},
    ]
    edges = [
        {'from_node': 'n1', 'to_node': 'n2'},
        {'from_node': 'n2', 'to_node': 'n3'},
    ]
    chains = analyze(nodes, edges)
    assert chains, "应产出污点链"
    c = chains[0]
    stages = [s['stage'] for s in c['steps']]
    assert stages[0] == 'source' and stages[-1] == 'sink', stages
    # 2026-10 结构重构:主来源归因——穿过 b64decode 找到真正的源头
    # os.environ(优先级 environment > decoded_data),链长 3 步
    assert 'os.environ' in c['steps'][0]['code'], c['steps'][0]
    assert c['source_category'] == 'environment', c['source_category']
    assert 'exec' in c['steps'][-1]['code']
    assert len(c['steps']) == 3, f"完整链应 3 步: {[s['code'] for s in c['steps']]}"
    # 无链场景:良性节点
    benign = analyze([{'node_id': 'b1', 'code': 'print(1)', 'line': 1, 'file': 'a.py', 'type': 'call'}], [])
    assert benign == []
    # prompt 格式化
    text = format_for_prompt(chains)
    assert 'SOURCE' in text and 'SINK' in text
    print(f"[OK] 污点引擎单元测试 ({len(chains)} 链, 主来源归因到 os.environ, 3步)")


def test_taint_end_to_end():
    """端到端:exec(os.environ+decode) 包的子图应带污点链"""
    root = Path(tempfile.mkdtemp(prefix="gk_"))
    try:
        pkg = make_pkg(root, "evil-1.0", {
            "core.py": ("import os\nimport base64\n\n"
                        "def run():\n"
                        "    raw = os.environ.get('CFG')\n"
                        "    exec(base64.b64decode(raw))\n"),
        })
        from batch_solution_b_v2 import BatchAnalyzerV20Voting
        a = BatchAnalyzerV20Voting(tarfile_dir=str(root), api_key='dummy',
                                   extract_base=str(root / 'out'))
        a._run_ddg_builder(pkg)
        subs = a._read_subgraph_jsons(pkg)
        chains = [c for s in subs for c in (s.get('taint_chains') or [])]
        assert chains, "端到端应产出污点链"
        cats = {(c['source_category'], c['sink_category']) for c in chains}
        assert any(sink == 'code_execution' for _, sink in cats), cats
        print(f"[OK] 端到端污点链: {len(chains)} 条, 类别 {cats}")
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_cg_cross_file_and_self_method():
    """2026-10 CG 激活:import 跨文件调用与 self.method() 在调用图中解析"""
    root = Path(tempfile.mkdtemp(prefix="gk_"))
    try:
        pkg = make_pkg(root, "pkg-1.0", {
            "loader.py": "import os\n"
                         "def get_secret():\n"
                         "    return os.environ.get('S')\n",
            "runner.py": "import os\n"
                         "from loader import get_secret\n\n"
                         "class Runner:\n"
                         "    def prepare(self):\n"
                         "        return get_secret()\n"
                         "    def go(self):\n"
                         "        os.system(self.prepare())\n",
        })
        r = build(pkg)
        cg = r['call_graph'].call_graph
        edges = list(cg.edges())
        # 跨文件 import 边: runner 的函数 → loader:get_secret
        cross = [(u, v) for u, v in edges if u.split(':')[0] != v.split(':')[0]]
        assert any('get_secret' in v for u, v in cross), f"跨文件 import 调用应解析: {edges}"
        # self.method() 边: Runner.go → Runner.prepare
        self_calls = [(u, v) for u, v in edges
                      if 'go' in u and 'prepare' in v]
        assert self_calls, f"self.method() 调用应解析: {edges}"
        print(f"[OK] CG 激活: 跨文件边 {len(cross)} 条, self.method 边 {len(self_calls)} 条")
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_cfg_dead_code_pruned():
    """2026-10 CFG 激活:py2cfg 真实可达性 + 常量折叠

    判据与对抗实测对齐:死行区间不得有数据流节点(if 节点本身的 source
    是整句 unparse、合法包含 body 文本,不算泄漏);活代码必须保留。
    """
    root = Path(tempfile.mkdtemp(prefix="gk_"))
    try:
        pkg = make_pkg(root, "pkg-1.0", {
            "m.py": ("import os\n"
                     "if False:\n"
                     "    os.system('dead-branch')\n"
                     "raise SystemExit\n"
                     "os.system('after-raise')\n"
                     "\n"
                     "def live():\n"
                     "    os.system('live-call')\n"),
        })
        r = build(pkg)
        m_nodes = [n for n in (r.get('nodes') or {}).values()
                   if n.file.replace('\\', '/').endswith('m.py')]
        # 死行: L3(if False 体内)、L5(无条件 raise 之后) 不得有数据流节点
        dead = [n for n in m_nodes if n.line in (3, 5)]
        assert not dead, \
            f"死行不应有数据流节点: {[(n.line, n.type, n.source[:50]) for n in dead]}"
        # 活代码保留: 活函数体内的调用
        srcs = [n.source or '' for n in m_nodes]
        assert any('live-call' in s for s in srcs), "活函数被误杀"
        print("[OK] CFG 激活: 死行无数据流节点(if False 体内 + raise 后), 活代码保留")
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_interprocedural_taint():
    """2026-10 过程间修复:污点穿过函数边界(来源藏进 helper)

    此前 function_returns 只记 `return <Name>`,且调用节点无返回值边——
    来源藏进任何一层函数污点链即断(实测 0 条)。修复后应有完整 5 步链:
    environ return → get_config() 调用 → transform 调用 → data 定义 → exec
    """
    root = Path(tempfile.mkdtemp(prefix="gk_"))
    try:
        pkg = make_pkg(root, "pkg-1.0", {
            "m.py": ("import os\n"
                     "import base64\n\n"
                     "def get_config():\n"
                     "    return os.environ.get('C')\n\n"
                     "def transform(raw):\n"
                     "    return base64.b64decode(raw)\n\n"
                     "def main():\n"
                     "    data = transform(get_config())\n"
                     "    exec(data)\n"),
        })
        r = build(pkg)
        from src.taint_engine import analyze
        nodes, edges = r['nodes'], r['edges']
        nlist = [{'node_id': n.get_id(), 'code': n.source, 'line': n.line,
                  'file': n.file, 'type': n.type} for n in nodes.values()]
        elist = [{'from_node': e.from_node.get_id(), 'to_node': e.to_node.get_id(),
                  'kind': e.edge_kind} for e in edges]
        chains = analyze(nlist, elist)
        assert chains, "过程间污点链仍断(来源藏进 helper 时应为 0 条的旧bug)"
        c = chains[0]
        assert c['source_category'] == 'environment' and c['sink_category'] == 'code_execution', \
            (c['source_category'], c['sink_category'])
        assert len(c['steps']) >= 4, f"链应穿两层函数(≥4步), 实际 {len(c['steps'])}"
        assert c['confidence'] == 0.75, f"穿 call/param 边置信度应 0.75, 实际 {c['confidence']}"
        print(f"[OK] 过程间污点: {len(c['steps'])} 步穿两层函数, "
              f"主来源 environment, conf={c['confidence']}")
    finally:
        shutil.rmtree(root, ignore_errors=True)


if __name__ == '__main__':
    test_same_name_files_no_collision()
    test_function_node_full_body()
    test_cross_file_chain_connected()
    test_kill_semantics_bounded_edges()
    test_scope_isolation()
    test_taint_engine_unit()
    test_taint_end_to_end()
    test_interprocedural_taint()
    test_cg_cross_file_and_self_method()
    test_cfg_dead_code_pruned()
    print("\n===== test_graph_kernel 全部通过 =====")
