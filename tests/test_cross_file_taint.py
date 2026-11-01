# -*- coding: utf-8 -*-
"""跨文件过程间污点回归测试:来源/变换/执行分散在三个文件"""
import sys
import shutil
import tempfile
from pathlib import Path

NEW_DDG = Path(__file__).parent.parent
sys.path.insert(0, str(NEW_DDG))


def test_cross_file_interprocedural_taint():
    """三文件链: source.py(os.environ) → transform.py(b64decode) → main.py(os.system)

    2026-10 过程间修复的跨文件验收:此前 return→调用点 链接只在同文件
    后处理中做,跨文件链为 0 条。
    """
    from src.ddg_builder_v7 import ProjectDDGBuilderV7
    from src.taint_engine import analyze

    root = Path(tempfile.mkdtemp(prefix="xft_"))
    try:
        pkg = root / 'xfile' / 'pkg'
        pkg.mkdir(parents=True)
        (pkg / '__init__.py').write_text("", encoding='utf-8')
        (pkg / 'source.py').write_text(
            "import os\n"
            "def get_config():\n"
            "    return os.environ.get('C')\n", encoding='utf-8')
        (pkg / 'transform.py').write_text(
            "import base64\n"
            "from pkg.source import get_config\n"
            "def decode():\n"
            "    return base64.b64decode(get_config())\n", encoding='utf-8')
        (pkg / 'main.py').write_text(
            "import os\n"
            "from pkg.transform import decode\n\n"
            "def run():\n"
            "    data = decode()\n"
            "    os.system(data)\n", encoding='utf-8')

        r = ProjectDDGBuilderV7(str(root / 'xfile')).build()
        nodes, edges = r['nodes'], r['edges']
        nlist = [{'node_id': n.get_id(), 'code': n.source, 'line': n.line,
                  'file': n.file, 'type': n.type} for n in nodes.values()]
        elist = [{'from_node': e.from_node.get_id(), 'to_node': e.to_node.get_id(),
                  'kind': e.edge_kind} for e in edges]
        chains = analyze(nlist, elist)
        assert chains, "✗ 跨文件污点链仍断"
        c = chains[0]
        files = {s['file'].replace('\\', '/').rsplit('/', 1)[-1]
                 for s in c['steps'] if s.get('file')}
        assert c['source_category'] == 'environment', c['source_category']
        assert c['sink_category'] == 'command_execution', c['sink_category']
        assert len(files) == 3, f"链应贯穿三个文件, 实际 {files}"
        print(f"[OK] 三文件跨层污点闭合: {len(c['steps'])} 步跨 3 文件, "
              f"conf={c['confidence']}")
    finally:
        shutil.rmtree(root, ignore_errors=True)


if __name__ == '__main__':
    test_cross_file_interprocedural_taint()
    print("\n===== test_cross_file_taint 通过 =====")
