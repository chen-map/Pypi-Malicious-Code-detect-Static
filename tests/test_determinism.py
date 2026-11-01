# -*- coding: utf-8 -*-
"""确定性回归 v2:同一目录路径三次独立进程重建,产物逐字节一致

设计说明:node_id/JSON 里嵌着构建路径,跨目录对比会被路径噪声淹没;
固定同一路径、只变 PYTHONHASHSEED(每进程不同),即可分离出纯内容差异。
"""
import hashlib
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

NEW_DDG = Path(__file__).parent.parent

BUILD_SNIPPET = (
    "import sys; sys.path.insert(0, r'{new}')\n"
    "from batch_solution_b_v2 import BatchAnalyzerV20Voting\n"
    "from pathlib import Path\n"
    "a = BatchAnalyzerV20Voting(tarfile_dir='.', api_key='dummy',\n"
    "    extract_base=r'{base}')\n"
    "a._run_ddg_builder(Path(r'{pkg}'))\n"
)


def _snapshot(d):
    out = {}
    for f in sorted(d.rglob('*.json')):
        out[f.relative_to(d).as_posix()] = hashlib.sha256(f.read_bytes()).hexdigest()
    return out


def test_three_run_determinism():
    work = Path(tempfile.mkdtemp(prefix='det_same_path_'))
    try:
        pkg = work / 'rgbcolor-0.1.7'
        shutil.copytree(NEW_DDG / 'output' / 'packages_line' / 'rgbcolor-0.1.7', pkg,
                        ignore=shutil.ignore_patterns('.ddg_output'))
        snapshots = []
        for run in range(3):
            ddg = pkg / '.ddg_output'
            if ddg.exists():
                shutil.rmtree(ddg)
            code = BUILD_SNIPPET.format(new=str(NEW_DDG),
                                        base=str(work / 'out'), pkg=str(pkg))
            subprocess.run(
                [sys.executable, '-c', code],
                capture_output=True, text=True, timeout=300,
                encoding='utf-8', errors='replace',
                env={'PYTHONHASHSEED': str(run + 1),
                     'PATH': __import__('os').environ['PATH'],
                     'SYSTEMROOT': __import__('os').environ.get('SYSTEMROOT', '')},
            )
            snapshots.append(_snapshot(pkg / '.ddg_output'))

        bad = [k for k in snapshots[0]
               if snapshots[0][k] != snapshots[1].get(k)
               or snapshots[0][k] != snapshots[2].get(k)]
        assert not bad, f"产物不一致: {bad[:8]}"
        print(f"[OK] 同路径三次独立构建(PYTHONHASHSEED=1/2/3) "
              f"产物哈希一致: {len(snapshots[0])} 个文件")
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == '__main__':
    test_three_run_determinism()
    print('\n===== test_determinism 通过 =====')
