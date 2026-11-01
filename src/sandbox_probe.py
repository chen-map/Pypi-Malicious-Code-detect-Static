# -*- coding: utf-8 -*-
"""沙箱行为探针 - 用 audit hook 记录 setup.py 安装期行为

原理(2026-10 行为模态):1inch 族恶意包的载荷发生在**安装时**(setup.py
顶层代码:下载 exe、写 ProgramData、隐蔽启动),静态包分析原理上看不见。
本模块在**子进程**里执行目标 setup.py,通过 Python 3.8+ 的 sys.addaudithook
记录:网络连接 / 子进程 / 敏感文件写入,产出行为证据。

安全边界(必读):
- 真实恶意包的 setup.py 会执行任意代码——**只能在隔离 VM/容器里对真实
  样本启用**(--sandbox 显式开启,默认关闭)
- 本模块的开发/测试只用**合成无害包**(echo/127.0.0.1/写临时目录)
- 子进程 60s 超时强杀;事件写 JSONL,主进程只读文件不碰子进程内存
"""

import json
import subprocess
import sys
import tempfile
from pathlib import Path

# sitecustomize 模板:注入子进程,启动即挂 audit hook
_SITECUSTOMIZE = '''
import json
import os
import sys

_OUT = os.environ.get("SANDBOX_EVENTS")
if _OUT:
    _fh = open(_OUT, "a", encoding="utf-8")

    def _emit(kind, detail):
        try:
            _fh.write(json.dumps({"kind": kind, "detail": str(detail)[:300]}) + "\\n")
            _fh.flush()
        except Exception:
            pass

    def _hook(event, args):
        try:
            if event in ("subprocess.Popen", "os.system", "os.exec",
                         "os.startfile", "os.spawn"):
                _emit("exec", args)
            elif event == "socket.connect":
                _emit("network", args[0])
            elif event == "urllib.Request":
                _emit("network", args[0])
            elif event == "open":
                path = str(args[0]) if args else ""
                mode = str(args[1]) if len(args) > 1 and args[1] else "r"
                if any(c in mode for c in "wxa"):
                    _emit("file_write", path)
        except Exception:
            pass

    sys.addaudithook(_hook)
'''


def probe_setup_py(pkg_dir: str, timeout: float = 60.0,
                   python_exe: str = None) -> dict:
    """在受监控子进程里执行 setup.py --name,记录安装期行为

    `setup.py --name` 会执行 setup.py 的**顶层代码**(正是 1inch 族
    藏载荷的位置),但不真正安装——比 install 更安全,覆盖面相同。

    Returns:
        {'ran': bool, 'behavioral_level': 'high'|'unknown',
         'network': [...], 'exec': [...], 'file_write': [...],
         'reason': str}
    """
    pkg_dir = Path(pkg_dir)
    setup_py = pkg_dir / 'setup.py'
    if not setup_py.exists():
        return {'ran': False, 'behavioral_level': 'unknown',
                'network': [], 'exec': [], 'file_write': [],
                'reason': '无 setup.py'}

    events_file = pkg_dir / '.sandbox_events.jsonl'
    site_dir = Path(tempfile.mkdtemp(prefix='sbx_'))
    (site_dir / 'sitecustomize.py').write_text(_SITECUSTOMIZE, encoding='utf-8')

    env = {
        'SYSTEMROOT': __import__('os').environ.get('SYSTEMROOT', ''),
        'PATH': __import__('os').environ.get('PATH', ''),
        'PYTHONPATH': str(site_dir),
        'SANDBOX_EVENTS': str(events_file),
    }
    if events_file.exists():
        events_file.unlink()

    ran = False
    try:
        proc = subprocess.run(
            [python_exe or sys.executable, 'setup.py', '--name'],
            cwd=str(pkg_dir), env=env, timeout=timeout,
            capture_output=True, text=True, encoding='utf-8', errors='replace')
        ran = True
    except subprocess.TimeoutExpired:
        pass
    except Exception:
        pass

    events = {'network': [], 'exec': [], 'file_write': []}
    if events_file.exists():
        try:
            for line in events_file.read_text(encoding='utf-8').splitlines():
                if not line.strip():
                    continue
                try:
                    ev = json.loads(line)
                    if ev['kind'] in events:
                        events[ev['kind']].append(ev['detail'])
                except (json.JSONDecodeError, KeyError):
                    continue
        except OSError:
            pass

    # 分类:安装期任何网络/子进程 = high(合法 setup.py 不需要联网或
    # 起子进程;PyPI 交互由 pip 负责,不由 setup.py 负责)
    if events['network'] or events['exec']:
        level = 'high'
        reason = (f'安装期行为: 网络{len(events["network"])}次 / '
                  f'子进程{len(events["exec"])}次 '
                  f'(如 {events["network"][:1] or events["exec"][:1]})')
    elif not ran:
        level = 'unknown'
        reason = 'setup.py 执行失败或超时(崩溃也是信号,但无法定性)'
    else:
        level = 'unknown'
        reason = '安装期无可疑行为'
        if events['file_write']:
            level = 'unknown'
            reason += f';文件写入{len(events["file_write"])}次(需人工看路径)'

    return {
        'ran': ran,
        'behavioral_level': level,
        'network': events['network'][:10],
        'exec': events['exec'][:10],
        'file_write': events['file_write'][:10],
        'reason': reason,
    }
