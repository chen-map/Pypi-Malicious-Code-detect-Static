# -*- coding: utf-8 -*-
"""两阶段判定：小模型提取链路，强模型判断

动机（2026-11）：
    链路提取与恶意判定是两种不同性质的认知任务，不该用同一个模型：
      - 链路提取：输入是整张图（大），但任务机械（找出连通的候选路径）
        → 小模型足够，成本低
      - 恶意判定：输入只有几行路径代码（小），但需要深度语义理解
        → 强模型，一次性判断，token 消耗很小

    成本结构因此是阶梯式的：强模型只在「小模型找到候选路径」时才被调用。
    良性包大多在第一阶段就没有路径，走不到第二阶段。

与 MalSkills 的差异：
    MalSkills 用符号规则提链、LLM 补缺口；
    这里两个阶段都是 LLM，但**链路必须通过图验证**（verify_paths），
    所以小模型的幻觉不会传播到强模型——强模型看到的永远是真实存在的路径。
"""
import json
import re
from pathlib import Path
from typing import Dict, List, Optional

from src.llm_graph_analyst import analyze as extract_paths, _parse_json


def _package_intent(package_dir) -> Optional[Dict]:
    """读取包的自我声明（2026-11 缺口2：意图 vs 行为比对）。

    人类分析师的第一个问题永远是"这个包声称自己是什么？行为匹配吗？"
    PKG-INFO 的 Name/Summary 是包的官方自我声明——判定时给强模型这个
    上下文，让它能识别"自称终端 UI 库却装了反弹 shell"的意图错位。
    """
    if package_dir is None:
        return None
    d = Path(package_dir)
    meta = {}
    for cand in (d / 'PKG-INFO', d / 'setup.py'):
        try:
            txt = cand.read_text(encoding='utf-8', errors='ignore')
        except Exception:
            continue
        for line in txt.split('\n'):
            m = re.match(r'^(Name|Summary)[:]\s*(.+)', line)
            if m:
                k = m.group(1).lower()
                if k not in meta:
                    meta[k] = m.group(2).strip().strip('"\'')[:200]
        if meta.get('name'):
            break
    return meta if meta else None


def _intent_block(pkg_info: Optional[Dict]) -> str:
    """渲染意图上下文块（无声明时为空）"""
    if not pkg_info:
        return ''
    lines = ['## Package self-description (claimed purpose)']
    if pkg_info.get('name'):
        lines.append(f'name: {pkg_info["name"]}')
    if pkg_info.get('summary'):
        lines.append(f'summary: {pkg_info["summary"]}')
    lines.append('Judge whether the flagged behavior MATCHES this claimed purpose.')
    lines.append('A terminal-UI library spawning hidden processes = mismatch '
                 '= strong malicious signal.')
    return '\n'.join(lines)


JUDGE_PROMPT = """You are a senior malware analyst. Below are data-flow paths
extracted from a Python package's dependency graph. Each path is a real,
verified chain of nodes (file:line + code). Your job: decide whether each path
constitutes malicious behavior.

## Paths
{paths}

## Well-known legitimate idioms (thousands of PyPI packages use these)
These look dangerous but are industry-standard patterns -> BENIGN:
  - `exec(open("_version.py").read())` / `exec(open("version.py").read())`
    -> setuptools-scm version detection, used by ~50k packages
  - reading a bundled `_version.py` / `version.py` and extracting __version__
  - `subprocess` invoking a literal compiler/git/make tool with fixed args
  - decoding a bundled asset file and loading it locally
  - optional-dependency try/except imports
If a path matches one of these idioms (or is equivalent in intent), judge BENIGN
even though the APIs are powerful.

## Judging criteria
A path is MALICIOUS only if the flow itself is an attack, e.g.:
  - remote/hidden content reaching code or command execution
  - credentials or private files reaching an outbound network call
  - downloaded content written to disk and then executed
  - install-time execution of a payload from a literal string
    (encoded command, reverse shell, miner pool, remote URL)
A path is NOT malicious if it is routine for the package's apparent purpose.
Consider the *flow*, not the vocabulary. A dangerous API name alone means nothing.

## Output (JSON only)
```json
{{"judgments": [{{"path_id": 1, "malicious": true, "confidence": 0.0,
                 "reason": "one sentence tied to the actual flow"}}],
  "overall": "MALICIOUS|SUSPICIOUS|BENIGN",
  "summary": "one paragraph"}}
```
"""


def _render_paths_for_judge(paths: List[Dict], nodes: List[Dict],
                            max_paths: int = 6, max_code: int = 110) -> str:
    """把已验证路径渲染成强模型可读的紧凑文本（只给路径，不给整图）"""
    by_id = {n.get('node_id'): n for n in nodes if n.get('node_id')}
    lines = []
    for i, p in enumerate(paths[:max_paths], 1):
        ids = p.get('nodes') or []
        lines.append(f"### Path {i}  (claimed: {p.get('behavior', '?')})")
        for nid in ids:
            n = by_id.get(nid) or {}
            code = ' '.join((n.get('code') or '').split())[:max_code]
            lines.append(f"  {n.get('file', '?')}:{n.get('line', 0)}  {code}")
        why = p.get('why_malicious')
        if why:
            lines.append(f"  (extractor's note: {why[:140]})")
        lines.append('')
    return '\n'.join(lines)


def _parse_json(text: str) -> Optional[Dict]:
    if not text:
        return None
    m = re.search(r'```json\s*(.*?)\s*```', text, re.DOTALL)
    raw = m.group(1) if m else text
    m2 = re.search(r'\{.*\}', raw, re.DOTALL)
    if not m2:
        return None
    try:
        return json.loads(m2.group())
    except Exception:
        return None


_CONTEXT_PROMPT = """You are a senior malware analyst. A static analyzer
flagged the following code snippets from a Python package as *potentially*
suspicious (they use powerful APIs). Decide the package-level verdict.

## Flagged code
{snippets}

## Judge by intent, not by API power
Powerful APIs are routine in legitimate software:
  - `exec(open("_version.py").read())` -> setuptools-scm version detection: BENIGN
  - `subprocess` calling a literal compiler/git tool with fixed args -> BENIGN
  - reading a config file and using it locally -> BENIGN
  - decoding a bundled data file (assets) -> BENIGN
MALICIOUS requires hostile *intent* in the flow:
  - reverse shell / hardcoded attacker IP or miner pool
  - credentials/keys leaving the machine
  - remote code downloaded and executed
  - install hooks running hidden payloads
If the snippets are explainable as ordinary library behavior -> BENIGN.
If powerful APIs with no benign explanation -> MALICIOUS.
In between -> SUSPICIOUS.

## Output (JSON only)
{{"overall": "MALICIOUS|SUSPICIOUS|BENIGN", "confidence": 0.0,
  "summary": "one sentence"}}
"""


def _context_judge(nodes: List[Dict], client, model: str,
                   pkg_info: Optional[Dict] = None,
                   max_snippets: int = 6) -> Optional[Dict]:
    """无路径时的上下文判定：把高危特征最强的节点代码给强模型看。

    只在第一阶段 SUSPICIOUS/UNKNOWN 时触发（省成本）。
    输入是节点的**真实代码**（已通过 AST-dump 修复），不是标签。
    """
    _HIGH_RISK = (
        'subprocess', 'os.system', 'popen', 'exec(', 'eval(', 'compile(',
        'socket.', '/dev/tcp', 'urlopen', 'requests.post', 'b64decode',
        'encodedcommand', 'powershell', 'marshal', 'chmod', 'setuid',
    )
    scored = []
    for n in nodes:
        code = (n.get('code') or '')
        hits = sum(1 for p in _HIGH_RISK if p in code.lower())
        if hits:
            scored.append((hits, -len(code), n))
    if not scored:
        return None
    # 按特征命中数排序（dict 不可比较，必须给 key——否则 TypeError）
    scored.sort(key=lambda t: (t[0], t[1]), reverse=True)
    snippets = []
    for _h, _l, n in scored[:max_snippets]:
        code = ' '.join((n.get('code') or '').split())[:220]
        snippets.append(f"{n.get('file', '?')}:{n.get('line', 0)}  {code}")
    prompt = _CONTEXT_PROMPT.format(snippets=chr(10).join(snippets))
    intent = _intent_block(pkg_info)
    if intent:
        prompt += chr(10) * 2 + intent
    try:
        resp = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content":
                 "You are a senior malware analyst. Output only JSON."},
                {"role": "user", "content": prompt},
            ],
            temperature=0.1, max_tokens=400)
        raw = resp.choices[0].message.content if resp.choices else ''
    except Exception:
        return None
    data = _parse_json(raw)
    if not data:
        return None
    overall = str(data.get('overall', '')).upper()
    if overall not in ('MALICIOUS', 'SUSPICIOUS', 'BENIGN'):
        return None
    return {'overall': overall,
            'confidence': float(data.get('confidence') or 0.6),
            'summary': (data.get('summary') or '')[:300],
            'judgments': []}


def judge_paths(paths: List[Dict], nodes: List[Dict], client, model: str,
                pkg_info: Optional[Dict] = None,
                max_paths: int = 6) -> Dict:
    """强模型判定：只看已验证路径，不看整图。

    Returns:
        {'judgments': [...], 'overall': str, 'confidence': float,
         'summary': str, 'error': str|None}
    """
    if not paths:
        return {'judgments': [], 'overall': 'BENIGN', 'confidence': 0.5,
                'summary': 'no verified path', 'error': None}

    prompt = JUDGE_PROMPT.format(
        paths=_render_paths_for_judge(paths, nodes, max_paths=max_paths))
    intent = _intent_block(pkg_info)
    if intent:
        prompt += '\n\n' + intent
    try:
        resp = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content":
                 "You are a senior malware analyst judging data-flow paths. "
                 "Output only JSON."},
                {"role": "user", "content": prompt},
            ],
            temperature=0.1, max_tokens=1200,
        )
        out = resp.choices[0].message.content if resp.choices else ''
    except Exception as e:
        return {'judgments': [], 'overall': 'UNKNOWN', 'confidence': 0.0,
                'summary': '', 'error': f'{type(e).__name__}: {e}'}

    data = _parse_json(out)
    if not data:
        return {'judgments': [], 'overall': 'UNKNOWN', 'confidence': 0.0,
                'summary': '', 'error': 'json_parse_failed'}

    overall = str(data.get('overall', 'UNKNOWN')).upper()
    if overall not in ('MALICIOUS', 'SUSPICIOUS', 'BENIGN'):
        overall = 'UNKNOWN'
    judgments = data.get('judgments') or []
    conf = 0.8
    if judgments:
        try:
            conf = sum(float(j.get('confidence') or 0.5) for j in judgments) / len(judgments)
        except Exception:
            conf = 0.8
    return {
        'judgments': judgments,
        'overall': overall,
        'confidence': round(conf, 2),
        'summary': (data.get('summary') or '')[:400],
        'error': None,
    }


def analyze_two_stage(nodes: List[Dict], edges: List[Dict],
                      small_client, small_model: str,
                      big_client, big_model: str,
                      samples: int = 1, show_danger: bool = False,
                      package_dir=None) -> Dict:
    """两阶段判定：小模型提链 → 强模型判链。

    返回值合并了两阶段信息，便于审计：
      stage1_verdict / stage1_paths   小模型的原始判断与路径
      stage2_*                        强模型的判定
      verdict                         最终结论（以强模型为准，无路径时用小模型）
    """
    # ---------- Stage 1: 小模型提取链路 ----------
    s1 = extract_paths(nodes, edges, small_client, small_model,
                       samples=samples, show_danger=show_danger)
    paths = s1.get('valid_paths') or []

    if not paths:
        # 没有验证通过的路径：默认沿用第一阶段（省成本）。
        # 但**第一阶段判 SUSPICIOUS/UNKNOWN 时要给强模型二次机会**（2026-11，
        # 良性回归驱动）：良性包大量停在 SUSPICIOUS——小模型找到了危险 API
        # 却连不出链（exec(open(_version.py).read()) 这类惯用法天然无数据流），
        # 强模型看一眼代码上下文往往能确认是惯用法 → BENIGN。
        s1v = s1.get('verdict', 'UNKNOWN')
        if s1v in ('SUSPICIOUS', 'UNKNOWN'):
            pkg_info = _package_intent(package_dir)
            ctx = _context_judge(nodes, big_client, big_model, pkg_info=pkg_info)
            if ctx and ctx.get('overall') in ('MALICIOUS', 'SUSPICIOUS', 'BENIGN'):
                return {
                    'verdict': ctx['overall'],
                    'confidence': ctx.get('confidence', 0.6),
                    'stage1_verdict': s1v,
                    'stage1_paths': 0,
                    'stage1_reasoning': s1.get('reasoning', ''),
                    'stage2_overall': ctx['overall'],
                    'stage2_judgments': ctx.get('judgments', []),
                    'stage2_summary': ctx.get('summary', ''),
                    'big_model_used': True,
                    'stage2_mode': 'context',
                    'rejected_paths': len(s1.get('rejected_paths') or []),
                }
        return {
            'verdict': s1v,
            'confidence': s1.get('confidence', 0.0),
            'stage1_verdict': s1v,
            'stage1_paths': 0,
            'stage1_reasoning': s1.get('reasoning', ''),
            'stage2_overall': None,
            'stage2_judgments': [],
            'stage2_summary': '',
            'big_model_used': False,
            'rejected_paths': len(s1.get('rejected_paths') or []),
        }

    # ---------- Stage 2: 强模型判定路径 ----------
    pkg_info = _package_intent(package_dir)
    s2 = judge_paths(paths, nodes, big_client, big_model, pkg_info=pkg_info)

    if s2.get('error'):
        # 强模型失败 → 回退到第一阶段结论（保守）
        return {
            'verdict': s1.get('verdict', 'UNKNOWN'),
            'confidence': s1.get('confidence', 0.0),
            'stage1_verdict': s1.get('verdict'),
            'stage1_paths': len(paths),
            'stage1_reasoning': s1.get('reasoning', ''),
            'stage2_overall': 'ERROR',
            'stage2_judgments': [],
            'stage2_summary': s2.get('error', ''),
            'big_model_used': True,
            'rejected_paths': len(s1.get('rejected_paths') or []),
        }

    return {
        'verdict': s2['overall'],
        'confidence': s2['confidence'],
        'stage1_verdict': s1.get('verdict'),
        'stage1_paths': len(paths),
        'stage1_reasoning': s1.get('reasoning', ''),
        'stage2_overall': s2['overall'],
        'stage2_judgments': s2['judgments'],
        'stage2_summary': s2['summary'],
        'big_model_used': True,
        'rejected_paths': len(s1.get('rejected_paths') or []),
    }
