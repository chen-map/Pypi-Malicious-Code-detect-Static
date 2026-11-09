# -*- coding: utf-8 -*-
"""审计：被判 BENIGN 的恶意包，代码里到底有没有载荷？

回答一个问题：这些漏报是"代码本身干净（名称抢注）"还是"我们图没抓住"。

对每个包扫静态载荷指纹（不执行）：
  - IP 字面量 / 可疑 TLD / 攻击者基础设施域名
  - base64+exec/eval 组合、marshal/zlib 反序列化后执行
  - os.system/popen/subprocess 带 curl|wget|bash|sh -c
  - 把 os.environ / 文件内容 POST 出去（同函数内出现）
  - .pth 注入、sitecustomize
  - 安装期（setup.py）出现网络+侦察
只有命中任一指纹才可能是图的漏报；全部不命中 → 代码层面无载荷。

用法:
    python v3_audit_benign.py <results_dir> <corpus_dir> <extract_glob>
"""
import glob
import json
import os
import re
import sys
from collections import Counter

SIGS = [
    ('ip_literal', re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')),
    ('exec_b64', re.compile(r'(b64decode|b85decode|decompress|marshal\.loads)'
                            r'[\s\S]{0,400}?\b(eval|exec)\s*\(')),
    ('shell_curl', re.compile(r'(os\.system|os\.popen|subprocess\.[a-z_]+|call|run|Popen)'
                              r'\s*\([\s\S]{0,200}?(curl|wget|bash|sh\s+-c|powershell)')),
    ('exfil_post', re.compile(r'(requests\.(post|get)|urlopen|socket\.socket)'
                              r'[\s\S]{0,300}?(os\.environ|open\()')),
    ('pth_inject', re.compile(r'^\s*import\s+', re.M)),
    ('susp_tld', re.compile(r'https?://[^\s\'"]*\.(top|xyz|tk|ml|ga|cf|gq|ru|su)\b')),
    ('onion_or_paste', re.compile(r'\.onion|pastebin|transfer\.sh|discord(app)?\.com/api/webhooks',
                                  re.I)),
    ('c2_tunnel', re.compile(r'ngrok|localtunnel|serveo\.net|trycloudflare|bore\.pub|'
                             r'ngrok-free\.app', re.I)),
    ('ip_port', re.compile(r'connect\s*\(\s*\(?\s*[\'"](?:\d{1,3}\.){3}\d{1,3}[\'"]\s*,'
                           r'\s*\d{2,5}')),
    ('reverse_shell', re.compile(r'socket\.socket[\s\S]{0,200}?connect[\s\S]{0,200}?'
                                 r'(dup2|subprocess|/bin/sh|cmd\.exe)', re.I)),
]
SKIP_DIRS = ('test', 'tests', 'testing', 'examples', 'docs', 'doc')


def scan_pkg(pkg_dir):
    hits = Counter()
    where = {}
    for root, dirs, files in os.walk(pkg_dir):
        dirs[:] = [d for d in dirs if d.lower() not in SKIP_DIRS
                   and not d.startswith('.')]
        for fn in files:
            if not (fn.endswith('.py') or fn.endswith('.pth')):
                continue
            path = os.path.join(root, fn)
            if fn.endswith('.pth'):
                rel = os.path.relpath(path, pkg_dir)
                try:
                    body = open(path, encoding='utf-8', errors='replace').read()
                except OSError:
                    continue
                if any(ln.strip().startswith('import ') for ln in body.splitlines()):
                    hits['pth_inject'] += 1
                    where.setdefault('pth_inject', rel)
                continue
            try:
                if os.path.getsize(path) > 2_000_000:
                    continue
                body = open(path, encoding='utf-8', errors='replace').read()
            except OSError:
                continue
            for name, rx in SIGS:
                if name == 'pth_inject':
                    continue
                if rx.search(body):
                    hits[name] += 1
                    where.setdefault(name, os.path.relpath(path, pkg_dir))
    return hits, where


def main():
    results_dir, corpus, extract_glob = sys.argv[1], sys.argv[2], sys.argv[3]
    names = {f[:-7] for f in os.listdir(corpus) if f.endswith('.tar.gz')}

    rows, seen = [], set()
    for fn in glob.glob(os.path.join(results_dir, '*.jsonl')):
        for line in open(fn, encoding='utf-8'):
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except Exception:
                continue
            n = (r.get('_input_name') or '').replace('.tar.gz', '')
            if n not in names:
                continue
            k = (n, r.get('_ts'))
            if k in seen:
                continue
            seen.add(k)
            rows.append(r)

    # 解压目录名可能与发行名不一致（如 -1000.0 vs -1000.0.6），按前缀兜底
    dirs = {}
    for d in glob.glob(extract_glob):
        base = os.path.basename(d)
        dirs.setdefault(base, d)
    def find_dir(pkg):
        if pkg in dirs:
            return dirs[pkg]
        cands = [d for b, d in dirs.items() if b.startswith(pkg)]
        return cands[0] if len(cands) == 1 else None

    benign = [r for r in rows if r.get('final_category') == 'BENIGN']
    print(f"恶意集已完成 {len(rows)}，判 BENIGN {len(benign)}")

    dirty, clean, no_dir = [], [], []
    for r in benign:
        pkg = r.get('package_name')
        d = find_dir(pkg)
        if not d:
            no_dir.append(pkg)
            continue
        hits, where = scan_pkg(d)
        if hits:
            dirty.append((pkg, hits, where))
        else:
            clean.append(pkg)

    print(f"\n[无载荷指纹] {len(clean)} 个 —— 代码层面干净，图判 BENIGN 正确")
    print(f"[有指纹待查] {len(dirty)} 个")
    print(f"[未找到目录] {len(no_dir)} 个")

    if dirty:
        print("\n待查明细（指纹 / 位置 / PyFlow 能力）：")
        for pkg, hits, where in dirty:
            row = next(r for r in benign if r.get('package_name') == pkg)
            caps = row.get('capabilities') or {}
            top = ', '.join(f'{k}={v}' for k, v in
                            sorted(caps.items(), key=lambda x: -x[1])[:4])
            print(f"  {pkg[:34]:36s} {dict(hits)}")
            print(f"      {where}")
            print(f"      caps: {top}   chains: "
                  f"{(row.get('attack_chains') or {}).get('chain_count', 0)}")

    print("\n[无载荷] 抽样 12 个：")
    for p in clean[:12]:
        print("   ", p)


if __name__ == '__main__':
    main()
