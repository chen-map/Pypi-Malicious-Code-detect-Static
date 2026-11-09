# NEW_DDG v3 Architecture — Data Flow & Runtime

This page shows how data actually moves through the system, with the artifacts
each stage produces and consumes. For the narrative and evaluation, see the
[README](../README.md) ([中文](../README_zh.md)).

## 1. End-to-end pipeline

```mermaid
flowchart TD
    IN([.tar.gz / source dir]) --> EX[extract]

    EX --> ENH["① ENHANCED DETECTION (factual)<br/>install hooks · PyPI 404 · typosquat<br/>artifact scan: .pth/.sh/data_files"]
    ENH -->|critical| SHORT["short-circuit MALICIOUS"]
    ENH --> PF

    EX --> PF["② PYFLOW (2-60 s)<br/>capabilities · GIR · callgraph · alias<br/>escape events · coverage"]
    PF --> MERGE["③ ENGINE MERGE<br/>SSO ∪ PyFlow capabilities<br/>constant folding · getattr · module_level"]
    MERGE --> CAT["④ FUNCTION CATALOG<br/>one line per function<br/>capability · degree · phase · score"]
    CAT --> SEL["⑤ TOP-N + CLUSTER<br/>seed + 2-hop call closure<br/>+ intermediate functions"]
    SEL --> D1["⑥ STAGE 1 — small model<br/>digest → proposed paths"]
    D1 --> V["⑦ VERIFY<br/>node exists · edge exists<br/>partial kept · single-node needs literal"]
    V --> D2["⑧ STAGE 2 — big model<br/>verified paths + source + intent"]
    SHORT --> G
    D2 --> G["⑨ GATES<br/>hostile literal · IOC target<br/>strong-source sink · coverage"]
    G --> OUT([MALICIOUS / SUSPICIOUS / BENIGN])
```

Every stage writes to `{pkg}/.ddg_output/`, so offline re-judgment can reuse the
artifacts without re-running analysis.

## 2. What each stage produces

| Stage | Output | Consumed by |
|---|---|---|
| ① enhanced detection | `enhanced_report` (threats, install hooks, registry status) | short-circuit; gates |
| ② PyFlow | `capabilities` (findings, coverage, escape), `GIR` (statements), `callgraph` | ③ |
| ③ merge | `nodes[]` (code, capability, phase, escape_to), `edges[]` (data/call/return/control/param) | ④⑤ |
| ④ catalog | `[{file, name, lines, stmt, caps, in, out, phase, score, reasons}]` | ⑤ |
| ⑤ clusters | `[{label, nodes, edges, boundary_edges, cluster}]` | ⑥ |
| ⑥ stage 1 | proposed paths (short node IDs), verdict | ⑦ |
| ⑦ verify | valid paths (real IDs), rejected paths + reasons | ⑧ |
| ⑧ stage 2 | per-path judgments, overall verdict | ⑨ |
| ⑨ gates | final category + audit fields | JSON output |

## 3. Node and edge schema

```python
node = {
  'node_id': 'pkg/setup.py:7:0',      # rel:line:col — unique per statement
  'file': '/abs/path/pkg/setup.py',   # absolute: digest._source_line needs it
  'line': 7, 'type': 'object_call_stmt',
  'code': "_ttmp.write(b\"...urlopen(...)...exec(...)\")",
  'function_name': '<module>' | 'run',
  'capability': 'process_spawn' | 'code_eval' | 'credential_access' | None,
  'is_dangerous': True, 'severity': 'critical',
  'phase': 'install' | 'import' | 'runtime',
  'module_level': True,
  'escape_to': ['builtins.map'], 'escape_kind': ['argument'],
}

edge = {
  'from_node': 'pkg/main.py:4:11', 'to_node': 'pkg/transform.py:3:0',
  'kind': 'call' | 'return' | 'param' | 'data' | 'control',
  'variable': 'decode',
  'from_file': '...', 'to_file': '...', 'is_cross_file': True,
}
```

Edge kinds and who consumes them:

| kind | Meaning | Taint | Digest | Boundary |
|---|---|---|---|---|
| `data` | value def → use within a function | ✅ | ✅ | ✅ |
| `call` | call statement → callee entry | ✅ | ✅ | ✅ |
| `return` | callee return → call statement | ✅ | ✅ | ✅ |
| `param` | escaping value → callee entry (escape events) | ✅ | ✅ | ✅ |
| `control` | statement order (`next_stmt`) | ❌ excluded | ✅ STRUCT-EDGES | ❌ |

`control` is deliberately excluded from taint: control dependency is not data
dependency, and letting it through produced false chains where a literal-argument
sink was never reached by tainted data.

## 4. Cluster delivery

```mermaid
flowchart LR
    F1["source.py::get_config<br/>score 3.2"] --> S
    F2["transform.py::decode<br/>score 5.1"] --> S
    S["seed selection<br/>top-N by score"] --> C
    C["cluster expansion<br/>2-hop call closure<br/>+ short-path intermediates"]
    C --> B1["block 1<br/>52-402 statements"]
    C --> B2["block 2"]
    C --> B3["block 3"]
```

Why clusters: if function `A` reads credentials and function `B` posts them, each
looks benign alone. Delivering them separately reproduces the split-attack failure
the design exists to prevent.

## 5. Anti-hallucination contract

```mermaid
flowchart LR
    P["model proposes<br/>N7 → N13 → N12 → N6"] --> V{verify_paths}
    V -->|all nodes exist,<br/>all hops are real edges| OK[valid path]
    V -->|unknown node| R1["reject: hallucinated_nodes"]
    V -->|hop not an edge| R2["reject: nonexistent_edges"]
    V -->|prefix valid, ≥2 steps, ≥50%| R2b["accept as partial"]
    V -->|single node + hostile literal| OK2[valid]
    OK --> J["stage 2 adjudication"]
    R1 --> DEMOTE["stage-1 MALICIOUS → SUSPICIOUS"]
```

Node IDs are assigned by `md5(node_id)` sort, not graph order, so a model cannot
produce a plausible-looking sequence by counting upward.

## 6. Evidence gates

```mermaid
flowchart TD
    L["candidate verdict"] --> G1{"factual?<br/>PyPI 404 · install hook · clone"}
    G1 -->|yes| MAL([MALICIOUS])
    G1 -->|no| G2{"structural?<br/>verified chain, strong source → exec/exfil"}
    G2 -->|yes, judge agrees| MAL
    G2 -->|yes, judge unsure| SUS([SUSPICIOUS])
    G2 -->|no| G3{"semantic only?"}
    G3 -->|yes| SUS
    G3 -->|no| G4{"heuristic only?"}
    G4 -->|yes| SUS
    G4 -->|no| G5{"coverage incomplete?<br/>skipped > 30%"}
    G5 -->|yes| SUS
    G5 -->|no| BEN([BENIGN])
```

Two invariants:

- **Heuristic evidence never convicts.** Regex hits and weak chains
  (`file_read → exec`, the setuptools-scm idiom) stop at SUSPICIOUS.
- **Unknown ≠ safe.** If the analyzer skipped more than the configured fraction of
  entries and no Tier-1 capability was found, BENIGN is forbidden.

## 7. Large-package path

```mermaid
flowchart LR
    BIG["graph > 6 000 nodes<br/>or > 200 subgraphs"] --> RULE["skip 20-call subgraph voting<br/>rule-only"]
    RULE --> CL["cluster analysis becomes<br/>the primary path"]
    CL --> MERGE["any cluster with a verified<br/>hostile chain ⇒ MALICIOUS"]
```

Measured: a 1 306-file package now completes in ~60 s (PyFlow budget) where the
hand-written builder needed 40 minutes and still timed out.

## 8. Registry channel relationship

The registry channel (PyPI 404, typosquat index, duplicate clone) is a separate,
factual-evidence channel. It catches **pure name-squatting with clean copied
code**, which the graph channel deliberately refuses to convict. The two channels
are complementary:

| Channel | Catches | Cannot catch |
|---|---|---|
| Graph + LLM | real-name packages with injected code (XMRig-mined `requess`) | clean-copy name-squats |
| Registry | name-squats, takedowns, clones | real-name injected-code packages |
| **Union** | **both classes** | — |

## 9. Obfuscation handling

```mermaid
flowchart LR
    S["long string literal"] --> D1{"base64 / hex / base32?"}
    D1 -->|decoded bytes| D2{"marshal?"}
    D2 -->|yes| M["walk co_consts / co_names<br/>(no execution)"]
    D2 -->|no| D3{"zlib / gzip / bz2 / lzma?"}
    D3 -->|yes| D4["decompress, repeat ≤3 layers"]
    D3 -->|no| T["decode as text if printable"]
    M --> E["evidence: payload strings + API names"]
    D4 --> E
    T --> E
    E --> G{"flows to exec / subprocess / socket?"}
    G -->|yes| MAL["malicious"]
    G -->|no| DATA["data only — no weight"]
```

Decoded output is never executed — only regex-scanned and shown to the judge.

## 10. Planned: legitimacy channel

The 7 % benign SUSPICIOUS are packages that genuinely exercise malicious-grade
capability (`intuit_oauth` handles OAuth credentials, `nvgpu` calls into native GPU
libraries). They stay SUSPICIOUS because the system currently collects only
*negative* evidence.

```mermaid
flowchart LR
    S["SUSPICIOUS"] --> L1["destination consistency<br/>sink domain == declared homepage"]
    S --> L2["ecosystem age<br/>downloads · versions · maintainer"]
    S --> L3["documentation match<br/>README describes the capability"]
    S --> L4["code style<br/>aliasing / encoded blobs / obfuscation"]
    S --> L5["dependency consistency<br/>capability comes from a known library"]
    L1 & L2 & L3 & L4 & L5 --> SC["legitimacy score"]
    SC -->|high| BEN["BENIGN"]
    SC -->|low| SUS["stays SUSPICIOUS"]
    SC -.->|NEVER| MAL["cannot convict"]
```

The symmetry matters: adversarial evidence may raise a verdict to MALICIOUS,
legitimacy evidence may lower it to BENIGN, and neither may do the other's job.
