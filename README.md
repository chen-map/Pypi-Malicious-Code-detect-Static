<div align="center">

# 🛡️ NEW_DDG

**Multi-Signal Interprocedural Taint Analysis for PyPI Malicious Package Detection**

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-46%2B%20passing-brightgreen.svg)](tests/)
[![LLM: GLM](https://img.shields.io/badge/LLM-GLM--4--FlashX-blueviolet)](https://open.bigmodel.cn/)
[![Detection: 4 Channels](https://img.shields.io/badge/channels-4%20independent-red)](#architecture)

*Interprocedural taint analysis · Function summaries · AST-resolved call targets · LLM-assisted verification*

</div>

---

## 📖 Overview

**NEW_DDG** detects malicious packages on PyPI by combining four independent detection
channels — regex-based enhanced detection, AST-level obfuscation analysis, interprocedural
taint analysis over a three-layer code property graph, and LLM-assisted semantic verification.

Unlike single-channel tools (Guarddog, Bandit4Mal) that rely on pattern matching,
NEW_DDG builds a **Code Property Graph (CPG-lite)** with three abstraction layers and
propagates taint through **function boundaries, cross-file call chains, and dynamic
dispatch targets** — detecting attacks that pattern-matching tools miss.

### Why another tool?

Existing tools (Guarddog, Bandit4Mal) are single-channel: they match API names
against known-dangerous patterns. If malware wraps `os.system` inside a custom
function named `_helper`, splits the payload across three files, or uses
`getattr(builtins, 'ev'+'al')`, these tools miss it.

NEW_DDG solves this by:

| Technique | What it catches | Previous tools |
|---|---|---|
| **Interprocedural taint** | Payload split across functions/files | ✗ Miss |
| **call_target as sink** | `getattr(builtins,'ev'+'al')(x)` — dynamic dispatch | ✗ Miss |
| **Function summaries** | `decode(x)` where `decode` wraps `os.system` | ✗ Miss |
| **Container tracking** | `data['k']=x; exec(data['k'])` — container-mediated flow | ✗ Miss |
| **Branch-aware kill** | 3+ branch `if/elif/else` taint retention | ✗ Lost |
| **PyPI registry check** | Typosquat, name-squat, package takedown | Partial |
| **Duplicate detection** | `botaa3` = exact copy of `boto3` with different name | ✗ Miss |

---

## ✨ Features

- 🔍 **Four independent detection channels** — regex, graph+taint, LLM semantic, registry
- 🧬 **Interprocedural taint analysis** — tracks untrusted data through function calls, return values, and cross-file imports
- 📊 **Three-layer CPG-lite** — Module → Function summaries → Statement-level DDG
- 🎯 **AST-resolved call targets** — penetrates `getattr(builtins,'ev'+'al')`, variable aliases, `globals()` subscripts
- 📦 **Container tracking** — `data['key']=x → exec(data['key'])` chain preserved
- 🌿 **Branch-aware kill semantics** — 3+ branch taint retention
- ☠️ **Dead code pruning** — `if False:` / post-`raise` blocks pruned via py2cfg + constant folding
- 🏷️ **Function summaries** — composable `param_to_sink` / `return_tainted` facts per function
- 🧹 **LLM input sanitization** — strips comments/docstrings, marks injection attempts
- 💾 **Verdict caching** — content-hash keyed, 40% hit rate on re-runs
- 🌐 **PyPI registry verification** — existence check, version validation, typosquat via full 500K index
- 🧪 **Deterministic output** — same input → byte-identical results across processes
- 🖥️ **Sandbox behavioral probe** — audit-hook based install-time monitoring (opt-in)

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Input: tar.gz / directory                 │
└────────────────────────────┬────────────────────────────────────┘
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│  Channel ① Enhanced Detection (regex, ms-level)                  │
│    install hooks · typosquat · metadata · distribution mismatch  │
│    PyPI 404 · fake version · duplicate detection · sandbox       │
├─────────────────────────────────────────────────────────────────┤
│  Channel ② Obfuscation Detection (AST + density gating)          │
│    hex/base64/encoding patterns · eval/exec/compile counting     │
├─────────────────────────────────────────────────────────────────┤
│  Channel ③ Graph + Taint (DDG V7 — core)                         │
│    ┌──────────────────────────────────────────────────────────┐  │
│    │ L1 Module:  dist name / PyPI verification / duplicate    │  │
│    │ L2 Function: summaries (return_tainted, param_to_sink)   │  │
│    │ L3 Statement: DDG (typed edges, kill, call_target)       │  │
│    └──────────────────────────────────────────────────────────┘  │
│    Taint Engine: reverse BFS (data/param/call/return edges only) │
├─────────────────────────────────────────────────────────────────┤
│  Channel ④ Voting (LLM semantic + rule scoring)                  │
│    Prioritizer → Rule Scorer → LLM Classifier (sanitized input)  │
│    ↳ Cross-channel corroboration                                 │
├─────────────────────────────────────────────────────────────────┤
│  Package-level LLM Aggregation                                   │
│    All signals → holistic judgment (borderline cases)            │
└─────────────────────────────────────────────────────────────────┘
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│  Verdict: MALICIOUS / SUSPICIOUS / BENIGN / ANALYSIS_FAILED      │
│  + taint chains + attack chains + function summaries + evidence  │
└─────────────────────────────────────────────────────────────────┘
```

<details>
<summary>🔍 <b>How taint chains work (click to expand)</b></summary>

```python
# Input: malicious package with payload split across 3 files

# source.py
def get_config():
    return os.environ.get('C')           # ← SOURCE: environment

# transform.py
def decode():
    return base64.b64decode(get_config())  # ← TRANSFORM: decoded_data

# main.py
def run():
    data = decode()                       # ← call to transform
    os.system(data)                       # ← SINK: command_execution
```

**Step 1**: Builder extracts DDG per file, creates interprocedural edges:
```
source.py: [environ.get] ──data──→ [return node]
                    ↕ (cross-file return edge)
transform.py: [get_config()] ──data──→ [b64decode] ──data──→ [return node]
                    ↕ (cross-file return edge)
main.py: [decode()] ──data──→ [data = ...] ──data──→ [os.system(data)]
```

**Step 2**: Taint engine runs reverse BFS from sink:
```
os.system(data) ← data ← decode() ← (cross-file) ← b64decode ← (cross-file) ← environ
    [SINK]                                                          [SOURCE: environment]
```

**Step 3**: Output chain:
```
[SOURCE] source.py:3 — environment
  → [PROPAGATE] transform.py:4 — b64decode(get_config())
    → [SINK] main.py:5 — os.system(data)
    (7 steps, 3 files, confidence=0.75)
```

</details>

---

## 📦 Installation

### Prerequisites

- Python 3.10+ (tested on 3.14)
- pip packages: `zhipuai`, `networkx`, `py2cfg`

```bash
pip install zhipuai networkx py2cfg
```

### Clone

```bash
git clone https://github.com/chen-map/Pypi-Malicious-Code-detect-Static.git
cd Pypi-Malicious-Code-detect-Static
```

---

## 🚀 Usage

### Basic Analysis (no LLM, regex + graph + index channels)

```bash
python batch_solution_b_v2.py ./packages/ --api-key <KEY> --count 50
```

### Full Analysis (all channels + LLM)

```bash
python batch_solution_b_v2.py ./packages/ \
    --api-key <GLM_API_KEY> \
    --count 100 \
    --llm-model glm-4-flashx \
    --verify-pypi \
    --parallel-workers 5
```

### With Sandbox Probe

> ⚠️ **Warning**: executes package code. Only use in isolated VM/container.

```bash
python batch_solution_b_v2.py ./packages/ --api-key <KEY> \
    --sandbox --verify-pypi --count 50
```

### CLI Options

```
positional:      tarfile_dir          Directory containing .tar.gz files
--api-key        KEY                  ZhipuAI API key
--llm-model      MODEL                LLM model (default: glm-4-flashx)
--count          N                    Max packages to analyze
--extract-base   DIR                  Extraction directory
--verify-pypi                         Enable PyPI index verification
--sandbox                             Enable behavioral probe (⚠️ executes code)
--parallel-workers N                  LLM call parallelism (default: 1)
--seed           N                    Sampling seed (default: 42)
--no-llm-cache                        Disable verdict caching
--skip-rule-scoring                   Skip rule scoring, LLM only
```

---

## 📊 Detection Capabilities

| Attack Pattern | Detection Channel | Example |
|---|---|---|
| Install hooks (`cmdclass`) | ① Enhanced | `setup(name='evil', cmdclass={'install': MaliciousInstall})` |
| Install-time exfiltration | ① Enhanced | `setup.py` reads env + sends to C2 |
| Typosquatting | ① + ⑤ | `botaa3` (≈ `boto3`), `python-dateutils` (≈ `python-dateutil`) |
| Name-squat / code duplicate | ⑤ Registry | `botaa3` = exact copy of `boto3` with different name |
| PyPI takedown (404) | ⑤ Registry | Package removed from PyPI |
| Base64-encoded payload | ② + ③ Graph | `exec(base64.b64decode(...))` |
| getattr dynamic dispatch | ③ AST resolver | `getattr(builtins, 'ev'+'al')(x)` |
| Variable alias | ③ AST resolver | `e = eval; e(x)` |
| globals subscript | ③ AST resolver | `globals()['ex'+'ec'](x)` |
| Cross-file payload split | ③ Interprocedural taint | source.py → transform.py → main.py |
| Custom function wrapper | ③ Summary expansion | `_run(x)` where `_run` calls `os.system` |
| Container-mediated flow | ③ Container tracking | `d['k']=x; exec(d['k'])` |
| Branch-tainted flow | ③ Branch-aware kill | `if c: a=taint; elif: a=safe; use(a)` |
| Semantic pattern | ④ LLM | LLM reads complete function + chain |

---

## 📊 Evaluation Results

### Holdout Set (zero-overlap, 20 malicious + 19 benign)

| Metric | Value |
|---|---|
| Recall | **100%** (20/20) |
| Hard false positive | **0%** (0/18) |
| LLM model | glm-4-flashx |

### Determinism

| Test | Result |
|---|---|
| Same package, 3 processes (PYTHONHASHSEED=1/2/3) | **Byte-identical** (16 files) |

### Channel Attribution (holdout, 20 malicious packages)

| Channel | Attribution |
|---|---|
| Code / install script signals | 9 (45%) |
| Index verification only | 11 (55%) |

---

## 🧪 Testing

```bash
# Run all 46+ tests across 10 test files
python tests/run_all.py

# Run specific test
python tests/test_graph_kernel.py   # Graph kernel (identity, taint, interprocedural)
python tests/test_determinism.py    # Cross-process byte-identical output
python tests/test_sandbox_probe.py  # Behavioral probe (synthetic packages only)
```

---

## 📁 Project Structure

```
NEW_DDG/
├── batch_solution_b_v2.py      # Main entry point
├── new_ddg_gui.py              # GUI launcher
├── danger_patterns.json        # Dangerous API patterns
│
├── src/                        # Core modules
│   ├── ddg_builder_v7.py       # DDG builder (kill, call_target, container)
│   ├── call_graph_analyzer.py  # Call graph + attack chains
│   ├── cfg_adapter.py          # py2cfg precise CFG
│   ├── taint_engine.py         # Interprocedural taint analysis
│   ├── call_resolver.py        # AST-level call target resolution
│   ├── enhanced_detector.py    # Non-code threats
│   ├── llm_sanitizer.py        # LLM input sanitization
│   ├── pypi_verifier.py        # PyPI verification
│   ├── pypi_index.py           # Full index (typosquat)
│   ├── duplicate_detector.py   # Code similarity
│   ├── sandbox_probe.py        # Behavioral probe
│   ├── attack_chain_rebuilder.py
│   ├── file_integrity_checker.py
│   ├── lightweight_cfg.py      # CFG fallback
│   └── common/
│       ├── graph_partitioner.py  # Function-level partitioning
│       └── pattern_matcher.py    # Dangerous node detection
│
├── SOLUTION_B_VOTING/          # Voting architecture
│   ├── src/                    #   Classifier, scorer, prioritizer
│   └── prompts/                #   LLM templates
│
├── prompts/                    # Shared prompts
├── config/                     # Configuration
├── tests/                      # 10 test files
├── docs/                       # Documentation
├── scripts/                    # Deployment
└── output/                     # Runtime output (gitignored)
```

---

## 🤝 Acknowledgments

- **[GLM (ZhipuAI)](https://open.bigmodel.cn/)** — Primary development assistant.
  GLM-4-FlashX was used throughout the project for LLM-assisted code analysis,
  and GLM participated as an AI pair programmer across all 22 rounds of
  architecture evolution — from initial design through debugging, testing,
  and documentation.

- **[py2cfg](https://github.com/jimenezj6/py2cfg)** — Control flow graph construction

- **[Guarddog](https://github.com/DataDog/guarddog)** / **[Bandit4Mal](https://github.com/ohmtech-research/bandit4mal)** — Baseline tools for comparison

- **[Backstabber's Knife Collection](https://github.com/cybertier/Backstabbers-Knife-Collection)** — Reference for dataset construction methodology

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">

**⚠️ Disclaimer**: This tool performs static analysis and optional behavioral probing.
It is designed for security research and package screening. Verdicts should be
reviewed by human analysts before taking action.

</div>
