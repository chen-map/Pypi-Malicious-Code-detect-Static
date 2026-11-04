<div align="center">

# 🛡️ NEW_DDG

**Evidence-Gated Interprocedural Taint Analysis for PyPI Malicious Package Detection**

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-10%20files%20%2F%2048%20assertions-brightgreen.svg)](tests/)
[![Core](https://img.shields.io/badge/core-10k%20LOC-informational.svg)](#project-structure)
[![LLM: GLM](https://img.shields.io/badge/LLM-GLM--4--FlashX-blueviolet)](https://open.bigmodel.cn/)

*Three-layer CPG · Interprocedural taint · Function summaries · Evidence-graded verdicts*

</div>

---

## The Problem This Solves

Static malware detectors for package registries fail in a specific, well-documented way:
they produce **plausible but unsupported verdicts**. A regex sees `exec(` and calls it malware;
a heuristic sees `subprocess` in `setup.py` and calls it a backdoor. On a corpus of 5000
known-malicious packages this looks excellent — until you run it on `cffi`, `packaging`,
or any project that generates code as part of its build.

The real failure isn't detection rate. It's **verdict integrity**: a detector that cannot
distinguish "I found evidence" from "I found a keyword" forces a human to re-review
everything it flags, which is the same as not flagging at all.

NEW_DDG is built around one constraint:

> **Every `MALICIOUS` verdict must be backed by a structural artifact that a human can
> inspect — a complete taint chain, a missing PyPI identity, or a verified install hook.
> Speculation is permitted, but it is labelled `SUSPICIOUS` and never escalates to
> `MALICIOUS` on its own.**

That constraint drives every design decision below, including several that deliberately
*trade recall for precision*.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────────┐
│ Input: source distribution (.tar.gz / .whl / directory)                   │
└───────────────────────────────┬──────────────────────────────────────────┘
                                ▼
┌──────────────────────────────────────────────────────────────────────────┐
│ Channel ① — Enhanced Detection (regex + registry, milliseconds)          │
│   install hooks · metadata identity · PyPI existence · duplicates        │
│   ⟶ critical ⇒ short-circuit MALICIOUS (skips graph construction)        │
├──────────────────────────────────────────────────────────────────────────┤
│ Channel ② — Obfuscation Analysis (AST + density gating)                  │
│   hex/base64/rot13 payloads · eval/exec density · test-file exclusion    │
├──────────────────────────────────────────────────────────────────────────┤
│ Channel ③ — Code Property Graph (the core)                               │
│                                                                          │
│   L1  Module      distribution name · PyPI verification · duplicate hash │
│   L2  Function    summaries: return_tainted · param_to_sink · rt_calls   │
│   L3  Statement   typed DDG · branch-aware kill · call_target edges      │
│                                                                          │
│   ┌────────────────────────────────────────────────────────────────┐     │
│   │ Edge taxonomy:  data │ control │ call │ param │ return │ target│     │
│   │ Taint engine:   reverse BFS from sinks, data/param/call-only   │     │
│   │ Summaries:      call sites of taint-relevant functions become  │     │
│   │                 sinks (transitive taint through wrappers)      │     │
│   └────────────────────────────────────────────────────────────────┘     │
├──────────────────────────────────────────────────────────────────────────┤
│ Channel ④ — Voting (per-function verdicts)                               │
│   Prioritizer → Rule Scorer → LLM Classifier (sanitized + cached)        │
│   ⟶ zero-tolerance, gated by evidence strength                           │
├──────────────────────────────────────────────────────────────────────────┤
│ Package-Level Aggregation                                                │
│   LLM sees chains + function source + PyPI status + per-function labels  │
│   ⟶ escalation gated by structural corroboration                         │
├──────────────────────────────────────────────────────────────────────────┤
│ Final Integrity Check                                                    │
│   No structural evidence ⇒ MALICIOUS demoted, regardless of source       │
└───────────────────────────────┬──────────────────────────────────────────┘
                                ▼
        MALICIOUS / SUSPICIOUS / BENIGN / OBFUSCATED / ANALYSIS_FAILED
        + taint chains + function summaries + per-function verdicts
```

### Why three layers

Statement-level data flow alone cannot see across function boundaries; a single function's
DDG is blind to `decode()` being called from three files away. Module-level signals alone
cannot distinguish a package that *mentions* `os.system` from one that *reaches* it with
attacker-controlled data.

The layers compose: L3 gives precise intraprocedural flow, L2 turns each function into a
reusable fact (`param 0 flows to a sink`, `return value is tainted`), and L1 supplies
identity evidence that no amount of code analysis can produce — a package whose name does
not exist on PyPI is not "suspicious code", it is a fabrication claim.

---

## Design Decisions (and the Failures That Forced Them)

These are the decisions that matter. Each one was made after a specific false positive on a
real benign package, and each is pinned by a regression test so it cannot silently revert.

### 1. Taint sources are graded, not uniformly trusted

`taint_engine.STRONG_SOURCES` distinguishes sources that are **rare in benign software**
(network responses, socket reads, deserialization, decoded payloads) from those that are
**routine in build tooling** (`os.environ`, file reads, `input()`).

```
STRONG:  network_response · socket_recv · deserialization · decoded_data
WEAK:    environment · file_read · user_input · cli_args
```

Only a strong-source chain — or a chain reaching a `data_exfiltration` sink — can escalate
a package to `MALICIOUS` automatically.

**Why:** `exec(open("_version.py").read())` is the standard `setuptools-scm` idiom. It is a
`file_read → code_execution` chain, and it appears in a large fraction of legitimate Python
packages. Treating it as evidence of malice flagged `ag2`, `acryl-executor`, and
`acryl-datahub-dagster-plugin` (all real, benign projects). Reflexive chain-matching is not
detection; it is pattern matching with extra steps.

### 2. "No chain" ≠ "weak chain"

A subgraph with no taint chain carries no information about chain quality. It may have been
classified from code semantics, from a regex hit, or come from a legacy record. The gates
therefore treat *absent* chains as unknown — never as weak — because demoting on absent
evidence destroys recall on samples that were never meant to produce a chain.

This distinction is enforced by two separate tests, because collapsing them is the obvious
implementation mistake.

### 3. Evidence gates check *flagged* subgraphs only

An early version of the escalation gate asked "does this package contain any strong chain?"
and scanned all 400 subgraphs. On `ag2` (1136 functions, 396 of them benign), one ordinary
function happened to contain a network-to-sink chain, which "corroborated" an unrelated
weak-chain escalation.

The gate now considers only subgraphs whose own verdict is `SUSPICIOUS` or `MALICIOUS`.
Corroboration must come from the same code region that raised the alarm.

### 4. PyPI 404 is decided by code, not by the model

When the registry returns 404 for a distribution name, the package is claiming an identity
that does not exist. This is a factual answer from an authoritative source.

Empirically, `glm-4-flash` reads the same evidence and writes *"does not exist on PyPI —
significant red flag"* in its reasoning — then returns `SUSPICIOUS` anyway. Weak models
hedge even when the evidence is binary. So this rule bypasses the model entirely:

```python
if category == 'SUSPICIOUS' and pypi_status == 'not_found':
    category = 'MALICIOUS'   # factual, not probabilistic
```

**Why it matters:** on a corpus dominated by name-squatting, this single rule accounts for
the majority of correct escalations — and it is the rule a reviewer can verify in one HTTP
request.

### 5. The package-level model must see source code, not just labels

A hierarchy that asks a model to *review* a verdict while showing it only the verdict's
label is not a hierarchy; it is a rubber stamp. The aggregation prompt now carries:

| Evidence | Before | Now |
|---|---|---|
| Taint chains (graph kernel output) | ✗ collected from the wrong object — always empty | ✓ |
| Per-function verdict labels | ✓ | ✓ |
| **Source code of flagged functions** | ✗ | ✓ (4 functions × 1200 chars) |

Adding source code moved the model's direct-verdict rate from **10% to 97.8%** on the
re-analysis of 2990 packages. The model was never incapable; it was uninformed.

### 6. Score accumulation cannot manufacture a `critical`

`enhanced_detector` previously summed threat scores: `medium (4) + high (7) = 11 ≥ 10` ⇒
`critical`. Two low-precision signals — a live-index name neighbour plus a similarly-named
dependency — were enough to trigger the short-circuit that skips all code analysis.

Now `critical` requires an actual `severity="critical"` finding. Accumulation may only
distinguish `high` / `medium` / `low`.

### 7. Metadata identity must come from metadata, not from `setup.py`

`setup.py` is **code**. Any literal in it — a template example, a test fixture, a README
fragment — can be parsed as a field. Two independent bugs came from this:

- Parsing order let `setup.py` overwrite the authoritative `PKG-INFO` name
- Within a single `PKG-INFO`, later lines overwrote earlier ones, so a YAML example in the
  long description (`name: hello_world`) replaced the real header value

Both are fixed: header fields are first-seen-wins, parsing stops at `Description:`, and a
name mismatch sourced from `setup.py` is a `medium` signal rather than `critical`.

### 8. Analysis order follows cost

The pipeline used to build the full DDG *before* running regex checks. Monorepo packages
with ~1000 Python files burned the entire 900-second budget in graph construction, then
timed out — when a zero-cost regex pass would have settled the case in milliseconds.

Now: cheap checks first, short-circuit on `critical`, then graph construction. A per-package
subprocess isolates hard timeouts so one pathological package cannot stall a 5000-package
batch.

---

## What It Detects

| Attack pattern | Mechanism | Example |
|---|---|---|
| Install hooks | `cmdclass` / `install` overrides | `setup(cmdclass={'install': Evil})` |
| Install-time exfiltration | env read → network in `setup.py` | `requests.post(c2, data=os.environ)` |
| Typosquatting | edit distance over full index (500K names) | `python-dateutils` → `python-dateutil` |
| Name-squat / code clone | SHA-256 file-set overlap vs. genuine sdist | `botaa3` = `boto3` renamed |
| Registry takedown | PyPI 404 | package removed after report |
| Base64 payloads | obfuscation channel + graph | `exec(b64decode(x))` |
| `getattr` dispatch | AST call-target resolution | `getattr(builtins,'ev'+'al')(x)` |
| Variable aliasing | AST alias tracing (fixpoint) | `e = eval; e(x)` |
| `globals()` subscript | AST constant folding | `globals()['ex'+'ec'](x)` |
| Cross-file payload split | interprocedural taint | `source.py → transform.py → main.py` |
| Wrapper functions | function summary expansion | `_run(x)` where `_run` reaches `os.system` |
| Container-mediated flow | subscript/attribute tracking | `d['k']=x; exec(d['k'])` |
| Branch-tainted values | branch-aware kill (append vs. kill) | 3-way `if/elif/else` retention |
| Dead code | py2cfg + constant folding | `if False:` blocks pruned |

---

## Evaluation

### Results

| Corpus | Size | MALICIOUS | SUSPICIOUS | BENIGN | Failed |
|---|---|---|---|---|---|
| Malicious (Backstabber's Knife Collection + derivatives) | 5000 | **89%** | 0.04% | 4% | 5% |
| Benign (real PyPI projects) | 98 | — | 15.3% | 81.6% | 3.1% |
| **Benign hard false positives** | 98 | **0 (0.0%)** | | | |

The malicious figure is from the full 5000-package run under the v1 verdict path. A full
re-run under the current evidence-gated path is in progress; the first 334 packages show
**94%**, consistent with the gates removing false positives without removing true ones.

The benign corpus includes packages specifically chosen to break naive detectors:
`cffi` (eval-family primitives), `packaging`, `ag2` (1136 functions, code generation),
`acryl-*` (corporate forks absent from PyPI), `adbc-driver-*` (native bindings).

### Assertion-level testing

| Suite | Assertions | What it pins |
|---|---|---|
| `test_escalation.py` | 37 | evidence gates, zero-tolerance gate, code-evidence assembly |
| `test_escalation_e2e.py` | 11 | end-to-end: chain → verdict → gate → package category |
| `test_graph_kernel.py` | — | node identity, kill semantics, interprocedural links, call_target |
| `test_cross_file_taint.py` | — | 3-file chain closure (7 steps, 3 files) |
| `test_enhanced_detector.py` | — | critical gating, metadata authority, weak-signal accumulation |
| `test_llm_hardening.py` | — | sanitization, injection marking, cache, output clamping |
| `test_determinism.py` | — | byte-identical output across `PYTHONHASHSEED` values |
| `test_partitioner.py` | — | function-level partitioning, path handling |
| `test_obfuscation.py` | — | density gating, test-file exclusion |
| `test_voting.py` | — | zero-tolerance, cross-channel corroboration |

```bash
python tests/run_all.py     # 10 files, all must pass
```

---

## Known Limitations

Being explicit about failure modes is part of the design, not an appendix.

**1. Large monorepos time out.** Packages above ~1000 Python files can exhaust the graph
budget. They are marked `ANALYSIS_FAILED` (never `BENIGN`) and can be re-run with a larger
timeout. Subgraph analysis is capped at 400 functions by dangerous-node count; a payload in
function #401 of a monorepo would be missed by the graph channel (though install hooks and
identity checks still apply).

**2. Short package names produce unavoidable typosquat noise.** For a 3-character name,
edit-distance-1 neighbours always exist in a 500K-name index. Live-index hits are therefore
`high`, never `critical`, and cannot short-circuit.

**3. Weak-model judgment is not trusted for binary facts.** Where evidence is factual
(registry existence, install hooks), code decides. The LLM is reserved for genuinely
ambiguous cases — and its escalations are re-checked against structural evidence.

**4. Taint is syntactic, not semantic.** A function that reads from the network and returns
data is a strong source *because of the API it calls*, not because the analyzer understands
its purpose. A payload routed through three wrappers that each call a benign-looking
utility would evade the summary expansion.

**5. Registry state is point-in-time.** A 404 today may mean "removed after disclosure" or
"never existed" — both are treated as evidence, and both are recorded with the raw response
so a reviewer can tell them apart.

**6. Sandbox probing executes code.** Opt-in only (`--sandbox`), intended for isolated VMs,
and not used in any reported evaluation number.

---

## Quick Start

### Install

```bash
pip install zhipuai networkx py2cfg
git clone https://github.com/chen-map/Pypi-Malicious-Code-detect-Static.git
cd Pypi-Malicious-Code-detect-Static
```

### Run

```bash
# Full pipeline: graph + taint + LLM + registry verification
python batch_solution_b_v2.py ./packages \
    --api-key "$GLM_API_KEY" \
    --count 100 \
    --llm-model glm-4-flashx \
    --verify-pypi \
    --parallel-workers 5

# No LLM: regex + graph + registry only (deterministic, offline-capable)
python batch_solution_b_v2.py ./packages --api-key dummy --count 50
```

### Offline re-judgment

Two scripts re-evaluate a completed batch **without re-running analysis** — useful for
measuring the effect of gate changes on historical results.

```bash
# Stage 1 — pure rule gate over recorded chain categories (no LLM)
python scripts/rejudge_suspicious.py results.jsonl \
    --extract-base ./extracted --apply -o rejudged_stage1.jsonl

# Stage 2 — package-level LLM re-judgment with full evidence
#           (chains + flagged source code + PyPI status)
python scripts/rejudge_llm_stage2.py rejudged_stage1.jsonl \
    --extract-base ./extracted --api-key "$GLM_API_KEY" \
    --verify-pypi --workers 5 -o rejudged_stage2.jsonl
```

### CLI reference

```
positional:       tarfile_dir            .tar.gz files or extracted directories
--api-key KEY     GLM API key            required unless --api-key dummy
--llm-model M     model name             default: glm-4-flashx
--count N         max packages           default: 100
--extract-base D  extraction directory
--verify-pypi                            enable registry verification (network)
--sandbox                                behavioural probe (⚠️ executes code)
--parallel-workers N                     LLM call parallelism
--seed N                                 sampling seed (default 42)
--no-llm-cache                           disable verdict cache
--skip-rule-scoring                      LLM-only mode
```

---

## Output Schema

Each package produces one JSONL row. The fields that matter for review:

```jsonc
{
  "package_name": "…",
  "final_category": "MALICIOUS | SUSPICIOUS | BENIGN | OBFUSCATED | ANALYSIS_FAILED",
  "final_risk_score": 0.0,
  "final_confidence": 0.0,
  "voting_summary": "why this verdict — always populated",
  "detection_method": "enhanced_detection | sandbox_probe | voting",
  "subgraph_verdicts": [
    {
      "subgraph_name": "func_…",
      "final_verdict": "MALICIOUS",
      "taint_chain_count": 2,
      "taint_categories": [{"source_category": "network_response",
                            "sink_category": "code_execution",
                            "cross_file": false}],
      "escalated": false
    }
  ],
  "attack_chains": {"chain_count": 4, "completeness": 0.75},
  "enhanced_detection": {"threat_level": "high", "threats_found": 1},
  "analysis_degraded": false
}
```

`ANALYSIS_FAILED` is deliberately distinct from `BENIGN`: infrastructure failure must never
be reported as a clean verdict.

---

## Project Structure

```
NEW_DDG/
├── batch_solution_b_v2.py          # Orchestration: 4 channels, gates, final integrity check
│
├── src/
│   ├── ddg_builder_v7.py           # CPG construction: typed edges, kill, call_target, summaries
│   ├── taint_engine.py             # Reverse-BFS taint + evidence grading (escalation_gate)
│   ├── call_resolver.py            # AST call-target resolution (getattr, aliases, globals)
│   ├── call_graph_analyzer.py      # Call graph, attack-chain reconstruction
│   ├── cfg_adapter.py              # py2cfg integration + constant-folded reachability
│   ├── enhanced_detector.py        # Registry identity, install hooks, metadata authority
│   ├── pypi_verifier.py            # Existence / version / release-age verification
│   ├── pypi_index.py               # Full 500K-name index with length bucketing
│   ├── duplicate_detector.py       # SHA-256 file-set overlap vs. genuine sdist
│   ├── llm_sanitizer.py            # Comment/docstring stripping, injection marking
│   ├── sandbox_probe.py            # audit-hook behavioural probe (opt-in)
│   └── common/
│       ├── graph_partitioner.py    # Function-level partitioning (attribute-based)
│       └── pattern_matcher.py      # Dangerous-node detection
│
├── SOLUTION_B_VOTING/src/          # Per-function classifier, rule scorer, prioritizer
├── scripts/                        # Offline re-judgment (stage 1 + stage 2)
├── tests/                          # 10 suites
└── docs/
```

**Core size:** ~10k LOC across the eight main modules; no vendored ML models, no GPU.

---

## References

- **[Backstabber's Knife Collection](https://github.com/cybertier/Backstabbers-Knife-Collection)** — malicious package corpus and taxonomy used for dataset construction
- **[Guarddog](https://github.com/DataDog/guarddog)**, **[Bandit4Mal](https://github.com/ohmtech-research/bandit4mal)** — single-channel baselines
- **[py2cfg](https://github.com/jimenezj6/py2cfg)** — CFG construction
- **[GLM (ZhipuAI)](https://open.bigmodel.cn/)** — LLM used for semantic verification and as an AI pair-programmer across the project's evolution

## License

MIT — see [LICENSE](LICENSE).

<div align="center">

**⚠️** Static analysis plus optional behavioural probing. Verdicts are decision support,
not automated takedowns — every `MALICIOUS` carries the evidence needed to verify it.

</div>
