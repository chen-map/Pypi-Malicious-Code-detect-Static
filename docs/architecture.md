# NEW_DDG Architecture — Data Flow & Runtime

This page shows how data actually moves through the system, with the artifacts
each stage produces and consumes. For the narrative and evaluation, see the
[README](../README.md) ([中文](../README_zh.md)).

## 1. End-to-end pipeline

Artifacts are shown on arrows; every stage writes files to
`{pkg}/.ddg_output/` which later stages (and offline re-judgment) consume.

```mermaid
flowchart TD
    IN([.tar.gz / source dir]) --> EX[extract<br/>tar-slip protected]

    EX --> SSO["① SSO PRE-FILTER<br/>AST walk · alias/getattr/globals resolution<br/>capability tagging (process_spawn, code_eval,<br/>network_in/out, deserialize, decode, ...)"]

    SSO -->|files_with_sso<br/>8-23% of files| DDG["② DDG BUILDER (trimmed graph)<br/>typed edges: data/call/param/return<br/>+ statement-sequence edges (next_stmt)<br/>+ function summaries (param→sink, return)<br/>+ AST call-target resolution"]

    DDG -->|nodes.json<br/>edges.json<br/>function_summaries.json| DIG["③ GRAPH DIGEST<br/>hash-shuffled short IDs (N1..Nn)<br/>NODES [type] L<line> code<br/>EDGES data-flow · STRUCT-EDGES context<br/>FUNCTIONS map · CROSS-SCOPE FLOWS<br/>ISOLATED PAYLOAD NODES · IOC LITERALS<br/>(no danger labels — no prompt bias)"]

    DIG -->|digest text| S1["④ STAGE 1 — CHAIN EXTRACTION<br/>GLM-4-Flash (small model)<br/>step-wise: entry points → sensitive ops<br/>→ walk edges hop by hop"]

    S1 -->|proposed paths| V["⑤ PROGRAM VERIFICATION<br/>every node ID exists<br/>every hop is a real edge<br/>partial paths: valid prefix kept<br/>single-node: hostile-literal gate"]

    V -->|verified paths| S2["⑥ STAGE 2 — ADJUDICATION<br/>GLM-4-Plus (strong model)<br/>sees only verified paths + flagged source<br/>idiom knowledge · intent-vs-behavior<br/>package self-description"]

    S2 -->|path judgments| GATES

    V -->|no valid paths| DEMOTE["structural-support gate<br/>MALICIOUS w/o verified paths<br/>⇒ SUSPICIOUS"]

    EX --> ENH["①b ENHANCED DETECTION<br/>(cheap, runs first)"]
    ENH -->|critical: install hook /<br/>404 / clone| SHORT["short-circuit MALICIOUS<br/>(factual evidence, skips model)"]
    ENH -->|recorded only| GATES

    GATES["⑦ EVIDENCE GATES<br/>weak chain (env→exec) never convicts<br/>verdict normalization (Uncertain→SUSPICIOUS)<br/>final integrity check before output"]

    GATES --> OUT([MALICIOUS / SUSPICIOUS /<br/>BENIGN / OBFUSCATED / ANALYSIS_FAILED<br/>+ verified chains as evidence])

    style S1 fill:#e8f0fe
    style S2 fill:#f3e8fd
    style V fill:#e6f4ea
```

## 2. Two-stage interaction (per package)

```mermaid
sequenceDiagram
    participant P as Pipeline
    participant G as Graph Digest
    participant S as GLM-4-Flash<br/>(chain extraction)
    participant V as verify_paths<br/>(program)
    participant J as GLM-4-Plus<br/>(adjudication)
    participant Gt as Evidence Gates

    P->>G: nodes + edges (full graph)
    G-->>P: digest text + short-ID map
    P->>S: "walk the graph, propose attack paths"
    S-->>V: proposed paths (node ID sequences)
    V->>V: node IDs exist?<br/>each hop is a real edge?<br/>single-node: hostile literal?

    alt valid paths found
        V-->>P: verified paths (real node IDs)
        P->>J: verified paths + flagged source code<br/>+ package self-description
        J-->>Gt: MALICIOUS / SUSPICIOUS / BENIGN<br/>(per-path judgments)
        Note over Gt: MALICIOUS w/o structural support<br/>is demoted to SUSPICIOUS
    else all proposals rejected (hallucinated)
        Note over V,Gt: judgments discarded —<br/>stage-1 verdict demoted if MALICIOUS
        P->>Gt: stage-1 verdict (never the fabricated paths)
    end

    Gt-->>P: final verdict + verified chains as evidence
```

## 3. Evidence grading (what can convict)

```mermaid
flowchart LR
    F["FACTUAL<br/>PyPI 404 · verified install hook · code clone"] -->|convict alone| MAL
    ST["STRUCTURAL<br/>verified chain: strong source → sink<br/>or any flow → exfiltration"] -->|convict w/ judge| MAL
    SE["SEMANTIC<br/>LLM judgment over verified paths"] -->|convict w/ structural support| MAL
    HE["HEURISTIC<br/>regex hits · weak chains (env→exec)<br/>name similarity"] -->|never convicts| SUS([SUSPICIOUS])

    MAL([MALICIOUS])
    INT["FINAL INTEGRITY CHECK<br/>MALICIOUS w/o factual+structural<br/>⇒ demoted"] --> SUS

    style MAL fill:#ffd7d7
    style SUS fill:#fff3cd
```

## 4. Large-package path (Phase A, integration pending)

```mermaid
flowchart LR
    BIG["graph > 500 nodes"] --> SPLIT["split by file → function<br/>≤500-node blocks"]
    SPLIT --> B1["block 1 digest+chain"] & B2["block 2 ..."] & B3["block N ..."]
    B1 --> MERGE["merge: any block with<br/>verified malicious chain<br/>⇒ package MALICIOUS"]
    B2 --> MERGE
    B3 --> MERGE
```

Status: implemented in `src/package_graph_analysis.py`, main-loop integration pending —
this is Phase A of the roadmap.

## 5. Registry channel relationship

The registry channel (PyPI 404, typosquat index, duplicate clone) is a
separate, factual-evidence channel. It catches **pure name-squatting with
clean copied code**, which the graph channel deliberately refuses to convict.
The two channels are complementary — measured on the 500-package corpus:

| Channel | Catches | Cannot catch |
|---|---|---|
| Graph + LLM | real-name packages with injected code (XMRig-mined `requess`) | clean-copy name-squats |
| Registry | name-squats, takedowns, clones | real-name injected-code packages |
| **Union** | **both classes** | — |
