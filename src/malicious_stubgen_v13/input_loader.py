from __future__ import annotations

import json
from pathlib import Path

from .models import StubGenerationTask, SubgraphSpec


def load_task(input_path: Path) -> StubGenerationTask:
    raw = json.loads(input_path.read_text(encoding="utf-8"))
    package_root = Path(raw["package_root"]).resolve()
    output_dir = Path(raw.get("output_dir", package_root / "generated_stubs")).resolve()
    max_candidates = int(raw.get("max_candidates_per_subgraph", 3))
    include_llm_payload = bool(raw.get("include_llm_payload", False))
    emit_debug_artifacts = bool(raw.get("emit_debug_artifacts", False))
    use_deepseek = bool(raw.get("use_deepseek", False))
    final_stub_value = raw.get("final_stub_path")
    final_stub_path = Path(final_stub_value).resolve() if final_stub_value else None
    subgraphs = [SubgraphSpec(**item) for item in raw["subgraphs"]]
    return StubGenerationTask(
        package_root=package_root,
        output_dir=output_dir,
        subgraphs=subgraphs,
        max_candidates_per_subgraph=max_candidates,
        include_llm_payload=include_llm_payload,
        emit_debug_artifacts=emit_debug_artifacts,
        use_deepseek=use_deepseek,
        final_stub_path=final_stub_path,
    )
