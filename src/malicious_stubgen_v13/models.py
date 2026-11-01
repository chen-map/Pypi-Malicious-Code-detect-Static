from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class SubgraphSpec:
    subgraph_id: str
    module_path: str
    package_name: str
    sensitive_apis: list[str]
    start_line: int
    end_line: int
    code: str | None = None
    notes: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def normalized_module_path(self) -> str:
        return self.module_path.replace("\\", "/")

    def module_file(self, package_root: Path) -> Path:
        return package_root / self.normalized_module_path

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class EntryPoint:
    kind: str
    module_qualname: str
    symbol_name: str | None
    callable_path: str | None
    trigger_expression: str
    reasoning: str
    confidence: float
    is_fallback: bool = False
    dependencies: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class StubCandidate:
    filename: str
    code: str
    entry_point: EntryPoint
    rationale: str

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["entry_point"] = self.entry_point.to_dict()
        return payload


@dataclass(slots=True)
class SkippedSource:
    path: str
    name: str
    folder: str
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class AnalysisResult:
    subgraph: SubgraphSpec
    entry_points: list[EntryPoint]
    module_qualname: str
    package_init_context: str | None
    module_context: str
    module_source: str
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "subgraph": self.subgraph.to_dict(),
            "entry_points": [entry.to_dict() for entry in self.entry_points],
            "module_qualname": self.module_qualname,
            "package_init_context": self.package_init_context,
            "module_context": self.module_context,
            "module_source": self.module_source,
            "warnings": self.warnings,
        }


@dataclass(slots=True)
class StubGenerationTask:
    package_root: Path
    output_dir: Path
    subgraphs: list[SubgraphSpec]
    source_snapshot: dict[str, str] = field(default_factory=dict)
    skipped_sources: list[SkippedSource] = field(default_factory=list)
    max_candidates_per_subgraph: int = 3
    include_llm_payload: bool = False
    emit_debug_artifacts: bool = False
    use_deepseek: bool = False
    final_stub_path: Path | None = None


@dataclass(slots=True)
class FinalStubArtifact:
    stub_path: Path
    code: str
    subgraph_id: str
    entry_point: EntryPoint


@dataclass(slots=True)
class FinalStubPlan:
    stub_artifacts: list[FinalStubArtifact]
    selected_subgraph_ids: list[str]
    selected_entry_points: list[EntryPoint]
    skipped_subgraph_ids: list[str]
