from __future__ import annotations

from pathlib import Path

from malicious_stubgen_v13.analyzers import EntryPointAnalyzer, PackageCallGraphBuilder
from malicious_stubgen_v13.generators import StubWriter
from malicious_stubgen_v13.models import AnalysisResult, FinalStubPlan, StubCandidate, StubGenerationTask


class StubGenerationPipeline:
    def __init__(self) -> None:
        self.analyzer = EntryPointAnalyzer()
        self.graph_builder = PackageCallGraphBuilder()
        self.writer = StubWriter()

    def run(self, task: StubGenerationTask) -> dict:
        task.output_dir.mkdir(parents=True, exist_ok=True)
        analyses: list[AnalysisResult] = []
        candidate_index: dict[str, list[StubCandidate]] = {}

        for subgraph in task.subgraphs:
            analysis = self.analyzer.analyze(task.package_root, subgraph, task.source_snapshot)
            analyses.append(analysis)
            if task.emit_debug_artifacts:
                subgraph_dir = task.output_dir / subgraph.subgraph_id
                candidates = self.writer.generate_candidates(task.package_root, analysis, task.max_candidates_per_subgraph)
                self.writer.write_candidates(subgraph_dir, candidates)
                if task.include_llm_payload:
                    self.writer.write_llm_payload(subgraph_dir, analysis, candidates)
                    self.writer.write_llm_prompt(subgraph_dir, analysis)
                candidate_index[subgraph.subgraph_id] = candidates

        package_names = {subgraph.package_name for subgraph in task.subgraphs}
        graph = self.graph_builder.build(task.package_root, package_names, task.source_snapshot)
        final_plan = self.writer.build_final_plan(task, analyses, graph)
        self.writer.write_final_stubs(final_plan)

        manifest = self._build_manifest(task, analyses, candidate_index, final_plan)
        self.writer.write_manifest(task.output_dir, manifest)
        return manifest

    def _build_manifest(
        self,
        task: StubGenerationTask,
        analyses: list[AnalysisResult],
        candidate_index: dict[str, list[StubCandidate]],
        final_plan: FinalStubPlan,
    ) -> dict:
        entries = []
        final_stub_paths = [str(item.stub_path) for item in final_plan.stub_artifacts]
        for analysis in analyses:
            subgraph_id = analysis.subgraph.subgraph_id
            output_dir = task.output_dir / subgraph_id
            entries.append(
                {
                    "subgraph_id": subgraph_id,
                    "module_path": analysis.subgraph.module_path,
                    "module_qualname": analysis.module_qualname,
                    "sensitive_apis": analysis.subgraph.sensitive_apis,
                    "warnings": analysis.warnings,
                    "entry_points": [entry.to_dict() for entry in analysis.entry_points],
                    "selected_for_final_stub": subgraph_id in final_plan.selected_subgraph_ids,
                    "generated_files": (
                        [str(output_dir / item.filename) for item in candidate_index.get(subgraph_id, [])]
                        if task.emit_debug_artifacts
                        else []
                    ),
                    "llm_payload": (
                        str(output_dir / f"llm_payload_{subgraph_id}.json")
                        if task.emit_debug_artifacts and task.include_llm_payload
                        else None
                    ),
                    "llm_prompt": (
                        str(output_dir / f"llm_prompt_{subgraph_id}.md")
                        if task.emit_debug_artifacts and task.include_llm_payload
                        else None
                    ),
                }
            )
        return {
            "generation_mode": "rules",
            "package_root": str(task.package_root),
            "output_dir": str(task.output_dir),
            "subgraph_count": len(task.subgraphs),
            "final_stub_count": len(final_plan.stub_artifacts),
            "final_stub_path": final_stub_paths[0] if final_stub_paths else None,
            "final_stub_paths": final_stub_paths,
            "final_stubs": [
                {
                    "path": str(item.stub_path),
                    "subgraph_id": item.subgraph_id,
                    "entry_point": item.entry_point.to_dict(),
                }
                for item in final_plan.stub_artifacts
            ],
            "selected_subgraph_ids": final_plan.selected_subgraph_ids,
            "skipped_subgraph_ids": final_plan.skipped_subgraph_ids,
            "selected_entry_points": [entry.to_dict() for entry in final_plan.selected_entry_points],
            "skipped_source_count": len(task.skipped_sources),
            "skipped_sources": [item.to_dict() for item in task.skipped_sources],
            "entries": entries,
        }
