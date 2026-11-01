from __future__ import annotations

import json
from dataclasses import dataclass, field
import keyword
import os
from pathlib import Path
import re
from malicious_stubgen_v13.analyzers import PackageCallGraph
from malicious_stubgen_v13.models import AnalysisResult, EntryPoint, FinalStubArtifact, FinalStubPlan, StubCandidate, StubGenerationTask
from malicious_stubgen_v13.prompts import build_stub_generation_prompt


@dataclass(slots=True)
class _PlannedEntry:
    order: int
    subgraph_id: str
    analysis: AnalysisResult
    entry_point: EntryPoint
    graph_key: str | None


@dataclass(slots=True)
class _RenderContext:
    imported_packages: set[str] = field(default_factory=set)
    bound_modules: dict[str, str] = field(default_factory=dict)
    used_names: set[str] = field(default_factory=set)


class StubWriter:
    """Render Python driver stubs and auxiliary manifests."""

    def generate_candidates(
        self,
        package_root: Path,
        analysis: AnalysisResult,
        max_candidates: int,
    ) -> list[StubCandidate]:
        candidates: list[StubCandidate] = []
        for index, entry_point in enumerate(analysis.entry_points[:max_candidates], start=1):
            filename = f"stub_{analysis.subgraph.subgraph_id}_{index:02d}.py"
            code = self._render_stub(package_root, analysis, entry_point)
            rationale = entry_point.reasoning
            candidates.append(
                StubCandidate(
                    filename=filename,
                    code=code,
                    entry_point=entry_point,
                    rationale=rationale,
                )
            )
        return candidates

    def write_candidates(self, output_dir: Path, candidates: list[StubCandidate]) -> list[Path]:
        output_dir.mkdir(parents=True, exist_ok=True)
        written: list[Path] = []
        for candidate in candidates:
            destination = output_dir / candidate.filename
            destination.write_text(candidate.code, encoding="utf-8")
            written.append(destination)
        return written

    def write_manifest(self, output_dir: Path, payload: dict) -> Path:
        output_dir.mkdir(parents=True, exist_ok=True)
        manifest_path = output_dir / "manifest.json"
        manifest_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        return manifest_path

    def write_llm_payload(self, output_dir: Path, analysis: AnalysisResult, candidates: list[StubCandidate]) -> Path:
        payload = {
            "subgraph_id": analysis.subgraph.subgraph_id,
            "module_qualname": analysis.module_qualname,
            "subgraph": analysis.subgraph.to_dict(),
            "module_context": analysis.module_context,
            "package_init_context": analysis.package_init_context,
            "entry_points": [entry.to_dict() for entry in analysis.entry_points],
            "generated_candidates": [candidate.to_dict() for candidate in candidates],
            "prompt_hint": (
                "You are given a suspicious code region inside an unpacked Python package. "
                "Choose the best runtime trigger and write a stub that lives beside the package "
                "without modifying package contents."
            ),
        }
        path = output_dir / f"llm_payload_{analysis.subgraph.subgraph_id}.json"
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        return path

    def write_llm_prompt(self, output_dir: Path, analysis: AnalysisResult) -> Path:
        prompt = build_stub_generation_prompt(analysis)
        path = output_dir / f"llm_prompt_{analysis.subgraph.subgraph_id}.md"
        path.write_text(prompt, encoding="utf-8")
        return path

    def build_final_plan(
        self,
        task: StubGenerationTask,
        analyses: list[AnalysisResult],
        graph: PackageCallGraph,
    ) -> FinalStubPlan:
        if not analyses:
            raise ValueError("Cannot build a final stub without analyses.")
        stub_base = analyses[0].subgraph.package_name or self._sanitize_name(task.package_root.name)
        stub_path = task.final_stub_path or task.package_root / f"{stub_base}_single_stub.py"
        selected_entries = self._select_final_entry_points(analyses, graph)
        selected_ids = [item.subgraph_id for item in selected_entries]
        skipped_ids = [analysis.subgraph.subgraph_id for analysis in analyses if analysis.subgraph.subgraph_id not in set(selected_ids)]
        stub_artifacts = self._build_final_stub_artifacts(task.package_root, stub_path, selected_entries)
        return FinalStubPlan(
            stub_artifacts=stub_artifacts,
            selected_subgraph_ids=selected_ids,
            selected_entry_points=[item.entry_point for item in selected_entries],
            skipped_subgraph_ids=skipped_ids,
        )

    def write_final_stubs(self, plan: FinalStubPlan) -> list[Path]:
        written: list[Path] = []
        for artifact in plan.stub_artifacts:
            artifact.stub_path.parent.mkdir(parents=True, exist_ok=True)
            artifact.stub_path.write_text(artifact.code, encoding="utf-8")
            written.append(artifact.stub_path)
        return written

    def _build_final_stub_artifacts(
        self,
        package_root: Path,
        base_stub_path: Path,
        selected_entries: list[_PlannedEntry],
    ) -> list[FinalStubArtifact]:
        stub_paths = self._split_final_stub_paths(base_stub_path, len(selected_entries))
        artifacts: list[FinalStubArtifact] = []
        for stub_path, item in zip(stub_paths, selected_entries):
            artifacts.append(
                FinalStubArtifact(
                    stub_path=stub_path,
                    code=self._render_final_stub(package_root, stub_path, [item]),
                    subgraph_id=item.subgraph_id,
                    entry_point=item.entry_point,
                )
            )
        return artifacts

    def _split_final_stub_paths(self, base_stub_path: Path, count: int) -> list[Path]:
        if count <= 1:
            return [base_stub_path]
        suffix = base_stub_path.suffix or ".py"
        stem = base_stub_path.stem
        return [
            base_stub_path.with_name(f"{stem}_{index:02d}{suffix}")
            for index in range(1, count + 1)
        ]

    def _render_stub(self, package_root: Path, analysis: AnalysisResult, entry_point: EntryPoint) -> str:
        package_root_literal = str(package_root.resolve())
        header = [
            '"""Auto-generated driver stub for a suspicious package subgraph."""',
            "",
            "from __future__ import annotations",
            "",
            "import json",
            "import sys",
            "import traceback",
            "from pathlib import Path",
            "",
            f"PACKAGE_ROOT = Path({package_root_literal!r})",
            "if str(PACKAGE_ROOT) not in sys.path:",
            "    sys.path.insert(0, str(PACKAGE_ROOT))",
            "",
        ]
        if entry_point.kind == "module_import":
            body = self._render_module_import_body(entry_point)
        elif entry_point.kind == "function_call":
            body = self._render_function_call_body(analysis, entry_point)
        elif entry_point.kind in {"class_instantiation", "classmethod_call", "staticmethod_call"}:
            body = self._render_direct_symbol_call_body(analysis, entry_point)
        elif entry_point.kind == "instance_method_call":
            body = self._render_instance_method_body(analysis, entry_point)
        elif entry_point.kind == "property_access":
            body = self._render_property_access_body(analysis, entry_point)
        else:
            body = self._render_module_import_body(entry_point)
        footer = [
            "",
            "if __name__ == \"__main__\":",
            "    try:",
            "        run()",
            "        print(json.dumps({\"status\": \"ok\"}, ensure_ascii=False))",
            "    except Exception as exc:",
            "        payload = {",
            "            \"status\": \"error\",",
            "            \"exception_type\": type(exc).__name__,",
            "            \"message\": str(exc),",
            "            \"traceback\": traceback.format_exc(),",
            "        }",
            "        print(json.dumps(payload, ensure_ascii=False))",
            "        raise",
            "",
        ]
        return "\n".join(header + body + footer)

    def _render_module_import_body(self, entry_point: EntryPoint) -> list[str]:
        if not self._can_use_direct_import(entry_point.module_qualname):
            return [
                "import importlib",
                "",
                "def run() -> None:",
                f"    importlib.import_module({entry_point.module_qualname!r})",
                "    return None",
            ]
        return [
            "def run() -> None:",
            f"    import {entry_point.module_qualname}",
            "    return None",
        ]

    def _render_function_call_body(self, analysis: AnalysisResult, entry_point: EntryPoint) -> list[str]:
        module_alias = "__stub_module"
        import_lines = self._render_module_alias_imports(analysis, module_alias)
        call_expression = f"{module_alias}.{entry_point.symbol_name}()"
        return import_lines + [
            "def run() -> None:",
            f"    {call_expression}",
            "    return None",
        ]

    def _render_direct_symbol_call_body(self, analysis: AnalysisResult, entry_point: EntryPoint) -> list[str]:
        symbol = (entry_point.callable_path or entry_point.symbol_name or "").split(".", maxsplit=1)[0]
        module_alias = "__stub_module"
        import_lines = self._render_module_alias_imports(analysis, module_alias)
        call_expression = entry_point.trigger_expression.replace(f"{symbol}(", f"{module_alias}.{symbol}(")
        call_expression = call_expression.replace(f"{symbol}.", f"{module_alias}.{symbol}.")
        call_expression = call_expression.replace("\n", "\n    ")
        return import_lines + [
            "def run() -> None:",
            f"    {call_expression}",
            "    return None",
        ]

    def _render_instance_method_body(self, analysis: AnalysisResult, entry_point: EntryPoint) -> list[str]:
        class_name, method_name = (entry_point.callable_path or "").rsplit(".", maxsplit=1)
        module_alias = "__stub_module"
        import_lines = self._render_module_alias_imports(analysis, module_alias)
        call_expression = f"obj = {module_alias}.{class_name}()\n    obj.{method_name}()"
        return import_lines + [
            "def run() -> None:",
            f"    {call_expression}",
            "    return None",
        ]

    def _render_property_access_body(self, analysis: AnalysisResult, entry_point: EntryPoint) -> list[str]:
        class_name, property_name = (entry_point.callable_path or "").rsplit(".", maxsplit=1)
        module_alias = "__stub_module"
        import_lines = self._render_module_alias_imports(analysis, module_alias)
        return import_lines + [
            "def run() -> None:",
            f"    obj = {module_alias}.{class_name}()",
            f"    _ = obj.{property_name}",
            "    return None",
        ]

    def _render_module_alias_imports(self, analysis: AnalysisResult, module_alias: str) -> list[str]:
        parts = analysis.module_qualname.split(".")
        package_name = analysis.subgraph.package_name
        if not self._can_use_direct_import(analysis.module_qualname):
            return [
                "import importlib",
                f"{module_alias} = importlib.import_module({analysis.module_qualname!r})",
                "",
            ]
        if not package_name:
            if len(parts) == 1:
                return [
                    f"import {analysis.module_qualname} as {module_alias}",
                    "",
                ]
            module_leaf = parts[-1]
            module_parent = ".".join(parts[:-1])
            return [
                f"from {module_parent} import {module_leaf} as {module_alias}",
                "",
            ]
        if analysis.module_qualname == package_name:
            return [
                f"import {package_name}",
                f"{module_alias} = {package_name}",
                "",
            ]
        module_leaf = parts[-1]
        module_parent = ".".join(parts[:-1])
        return [
            f"import {package_name}",
            f"from {module_parent} import {module_leaf} as {module_alias}",
            "",
        ]

    def _select_final_entry_points(
        self,
        analyses: list[AnalysisResult],
        graph: PackageCallGraph,
    ) -> list[_PlannedEntry]:
        planned = [self._make_planned_entry(index, analysis, graph) for index, analysis in enumerate(analyses)]

        explicit_package_imports: list[_PlannedEntry] = []
        retained_package_names: set[str] = set()
        for item in planned:
            if item.entry_point.kind == "module_import" and item.entry_point.module_qualname == item.analysis.subgraph.package_name:
                if item.analysis.subgraph.package_name not in retained_package_names:
                    explicit_package_imports.append(item)
                    retained_package_names.add(item.analysis.subgraph.package_name)

        execution_candidates = [
            item
            for item in planned
            if not (item.entry_point.kind == "module_import" and item.entry_point.module_qualname == item.analysis.subgraph.package_name)
        ]

        uncovered = {item.subgraph_id for item in execution_candidates}
        chosen: list[_PlannedEntry] = []
        while uncovered:
            best: _PlannedEntry | None = None
            best_gain = -1
            for item in execution_candidates:
                if item.subgraph_id not in uncovered:
                    continue
                gain = len(self._coverage_for(item, execution_candidates, graph) & uncovered)
                if gain > best_gain:
                    best = item
                    best_gain = gain
                elif gain == best_gain and best is not None and item.order < best.order:
                    best = item
            if best is None:
                break
            chosen.append(best)
            uncovered -= self._coverage_for(best, execution_candidates, graph)

        return explicit_package_imports + sorted(chosen, key=self._execution_sort_key)

    def _make_planned_entry(self, order: int, analysis: AnalysisResult, graph: PackageCallGraph) -> _PlannedEntry:
        primary = self._normalize_primary_entry_point(analysis, graph)
        return _PlannedEntry(
            order=order,
            subgraph_id=analysis.subgraph.subgraph_id,
            analysis=analysis,
            entry_point=primary,
            graph_key=self._entry_graph_key(primary, graph),
        )

    def _execution_sort_key(self, item: _PlannedEntry) -> tuple[int, int, str]:
        module_name = item.entry_point.module_qualname.rsplit(".", maxsplit=1)[-1]
        if item.entry_point.kind == "module_import" and item.entry_point.module_qualname == item.analysis.subgraph.package_name:
            priority = 0
        elif module_name == "main":
            priority = 1
        elif module_name == "setup":
            priority = 2
        else:
            priority = 3
        return (priority, item.order, item.subgraph_id)

    def _normalize_primary_entry_point(self, analysis: AnalysisResult, graph: PackageCallGraph) -> EntryPoint:
        primary = next((item for item in analysis.entry_points if not item.is_fallback), analysis.entry_points[0])
        if primary.kind != "instance_method_call" or not primary.callable_path:
            return primary
        class_name, method_name = primary.callable_path.rsplit(".", maxsplit=1)
        class_symbol = f"{primary.module_qualname}.{class_name}"
        init_key = graph.init_key_for_class(class_symbol)
        method_key = f"{primary.module_qualname}.{primary.callable_path}"
        if init_key and graph.reaches(init_key, method_key):
            return EntryPoint(
                kind="class_instantiation",
                module_qualname=primary.module_qualname,
                symbol_name=class_name,
                callable_path=class_name,
                trigger_expression=f"{class_name}()",
                reasoning=(
                    f"Method `{primary.callable_path}` is reached automatically from `{class_name}.__init__`, "
                    f"so instantiating `{class_name}` is the shorter entry point."
                ),
                confidence=max(primary.confidence, 0.86),
            )
        return primary

    def _coverage_for(
        self,
        candidate: _PlannedEntry,
        population: list[_PlannedEntry],
        graph: PackageCallGraph,
    ) -> set[str]:
        covered = {candidate.subgraph_id}
        for other in population:
            if other.subgraph_id == candidate.subgraph_id:
                continue
            if self._covers(candidate, other, graph):
                covered.add(other.subgraph_id)
        return covered

    def _covers(self, candidate: _PlannedEntry, other: _PlannedEntry, graph: PackageCallGraph) -> bool:
        if candidate.graph_key and other.graph_key and graph.reaches(candidate.graph_key, other.graph_key):
            return True
        if other.entry_point.kind == "module_import":
            if other.entry_point.module_qualname == other.analysis.subgraph.package_name:
                return False
            return (
                candidate.entry_point.module_qualname == other.entry_point.module_qualname
                and candidate.entry_point.kind != "module_import"
            )
        return False

    def _entry_graph_key(self, entry_point: EntryPoint, graph: PackageCallGraph) -> str | None:
        if entry_point.kind == "module_import":
            return f"module:{entry_point.module_qualname}"
        if entry_point.kind == "function_call" and entry_point.symbol_name:
            return f"{entry_point.module_qualname}.{entry_point.symbol_name}"
        if entry_point.kind == "class_instantiation":
            class_symbol = f"{entry_point.module_qualname}.{entry_point.callable_path or entry_point.symbol_name}"
            return graph.init_key_for_class(class_symbol)
        if entry_point.kind in {"instance_method_call", "classmethod_call", "staticmethod_call", "property_access"} and entry_point.callable_path:
            return f"{entry_point.module_qualname}.{entry_point.callable_path}"
        return None

    def _render_final_stub(
        self,
        package_root: Path,
        stub_path: Path,
        selected_entries: list[_PlannedEntry],
    ) -> str:
        context = _RenderContext()
        lines: list[str] = []
        if stub_path.resolve().parent != package_root.resolve():
            context.used_names.add("__imported_sys_runtime")
            context.used_names.add("__imported_pathlib_runtime")
            context.used_names.add("__declared_package_root")
            relative_package_root = self._relative_path_literal(stub_path.resolve().parent, package_root.resolve())
            lines.extend(
                [
                    "import sys",
                    "from pathlib import Path",
                    f"PACKAGE_ROOT = (Path(__file__).resolve().parent / {relative_package_root}).resolve()",
                    "sys.path.insert(0, str(PACKAGE_ROOT))",
                ]
            )
        for item in selected_entries:
            lines.extend(self._render_final_entry(item.analysis, item.entry_point, context))
        return "\n".join(lines).rstrip() + "\n"

    def _render_final_entry(
        self,
        analysis: AnalysisResult,
        entry_point: EntryPoint,
        context: _RenderContext,
    ) -> list[str]:
        package_name = analysis.subgraph.package_name
        module_qualname = entry_point.module_qualname
        lines = self._ensure_root_setup_patch(analysis, context)
        lines.extend(self._ensure_root_setup_workdir_patch(analysis, context))
        lines.extend(self._ensure_root_setup_argv_patch(analysis, context))
        lines.extend(self._ensure_root_setup_install_run_patch(analysis, context))
        lines.extend(self._ensure_runtime_compatibility_shims(analysis, context))
        if entry_point.kind == "module_import" and module_qualname == package_name:
            if self._can_use_direct_import(module_qualname):
                lines.extend(self._ensure_package_import(package_name, context))
            else:
                if module_qualname not in context.imported_packages:
                    context.imported_packages.add(module_qualname)
                    lines.extend(self._ensure_importlib(context))
                    lines.append(f"importlib.import_module({module_qualname!r})")
            return lines
        lines.extend(self._ensure_package_import(package_name, context))
        module_lines, access_expr = self._ensure_module_binding(module_qualname, package_name, context)
        lines.extend(module_lines)

        if entry_point.kind == "module_import":
            return lines
        if entry_point.kind == "function_call":
            lines.append(f"{access_expr}.{entry_point.symbol_name}()")
            return lines
        if entry_point.kind == "class_instantiation":
            class_name = entry_point.callable_path or entry_point.symbol_name
            lines.extend(self._render_class_instantiation(analysis, access_expr, class_name, context))
            return lines
        if entry_point.kind == "instance_method_call" and entry_point.callable_path:
            class_name, method_name = entry_point.callable_path.rsplit(".", maxsplit=1)
            lines.extend(self._render_instance_method_invocation(analysis, access_expr, class_name, method_name, context))
            return lines
        if entry_point.kind in {"classmethod_call", "staticmethod_call"} and entry_point.callable_path:
            lines.append(f"{access_expr}.{entry_point.callable_path}()")
            return lines
        if entry_point.kind == "property_access" and entry_point.callable_path:
            class_name, property_name = entry_point.callable_path.rsplit(".", maxsplit=1)
            lines.append(f"{access_expr}.{class_name}().{property_name}")
            return lines
        return lines

    def _ensure_package_import(self, package_name: str, context: _RenderContext) -> list[str]:
        if not package_name:
            return []
        if not self._can_use_direct_import(package_name):
            return []
        if package_name in context.imported_packages:
            return []
        context.imported_packages.add(package_name)
        context.used_names.add(package_name)
        return [f"import {package_name}"]

    def _ensure_module_binding(
        self,
        module_qualname: str,
        package_name: str,
        context: _RenderContext,
    ) -> tuple[list[str], str]:
        if not self._can_use_direct_import(module_qualname):
            if module_qualname in context.bound_modules:
                return [], context.bound_modules[module_qualname]
            binding_name = self._allocate_binding_name(module_qualname.rsplit(".", maxsplit=1)[-1], context)
            lines = self._ensure_importlib(context)
            lines.append(f"{binding_name} = importlib.import_module({module_qualname!r})")
            context.bound_modules[module_qualname] = binding_name
            return lines, binding_name
        if not package_name and "." not in module_qualname:
            if module_qualname in context.bound_modules:
                return [], context.bound_modules[module_qualname]
            binding_name = self._allocate_binding_name(module_qualname, context)
            line = f"import {module_qualname}"
            if binding_name != module_qualname:
                line = f"{line} as {binding_name}"
            context.bound_modules[module_qualname] = binding_name
            return [line], binding_name
        if module_qualname == package_name:
            return [], package_name
        if module_qualname in context.bound_modules:
            return [], context.bound_modules[module_qualname]

        parts = module_qualname.split(".")
        module_leaf = parts[-1]
        module_parent = ".".join(parts[:-1])
        binding_name = self._allocate_binding_name(module_leaf, context)
        line = f"from {module_parent} import {module_leaf}"
        if binding_name != module_leaf:
            line = f"{line} as {binding_name}"
        context.bound_modules[module_qualname] = binding_name
        return [line], binding_name

    def _allocate_binding_name(self, preferred: str, context: _RenderContext) -> str:
        preferred = self._sanitize_identifier(preferred)
        if preferred not in context.used_names:
            context.used_names.add(preferred)
            return preferred
        index = 2
        while True:
            candidate = f"{preferred}_{index}"
            if candidate not in context.used_names:
                context.used_names.add(candidate)
                return candidate
            index += 1

    def _ensure_root_setup_patch(self, analysis: AnalysisResult, context: _RenderContext) -> list[str]:
        if analysis.subgraph.package_name or analysis.module_qualname != "setup":
            return []
        sentinel = "__patched_setuptools_setup"
        if sentinel in context.used_names:
            return []
        context.used_names.add(sentinel)
        return [
            "import setuptools",
            "setuptools.setup = lambda *args, **kwargs: None",
        ]

    def _ensure_root_setup_install_run_patch(self, analysis: AnalysisResult, context: _RenderContext) -> list[str]:
        if analysis.subgraph.package_name or analysis.module_qualname != "setup":
            return []
        if not self._needs_install_run_patch(analysis.module_source):
            return []
        sentinel = "__patched_install_run"
        if sentinel in context.used_names:
            return []
        context.used_names.add(sentinel)
        return [
            "from setuptools.command.install import install as __stubgen_install_base",
            "__stubgen_install_base.run = lambda self: None",
        ]

    def _ensure_root_setup_workdir_patch(self, analysis: AnalysisResult, context: _RenderContext) -> list[str]:
        if analysis.subgraph.package_name or analysis.module_qualname != "setup":
            return []
        sentinel = "__patched_root_setup_workdir"
        if sentinel in context.used_names:
            return []
        context.used_names.add(sentinel)
        lines: list[str] = []
        if "__imported_os_runtime" not in context.used_names:
            context.used_names.add("__imported_os_runtime")
            lines.append("import os")
        if "__declared_package_root" not in context.used_names:
            context.used_names.add("__declared_package_root")
            if "__imported_pathlib_runtime" not in context.used_names:
                context.used_names.add("__imported_pathlib_runtime")
                lines.append("from pathlib import Path")
            lines.append("PACKAGE_ROOT = Path(__file__).resolve().parent")
        lines.append("os.chdir(PACKAGE_ROOT)")
        return lines

    def _ensure_root_setup_argv_patch(self, analysis: AnalysisResult, context: _RenderContext) -> list[str]:
        if analysis.subgraph.package_name or analysis.module_qualname != "setup":
            return []
        if not self._needs_sys_argv_patch(analysis.module_source):
            return []
        sentinel = "__patched_root_setup_argv"
        if sentinel in context.used_names:
            return []
        context.used_names.add(sentinel)
        lines: list[str] = []
        if "__imported_sys_runtime" not in context.used_names:
            context.used_names.add("__imported_sys_runtime")
            lines.append("import sys")
        lines.extend(
            [
                "if not sys.argv:",
                '    sys.argv = ["stub.py", "install"]',
                "elif len(sys.argv) == 1:",
                '    sys.argv.append("install")',
            ]
        )
        return lines

    def _ensure_runtime_compatibility_shims(self, analysis: AnalysisResult, context: _RenderContext) -> list[str]:
        if not self._needs_windows_pty_shim(analysis.module_source):
            return []
        sentinel = "__windows_pty_shim"
        if sentinel in context.used_names:
            return []
        context.used_names.add(sentinel)
        lines: list[str] = []
        if "__imported_sys_runtime" not in context.used_names:
            context.used_names.add("__imported_sys_runtime")
            lines.append("import sys")
        if "__imported_types_runtime" not in context.used_names:
            context.used_names.add("__imported_types_runtime")
            lines.append("import types")
        lines.extend(
            [
                'if sys.platform == "win32":',
                '    sys.modules.setdefault("termios", types.ModuleType("termios"))',
                '    sys.modules.setdefault("tty", types.ModuleType("tty"))',
                '    if "pty" not in sys.modules:',
                '        _stub_pty = types.ModuleType("pty")',
                '        _stub_pty.spawn = lambda *args, **kwargs: None',
                '        sys.modules["pty"] = _stub_pty',
            ]
        )
        return lines

    def _render_class_instantiation(
        self,
        analysis: AnalysisResult,
        access_expr: str,
        class_name: str,
        context: _RenderContext,
    ) -> list[str]:
        if self._needs_distribution_helper(analysis):
            lines = self._ensure_distribution_import(context)
            lines.append(f"{access_expr}.{class_name}(Distribution())")
            return lines
        return [f"{access_expr}.{class_name}()"]

    def _render_instance_method_invocation(
        self,
        analysis: AnalysisResult,
        access_expr: str,
        class_name: str,
        method_name: str,
        context: _RenderContext,
    ) -> list[str]:
        if self._needs_distribution_helper(analysis):
            lines = self._ensure_distribution_import(context)
            lines.append(f"{access_expr}.{class_name}(Distribution()).{method_name}()")
            return lines
        return [f"{access_expr}.{class_name}().{method_name}()"]

    def _ensure_distribution_import(self, context: _RenderContext) -> list[str]:
        sentinel = "__imported_distribution"
        if sentinel in context.used_names:
            return []
        context.used_names.add(sentinel)
        return ["from setuptools.dist import Distribution"]

    def _needs_distribution_helper(self, analysis: AnalysisResult) -> bool:
        return not analysis.subgraph.package_name and analysis.module_qualname == "setup"

    def _sanitize_name(self, value: str) -> str:
        return "".join(char if char.isalnum() or char == "_" else "_" for char in value).strip("_") or "project"

    def _ensure_importlib(self, context: _RenderContext) -> list[str]:
        sentinel = "__imported_importlib"
        if sentinel in context.used_names:
            return []
        context.used_names.add(sentinel)
        return ["import importlib"]

    def _can_use_direct_import(self, module_qualname: str) -> bool:
        if not module_qualname:
            return False
        return all(part.isidentifier() and not keyword.iskeyword(part) for part in module_qualname.split("."))

    def _sanitize_identifier(self, value: str) -> str:
        candidate = "".join(char if char.isalnum() or char == "_" else "_" for char in value).strip("_")
        if not candidate:
            candidate = "module"
        if candidate[0].isdigit():
            candidate = f"module_{candidate}"
        if keyword.iskeyword(candidate):
            candidate = f"{candidate}_module"
        return candidate

    def _needs_windows_pty_shim(self, module_source: str) -> bool:
        return bool(re.search(r"^\s*(?:from|import)\s+(?:pty|tty|termios)\b", module_source, flags=re.MULTILINE))

    def _needs_install_run_patch(self, module_source: str) -> bool:
        return bool(
            re.search(
                r"^\s*from\s+setuptools\.command\.install\s+import\s+install\b|^\s*import\s+setuptools\.command\.install\b",
                module_source,
                flags=re.MULTILINE,
            )
        )

    def _needs_sys_argv_patch(self, module_source: str) -> bool:
        return "sys.argv[" in module_source

    def _relative_path_literal(self, start: Path, target: Path) -> str:
        relative = Path(os.path.relpath(target, start))
        parts = relative.parts
        if not parts:
            return "."
        return " / ".join(repr(part) for part in parts)
