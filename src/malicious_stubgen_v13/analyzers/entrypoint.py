from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

from malicious_stubgen_v13.models import AnalysisResult, EntryPoint, SubgraphSpec


@dataclass(slots=True)
class _ScopeContext:
    module_qualname: str
    package_init_context: str | None
    module_context: str


class EntryPointAnalyzer:
    """Infer likely runtime entry points for suspicious code regions."""

    def analyze(
        self,
        package_root: Path,
        subgraph: SubgraphSpec,
        source_snapshot: dict[str, str] | None = None,
    ) -> AnalysisResult:
        module_file = subgraph.module_file(package_root)
        module_source = None
        if source_snapshot:
            module_source = source_snapshot.get(subgraph.normalized_module_path)
        if module_source is None and not module_file.exists():
            raise FileNotFoundError(f"Module file not found: {module_file}")

        if module_source is None:
            module_source = self._read_source(module_file)
        module_ast = ast.parse(module_source, filename=str(module_file))
        normalized_module_path = subgraph.normalized_module_path
        module_qualname = self._module_qualname(subgraph.package_name, normalized_module_path)
        init_context = self._load_package_init(package_root, subgraph, source_snapshot)
        scope_context = _ScopeContext(
            module_qualname=module_qualname,
            package_init_context=init_context,
            module_context=self._extract_module_context(module_source, subgraph.start_line, subgraph.end_line),
        )
        entry_points, warnings = self._infer_entry_points(module_ast, scope_context, subgraph)
        return AnalysisResult(
            subgraph=subgraph,
            entry_points=entry_points,
            module_qualname=module_qualname,
            package_init_context=init_context,
            module_context=scope_context.module_context,
            module_source=module_source,
            warnings=warnings,
        )

    def _infer_entry_points(
        self,
        tree: ast.Module,
        scope_context: _ScopeContext,
        subgraph: SubgraphSpec,
    ) -> tuple[list[EntryPoint], list[str]]:
        parent_map = self._build_parent_map(tree)
        relevant_nodes = self._find_relevant_nodes(tree, subgraph.start_line, subgraph.end_line)
        warnings: list[str] = []
        if not relevant_nodes:
            warnings.append("No AST node intersects the suspicious line range; falling back to module import.")
            return [self._make_module_import(scope_context, "No matching AST node found for suspicious span.", 0.25)], warnings

        contexts = {self._classify_node(node, parent_map, scope_context) for node in relevant_nodes}
        contexts = self._refine_contexts(tree, parent_map, contexts, warnings)
        entry_points = self._rank_contexts(contexts, scope_context)
        if not entry_points:
            warnings.append("No specific entry point inferred; falling back to module import.")
            entry_points = [self._make_module_import(scope_context, "Inference failed, fallback to importing the module.", 0.2)]
        return entry_points, warnings

    def _refine_contexts(
        self,
        tree: ast.Module,
        parent_map: dict[ast.AST, ast.AST | None],
        contexts: set[tuple[str, str | None, str | None, str]],
        warnings: list[str],
    ) -> set[tuple[str, str | None, str | None, str]]:
        refined = set(contexts)
        for context in list(contexts):
            kind, symbol_name, callable_path, _reasoning = context
            if kind != "function_call" or not symbol_name:
                continue
            function = self._find_module_level_function(tree, symbol_name)
            if function is None:
                continue
            if self._is_function_called_from_module_scope(tree, parent_map, symbol_name):
                refined.add(
                    (
                        "module_import",
                        None,
                        None,
                        f"Function `{symbol_name}` is invoked from module-level code, so importing the module should trigger it.",
                    )
                )
                continue
            if self._has_required_positional_args(function):
                refined.discard(context)
                warnings.append(
                    f"Function `{symbol_name}` requires positional arguments and no module-level trigger was inferred; "
                    "falling back to module import."
                )
                refined.add(
                    (
                        "module_import",
                        None,
                        None,
                        f"Function `{symbol_name}` requires arguments, so importing the module is the safest runnable trigger.",
                    )
                )
        return refined

    def _rank_contexts(self, contexts: set[tuple[str, str | None, str | None, str]], scope_context: _ScopeContext) -> list[EntryPoint]:
        scored: list[EntryPoint] = []
        for kind, symbol_name, callable_path, reasoning in sorted(contexts):
            if kind == "module_import":
                scored.append(self._make_module_import(scope_context, reasoning, 0.92))
            elif kind == "function_call":
                trigger = f"{callable_path}()"
                scored.append(
                    EntryPoint(
                        kind=kind,
                        module_qualname=scope_context.module_qualname,
                        symbol_name=symbol_name,
                        callable_path=callable_path,
                        trigger_expression=trigger,
                        reasoning=reasoning,
                        confidence=0.9,
                    )
                )
            elif kind == "class_instantiation":
                trigger = f"{callable_path}()"
                scored.append(
                    EntryPoint(
                        kind=kind,
                        module_qualname=scope_context.module_qualname,
                        symbol_name=symbol_name,
                        callable_path=callable_path,
                        trigger_expression=trigger,
                        reasoning=reasoning,
                        confidence=0.85,
                    )
                )
            elif kind == "instance_method_call":
                class_name, method_name = callable_path.rsplit(".", maxsplit=1)
                trigger = f"obj = {class_name}()\nobj.{method_name}()"
                scored.append(
                    EntryPoint(
                        kind=kind,
                        module_qualname=scope_context.module_qualname,
                        symbol_name=symbol_name,
                        callable_path=callable_path,
                        trigger_expression=trigger,
                        reasoning=reasoning,
                        confidence=0.82,
                    )
                )
            elif kind == "classmethod_call":
                trigger = f"{callable_path}()"
                scored.append(
                    EntryPoint(
                        kind=kind,
                        module_qualname=scope_context.module_qualname,
                        symbol_name=symbol_name,
                        callable_path=callable_path,
                        trigger_expression=trigger,
                        reasoning=reasoning,
                        confidence=0.82,
                    )
                )
            elif kind == "staticmethod_call":
                trigger = f"{callable_path}()"
                scored.append(
                    EntryPoint(
                        kind=kind,
                        module_qualname=scope_context.module_qualname,
                        symbol_name=symbol_name,
                        callable_path=callable_path,
                        trigger_expression=trigger,
                        reasoning=reasoning,
                        confidence=0.8,
                    )
                )
            elif kind == "property_access":
                class_name, property_name = callable_path.rsplit(".", maxsplit=1)
                trigger = f"obj = {class_name}()\nobj.{property_name}"
                scored.append(
                    EntryPoint(
                        kind=kind,
                        module_qualname=scope_context.module_qualname,
                        symbol_name=symbol_name,
                        callable_path=callable_path,
                        trigger_expression=trigger,
                        reasoning=reasoning,
                        confidence=0.68,
                    )
                )

        scored.sort(key=lambda item: (item.is_fallback, -item.confidence, item.kind, item.callable_path or ""))
        if not scored:
            return scored

        module_import = self._make_module_import(
            scope_context,
            "Fallback candidate in case the suspicious behavior executes during import side effects.",
            0.45,
            is_fallback=True,
        )
        seen = {(item.kind, item.callable_path, item.trigger_expression) for item in scored}
        if (module_import.kind, module_import.callable_path, module_import.trigger_expression) not in seen:
            scored.append(module_import)
        return scored

    def _classify_node(
        self,
        node: ast.AST,
        parent_map: dict[ast.AST, ast.AST | None],
        scope_context: _ScopeContext,
    ) -> tuple[str, str | None, str | None, str]:
        function = self._nearest_function(node, parent_map)
        if function is None:
            return (
                "module_import",
                None,
                None,
                "Suspicious code is located at module scope, so importing the module should execute it.",
            )

        cls = self._nearest_class(function, parent_map)
        if cls is None:
            symbol_name = function.name
            return (
                "function_call",
                symbol_name,
                symbol_name,
                f"Suspicious code is inside function `{symbol_name}`, so it likely requires an explicit function call.",
            )

        decorated_with = self._decorator_names(function)
        if function.name == "__init__":
            callable_path = cls.name
            return (
                "class_instantiation",
                cls.name,
                callable_path,
                f"Suspicious code is inside `{cls.name}.__init__`, so instantiating `{cls.name}` should trigger it.",
            )
        if "property" in decorated_with:
            callable_path = f"{cls.name}.{function.name}"
            return (
                "property_access",
                function.name,
                callable_path,
                f"Suspicious code is inside property `{callable_path}`, so accessing the property may trigger it.",
            )
        if "classmethod" in decorated_with:
            callable_path = f"{cls.name}.{function.name}"
            return (
                "classmethod_call",
                function.name,
                callable_path,
                f"Suspicious code is inside class method `{callable_path}`, so calling it on the class may trigger it.",
            )
        if "staticmethod" in decorated_with:
            callable_path = f"{cls.name}.{function.name}"
            return (
                "staticmethod_call",
                function.name,
                callable_path,
                f"Suspicious code is inside static method `{callable_path}`, so calling it directly may trigger it.",
            )
        callable_path = f"{cls.name}.{function.name}"
        return (
            "instance_method_call",
            function.name,
            callable_path,
            f"Suspicious code is inside instance method `{callable_path}`, so instantiation plus method call is the strongest candidate.",
        )

    def _make_module_import(
        self,
        scope_context: _ScopeContext,
        reasoning: str,
        confidence: float,
        is_fallback: bool = False,
    ) -> EntryPoint:
        return EntryPoint(
            kind="module_import",
            module_qualname=scope_context.module_qualname,
            symbol_name=None,
            callable_path=None,
            trigger_expression=f"import {scope_context.module_qualname}",
            reasoning=reasoning,
            confidence=confidence,
            is_fallback=is_fallback,
        )

    def _find_relevant_nodes(self, tree: ast.Module, start_line: int, end_line: int) -> list[ast.AST]:
        matches: list[ast.AST] = []
        for node in ast.walk(tree):
            lineno = getattr(node, "lineno", None)
            end_lineno = getattr(node, "end_lineno", None)
            if lineno is None or end_lineno is None:
                continue
            if self._ranges_overlap(lineno, end_lineno, start_line, end_line):
                if isinstance(node, (ast.Call, ast.Import, ast.ImportFrom, ast.Assign, ast.Expr, ast.Return, ast.Await)):
                    matches.append(node)
        return matches

    @staticmethod
    def _ranges_overlap(start_a: int, end_a: int, start_b: int, end_b: int) -> bool:
        return start_a <= end_b and start_b <= end_a

    def _build_parent_map(self, tree: ast.AST) -> dict[ast.AST, ast.AST | None]:
        parents: dict[ast.AST, ast.AST | None] = {tree: None}
        for parent in ast.walk(tree):
            for child in ast.iter_child_nodes(parent):
                parents[child] = parent
        return parents

    def _nearest_function(self, node: ast.AST, parent_map: dict[ast.AST, ast.AST | None]) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
        current = node
        while current is not None:
            if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
                return current
            current = parent_map.get(current)
        return None

    def _nearest_class(self, node: ast.AST, parent_map: dict[ast.AST, ast.AST | None]) -> ast.ClassDef | None:
        current = parent_map.get(node)
        while current is not None:
            if isinstance(current, ast.ClassDef):
                return current
            current = parent_map.get(current)
        return None

    def _decorator_names(self, function: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
        names: set[str] = set()
        for decorator in function.decorator_list:
            if isinstance(decorator, ast.Name):
                names.add(decorator.id)
            elif isinstance(decorator, ast.Attribute):
                names.add(decorator.attr)
        return names

    def _module_qualname(self, package_name: str, module_path: str) -> str:
        normalized = module_path.replace("\\", "/")
        suffix = normalized[:-3] if normalized.endswith(".py") else normalized
        parts = [part for part in suffix.split("/") if part]
        if not parts:
            return package_name
        if not package_name:
            if parts[-1] == "__init__":
                parts = parts[:-1]
            return ".".join(parts)
        if parts[-1] == "__init__":
            parts = parts[:-1]
        if parts and parts[0] == package_name:
            parts = parts[1:]
        if not parts:
            return package_name
        return ".".join([package_name, *parts])

    def _load_package_init(
        self,
        package_root: Path,
        subgraph: SubgraphSpec,
        source_snapshot: dict[str, str] | None = None,
    ) -> str | None:
        if not subgraph.package_name:
            return None
        normalized = subgraph.normalized_module_path
        if "/" not in normalized:
            init_path = "__init__.py"
        else:
            module_dir = normalized.rsplit("/", maxsplit=1)[0]
            init_path = f"{module_dir}/__init__.py"
        if source_snapshot and init_path in source_snapshot:
            return source_snapshot[init_path]
        init_file = package_root / init_path
        if not init_file.exists():
            return None
        return self._read_source(init_file)

    def _extract_module_context(self, source: str, start_line: int, end_line: int, radius: int = 12) -> str:
        lines = source.splitlines()
        start = max(1, start_line - radius)
        end = min(len(lines), end_line + radius)
        snippet = []
        for number in range(start, end + 1):
            snippet.append(f"{number:04d}: {lines[number - 1]}")
        return "\n".join(snippet)

    def _read_source(self, path: Path) -> str:
        try:
            return path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            return path.read_text(encoding="utf-8", errors="replace")

    def _find_module_level_function(self, tree: ast.Module, function_name: str) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
        for statement in tree.body:
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)) and statement.name == function_name:
                return statement
        return None

    def _has_required_positional_args(self, function: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        positional = list(function.args.posonlyargs) + list(function.args.args)
        defaults = list(function.args.defaults)
        required_count = len(positional) - len(defaults)
        return required_count > 0

    def _is_function_called_from_module_scope(
        self,
        tree: ast.Module,
        parent_map: dict[ast.AST, ast.AST | None],
        function_name: str,
    ) -> bool:
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if not isinstance(node.func, ast.Name) or node.func.id != function_name:
                continue
            if self._nearest_function(node, parent_map) is None:
                return True
        return False
