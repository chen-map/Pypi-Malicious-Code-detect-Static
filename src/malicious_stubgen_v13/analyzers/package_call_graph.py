from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(slots=True)
class PackageCallGraph:
    edges: dict[str, set[str]] = field(default_factory=dict)
    known_modules: set[str] = field(default_factory=set)
    known_classes: set[str] = field(default_factory=set)
    known_symbols: set[str] = field(default_factory=set)
    class_to_init: dict[str, str] = field(default_factory=dict)

    def reaches(self, start: str | None, target: str | None) -> bool:
        if not start or not target:
            return False
        if start == target:
            return True
        seen: set[str] = set()
        stack = [start]
        while stack:
            current = stack.pop()
            if current in seen:
                continue
            seen.add(current)
            for neighbor in self.edges.get(current, set()):
                if neighbor == target:
                    return True
                if neighbor not in seen:
                    stack.append(neighbor)
        return False

    def init_key_for_class(self, class_symbol: str | None) -> str | None:
        if not class_symbol:
            return None
        return self.class_to_init.get(class_symbol, class_symbol)


@dataclass(slots=True)
class _ModuleInfo:
    module_qualname: str
    package_name: str
    tree: ast.Module
    local_symbols: dict[str, str]
    import_aliases: dict[str, str]
    class_symbols: set[str]
    method_symbols: set[str]


class PackageCallGraphBuilder:
    """Build a lightweight intra-package call graph for entry-point reduction."""

    def build(
        self,
        package_root: Path,
        package_names: set[str],
        source_snapshot: dict[str, str] | None = None,
    ) -> PackageCallGraph:
        modules = self._load_modules(package_root, package_names, source_snapshot)
        graph = PackageCallGraph()
        for module in modules:
            graph.known_modules.add(module.module_qualname)
            graph.known_classes.update(module.class_symbols)
            graph.known_symbols.update(module.local_symbols.values())
            graph.known_symbols.update(module.method_symbols)

        for class_symbol in graph.known_classes:
            init_symbol = f"{class_symbol}.__init__"
            if init_symbol in graph.known_symbols:
                graph.class_to_init[class_symbol] = init_symbol

        for module in modules:
            module_key = f"module:{module.module_qualname}"
            graph.edges[module_key] = self._collect_edges_for_statements(module, module.tree.body, graph)
            for statement in module.tree.body:
                if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    symbol_key = module.local_symbols[statement.name]
                    graph.edges[symbol_key] = self._collect_edges_for_statements(module, statement.body, graph)
                elif isinstance(statement, ast.ClassDef):
                    class_symbol = f"{module.module_qualname}.{statement.name}"
                    for item in statement.body:
                        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                            symbol_key = f"{module.module_qualname}.{statement.name}.{item.name}"
                            graph.edges[symbol_key] = self._collect_edges_for_statements(
                                module,
                                item.body,
                                graph,
                                bound_var_types=self._bound_method_vars(class_symbol, item),
                            )
        return graph

    def _collect_edges_for_statements(
        self,
        module: _ModuleInfo,
        statements: list[ast.stmt],
        graph: PackageCallGraph,
        bound_var_types: dict[str, str] | None = None,
    ) -> set[str]:
        collector = _FunctionBodyCollector(module, graph, bound_var_types=bound_var_types)
        return collector.collect(statements)

    def _bound_method_vars(
        self,
        class_symbol: str,
        function: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> dict[str, str]:
        if not function.args.args:
            return {}
        if "staticmethod" in self._decorator_names(function):
            return {}
        return {function.args.args[0].arg: class_symbol}

    def _decorator_names(self, function: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
        names: set[str] = set()
        for decorator in function.decorator_list:
            if isinstance(decorator, ast.Name):
                names.add(decorator.id)
            elif isinstance(decorator, ast.Attribute):
                names.add(decorator.attr)
        return names

    def _load_modules(
        self,
        package_root: Path,
        package_names: set[str],
        source_snapshot: dict[str, str] | None = None,
    ) -> list[_ModuleInfo]:
        if source_snapshot:
            return self._load_modules_from_snapshot(package_names, source_snapshot)

        modules: list[_ModuleInfo] = []
        for package_name in sorted(package_names):
            if package_name:
                package_dir = package_root / package_name
                if not package_dir.exists():
                    continue
                module_files = [
                    path
                    for path in sorted(package_dir.rglob("*.py"))
                    if not self._should_skip_file(path) and not any(self._should_skip_dir(part) for part in path.parents)
                ]
            else:
                module_files = [
                    path
                    for path in sorted(package_root.iterdir())
                    if path.is_file() and path.suffix == ".py" and not self._should_skip_file(path)
                ]
            for path in module_files:
                relative_path = path.relative_to(package_root).as_posix()
                module_qualname = self._module_qualname(package_name, relative_path)
                tree = ast.parse(self._read_source(path), filename=str(path))
                local_symbols: dict[str, str] = {}
                class_symbols: set[str] = set()
                method_symbols: set[str] = set()
                for statement in tree.body:
                    if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        local_symbols[statement.name] = f"{module_qualname}.{statement.name}"
                    elif isinstance(statement, ast.ClassDef):
                        class_symbol = f"{module_qualname}.{statement.name}"
                        local_symbols[statement.name] = class_symbol
                        class_symbols.add(class_symbol)
                        for item in statement.body:
                            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                                method_symbols.add(f"{class_symbol}.{item.name}")
                import_aliases = self._extract_import_aliases(tree, module_qualname)
                modules.append(
                    _ModuleInfo(
                        module_qualname=module_qualname,
                        package_name=package_name,
                        tree=tree,
                        local_symbols=local_symbols,
                        import_aliases=import_aliases,
                        class_symbols=class_symbols,
                        method_symbols=method_symbols,
                    )
                )
        return modules

    def _load_modules_from_snapshot(
        self,
        package_names: set[str],
        source_snapshot: dict[str, str],
    ) -> list[_ModuleInfo]:
        modules: list[_ModuleInfo] = []
        non_empty_package_names = sorted(name for name in package_names if name)
        root_package_name = self._infer_root_package_name(non_empty_package_names, source_snapshot)
        for relative_path, source in sorted(source_snapshot.items()):
            if self._should_skip_file(Path(relative_path)):
                continue
            package_name = self._package_name_for_snapshot_path(relative_path, non_empty_package_names, root_package_name)
            if package_name not in package_names:
                continue
            module_qualname = self._module_qualname(package_name, relative_path)
            tree = ast.parse(source, filename=relative_path)
            local_symbols: dict[str, str] = {}
            class_symbols: set[str] = set()
            method_symbols: set[str] = set()
            for statement in tree.body:
                if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    local_symbols[statement.name] = f"{module_qualname}.{statement.name}"
                elif isinstance(statement, ast.ClassDef):
                    class_symbol = f"{module_qualname}.{statement.name}"
                    local_symbols[statement.name] = class_symbol
                    class_symbols.add(class_symbol)
                    for item in statement.body:
                        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                            method_symbols.add(f"{class_symbol}.{item.name}")
            import_aliases = self._extract_import_aliases(tree, module_qualname)
            modules.append(
                _ModuleInfo(
                    module_qualname=module_qualname,
                    package_name=package_name,
                    tree=tree,
                    local_symbols=local_symbols,
                    import_aliases=import_aliases,
                    class_symbols=class_symbols,
                    method_symbols=method_symbols,
                )
            )
        return modules

    def _read_source(self, path: Path) -> str:
        try:
            return path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            return path.read_text(encoding="utf-8", errors="replace")

    def _infer_root_package_name(self, package_names: list[str], source_snapshot: dict[str, str]) -> str | None:
        if len(package_names) != 1:
            return None
        candidate = package_names[0]
        has_prefixed_paths = any(path == candidate or path.startswith(f"{candidate}/") for path in source_snapshot)
        if has_prefixed_paths:
            return None
        if "__init__.py" in source_snapshot:
            return candidate
        return None

    def _package_name_for_snapshot_path(
        self,
        relative_path: str,
        package_names: list[str],
        root_package_name: str | None,
    ) -> str:
        if root_package_name:
            return root_package_name
        for package_name in package_names:
            if relative_path == package_name or relative_path.startswith(f"{package_name}/"):
                return package_name
        return ""

    def _should_skip_dir(self, path: Path) -> bool:
        lowered = path.name.lower()
        if lowered in {"__pycache__", ".stubgen_extracted", "generated_stubs", "generated_stubs_auto"}:
            return True
        if lowered.endswith(".egg-info"):
            return True
        if lowered.startswith(".ddg"):
            return True
        return False

    def _should_skip_file(self, path: Path) -> bool:
        lowered = path.name.lower()
        return lowered.endswith("_single_stub.py") or lowered.endswith("_final_single_stub.py")

    def _extract_import_aliases(self, tree: ast.Module, module_qualname: str) -> dict[str, str]:
        aliases: dict[str, str] = {}
        for statement in tree.body:
            if isinstance(statement, ast.Import):
                for item in statement.names:
                    target = item.name
                    local_name = item.asname or target.split(".")[-1]
                    aliases[local_name] = target
            elif isinstance(statement, ast.ImportFrom):
                base_module = self._resolve_from_module(module_qualname, statement.level, statement.module)
                for item in statement.names:
                    local_name = item.asname or item.name
                    if item.name == "*":
                        continue
                    if base_module:
                        aliases[local_name] = f"{base_module}.{item.name}"
        return aliases

    def _resolve_from_module(self, module_qualname: str, level: int, module: str | None) -> str:
        module_parts = module_qualname.split(".")
        package_parts = module_parts if len(module_parts) == 1 else module_parts[:-1]
        if level > 0:
            keep = len(package_parts) - (level - 1)
            base_parts = package_parts[: max(keep, 0)]
        else:
            base_parts = []
        if module:
            extra_parts = module.split(".")
            return ".".join([*base_parts, *extra_parts])
        return ".".join(base_parts)

    def _module_qualname(self, package_name: str, module_path: str) -> str:
        normalized = module_path.replace("\\", "/")
        suffix = normalized[:-3] if normalized.endswith(".py") else normalized
        parts = [part for part in suffix.split("/") if part]
        if not package_name:
            if parts and parts[-1] == "__init__":
                parts = parts[:-1]
            return ".".join(parts)
        if parts and parts[-1] == "__init__":
            parts = parts[:-1]
        if parts and parts[0] == package_name:
            parts = parts[1:]
        return package_name if not parts else ".".join([package_name, *parts])


class _FunctionBodyCollector(ast.NodeVisitor):
    def __init__(
        self,
        module: _ModuleInfo,
        graph: PackageCallGraph,
        bound_var_types: dict[str, str] | None = None,
    ) -> None:
        self.module = module
        self.graph = graph
        self.edges: set[str] = set()
        self.local_var_types: dict[str, str] = dict(bound_var_types or {})
        self.local_aliases = dict(module.import_aliases)

    def collect(self, statements: list[ast.stmt]) -> set[str]:
        for statement in statements:
            self.visit(statement)
        return self.edges

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        return None

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:  # noqa: N802
        return None

    def visit_ClassDef(self, node: ast.ClassDef) -> None:  # noqa: N802
        return None

    def visit_Import(self, node: ast.Import) -> None:  # noqa: N802
        for item in node.names:
            target = item.name
            local_name = item.asname or target.split(".")[-1]
            self.local_aliases[local_name] = target

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:  # noqa: N802
        builder = PackageCallGraphBuilder()
        base_module = builder._resolve_from_module(self.module.module_qualname, node.level, node.module)
        for item in node.names:
            local_name = item.asname or item.name
            if item.name == "*":
                continue
            if base_module:
                self.local_aliases[local_name] = f"{base_module}.{item.name}"

    def visit_Assign(self, node: ast.Assign) -> None:  # noqa: N802
        self._track_assignment_types(node.targets, node.value)
        self.visit(node.value)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:  # noqa: N802
        self._track_assignment_types([node.target], node.value)
        if node.value is not None:
            self.visit(node.value)

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        target = self._resolve_call_target(node.func)
        if target:
            self.edges.add(target)
        for argument in node.args:
            self.visit(argument)
        for keyword in node.keywords:
            if keyword.value is not None:
                self.visit(keyword.value)

    def _track_assignment_types(self, targets: list[ast.expr], value: ast.expr | None) -> None:
        if value is None or not isinstance(value, ast.Call):
            return
        constructed = self._resolve_constructed_class(value.func)
        if not constructed:
            return
        for target in targets:
            for name in self._extract_target_names(target):
                self.local_var_types[name] = constructed

    def _extract_target_names(self, target: ast.expr) -> list[str]:
        if isinstance(target, ast.Name):
            return [target.id]
        if isinstance(target, (ast.Tuple, ast.List)):
            names: list[str] = []
            for item in target.elts:
                names.extend(self._extract_target_names(item))
            return names
        return []

    def _resolve_call_target(self, func: ast.expr) -> str | None:
        symbol = self._resolve_expr_symbol(func)
        if not symbol:
            return None
        if symbol in self.graph.known_classes:
            return self.graph.init_key_for_class(symbol)
        if symbol in self.graph.known_symbols:
            return symbol
        if symbol in self.graph.known_modules:
            return f"module:{symbol}"
        return None

    def _resolve_constructed_class(self, func: ast.expr) -> str | None:
        symbol = self._resolve_expr_symbol(func)
        if symbol in self.graph.known_classes:
            return symbol
        return None

    def _resolve_expr_symbol(self, expr: ast.expr) -> str | None:
        if isinstance(expr, ast.Name):
            if expr.id in self.local_var_types:
                return self.local_var_types[expr.id]
            if expr.id in self.module.local_symbols:
                return self.module.local_symbols[expr.id]
            return self.local_aliases.get(expr.id)
        if isinstance(expr, ast.Attribute):
            base = self._resolve_expr_symbol(expr.value)
            if not base:
                return None
            candidate = f"{base}.{expr.attr}"
            if candidate in self.graph.known_symbols or candidate in self.graph.known_classes or candidate in self.graph.known_modules:
                return candidate
            if base in self.graph.known_classes:
                return candidate
            return candidate if base in self.graph.known_modules else None
        return None
