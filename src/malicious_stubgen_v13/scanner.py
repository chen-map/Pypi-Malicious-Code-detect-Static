from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
import re
import shutil
import tarfile
import zipfile

from malicious_stubgen_v13.models import SkippedSource, StubGenerationTask, SubgraphSpec


SENSITIVE_API_PATTERNS: dict[str, tuple[str, ...]] = {
    "Dispatch": ("Dispatch", "win32com.client.Dispatch"),
    "Request": ("Request",),
    "RequestsWebhookAdapter": ("RequestsWebhookAdapter", "discord.RequestsWebhookAdapter"),
    "SyncWebhook.from_url": ("SyncWebhook.from_url", "discord.SyncWebhook.from_url"),
    "Webhook.from_url": ("Webhook.from_url", "discord.Webhook.from_url"),
    "__import__": ("__import__",),
    "__pyarmor__": ("__pyarmor__",),
    "aiohttp.ClientSession": ("aiohttp.ClientSession",),
    "AsyncWebhookAdapter": ("AsyncWebhookAdapter", "discord.AsyncWebhookAdapter"),
    "base64.b32encode": ("base64.b32encode",),
    "base64.b64encode": ("base64.b64encode",),
    "exec": ("exec",),
    "eval": ("eval",),
    "compile": ("compile",),
    "ctypes.windll.shell32.IsUserAnAdmin": ("ctypes.windll.shell32.IsUserAnAdmin",),
    "importlib.import_module": ("importlib.import_module",),
    "importlib.util.spec_from_file_location": ("importlib.util.spec_from_file_location",),
    "importlib.util.module_from_spec": ("importlib.util.module_from_spec",),
    "distutils.core.setup": ("distutils.core.setup",),
    "exit": ("exit",),
    "getattr": ("getattr",),
    "getpass.getuser": ("getpass.getuser",),
    "http.client.HTTPConnection": ("http.client.HTTPConnection",),
    "http_request.Request": ("http_request.Request",),
    "http_request.urlopen": ("http_request.urlopen",),
    "os.system": ("os.system",),
    "system": ("system",),
    "os.popen": ("os.popen",),
    "os.chdir": ("os.chdir",),
    "os.chmod": ("os.chmod",),
    "os.environ.get": ("os.environ.get",),
    "os.getenv": ("os.getenv",),
    "os.getlogin": ("os.getlogin",),
    "os.mkdir": ("os.mkdir",),
    "os.remove": ("os.remove",),
    "os.unlink": ("os.unlink",),
    "os.startfile": ("os.startfile",),
    "os.kill": ("os.kill",),
    "os.execv": ("os.execv",),
    "os.makedirs": ("os.makedirs",),
    "os.path.abspath": ("os.path.abspath",),
    "os.path.basename": ("os.path.basename",),
    "os.path.dirname": ("os.path.dirname",),
    "os.path.exists": ("os.path.exists",),
    "os.path.expanduser": ("os.path.expanduser",),
    "os.path.join": ("os.path.join",),
    "os.stat": ("os.stat",),
    "os.walk": ("os.walk",),
    "open": ("open",),
    "pip.main": ("pip.main",),
    "platform.system": ("platform.system",),
    "platform.uname": ("platform.uname",),
    "pytransform.pyarmor_runtime": ("pytransform.pyarmor_runtime",),
    "response.read": ("response.read",),
    "setattr": ("setattr",),
    "setuptools.command.develop.develop.run": ("setuptools.command.develop.develop.run",),
    "setuptools.command.egg_info.egg_info.run": ("setuptools.command.egg_info.egg_info.run",),
    "setuptools.command.install.install.run": ("setuptools.command.install.install.run",),
    "setuptools.setup": ("setuptools.setup",),
    "socket.getaddrinfo": ("socket.getaddrinfo",),
    "socket.gethostbyname": ("socket.gethostbyname",),
    "socket.gethostname": ("socket.gethostname",),
    "subprocess.run": ("subprocess.run",),
    "subprocess.call": ("subprocess.call",),
    "subprocess.Popen": ("subprocess.Popen",),
    "subprocess.check_output": ("subprocess.check_output",),
    "subprocess.check_call": ("subprocess.check_call",),
    "subprocess.getoutput": ("subprocess.getoutput",),
    "sys.exit": ("sys.exit",),
    "sys.stderr.write": ("sys.stderr.write",),
    "tempfile.gettempdir": ("tempfile.gettempdir",),
    "urllib.parse.urlencode": ("urllib.parse.urlencode",),
    "urllib.request.Request": ("urllib.request.Request",),
    "urllib.request.urlretrieve": ("urllib.request.urlretrieve",),
    "urllib.request.urlopen": ("urllib.request.urlopen",),
    "urllib.urlopen": ("urllib.urlopen",),
    "urllib2.urlopen": ("urllib2.urlopen",),
    "urlopen": ("urlopen",),
    "urlrequest.Request": ("urlrequest.Request",),
    "urlrequest.urlopen": ("urlrequest.urlopen",),
    "requests.get": ("requests.get",),
    "requests.head": ("requests.head",),
    "requests.post": ("requests.post",),
    "requests.put": ("requests.put",),
    "requests.delete": ("requests.delete",),
    "requests.patch": ("requests.patch",),
    "requests.request": ("requests.request",),
    "asyncio.open_connection": ("asyncio.open_connection",),
    "socket.socket": ("socket.socket",),
    "socket.connect": ("socket.connect",),
    "socket.create_connection": ("socket.create_connection",),
    "os.dup2": ("os.dup2",),
    "pty.spawn": ("pty.spawn",),
    "marshal.loads": ("marshal.loads",),
    "pickle.loads": ("pickle.loads",),
    "base64.b64decode": ("base64.b64decode",),
    "base64.urlsafe_b64decode": ("base64.urlsafe_b64decode",),
    "base64.b32decode": ("base64.b32decode",),
    "base64.b85decode": ("base64.b85decode",),
    "ssl._create_unverified_context": ("ssl._create_unverified_context",),
    "ssl.wrap_socket": ("ssl.wrap_socket",),
    "winreg.OpenKey": ("winreg.OpenKey",),
    "winreg.QueryValueEx": ("winreg.QueryValueEx",),
    "winreg.ConnectRegistry": ("winreg.ConnectRegistry",),
    "winreg.EnumKey": ("winreg.EnumKey",),
    "winreg.EnumValue": ("winreg.EnumValue",),
    "winreg.CreateKey": ("winreg.CreateKey",),
    "winreg.SetValueEx": ("winreg.SetValueEx",),
    "ctypes.windll.shell32.ShellExecuteW": ("ctypes.windll.shell32.ShellExecuteW",),
    "ctypes.windll.crypt32.CryptUnprotectData": ("ctypes.windll.crypt32.CryptUnprotectData",),
    "ctypes.windll.kernel32.SetFileAttributesW": ("ctypes.windll.kernel32.SetFileAttributesW",),
    "ctypes.windll.kernel32.OpenProcess": ("ctypes.windll.kernel32.OpenProcess",),
    "ctypes.windll.kernel32.TerminateProcess": ("ctypes.windll.kernel32.TerminateProcess",),
    "ctypes.windll.kernel32.ExitProcess": ("ctypes.windll.kernel32.ExitProcess",),
    "ctypes.windll.user32.LockWorkStation": ("ctypes.windll.user32.LockWorkStation",),
    "ctypes.windll.ntdll.RtlAdjustPrivilege": ("ctypes.windll.ntdll.RtlAdjustPrivilege",),
    "ctypes.windll.ntdll.NtRaiseHardError": ("ctypes.windll.ntdll.NtRaiseHardError",),
    "psutil.process_iter": ("psutil.process_iter",),
    "wmi.WMI": ("wmi.WMI",),
    "brc.close": ("brc.close",),
    "brc.write": ("brc.write",),
    "d.close": ("d.close",),
    "d.write": ("d.write",),
}

SUPPORTED_ARCHIVE_SUFFIXES = (".tar.gz", ".tgz", ".tar", ".whl", ".zip")
ARCHIVE_MARKER_FILENAME = ".stubgen_archive_source"
SKIPPED_DIRECTORY_NAMES = {
    "__pycache__",
    ".git",
    ".hg",
    ".svn",
    ".stubgen_extracted",
    "generated_stubs",
    "generated_stubs_auto",
}


@dataclass(slots=True)
class _ModuleContext:
    module_path: str
    package_name: str
    aliases: dict[str, str]
    source_lines: list[str]


class SuspiciousProjectScanner:
    """Build a StubGenerationTask directly from a package directory or archive."""

    def __init__(self) -> None:
        self._archive_source_cache: dict[Path, dict[str, str]] = {}
        self.last_skipped_sources: list[SkippedSource] = []

    def discover_project_roots(self, root: Path) -> list[Path]:
        root = root.resolve()
        if root.is_file():
            return [root] if self.is_supported_archive(root) else []

        direct_packages, root_scripts = self._find_package_dirs(root)
        if direct_packages or root_scripts:
            return [root]

        return self._dedupe_paths(self._discover_nested_sources(root))

    def is_supported_archive(self, path: Path) -> bool:
        return self._is_supported_archive(path)

    def scan(self, package_root: Path, output_dir: Path | None = None, final_stub_path: Path | None = None) -> StubGenerationTask:
        self.last_skipped_sources = []
        requested_root = package_root.resolve()
        scan_root, packages, root_scripts = self._resolve_scan_root(requested_root)
        subgraphs: list[SubgraphSpec] = []
        source_snapshot: dict[str, str] = {}
        archive_sources = self._lookup_archive_sources(scan_root)

        for package_dir in packages:
            package_name = package_dir.name
            if archive_sources is not None:
                prefix = f"{package_name}/"
                package_items = [
                    (relative_path, source)
                    for relative_path, source in sorted(archive_sources.items())
                    if relative_path.startswith(prefix)
                ]
                for relative_path, source in package_items:
                    tree, parse_error = self._parse_source(source, scan_root / relative_path)
                    if tree is None:
                        self._record_skipped_source(scan_root, scan_root / relative_path, parse_error or "parse_error")
                        continue
                    source_snapshot[relative_path] = source
                    context = _ModuleContext(
                        module_path=relative_path,
                        package_name=package_name,
                        aliases=self._build_alias_map(tree),
                        source_lines=source.splitlines(),
                    )
                    subgraphs.extend(self._collect_subgraphs(tree, context))
                continue

            for file_path in sorted(package_dir.rglob("*.py")):
                if self._should_skip_file(file_path):
                    self._record_skipped_source(scan_root, file_path, "generated_stub_file")
                    continue
                source, read_error = self._read_source(file_path)
                if source is None:
                    self._record_skipped_source(scan_root, file_path, read_error or "read_error")
                    continue
                tree, parse_error = self._parse_source(source, file_path)
                if tree is None:
                    self._record_skipped_source(scan_root, file_path, parse_error or "parse_error")
                    continue
                relative_path = file_path.relative_to(scan_root).as_posix()
                source_snapshot[relative_path] = source
                context = _ModuleContext(
                    module_path=relative_path,
                    package_name=package_name,
                    aliases=self._build_alias_map(tree),
                    source_lines=source.splitlines(),
                )
                subgraphs.extend(self._collect_subgraphs(tree, context))

        for file_path in root_scripts:
            if self._should_skip_file(file_path):
                self._record_skipped_source(scan_root, file_path, "generated_stub_file")
                continue
            relative_path = file_path.relative_to(scan_root).as_posix()
            if archive_sources is not None:
                source = archive_sources.get(relative_path)
                if source is None:
                    self._record_skipped_source(scan_root, scan_root / relative_path, "missing_archive_source")
                    continue
                tree, parse_error = self._parse_source(source, scan_root / relative_path)
            else:
                source, read_error = self._read_source(file_path)
                if source is None:
                    self._record_skipped_source(scan_root, file_path, read_error or "read_error")
                    continue
                tree, parse_error = self._parse_source(source, file_path)
            if tree is None:
                self._record_skipped_source(scan_root, file_path, parse_error or "parse_error")
                continue
            source_snapshot[relative_path] = source
            context = _ModuleContext(
                module_path=relative_path,
                package_name="",
                aliases=self._build_alias_map(tree),
                source_lines=source.splitlines(),
            )
            subgraphs.extend(self._collect_subgraphs(tree, context))

        if not subgraphs:
            raise ValueError(f"No suspicious API calls found under {scan_root}")

        package_name = next((item.package_name for item in subgraphs if item.package_name), subgraphs[0].package_name)
        stub_base_name = package_name or self._sanitize_name(self._default_stub_base_name(requested_root))
        output_base = self._default_output_base(requested_root)
        resolved_output = (output_dir or output_base / "generated_stubs").resolve()
        resolved_final_stub = (final_stub_path or output_base / f"{stub_base_name}_single_stub.py").resolve()
        return StubGenerationTask(
            package_root=scan_root,
            output_dir=resolved_output,
            subgraphs=subgraphs,
            source_snapshot=source_snapshot,
            skipped_sources=list(self.last_skipped_sources),
            include_llm_payload=False,
            emit_debug_artifacts=False,
            final_stub_path=resolved_final_stub,
        )

    def _resolve_scan_root(self, package_root: Path) -> tuple[Path, list[Path], list[Path]]:
        if package_root.is_file():
            if not self._is_supported_archive(package_root):
                raise ValueError(f"Unsupported input file: {package_root}")
            extracted_root = self._extract_archive(package_root)
            self._archive_source_cache[extracted_root] = self._load_archive_source_map(package_root)
            return self._resolve_scan_root(extracted_root)

        nested_root = self._unwrap_single_nested_project_dir(package_root)
        if nested_root is not None:
            return self._resolve_scan_root(nested_root)

        direct_packages, root_scripts = self._find_package_dirs(package_root)
        if direct_packages or root_scripts:
            return package_root, direct_packages, root_scripts

        suggestions = [item for item in self.discover_project_roots(package_root) if item.is_dir()]
        unique = self._dedupe_paths(suggestions)
        if len(unique) == 1:
            resolved_root = unique[0]
            packages, scripts = self._find_package_dirs(resolved_root)
            return resolved_root, packages, scripts
        if unique:
            preview = ", ".join(str(path) for path in unique[:3])
            raise ValueError(
                "No concrete Python project root found directly under "
                f"{package_root}. Multiple candidate project folders were found: {preview}"
            )

        direct_archives = self._select_direct_archives(package_root)
        if len(direct_archives) == 1:
            return self._resolve_scan_root(direct_archives[0])
        if direct_archives:
            preview = ", ".join(str(path) for path in direct_archives[:3])
            raise ValueError(
                "Multiple archive candidates were found directly under "
                f"{package_root}: {preview}"
            )
        raise ValueError(f"No Python package, root Python module, or supported archive was found under {package_root}")

    def _find_package_dirs(self, package_root: Path) -> tuple[list[Path], list[Path]]:
        if not package_root.is_dir():
            return [], []

        root_scripts = self._root_python_scripts(package_root)
        if (package_root / "__init__.py").exists() and package_root.name.isidentifier():
            return [package_root], root_scripts

        direct_packages = [
            path
            for path in sorted(package_root.iterdir())
            if path.is_dir() and not self._should_skip_dir(path) and (path / "__init__.py").exists()
        ]
        return direct_packages, root_scripts

    def _unwrap_single_nested_project_dir(self, package_root: Path) -> Path | None:
        if not package_root.is_dir():
            return None
        children = [
            path
            for path in sorted(package_root.iterdir())
            if not self._should_skip_dir(path)
        ]
        dir_children = [path for path in children if path.is_dir()]
        file_children = [path for path in children if path.is_file()]
        if file_children or len(dir_children) != 1:
            return None
        candidate = dir_children[0]
        candidate_scripts = self._root_python_scripts(candidate)
        if any(path.name == "setup.py" for path in candidate_scripts):
            return candidate
        return None

    def _root_python_scripts(self, package_root: Path) -> list[Path]:
        return [
            path
            for path in sorted(package_root.iterdir())
            if path.is_file() and path.suffix == ".py" and not self._should_skip_file(path)
        ]

    def _collect_subgraphs(self, tree: ast.Module, context: _ModuleContext) -> list[SubgraphSpec]:
        matches: list[SubgraphSpec] = []
        source_lines = context.source_lines
        index = 1
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            qualified_name = self._resolve_call_name(node.func, context.aliases)
            sensitive_apis = self._match_sensitive_apis(qualified_name)
            if not sensitive_apis:
                continue
            start_line = getattr(node, "lineno", None)
            end_line = getattr(node, "end_lineno", start_line)
            if start_line is None or end_line is None:
                continue
            code = "\n".join(source_lines[start_line - 1 : end_line])
            matches.append(
                SubgraphSpec(
                    subgraph_id=f"{Path(context.module_path).stem}_{index:03d}",
                    module_path=context.module_path,
                    package_name=context.package_name,
                    sensitive_apis=sensitive_apis,
                    start_line=start_line,
                    end_line=end_line,
                    code=code,
                )
            )
            index += 1
        matches.sort(key=lambda item: (item.module_path, item.start_line, item.end_line))
        return matches

    def _build_alias_map(self, tree: ast.Module) -> dict[str, str]:
        aliases: dict[str, str] = {}
        for node in tree.body:
            if isinstance(node, ast.Import):
                for item in node.names:
                    aliases[item.asname or item.name.split(".")[-1]] = item.name
            elif isinstance(node, ast.ImportFrom):
                base_module = node.module or ""
                for item in node.names:
                    if item.name == "*":
                        continue
                    aliases[item.asname or item.name] = f"{base_module}.{item.name}" if base_module else item.name
        return aliases

    def _resolve_call_name(self, func: ast.expr, aliases: dict[str, str]) -> str | None:
        if isinstance(func, ast.Name):
            return aliases.get(func.id, func.id)
        if isinstance(func, ast.Attribute):
            base = self._resolve_call_name(func.value, aliases)
            if not base:
                return None
            return f"{base}.{func.attr}"
        return None

    def _match_sensitive_apis(self, qualified_name: str | None) -> list[str]:
        if not qualified_name:
            return []
        matched: list[str] = []
        for label, candidates in SENSITIVE_API_PATTERNS.items():
            if qualified_name in candidates:
                matched.append(label)
        return matched

    def _discover_nested_sources(self, root: Path) -> list[Path]:
        if self._should_skip_dir(root):
            return []

        direct_packages, root_scripts = self._find_package_dirs(root)
        if direct_packages or root_scripts:
            return [root]

        direct_archives = self._select_direct_archives(root)
        archive_dir_names = {self._archive_base_name(path) for path in direct_archives}
        discovered: list[Path] = []
        for child in sorted(root.iterdir()):
            if not child.is_dir() or self._should_skip_dir(child):
                continue
            if child.name in archive_dir_names:
                continue
            discovered.extend(self._discover_nested_sources(child))
        return self._dedupe_paths(discovered + direct_archives)

    def _select_direct_archives(self, root: Path) -> list[Path]:
        archives = [
            path
            for path in sorted(root.iterdir())
            if path.is_file() and self._is_supported_archive(path)
        ]
        if not archives:
            return []

        grouped: dict[str, Path] = {}
        for archive in archives:
            key = self._archive_base_name(archive).lower()
            current = grouped.get(key)
            if current is None or self._archive_priority(archive) < self._archive_priority(current):
                grouped[key] = archive
        return sorted(grouped.values(), key=lambda item: item.name.lower())

    def _archive_priority(self, archive_path: Path) -> int:
        lower_name = archive_path.name.lower()
        for index, suffix in enumerate(SUPPORTED_ARCHIVE_SUFFIXES):
            if lower_name.endswith(suffix):
                return index
        return len(SUPPORTED_ARCHIVE_SUFFIXES)

    def _is_supported_archive(self, path: Path) -> bool:
        if not path.is_file():
            return False
        lower_name = path.name.lower()
        return any(lower_name.endswith(suffix) for suffix in SUPPORTED_ARCHIVE_SUFFIXES)

    def _archive_base_name(self, path: Path) -> str:
        lower_name = path.name.lower()
        for suffix in SUPPORTED_ARCHIVE_SUFFIXES:
            if lower_name.endswith(suffix):
                return path.name[: -len(suffix)]
        return path.stem

    def _extract_archive(self, archive_path: Path) -> Path:
        archive_path = archive_path.resolve()
        extract_root = archive_path.parent / self._archive_base_name(archive_path)
        strip_prefix = self._common_archive_prefix(archive_path)
        if extract_root.exists():
            shutil.rmtree(extract_root)
        extract_root.mkdir(parents=True, exist_ok=True)

        lower_name = archive_path.name.lower()
        if lower_name.endswith((".whl", ".zip")):
            self._extract_zip_archive(archive_path, extract_root, strip_prefix)
        else:
            self._extract_tar_archive(archive_path, extract_root, strip_prefix)
        return extract_root

    def _extract_tar_archive(self, archive_path: Path, extract_root: Path, strip_prefix: str | None) -> None:
        resolved_root = extract_root.resolve()
        with tarfile.open(archive_path) as archive:
            for member in archive.getmembers():
                member_name = self._normalize_archive_member_name(member.name, strip_prefix)
                if not member_name or member.issym() or member.islnk() or member.isdev():
                    continue
                destination = (extract_root / member_name).resolve()
                if not destination.is_relative_to(resolved_root):
                    raise ValueError(f"Unsafe archive member path detected in {archive_path}: {member_name}")
                if member.isdir():
                    destination.mkdir(parents=True, exist_ok=True)
                    continue
                source = archive.extractfile(member)
                if source is None:
                    continue
                destination.parent.mkdir(parents=True, exist_ok=True)
                with source, destination.open("wb") as handle:
                    shutil.copyfileobj(source, handle)

    def _extract_zip_archive(self, archive_path: Path, extract_root: Path, strip_prefix: str | None) -> None:
        resolved_root = extract_root.resolve()
        with zipfile.ZipFile(archive_path) as archive:
            for member in archive.infolist():
                member_name = self._normalize_archive_member_name(member.filename, strip_prefix)
                if not member_name:
                    continue
                destination = (extract_root / member_name).resolve()
                if not destination.is_relative_to(resolved_root):
                    raise ValueError(f"Unsafe archive member path detected in {archive_path}: {member_name}")
                if member.is_dir():
                    destination.mkdir(parents=True, exist_ok=True)
                    continue
                destination.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(member) as source, destination.open("wb") as handle:
                    shutil.copyfileobj(source, handle)

    def _load_archive_source_map(self, archive_path: Path) -> dict[str, str]:
        strip_prefix = self._common_archive_prefix(archive_path)
        lower_name = archive_path.name.lower()
        if lower_name.endswith((".whl", ".zip")):
            return self._load_zip_source_map(archive_path, strip_prefix)
        return self._load_tar_source_map(archive_path, strip_prefix)

    def _load_tar_source_map(self, archive_path: Path, strip_prefix: str | None) -> dict[str, str]:
        source_map: dict[str, str] = {}
        with tarfile.open(archive_path) as archive:
            for member in archive.getmembers():
                member_name = self._normalize_archive_member_name(member.name, strip_prefix)
                if not member.isfile() or not member_name or not member_name.endswith(".py"):
                    continue
                source = archive.extractfile(member)
                if source is None:
                    continue
                text = source.read().decode("utf-8", errors="replace")
                source_map[member_name] = text
        return source_map

    def _load_zip_source_map(self, archive_path: Path, strip_prefix: str | None) -> dict[str, str]:
        source_map: dict[str, str] = {}
        with zipfile.ZipFile(archive_path) as archive:
            for member in archive.infolist():
                member_name = self._normalize_archive_member_name(member.filename, strip_prefix)
                if member.is_dir() or not member_name or not member_name.endswith(".py"):
                    continue
                with archive.open(member) as source:
                    text = source.read().decode("utf-8", errors="replace")
                source_map[member_name] = text
        return source_map

    def _common_archive_prefix(self, archive_path: Path) -> str | None:
        lower_name = archive_path.name.lower()
        if lower_name.endswith((".whl", ".zip")):
            names = self._zip_member_names(archive_path)
        else:
            names = self._tar_member_names(archive_path)
        normalized = [name for name in names if name]
        if not normalized:
            return None
        first_parts = {name.split("/", maxsplit=1)[0] for name in normalized}
        if len(first_parts) != 1:
            return None
        prefix = next(iter(first_parts))
        if all(name == prefix for name in normalized):
            return None
        return prefix

    def _tar_member_names(self, archive_path: Path) -> list[str]:
        with tarfile.open(archive_path) as archive:
            return [
                normalized
                for member in archive.getmembers()
                if (normalized := self._normalize_archive_member_name(member.name, None))
            ]

    def _zip_member_names(self, archive_path: Path) -> list[str]:
        with zipfile.ZipFile(archive_path) as archive:
            return [
                normalized
                for member in archive.infolist()
                if (normalized := self._normalize_archive_member_name(member.filename, None))
            ]

    def _normalize_archive_member_name(self, member_name: str, strip_prefix: str | None) -> str:
        normalized = member_name.replace("\\", "/").lstrip("./")
        if not normalized:
            return ""
        if strip_prefix:
            prefix_with_slash = f"{strip_prefix}/"
            if normalized == strip_prefix:
                return ""
            if normalized.startswith(prefix_with_slash):
                normalized = normalized[len(prefix_with_slash) :]
        return normalized

    def _lookup_archive_sources(self, scan_root: Path) -> dict[str, str] | None:
        for extract_root, source_map in self._archive_source_cache.items():
            if scan_root == extract_root:
                return dict(source_map)
            if not scan_root.is_relative_to(extract_root):
                continue
            prefix = scan_root.relative_to(extract_root).as_posix()
            if not prefix:
                return dict(source_map)
            scoped: dict[str, str] = {}
            prefix_with_slash = f"{prefix}/"
            for relative_path, source in source_map.items():
                if relative_path == prefix:
                    continue
                if not relative_path.startswith(prefix_with_slash):
                    continue
                scoped[relative_path[len(prefix_with_slash) :]] = source
            return scoped
        return None

    def _parse_source(self, source: str, file_path: Path) -> tuple[ast.Module | None, str | None]:
        try:
            return ast.parse(source, filename=str(file_path)), None
        except SyntaxError as exc:
            line_info = f"line {exc.lineno}" if exc.lineno else "unknown line"
            return None, f"syntax_error: {line_info}: {exc.msg}"

    def _read_source(self, file_path: Path) -> tuple[str | None, str | None]:
        try:
            return file_path.read_text(encoding="utf-8"), None
        except UnicodeDecodeError:
            return file_path.read_text(encoding="utf-8", errors="replace"), None
        except OSError as exc:
            return None, f"read_error: {type(exc).__name__}: {exc}"

    def _record_skipped_source(self, scan_root: Path, file_path: Path, reason: str) -> None:
        relative_path: str
        folder: str
        try:
            relative = file_path.relative_to(scan_root)
            relative_path = relative.as_posix()
            folder = relative.parent.as_posix() or "."
        except ValueError:
            relative_path = file_path.as_posix()
            folder = file_path.parent.as_posix() or "."
        self.last_skipped_sources.append(
            SkippedSource(
                path=relative_path,
                name=file_path.name,
                folder=folder,
                reason=reason,
            )
        )

    def _default_output_base(self, requested_root: Path) -> Path:
        if requested_root.is_file():
            return requested_root.parent
        return requested_root

    def _default_stub_base_name(self, requested_root: Path) -> str:
        if requested_root.is_file():
            return self._archive_base_name(requested_root)
        return requested_root.name

    def _should_skip_dir(self, path: Path) -> bool:
        lowered = path.name.lower()
        if lowered in SKIPPED_DIRECTORY_NAMES:
            return True
        if lowered.startswith("generated"):
            return True
        if lowered.startswith("generated_stubs"):
            return True
        if lowered.endswith(".egg-info"):
            return True
        if lowered.startswith(".ddg"):
            return True
        return False

    def _should_skip_file(self, path: Path) -> bool:
        return self._is_generated_stub_file(path.name)

    def _is_generated_stub_file(self, name: str) -> bool:
        lowered = name.lower()
        return lowered.endswith("_single_stub.py") or lowered.endswith("_final_single_stub.py")

    def _dedupe_paths(self, paths: list[Path]) -> list[Path]:
        unique: list[Path] = []
        seen: set[Path] = set()
        for item in paths:
            if item in seen:
                continue
            seen.add(item)
            unique.append(item)
        return unique

    def _sanitize_name(self, value: str) -> str:
        sanitized = re.sub(r"[^0-9A-Za-z_]+", "_", value).strip("_")
        return sanitized or "project"
