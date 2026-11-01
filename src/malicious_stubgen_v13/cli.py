from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
from typing import Any

from malicious_stubgen_v13.input_loader import load_task
from malicious_stubgen_v13.pipeline import StubGenerationPipeline
from malicious_stubgen_v13.scanner import SuspiciousProjectScanner


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="malstub-v13",
        description="Generate a final runnable stub for a suspicious Python package.",
    )
    parser.add_argument("input", type=Path, help="Path to a task JSON file or a package project directory.")
    parser.add_argument(
        "--output-dir",
        type=Path,
        help="Directory for manifests and optional debug artifacts when scanning a project directory directly.",
    )
    parser.add_argument(
        "--final-stub",
        type=Path,
        help="Base path of the final stub file(s) when scanning a project directory directly.",
    )
    parser.add_argument(
        "--print-manifest",
        action="store_true",
        help="Print the generated manifest to stdout after generation.",
    )
    parser.add_argument(
        "--emit-debug-artifacts",
        action="store_true",
        help="Write per-subgraph candidate stubs into the output directory.",
    )
    parser.add_argument(
        "--include-llm-payload",
        action="store_true",
        help="Also write llm_payload_*.json and llm_prompt_*.md files. Implies --emit-debug-artifacts.",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    pipeline = StubGenerationPipeline()
    manifest = _run_from_cli(
        pipeline,
        args.input,
        args.output_dir,
        args.final_stub,
        emit_debug_artifacts=args.emit_debug_artifacts,
        include_llm_payload=args.include_llm_payload,
    )
    if args.print_manifest:
        print(json.dumps(manifest, indent=2, ensure_ascii=False))
    return 0


def _run_from_cli(
    pipeline: StubGenerationPipeline,
    input_path: Path,
    output_dir: Path | None,
    final_stub: Path | None,
    *,
    emit_debug_artifacts: bool = False,
    include_llm_payload: bool = False,
) -> dict[str, Any]:
    input_path = input_path.resolve()
    scanner = SuspiciousProjectScanner()
    if input_path.is_file() and scanner.is_supported_archive(input_path):
        task = scanner.scan(
            package_root=input_path,
            output_dir=output_dir.resolve() if output_dir else None,
            final_stub_path=final_stub.resolve() if final_stub else None,
        )
        return pipeline.run(_apply_debug_options(task, emit_debug_artifacts, include_llm_payload))
    if input_path.is_dir():
        project_roots = scanner.discover_project_roots(input_path)
        if output_dir:
            resolved_output = output_dir.resolve()
            if resolved_output.is_relative_to(input_path):
                project_roots = [
                    path
                    for path in project_roots
                    if path != resolved_output and not path.is_relative_to(resolved_output)
                ]
        if not project_roots:
            raise ValueError(f"No scannable Python projects found under {input_path}")
        if len(project_roots) == 1:
            task = scanner.scan(
                package_root=project_roots[0],
                output_dir=output_dir.resolve() if output_dir else None,
                final_stub_path=final_stub.resolve() if final_stub else None,
            )
            return pipeline.run(_apply_debug_options(task, emit_debug_artifacts, include_llm_payload))
        return _run_collection(
            pipeline,
            scanner,
            input_path,
            project_roots,
            output_dir,
            final_stub,
            emit_debug_artifacts=emit_debug_artifacts,
            include_llm_payload=include_llm_payload,
        )
    task = load_task(input_path)
    return pipeline.run(_apply_debug_options(task, emit_debug_artifacts, include_llm_payload))


def _run_collection(
    pipeline: StubGenerationPipeline,
    scanner: SuspiciousProjectScanner,
    collection_root: Path,
    project_roots: list[Path],
    output_dir: Path | None,
    final_stub: Path | None,
    *,
    emit_debug_artifacts: bool = False,
    include_llm_payload: bool = False,
) -> dict[str, Any]:
    manifests: list[dict[str, Any]] = []
    skipped_projects: list[dict[str, Any]] = []
    resolved_output = output_dir.resolve() if output_dir else None
    resolved_final_stub = final_stub.resolve() if final_stub else None
    for project_root in project_roots:
        project_label = _project_label(collection_root, project_root)
        task_output_dir = (resolved_output / project_label) if resolved_output else None
        try:
            task = scanner.scan(
                package_root=project_root,
                output_dir=task_output_dir,
                final_stub_path=None,
            )
        except ValueError as exc:
            skipped_projects.append(
                {
                    "project_root": str(project_root),
                    "folder": str(project_root.parent),
                    "name": project_root.name,
                    "reason": str(exc),
                    "skipped_file_count": len(scanner.last_skipped_sources),
                    "skipped_files": [item.to_dict() for item in scanner.last_skipped_sources],
                }
            )
            continue
        if resolved_final_stub:
            task.final_stub_path = task.package_root / resolved_final_stub.name
        manifest = pipeline.run(_apply_debug_options(task, emit_debug_artifacts, include_llm_payload))
        manifest["project_root"] = str(project_root)
        manifest["project_name"] = project_root.name
        manifest["project_folder"] = str(project_root.parent)
        manifests.append(manifest)
    return {
        "collection_root": str(collection_root),
        "project_count": len(manifests),
        "skipped_project_count": len(skipped_projects),
        "skipped_projects": skipped_projects,
        "projects": manifests,
    }


def _project_label(collection_root: Path, project_root: Path) -> str:
    relative = project_root.relative_to(collection_root).as_posix()
    normalized = re.sub(r"(?i)(\.tar\.gz|\.tgz|\.tar|\.whl|\.zip)$", "", relative)
    normalized = normalized.replace("/", "__")
    return re.sub(r"[^0-9A-Za-z._]+", "_", normalized).strip("_")


def _apply_debug_options(
    task: Any,
    emit_debug_artifacts: bool,
    include_llm_payload: bool,
) -> Any:
    task.emit_debug_artifacts = task.emit_debug_artifacts or emit_debug_artifacts or include_llm_payload
    task.include_llm_payload = task.include_llm_payload or include_llm_payload
    task.use_deepseek = False
    return task


if __name__ == "__main__":
    raise SystemExit(main())
