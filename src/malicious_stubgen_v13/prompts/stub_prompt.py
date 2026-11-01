from __future__ import annotations

from malicious_stubgen_v13.models import AnalysisResult


def build_stub_generation_prompt(analysis: AnalysisResult) -> str:
    sensitive_api_text = ", ".join(analysis.subgraph.sensitive_apis) or "unknown"
    package_init = analysis.package_init_context or "<missing __init__.py>"
    candidate_lines: list[str] = []
    for index, entry in enumerate(analysis.entry_points, start=1):
        candidate_lines.append(
            f"{index}. kind={entry.kind}, trigger={entry.trigger_expression}, confidence={entry.confidence:.2f}"
        )
        candidate_lines.append(f"   reasoning={entry.reasoning}")
    candidate_block = "\n".join(candidate_lines)
    return (
        "你是一个 Python 恶意代码动态分析辅助器。目标是在不修改原始恶意包内容的前提下，"
        "为当前疑似恶意子图编写一个可运行的桩程序。\n\n"
        "要求：\n"
        "1. 原始恶意包文件不能改动。\n"
        "2. 桩程序放在恶意包解压目录外层或同级分析目录中运行。\n"
        "3. 只做最小驱动，优先触发疑似恶意代码。\n"
        "4. 如果首选入口点不稳，可以输出备选触发方式。\n"
        "5. 输出完整 Python 代码，并简要解释为什么这样触发。\n\n"
        f"子图编号：{analysis.subgraph.subgraph_id}\n"
        f"包名：{analysis.subgraph.package_name}\n"
        f"模块路径：{analysis.subgraph.module_path}\n"
        f"模块限定名：{analysis.module_qualname}\n"
        f"敏感 API：{sensitive_api_text}\n"
        f"可疑行范围：{analysis.subgraph.start_line}-{analysis.subgraph.end_line}\n\n"
        "规则推断出的候选入口点：\n"
        f"{candidate_block}\n\n"
        "可疑模块上下文：\n"
        f"{analysis.module_context}\n\n"
        "所在包级 __init__.py 内容：\n"
        f"{package_init}\n\n"
        "请先判断最可能的入口点，再输出最终桩程序。"
    )
