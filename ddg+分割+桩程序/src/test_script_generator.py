"""
测试脚本生成器 - 集成到 V7 主流程

功能：在 DDG 分析完成后，自动为每个子图生成测试脚本
"""

import sys
import os
from pathlib import Path

# 添加 ddg_test_generator 到路径
test_gen_path = Path(__file__).parent.parent.parent / 'ddg_test_generator'
sys.path.insert(0, str(test_gen_path))

from ddg_parser import DDGParser
from module_extractor import ModuleInfoExtractor
from test_generator import TestScriptGenerator
from readme_generator import ReadmeGenerator


def generate_test_scripts_for_subgraphs(sub_ddgs_dir: str, verbose: bool = False) -> dict:
    """
    为所有子图生成测试脚本

    Args:
        sub_ddgs_dir: 子图目录路径 (.ddg_output/sub_ddgs)
        verbose: 是否显示详细输出

    Returns:
        统计信息字典
    """
    print("\n" + "=" * 70)
    print("  测试脚本生成器")
    print("=" * 70)
    print(f"\n[*] 子图目录: {sub_ddgs_dir}")

    # 查找所有子图
    subgraph_dirs = find_all_subgraphs(sub_ddgs_dir)

    if not subgraph_dirs:
        print("[ERROR] 未找到任何 DDG 子图")
        return {'total': 0, 'success': 0, 'failed': 0}

    print(f"[*] 找到 {len(subgraph_dirs)} 个子图\n")

    success_count = 0
    fail_count = 0
    results = []

    # 处理每个子图
    for i, subgraph_dir in enumerate(subgraph_dirs, 1):
        print(f"\n{'=' * 70}")
        print(f"  处理子图 {i}/{len(subgraph_dirs)}")
        print(f"  子图: {Path(subgraph_dir).name}")
        print(f"{'=' * 70}")

        # 在子图目录下创建 extracted_test 子目录
        output_dir = os.path.join(subgraph_dir, 'extracted_test')

        try:
            result = process_single_subgraph(subgraph_dir, output_dir, verbose)
            if result == 0:
                success_count += 1
                results.append({
                    'subgraph': Path(subgraph_dir).name,
                    'status': 'success',
                    'output_dir': output_dir
                })
            else:
                fail_count += 1
                results.append({
                    'subgraph': Path(subgraph_dir).name,
                    'status': 'failed',
                    'error': '处理失败'
                })
        except Exception as e:
            print(f"\n[ERROR] 处理子图 {Path(subgraph_dir).name} 失败: {e}")
            if verbose:
                import traceback
                traceback.print_exc()
            fail_count += 1
            results.append({
                'subgraph': Path(subgraph_dir).name,
                'status': 'failed',
                'error': str(e)
            })

    # 汇总
    print("\n" + "=" * 70)
    print("  测试脚本生成完成")
    print("=" * 70)
    print(f"\n总子图数: {len(subgraph_dirs)}")
    print(f"成功: {success_count}")
    print(f"失败: {fail_count}")
    print(f"\n输出位置:")
    print(f"  每个子图目录下的 extracted_test/ 子目录")
    print(f"  例如: {sub_ddgs_dir}/001_xxx/extracted_test/")
    print("=" * 70)

    return {
        'total': len(subgraph_dirs),
        'success': success_count,
        'failed': fail_count,
        'results': results
    }


def process_single_subgraph(subgraph_dir: str, output_dir: str, verbose: bool = False) -> int:
    """处理单个 DDG 子图"""
    # 步骤 1：解析 DDG 子图
    if verbose:
        print("\n[步骤 1] 解析 DDG 子图")
    ddg_parser = DDGParser(subgraph_dir)
    ddg_data = ddg_parser.parse()

    # 步骤 2：提取模块信息
    if verbose:
        print("\n[步骤 2] 提取模块信息")
    module_extractor = ModuleInfoExtractor(ddg_data['main_file'])
    module_info = module_extractor.extract()

    # 步骤 3：创建输出目录
    if verbose:
        print("\n[步骤 3] 创建输出目录")
    os.makedirs(output_dir, exist_ok=True)
    if verbose:
        print(f"[OK] 输出目录已创建: {output_dir}")

    # 步骤 4：生成测试脚本
    if verbose:
        print("\n[步骤 4] 生成测试脚本")
    test_generator = TestScriptGenerator()
    test_script_content = test_generator.generate(ddg_data, module_info)

    test_script_path = os.path.join(output_dir, 'test_ddg_results.py')
    with open(test_script_path, 'w', encoding='utf-8') as f:
        f.write(test_script_content)

    if verbose:
        print(f"[OK] 测试脚本已生成: test_ddg_results.py")

    # 步骤 5：生成 README 文档
    if verbose:
        print("\n[步骤 5] 生成 README 文档")
    readme_generator = ReadmeGenerator()
    readme_content = readme_generator.generate(ddg_data, module_info)

    readme_path = os.path.join(output_dir, 'README.md')
    with open(readme_path, 'w', encoding='utf-8') as f:
        f.write(readme_content)

    if verbose:
        print(f"[OK] README 文档已生成: README.md")

    # 步骤 6：保存元数据
    if verbose:
        print("\n[步骤 6] 保存元数据")
    import json
    import datetime
    metadata = {
        'generation_time': datetime.datetime.now().isoformat(),
        'subgraph_id': ddg_data['subgraph_id'],
        'subgraph_dir': subgraph_dir,
        'output_dir': output_dir,
        'module_info': module_info,
        'statistics': ddg_data['statistics'],
        'dangerous_functions': [
            {
                'name': f['name'],
                'line': f['line'],
                'node_count': f['node_count']
            }
            for f in ddg_data['dangerous_functions']
        ]
    }

    metadata_path = os.path.join(output_dir, 'metadata.json')
    with open(metadata_path, 'w', encoding='utf-8') as f:
        json.dump(metadata, f, indent=2, ensure_ascii=False)

    if verbose:
        print(f"[OK] 元数据已保存: metadata.json")

    return 0


def find_all_subgraphs(subgraph_root_dir: str) -> list:
    """查找所有 DDG 子图目录"""
    subgraph_dirs = []

    for root, dirs, files in os.walk(subgraph_root_dir):
        # 检查是否包含 nodes.json 和 edges.json
        if 'nodes.json' in files and 'edges.json' in files:
            subgraph_dirs.append(root)

    return sorted(subgraph_dirs)
