"""
项目级DDG构建器 V7 - 主入口

DDG V7 - 完整安全分析版

整合功能:
- V4: CFG 增强分析
- V6: 安全检测
- V6.1: 供应链攻击检测
- V7: 分层分析 (小文件完整DDG + 大文件快速扫描)

使用方法:
    python main.py <project_directory> [--v7]

示例:
    python main.py C:/my_project
    python main.py C:/my_project --v7
"""

import sys
import json
import io
from pathlib import Path

# 设置标准输出编码为 UTF-8（处理 Windows 中文问题）
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

# 添加 src 目录到路径
sys.path.insert(0, str(Path(__file__).parent / 'src'))

# 导入 V7 组件
from src.ddg_builder_v7 import ProjectDDGBuilderV7, ProjectSymbolTable, GlobalNode, GlobalEdge
from src.visualizer_v7 import VisualizerV7

# 导入统一的图分割模块
from src.common import GraphPartitioner, PartitionConfig, partition_graph


def main():
    # 解析命令行参数
    use_v7 = '--v7' in sys.argv or '-v7' in sys.argv or '--V7' in sys.argv
    project_dir = None  # 初始化变量

    try:
        # 如果没有命令行参数，则交互式输入
        if len(sys.argv) < 2 or (len(sys.argv) == 2 and sys.argv[1] in ['--v7', '-v7', '--V7']):
            print("=" * 50)
            print("  DDG Builder V7 - Project Security Analyzer")
            print("  Layered Analysis: Full DDG + Fast Scan")
            print("=" * 50)
            print()

            while True:
                project_dir = input("Enter project path: ").strip().strip('"').strip("'")

                if not project_dir:
                    print("Error: Path cannot be empty, please try again")
                    continue

                if not Path(project_dir).exists():
                    print(f"Error: Directory does not exist: {project_dir}")
                    print("Please try again")
                    continue

                break
        else:
            # 从命令行参数获取路径
            for arg in sys.argv[1:]:
                if not arg.startswith('-'):
                    project_dir = arg
                    break

        # 检查是否获取到有效路径
        if project_dir is None or not Path(project_dir).exists():
            print(f"Error: Directory '{project_dir}' does not exist.")
            input("\nPress Enter to exit...")
            sys.exit(1)

        # 构建 V7 DDG
        print("\n[Analysis] Building DDG V7...")
        builder = ProjectDDGBuilderV7(project_dir)
        result = builder.build()

        # 输出结果
        output_dir = Path(project_dir) / '.ddg_output'
        output_dir.mkdir(exist_ok=True)

        # 保存节点
        nodes_file = output_dir / 'nodes.json'
        nodes_data = {}
        for key, node in result['nodes'].items():
            node_dict = {
                'file': node.file,
                'line': node.line,
                'type': node.type,
                'source': node.source,
                # ✅ 新增：记录函数和类信息
                'function_name': getattr(node, 'function_name', None),
                'class_name': getattr(node, 'class_name', None)
            }
            nodes_data[f"{key[0]}_{key[1]}"] = node_dict

        with open(nodes_file, 'w', encoding='utf-8') as f:
            json.dump(nodes_data, f, indent=2, ensure_ascii=False)
        print(f"\n[Output] Nodes saved to: {nodes_file}")

        # 保存边
        edges_file = output_dir / 'edges.json'
        with open(edges_file, 'w', encoding='utf-8') as f:
            edges_data = [edge.to_dict() for edge in result['edges']]
            json.dump(edges_data, f, indent=2, ensure_ascii=False)
        print(f"[Output] Edges saved to: {edges_file}")

        # 保存符号表
        symbol_file = output_dir / 'symbols.json'
        with open(symbol_file, 'w', encoding='utf-8') as f:
            functions_data = {}
            for k, v in result['symbol_table'].functions.items():
                functions_data[f"{k[0]}:{k[1]}"] = {
                    'file': v['file'],
                    'name': v['name'],
                    'short_name': v['short_name'],
                    'line': v['line'],
                    'params': v['params'],
                    'class': v['class']
                }
            classes_data = {}
            for k, v in result['symbol_table'].classes.items():
                classes_data[f"{k[0]}:{k[1]}"] = {
                    'file': v['file'],
                    'name': v['name'],
                    'line': v['line'],
                    'attributes': list(v.get('attributes', set()))
                }
            symbols = {
                'functions': functions_data,
                'classes': classes_data
            }
            json.dump(symbols, f, indent=2, ensure_ascii=False)
        print(f"[Output] Symbols saved to: {symbol_file}")

        # 保存快速扫描结果
        if result.get('fast_scan_results'):
            scan_file = output_dir / 'fast_scan_results.json'
            with open(scan_file, 'w', encoding='utf-8') as f:
                json.dump(result['fast_scan_results'], f, indent=2, ensure_ascii=False)
            print(f"[Output] Fast scan results saved to: {scan_file}")

        # 保存安全报告
        if result.get('security_report'):
            security_file = output_dir / 'security_report.json'
            with open(security_file, 'w', encoding='utf-8') as f:
                json.dump(result['security_report'], f, indent=2, ensure_ascii=False)
            print(f"[Output] Security report saved to: {security_file}")

        print("\n[Done] DDG V7 analysis complete!")

        # ============ 新增：统一的图分割 ============
        print(f"\n[Partition] Performing graph partition...")

        # 检查是否有 NetworkX 图
        if result.get('nx_graph'):
            # 直接使用内存中的 NetworkX 图（推荐方式）
            nx_graph = result['nx_graph']

            # 创建分割配置
            config = PartitionConfig(
                max_nodes=500,           # 最大节点数
                max_depth=10,            # 最大深度
                timeout=30,              # 30秒超时
                max_iterations=10000,    # 最大迭代次数
                verbose=True
            )

            # 创建分割器并执行分割
            partitioner = GraphPartitioner(nx_graph, config)

            # 检测命令行参数选择分割方法
            partition_method = 'hybrid'  # 默认使用hybrid模式
            if '--partition-wcc' in sys.argv:
                partition_method = 'wcc'
                print(f"  [Partition] Using WCC method (Weakly Connected Components)")
            elif '--partition-bfs' in sys.argv:
                partition_method = 'bfs'
                print(f"  [Partition] Using BFS method (Bidirectional Data Flow)")
            elif '--partition-hybrid' in sys.argv or True:  # 默认hybrid
                partition_method = 'hybrid'
                print(f"  [Partition] Using HYBRID method (WCC + BFS)")
                print(f"  [Partition] Strategy: WCC splits large components, then BFS truncates oversized subgraphs")

            print(f"  [Partition] Max nodes per subgraph: {config.max_nodes}")

            # 执行分割
            subgraphs = partitioner.partition(method=partition_method)

            # 保存分割结果
            if subgraphs:
                sub_output_dir = output_dir / 'sub_ddgs'
                saved_files = partitioner.save_results(subgraphs, sub_output_dir, method=partition_method)
                print(f"\n[Partition] Saved {len(subgraphs)} subgraphs to: {sub_output_dir}")

                # ============ 新增：生成测试脚本 ============
                try:
                    from src.simple_stub_generator import SimpleStubGenerator

                    print(f"\n[Test Generation] Generating executable test stubs...")
                    print(f"[Test Generation] Original package: {project_dir}")
                    print(f"[Test Generation] Subgraphs directory: {sub_output_dir}")

                    # 使用新的简单生成器
                    test_results = SimpleStubGenerator.generate_all_stubs(
                        str(sub_output_dir),
                        str(project_dir),  # 原包目录
                        verbose=True
                    )

                    # 保存测试脚本生成统计
                    stats_file = sub_output_dir / 'test_generation_stats.json'
                    with open(stats_file, 'w', encoding='utf-8') as f:
                        json.dump(test_results, f, indent=2, ensure_ascii=False)
                    print(f"\n[Test Generation] Stats saved to: {stats_file}")

                    # 打印摘要
                    print(f"\n[Test Generation] Summary:")
                    print(f"  Total subgraphs: {test_results['total']}")
                    print(f"  Successfully generated: {test_results['success']}")
                    print(f"  Failed: {test_results['failed']}")

                except Exception as e:
                    print(f"\n[WARNING] Test script generation failed: {e}")
                    print("[INFO] DDG analysis completed successfully, but test scripts were not generated")
                    import traceback
                    traceback.print_exc()
            else:
                print(f"\n[Partition] No dangerous subgraphs found")

        # 生成可视化
        print(f"\n[Visualization] Generating V7 graphs...")
        viz = VisualizerV7(str(output_dir))

        # 生成所有可视化 (包括大文件的.dot)
        viz_files = viz.visualize_all(result, project_dir)

        print(f"\n[Visualization] Complete!")
        for name, path in viz_files.items():
            print(f"  {name}: {path}")

        html_file = viz_files.get('security_report', 'N/A')
        print(f"\n  To view: Open {html_file} in your browser")

    except Exception as e:
        print(f"\n[Error] {e}")
        import traceback
        traceback.print_exc()

    # 防止窗口闪退
    print("\nPress Enter to exit...")
    input()


if __name__ == '__main__':
    main()
