"""
可视化器 V7 - 完整安全分析版

V7 整合所有之前版本的可视化功能:
- V4: 基础 DDG + CFG 可视化
- V5: 改进布局 + 危险检测
- V6: 安全检测可视化
- V6.1: 供应链攻击检测 + 上下文感知
- V7新增: 分层分析结果可视化 + 外部字典模式匹配
"""

import os
import re
import json
import hashlib
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Set
from collections import defaultdict

# 导入统一的危险模式检测器
from .common.pattern_matcher import DangerPatternLoader


class VisualizerV7:
    """V7 可视化器 - 完整安全分析可视化"""

    # V5: 危险函数/操作模式
    DANGEROUS_PATTERNS = [
        r'\bexec\s*\(',
        r'\beval\s*\(',
        r'\bcompile\s*\(',
        r'\b__import__\s*\(',
        r'\bgetattr\s*\(',
        r'\bsetattr\s*\(',
        r'\bdelattr\s*\(',
        r'\bopen\s*\(',
        r'\bPopen\s*\(',
        r'\bsubprocess\.',
        r'\bos\.system',
        r'\bbase64\.',
        r'\bFernet\s*\(',
    ]

    # V5 增强颜色方案
    COLORS = {
        'node': {
            'function': '#FFF9C4',      # 浅黄 - 函数定义
            'call': '#E1BEE7',          # 浅紫 - 函数调用
            'statement': '#FFFFFF',     # 白 - 普通语句
            'import': '#B3E5FC',        # 浅蓝 - import
            'attribute': '#D1C4E9',     # 浅紫 - 属性访问
            'if': '#FFE0B2',            # 浅橙 - if条件
            'for': '#C5E1A5',           # 浅绿 - for循环
            'while': '#FFCCBC',         # 浅橙红 - while循环
            'return': '#F8BBD0',        # 浅粉 - return
            'class': '#FFAB91',         # 橙色 - 类定义
            'subscript': '#C5CAE9',     # 靛青 - 索引访问
            'try': '#E1BEE7',           # 紫色 - try-except
            # V5 新增：危险操作
            'dangerous': '#FF5252',     # 红色 - 危险操作
            'suspicious': '#FFAB40',    # 橙红 - 可疑操作
        },
        'edge': {
            'cross_file_return': '#43A047',    # 深绿 - 跨文件返回
            'cross_file_call': '#1E88E5',      # 深蓝 - 跨文件调用
            'true_branch': '#FB8C00',          # 橙色 - 真分支
            'false_branch': '#E53935',         # 红色 - 假分支
            'loop_body': '#8E24AA',            # 紫色 - 循环体
            'param_flow': '#00ACC1',           # 青色 - 参数传递
            'intra_file': '#616161',           # 灰色 - 文件内依赖
            # V5 新增
            'dangerous_flow': '#D32F2F',       # 深红 - 危险数据流
            'return_flow': '#2E7D32',          # 绿色 - 返回值流
        },
        'file_bg': ['#E3F2FD', '#C8E6C9', '#FFCDD2', '#FFF9C4', '#E1BEE7', '#D1C4E9', '#B2DFDB'],
    }

    def __init__(self, output_dir: str, patterns_file: Optional[str] = None):
        self.output_dir = Path(output_dir)
        self.dot_dir = self.output_dir / 'dot'
        self.png_dir = self.output_dir / 'png'
        self.svg_dir = self.output_dir / 'svg'
        self.html_dir = self.output_dir / 'html'
        self.dot_dir.mkdir(parents=True, exist_ok=True)
        self.png_dir.mkdir(parents=True, exist_ok=True)
        self.svg_dir.mkdir(parents=True, exist_ok=True)
        self.html_dir.mkdir(parents=True, exist_ok=True)

        # 【新增】加载危险模式字典（复用 graph_partitioner_v7 逻辑）
        self.pattern_loader = DangerPatternLoader(patterns_file)

    def _is_dangerous_node(self, node) -> tuple:
        """检测节点是否包含危险操作（使用外部字典模式）"""
        source = getattr(node, 'source', '')
        node_type = getattr(node, 'type', '')

        # 【新增】使用外部字典模式检测
        pattern_result = self.pattern_loader.check_node(source, node_type)
        if pattern_result:
            severity = pattern_result['severity']
            reason = pattern_result['category']
            if severity == 'critical':
                return 'dangerous', reason
            elif severity == 'high':
                return 'dangerous', reason
            elif severity == 'medium':
                return 'suspicious', reason
            else:
                return 'suspicious', reason

        # 后备：使用内置模式检测
        danger_level = 'none'
        reason = ''

        for pattern in self.DANGEROUS_PATTERNS:
            if re.search(pattern, source):
                if 'exec' in source or 'eval' in source or 'compile' in source:
                    danger_level = 'dangerous'
                    reason = 'code_execution'
                    break
                elif 'Fernet' in source or 'base64' in source:
                    danger_level = 'suspicious'
                    reason = 'obfuscation'
                elif 'subprocess' in source or 'Popen' in source or 'os.system' in source:
                    danger_level = 'dangerous'
                    reason = 'command_execution'
                elif '__import__' in source or 'getattr' in source:
                    danger_level = 'suspicious'
                    reason = 'dynamic_import'
                else:
                    danger_level = 'suspicious'
                    reason = 'file_operation'

        return danger_level, reason

    def _get_node_color(self, node) -> str:
        """V5: 获取节点颜色（考虑危险级别）"""
        danger_level, _ = self._is_dangerous_node(node)
        if danger_level == 'dangerous':
            return self.COLORS['node']['dangerous']
        elif danger_level == 'suspicious':
            return self.COLORS['node']['suspicious']
        else:
            return self.COLORS['node'].get(node.type, '#FFFFFF')

    def visualize_all(self, result: Dict, project_dir: str) -> Dict:
        """生成所有可视化"""
        viz_files = {}

        # 【修复】计算项目总行数（包括小文件和大文件）
        total_lines = 0

        # 统计小文件行数
        small_files = result.get('small_files', [])
        if small_files:
            for file_path in small_files:
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        total_lines += sum(1 for _ in f)
                except:
                    pass

        # 统计大文件行数
        fast_scan_results = result.get('fast_scan_results', {})
        total_lines += sum(r.get('line_count', 0) for r in fast_scan_results.values())

        # 1. 统一 DDG 可视化
        dot_file = self.dot_dir / 'unified_ddg_v7.dot'
        self._generate_unified_ddg(result, dot_file)
        viz_files['unified_dot'] = str(dot_file)

        # 生成 PNG (只有小项目，< 1000 行才生成PNG)
        if total_lines < 1000:
            print(f"  Generating PNG (project size: {total_lines} lines)...")
            png_file = self._generate_png(dot_file, 'unified_ddg_v7.png')
            if png_file:
                viz_files['unified_png'] = str(png_file)
            else:
                print("  PNG generation failed (Graphviz not installed or timeout)")
        else:
            print(f"  Skipping PNG generation (project too large: {total_lines} lines, only .dot generated)")

        # 2. V6.1: 安全DDG - 单独提取危险节点
        security_ddg = self.dot_dir / 'security_ddg_v6_1.dot'
        self._generate_security_ddg(result, security_ddg)
        viz_files['security_ddg'] = str(security_ddg)
        # 为安全DDG生成PNG
        if total_lines < 1000:
            security_png = self._generate_png(security_ddg, 'security_ddg_v6_1.png')
            if security_png:
                viz_files['security_ddg_png'] = str(security_png)

        # 3. 为大文件生成单独的扫描结果 .dot
        for file_path, scan_result in fast_scan_results.items():
            if scan_result.get('line_count', 0) >= 3000:  # 只为大文件生成
                file_name = Path(file_path).name
                scan_dot = self.dot_dir / f'{file_name}_fast_scan.dot'
                self._generate_fast_scan_dot(file_path, scan_result, scan_dot)
                viz_files[f'{file_name}_scan_dot'] = str(scan_dot)

        # 4. 【已禁用】子图分割 - 现在使用统一的图分割器（main.py中的GraphPartitioner）
        # 不再在这里生成子图，避免重复
        # if sub_ddg_summary:
        #     viz_files['sub_ddgs'] = str(sub_ddg_dir)
        #     viz_files['sub_ddg_summary'] = str(sub_ddg_dir / 'summary.json')

        # 5. 混合视图
        hybrid_dot = self.dot_dir / 'hybrid_view.dot'
        self._generate_hybrid_view(result, hybrid_dot)

        # 6. 调用图
        call_graph_dot = self.dot_dir / 'call_graph.dot'
        self._generate_call_graph(result, call_graph_dot)

        # 7. 安全报告 HTML
        security_report = self._generate_security_report(result, project_dir)
        viz_files['security_report'] = str(security_report)

        return viz_files

    def _generate_unified_ddg(self, result: Dict, output_file: Path):
        """生成统一 DDG DOT 文件 (V5增强版)"""
        nodes = result['nodes']
        edges = result['edges']
        fast_scan_results = result.get('fast_scan_results', {})

        # 严重程度颜色
        severity_colors = {
            'critical': '#B71C1C',  # 深红
            'high': '#D32F2F',      # 红
            'medium': '#F57C00',    # 橙
            'low': '#FBC02D',       # 黄
        }

        dot_lines = [
            'digraph ProjectDDG_V7 {',
            '  rankdir=LR;',
            '  splines=spline;',
            '  overlap=scalexy;',
            '  nodesep=0.8;',
            '  ranksep=0.6;',
            '  dpi=150;',  # V5: 降低DPI避免过大文件
            '  node [shape=box, style="filled,rounded", fontname="Arial", fontsize=8];',
            '  edge [fontname="Arial", fontsize=7];',
            '  label="Data Dependence Graph V7 - Enhanced Security Analysis";',
            '  labelloc="t";',
            '  fontsize=16;',
            '  newrank=true;',
        ]

        # 按文件分组节点
        file_clusters = defaultdict(list)
        for key, node in nodes.items():
            file_clusters[node.file].append((key, node))

        # 生成子图 (V5: 危险节点优先排序)
        color_idx = 0
        for i, (file_path, file_nodes) in enumerate(sorted(file_clusters.items())):
            cluster_id = f"cluster_{i}"
            file_name = Path(file_path).name
            # 检查是否是大文件
            is_large = any(str(file_path) in fast_scan_results for _ in [None])
            bg_color = self.COLORS['file_bg'][color_idx % len(self.COLORS['file_bg'])]
            color_idx += 1

            dot_lines.append(f'  subgraph {cluster_id} {{')
            dot_lines.append(f'    label="{file_name}";')
            dot_lines.append(f'    style="filled";')
            dot_lines.append(f'    fillcolor="{bg_color}40";')
            dot_lines.append(f'    fontname="Arial:bold";')
            dot_lines.append(f'    fontsize=11;')

            # V5: 按危险级别排序节点
            def node_danger_score(item):
                node = item[1]
                danger_level, _ = self._is_dangerous_node(node)
                if danger_level == 'dangerous':
                    return 2
                elif danger_level == 'suspicious':
                    return 1
                return 0

            sorted_nodes = sorted(file_nodes, key=node_danger_score, reverse=True)

            for key, node in sorted_nodes:
                node_id = self._escape_id(f"{Path(node.file).name}_{node.line}")

                # V5: 使用更短的标签，处理中文
                source = node.source
                # 保存原始 source 用于 _source 属性
                full_source = source
                # 清理中文引号和其他特殊字符（用于 label 显示）
                source = source.replace('"', "'").replace('"', "'").replace('"', "'").replace('"', "'")
                source = source.replace('"', "'").replace('"', "'").replace('"', "'").replace('"', "'")
                # 将换行符替换为空格（用于 label）
                source = source.replace('\n', ' ').replace('\r', '').replace('\t', ' ')
                label = self._truncate_label(source, 50)

                # V5: 使用危险检测颜色
                fillcolor = self._get_node_color(node)

                # V5: 危险节点加粗边框
                danger_level, _ = self._is_dangerous_node(node)

                # 添加 _source 属性保存完整代码（用于子图提取交付给动态分析）
                if full_source:
                    # 转义特殊字符
                    source_escaped = full_source.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n')
                    source_attr = f', _source="{source_escaped}"'
                else:
                    source_attr = ''

                if danger_level == 'dangerous':
                    dot_lines.append(f'    "{node_id}" [label="{label}", fillcolor="{fillcolor}", penwidth=2.0, color="#D32F2F", fontsize=9{source_attr}];')
                elif danger_level == 'suspicious':
                    dot_lines.append(f'    "{node_id}" [label="{label}", fillcolor="{fillcolor}", penwidth=1.5, color="#FF6F00"{source_attr}];')
                else:
                    dot_lines.append(f'    "{node_id}" [label="{label}", fillcolor="{fillcolor}"{source_attr}];')

            dot_lines.append('  }')
            dot_lines.append('')

        # 生成边 (V5: 限制边的数量，增强标签)
        edge_count = 0
        for edge in edges:
            edge_count += 1
            if edge_count > 200:  # 限制边的数量
                break

            from_id = self._escape_id(f"{Path(edge.from_node.file).name}_{edge.from_node.line}")
            to_id = self._escape_id(f"{Path(edge.to_node.file).name}_{edge.to_node.line}")

            # V5: 构建增强的边标签
            label_parts = []

            # 变量名
            if edge.variable and edge.variable != 'data_flow':
                var_display = edge.variable.replace('\\n', ' ')
                if len(var_display) > 15:
                    var_display = var_display[:12] + ".."
                label_parts.append(var_display)

            # 函数上下文
            if hasattr(edge, 'function') and edge.function:
                func_short = edge.function.split('(')[0]
                if len(func_short) > 12:
                    func_short = func_short[:10] + ".."
                label_parts.append(f"@{func_short}")

            # 边类型图标
            edge_icon = ''
            if edge.type == 'cross_file_return':
                edge_icon = 'R'
            elif edge.type == 'cross_file_call':
                edge_icon = 'C'
            elif edge.variable == 'true_branch':
                edge_icon = 'T'
            elif edge.variable == 'false_branch':
                edge_icon = 'F'

            # 限制标签总长度
            if label_parts:
                label = (edge_icon + ' ' + ' | '.join(label_parts))
                if len(label) > 25:
                    label = edge_icon + ' ' + label_parts[0][:20]
            else:
                label = edge_icon

            label = self._escape_label(label)

            # V5: 边类型样式 + 危险数据流检测
            from_danger, _ = self._is_dangerous_node(edge.from_node)
            to_danger, _ = self._is_dangerous_node(edge.to_node)

            if edge.type == 'cross_file_return':
                color = self.COLORS['edge']['cross_file_return']
                penwidth = 2.0
                style = 'solid'
            elif edge.type == 'cross_file_call':
                color = self.COLORS['edge']['cross_file_call']
                penwidth = 1.8
                style = 'solid'
            elif edge.variable == 'true_branch':
                color = self.COLORS['edge']['true_branch']
                penwidth = 1.3
                style = 'solid'
            elif edge.variable == 'false_branch':
                color = self.COLORS['edge']['false_branch']
                penwidth = 1.0
                style = 'dashed'
            elif edge.variable == 'loop_body':
                color = self.COLORS['edge']['loop_body']
                penwidth = 1.3
                style = 'solid'
            elif hasattr(edge, 'arg_mappings') and edge.arg_mappings:
                color = self.COLORS['edge']['param_flow']
                penwidth = 1.8
                style = 'bold'
            else:
                color = self.COLORS['edge']['intra_file']
                penwidth = 0.8
                style = 'solid'

            # V5: 检测危险数据流
            if from_danger == 'dangerous' or to_danger == 'dangerous':
                color = self.COLORS['edge']['dangerous_flow']
                penwidth = 1.8

            dot_lines.append(f'  "{from_id}" -> "{to_id}" [label="{label}", color="{color}", penwidth={penwidth}, style={style}];')

        dot_lines.append('}')

        output_file.write_text('\n'.join(dot_lines), encoding='utf-8')

    def _generate_hybrid_view(self, result: Dict, output_file: Path):
        """生成混合视图 (DDG + 调用图)"""
        dot_lines = [
            'digraph HybridView_V7 {',
            '  rankdir=TB;',
            '  splines=spline;',
            '  overlap=scalexy;',
            '  node [shape=box, style="filled,rounded", fontsize=10];',
            '  label="Hybrid View V7 - DDG + Call Graph";',
            '  labelloc="t";',
            '  fontsize=14;',
        ]

        # 添加文件级节点
        file_nodes = defaultdict(list)
        for key, node in result['nodes'].items():
            file_nodes[node.file].append(node)

        for i, (file_path, nodes) in enumerate(sorted(file_nodes.items())):
            file_name = Path(file_path).name
            node_count = len(nodes)
            # 检查风险等级
            fast_scan = result.get('fast_scan_results', {}).get(str(file_path), {})
            risk = fast_scan.get('risk_level', 'safe')
            risk_emoji = {'safe': '🟢', 'low': '🟡', 'medium': '🟠', 'high': '🔴', 'critical': '🚨'}
            label = f"{file_name}\\n({node_count} nodes) {risk_emoji.get(risk, '')}"

            color = '#C8E6C9'
            if risk == 'high':
                color = '#FFCDD2'
            elif risk == 'medium':
                color = '#FFE0B2'

            dot_lines.append(f'  "file_{i}" [label="{label}", fillcolor="{color}", penwidth=2.0];')

        # 添加跨文件调用边
        for call in result.get('cross_file_calls', []):
            caller_file = Path(call['caller_file']).name
            callee_file = Path(call['callee_file']).name
            # 找到对应的文件节点索引
            files = sorted(file_nodes.keys())
            try:
                caller_idx = files.index(call['caller_file'])
                callee_idx = files.index(call['callee_file'])
                callee_func = call.get('callee_func', 'call')
                dot_lines.append(f'  "file_{caller_idx}" -> "file_{callee_idx}" [label="{callee_func}()", color="#1976D2", penwidth=1.5];')
            except ValueError:
                pass

        dot_lines.append('}')
        output_file.write_text('\n'.join(dot_lines), encoding='utf-8')

    def _generate_call_graph(self, result: Dict, output_file: Path):
        """生成调用图"""
        dot_lines = [
            'digraph CallGraph_V7 {',
            '  rankdir=LR;',
            '  node [shape=ellipse, style="filled", fontsize=10];',
            '  label="Call Graph V7";',
            '  labelloc="t";',
        ]

        # 收集所有函数
        functions = set()
        for (file, func_name), info in result['symbol_table'].functions.items():
            functions.add((func_name, file))

        # 添加节点
        func_ids = {}
        for i, (func, file) in enumerate(sorted(functions)):
            func_id = f"func_{i}"
            func_ids[func] = func_id
            short_name = Path(file).name
            dot_lines.append(f'  "{func_id}" [label="{func}\\n({short_name})", fillcolor="#E1BEE7"];')

        # 添加调用边
        seen_calls = set()
        for call in result.get('cross_file_calls', []):
            caller = call['caller_func']
            callee = call['callee_func']
            call_key = (caller, callee)
            if call_key not in seen_calls:
                seen_calls.add(call_key)
                if caller in func_ids and callee in func_ids:
                    dot_lines.append(f'  "{func_ids[caller]}" -> "{func_ids[callee]}" [label="calls"];')

        dot_lines.append('}')
        output_file.write_text('\n'.join(dot_lines), encoding='utf-8')

    def _generate_security_report(self, result: Dict, project_dir: str) -> Path:
        """生成安全报告 HTML"""
        security_report = result.get('security_report', {})
        fast_scan_results = result.get('fast_scan_results', {})

        # 风险统计
        risk_counts = security_report.get('by_severity', {})
        total_issues = security_report.get('total_issues', 0)
        overall_risk = security_report.get('risk_level', 'safe')

        risk_emoji = {'safe': '🟢', 'low': '🟡', 'low-medium': '🟡',
                      'medium': '🟠', 'high': '🔴', 'critical': '🚨'}

        html = f'''<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Report V7 - Complete Analysis</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #0d1117; color: #c9d1d9; }}
        .header {{ background: linear-gradient(135deg, #8B0000 0%, #1a237e 100%); color: white; padding: 30px; }}
        .header h1 {{ font-size: 28px; }}
        .subtitle {{ opacity: 0.9; font-size: 14px; margin-top: 5px; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; padding: 20px; background: #161b22; }}
        .stat-card {{ background: #21262d; padding: 15px; border-radius: 8px; border-left: 4px solid #757575; }}
        .stat-card.critical {{ border-left-color: #B71C1C; }}
        .stat-card.high {{ border-left-color: #D32F2F; }}
        .stat-card.medium {{ border-left-color: #F57C00; }}
        .stat-card.low {{ border-left-color: #FBC02D; }}
        .stat-card.safe {{ border-left-color: #388E3C; }}
        .stat-card .value {{ font-size: 32px; font-weight: bold; }}
        .stat-card .label {{ font-size: 12px; opacity: 0.7; }}
        .container {{ max-width: 1400px; margin: 0 auto; padding: 20px; }}
        .section {{ background: #161b22; border-radius: 8px; margin-bottom: 20px; overflow: hidden; }}
        .section-header {{ padding: 12px 20px; font-weight: 600; }}
        .section-header.critical {{ background: #B71C1C; color: white; }}
        .section-header.high {{ background: #D32F2F; color: white; }}
        .section-header.medium {{ background: #F57C00; color: white; }}
        .section-header.low {{ background: #FBC02D; color: #21262d; }}
        .section-header.safe {{ background: #388E3C; color: white; }}
        .section-header.info {{ background: #1976D2; color: white; }}
        .finding {{ padding: 12px 20px; border-bottom: 1px solid #30363d; }}
        .finding:hover {{ background: #1c2128; }}
        .finding-header {{ display: flex; justify-content: space-between; margin-bottom: 8px; }}
        .finding-location {{ font-family: 'Consolas', monospace; font-size: 12px; color: #8b949e; }}
        .finding-source {{ background: #0d1117; padding: 8px 12px; border-radius: 4px; font-family: 'Consolas', monospace; font-size: 12px; overflow-x: auto; }}
        .badge {{ display: inline-block; padding: 3px 8px; border-radius: 4px; font-size: 10px; font-weight: 600; text-transform: uppercase; }}
        .badge.critical {{ background: #B71C1C; }}
        .badge.high {{ background: #D32F2F; }}
        .badge.medium {{ background: #F57C00; }}
        .badge.low {{ background: #FBC02D; color: #21262d; }}
        .empty {{ padding: 30px; text-align: center; opacity: 0.5; }}
        .risk-gauge {{ text-align: center; padding: 20px; }}
        .risk-gauge .gauge {{ font-size: 64px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ Security Report V7</h1>
        <div class="subtitle">Complete Security Analysis | Layered DDG + Fast Scan</div>
    </div>

    <div class="summary">
        <div class="stat-card critical">
            <div class="value">{risk_counts.get('critical', 0)}</div>
            <div class="label">CRITICAL</div>
        </div>
        <div class="stat-card high">
            <div class="value">{risk_counts.get('high', 0)}</div>
            <div class="label">HIGH</div>
        </div>
        <div class="stat-card medium">
            <div class="value">{risk_counts.get('medium', 0)}</div>
            <div class="label">MEDIUM</div>
        </div>
        <div class="stat-card low">
            <div class="value">{risk_counts.get('low', 0)}</div>
            <div class="label">LOW</div>
        </div>
        <div class="stat-card safe">
            <div class="value" style="font-size: 24px;">{risk_emoji.get(overall_risk, '🟢')}</div>
            <div class="label">OVERALL RISK</div>
        </div>
    </div>

    <div class="container">
'''

        # 按文件显示发现
        if fast_scan_results:
            for file_path, scan_result in fast_scan_results.items():
                findings = scan_result.get('findings', [])
                if not findings:
                    continue

                file_name = Path(file_path).name
                risk = scan_result.get('risk_level', 'safe')
                line_count = scan_result.get('line_count', 0)
                size_mb = scan_result.get('size_mb', 0)

                # 按严重程度分组
                by_severity = {'critical': [], 'high': [], 'medium': [], 'low': []}
                for f in findings:
                    sev = f.get('severity', 'low')
                    if sev in by_severity:
                        by_severity[sev].append(f)

                # 确定头部颜色
                header_class = risk if risk in ['critical', 'high', 'medium', 'low'] else 'info'

                html += f'''
        <div class="section">
            <div class="section-header {header_class}">
                📁 {file_name} ({line_count:,} lines, {size_mb} MB) - Risk: {risk.upper()}
            </div>
'''

                for sev in ['critical', 'high', 'medium', 'low']:
                    if by_severity[sev]:
                        html += f'<div class="finding">\n'
                        html += f'  <div class="finding-header">\n'
                        html += f'    <span class="badge {sev}">{sev.upper()}</span>\n'
                        html += f'    <span>{len(by_severity[sev])} findings</span>\n'
                        html += f'  </div>\n'

                        for finding in by_severity[sev][:5]:  # 最多显示5个
                            line = finding.get('line', '?')
                            content = finding.get('content', finding.get('info', ''))[:100]
                            html += f'  <div class="finding-location">Line {line}: {self._escape_html(content)}</div>\n'

                        if len(by_severity[sev]) > 5:
                            html += f'  <div class="finding-location">... and {len(by_severity[sev]) - 5} more</div>\n'

                        html += f'</div>\n'

                html += f'  </div>\n'

        # 如果没有发现
        if total_issues == 0:
            html += '''
        <div class="section">
            <div class="section-header safe">
                ✅ No Security Issues Found
            </div>
            <div class="empty">
                All files passed security analysis. No suspicious patterns detected.
            </div>
        </div>
'''

        html += '''
    </div>
</body>
</html>
'''

        report_file = self.html_dir / 'security_report_v7.html'
        report_file.write_text(html, encoding='utf-8')
        return report_file

    def _generate_file_cfgs(self, result: Dict):
        """为小文件生成单独的 CFG DOT 和 PNG"""
        cfg_manager = result.get('cfg_manager')
        if not cfg_manager:
            return

        # 为每个有CFG的文件生成可视化
        for file_path, cfg_info in cfg_manager.cfgs.items():
            # 安全的文件名（处理中文和特殊字符）
            file_hash = hashlib.md5(str(file_path).encode()).hexdigest()[:8]
            file_name = Path(file_path).stem
            dot_file = self.dot_dir / f'{file_hash}_cfg.dot'
            self._write_cfg_dot(cfg_info, dot_file, file_name)
            # 生成PNG
            self._generate_png(dot_file, f'{file_hash}_cfg.png')

            # 为每个函数生成CFG
            for func_name, func_cfg in cfg_info.function_cfgs.items():
                # 安全的函数名
                func_hash = hashlib.md5(func_name.encode()).hexdigest()[:8]
                func_dot_file = self.dot_dir / f'{file_hash}_{func_hash}_cfg.dot'
                self._write_cfg_dot(func_cfg, func_dot_file, f"{file_name}.{func_name}")
                # 生成PNG
                self._generate_png(func_dot_file, f'{file_hash}_{func_hash}_cfg.png')

    def _write_cfg_dot(self, cfg_info, output_file: Path, title: str):
        """写入 CFG DOT 文件"""
        # 安全的标题（移除特殊字符）
        safe_title = title.replace(".", "_").replace(" ", "_").replace("(", "_").replace(")", "")

        dot_lines = [
            f'digraph CFG_{safe_title} {{',
            '  rankdir=TB;',
            '  node [shape=box, style="filled", fontname="Arial", fontsize=10];',
            f'  label="CFG: {safe_title}";',
            '  labelloc="t";',
        ]

        for block in cfg_info.all_blocks:
            color = '#C8E6C9' if block.is_entry else '#FFFFFF'
            label = f"L{block.line}"
            if block.is_entry:
                label += " (entry)"
            block_id = block.block.id
            dot_lines.append(f'  "block_{block_id}" [label="{label}", fillcolor="{color}"];')

            # 使用 exits 属性 (LinkInfo)
            for link in block.exits:
                target_id = link.target.block.id
                # 安全的条件标签
                condition = link.condition if link.condition else "unconditional"
                condition = condition.replace('"', "'")
                dot_lines.append(f'  "block_{block_id}" -> "block_{target_id}" [label="{condition}"];')

        dot_lines.append('}')
        output_file.write_text('\n'.join(dot_lines), encoding='utf-8')

    def _generate_png(self, dot_file: Path, output_name: str, high_res: bool = False) -> Optional[Path]:
        """使用 Graphviz 生成 PNG (输出到 png/ 目录)"""
        output_file = self.png_dir / output_name

        try:
            result = subprocess.run(
                ['dot', '-Tpng', str(dot_file), '-o', str(output_file)],
                capture_output=True,
                text=True,
                timeout=60
            )
            if result.returncode == 0:
                return output_file
            else:
                # 打印错误信息
                print(f"    Graphviz error: {result.stderr[:200]}")
        except FileNotFoundError:
            print("    Graphviz 'dot' command not found")
        except subprocess.TimeoutExpired:
            print("    Graphviz timeout (60s)")

        return None

    def _generate_security_ddg(self, result: Dict, output_file: Path):
        """V6.1: 生成只包含危险节点的安全DDG（带文件名和行号）"""
        nodes = result['nodes']
        edges = result['edges']
        security_report = result.get('security_report', {})

        # 构建有问题节点的映射
        security_findings_by_location = {}
        for finding in security_report.get('findings', []):
            key = (finding['file'], finding['line'])
            if key not in security_findings_by_location:
                security_findings_by_location[key] = []
            security_findings_by_location[key].append(finding)

        # 收集危险节点及其相连的边
        dangerous_nodes = set()
        dangerous_edges = []

        for key, node in nodes.items():
            security_key = (node.file, node.line)
            if security_key in security_findings_by_location:
                dangerous_nodes.add(key)

        # 如果没有安全发现，使用危险模式检测
        if not dangerous_nodes:
            for key, node in nodes.items():
                danger_level, _ = self._is_dangerous_node(node)
                if danger_level in ['dangerous', 'suspicious']:
                    dangerous_nodes.add(key)

        # 收集相关的边（连接危险节点的边）
        node_set = dangerous_nodes
        for edge in edges:
            from_key = (edge.from_node.file, edge.from_node.line)
            to_key = (edge.to_node.file, edge.to_node.line)
            # 如果边的任一端是危险节点，或者边连接两个危险节点
            if from_key in node_set or to_key in node_set:
                dangerous_edges.append(edge)
                # 也把相连的普通节点加入，为了更好的可视化
                if from_key not in node_set:
                    node_set.add(from_key)
                if to_key not in node_set:
                    node_set.add(to_key)

        # 严重程度颜色
        severity_colors = {
            'critical': '#B71C1C',
            'high': '#D32F2F',
            'medium': '#F57C00',
            'low': '#FBC02D',
        }

        dot_lines = [
            'digraph SecurityDDG_V6_1 {',
            '  rankdir=TB;',
            '  splines=spline;',
            '  overlap=scalexy;',
            '  nodesep=0.5;',
            '  ranksep=0.7;',
            '  dpi=150;',
            '  node [shape=box, style="filled,rounded", fontname="Consolas", fontsize=8];',
            '  edge [fontname="Arial", fontsize=8];',
            '  label="Security DDG V6.1 - Dangerous Nodes (with file:line)";',
            '  labelloc="t";',
            '  fontsize=16;',
            '  newrank=true;',
        ]

        # 按严重程度分组
        nodes_by_severity = {'critical': [], 'high': [], 'medium': [], 'low': [], 'other': []}

        for key in node_set:
            if key not in nodes:
                continue
            node = nodes[key]
            security_key = (node.file, node.line)

            # 确定严重程度
            if security_key in security_findings_by_location:
                findings = security_findings_by_location[security_key]
                highest_sev = 'other'
                for f in findings:
                    sev = f['severity']
                    if sev == 'critical':
                        highest_sev = 'critical'
                        break
                    elif sev == 'high' and highest_sev != 'critical':
                        highest_sev = 'high'
                    elif sev == 'medium' and highest_sev not in ['critical', 'high']:
                        highest_sev = 'medium'
                    elif sev == 'low' and highest_sev == 'other':
                        highest_sev = 'low'
                nodes_by_severity[highest_sev].append((key, node))
            else:
                # 使用危险模式检测
                danger_level, _ = self._is_dangerous_node(node)
                if danger_level == 'dangerous':
                    nodes_by_severity['high'].append((key, node))
                elif danger_level == 'suspicious':
                    nodes_by_severity['medium'].append((key, node))
                else:
                    nodes_by_severity['other'].append((key, node))

        # 【修复】生成节点（带文件名:行号）
        for severity in ['critical', 'high', 'medium', 'low', 'other']:
            if not nodes_by_severity[severity]:
                continue

            for key, node in nodes_by_severity[severity]:
                node_id = self._escape_id(f"{Path(node.file).name}_{node.line}")
                source = node.source
                # 保存完整 source 用于 _source
                full_source = source
                # 清理特殊字符用于 label
                source = source.replace('"', "'").replace('"', "'").replace('"', "'").replace('"', "'")
                # 将换行符替换为空格（用于 label）
                source = source.replace('\n', ' ').replace('\r', '').replace('\t', ' ')

                # 【修复】label 包含文件名和行号
                file_name = Path(node.file).name
                label = f"{file_name}:{node.line}\\n{self._truncate_label(source, 50)}"

                # 添加 _source 属性
                if full_source:
                    source_escaped = full_source.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n')
                    source_attr = f', _source="{source_escaped}"'
                else:
                    source_attr = ''

                if severity != 'other':
                    fillcolor = severity_colors.get(severity, '#FFFFFF')
                    fontcolor = 'white' if severity in ['critical', 'high'] else 'black'
                    penwidth = 2.5 if severity == 'critical' else 2.0
                    dot_lines.append(f'  "{node_id}" [label="{label}", fillcolor="{fillcolor}", fontcolor="{fontcolor}", penwidth={penwidth}{source_attr}];')
                else:
                    dot_lines.append(f'  "{node_id}" [label="{label}", fillcolor="#E0E0E0", style="filled,dashed"{source_attr}];')

        # 生成边
        seen_edges = set()
        for edge in dangerous_edges:
            from_id = self._escape_id(f"{Path(edge.from_node.file).name}_{edge.from_node.line}")
            to_id = self._escape_id(f"{Path(edge.to_node.file).name}_{edge.to_node.line}")
            edge_key = (from_id, to_id)

            if edge_key in seen_edges:
                continue
            seen_edges.add(edge_key)

            # 边标签
            label = self._escape_label(edge.variable[:15] if edge.variable else '')

            # 根据边的目标确定颜色
            to_key = (edge.to_node.file, edge.to_node.line)
            if to_key in security_findings_by_location:
                findings = security_findings_by_location[to_key]
                highest_sev = 'low'
                for f in findings:
                    if f['severity'] == 'critical':
                        highest_sev = 'critical'
                        break
                    elif f['severity'] == 'high' and highest_sev != 'critical':
                        highest_sev = 'high'
                    elif f['severity'] == 'medium' and highest_sev not in ['critical', 'high']:
                        highest_sev = 'medium'
                color = severity_colors.get(highest_sev, '#757575')
            else:
                color = '#757575'

            dot_lines.append(f'  "{from_id}" -> "{to_id}" [label="{label}", color="{color}", penwidth=1.5];')

        # 添加统计信息
        stats_comment = f'  // Security Stats: {len(dangerous_nodes)} dangerous nodes, {len(dangerous_edges)} related edges'
        dot_lines.insert(-1, stats_comment)

        dot_lines.append('}')
        output_file.write_text('\n'.join(dot_lines), encoding='utf-8')

    def _escape_id(self, s: str) -> str:
        """转义 DOT ID"""
        return s.replace('-', '_').replace('.', '_').replace('/', '_')

    def _escape_label(self, s: str) -> str:
        """转义 DOT 标签"""
        # 转义特殊字符
        s = s.replace('\\', '\\\\')  # 反斜杠
        s = s.replace('"', '\\"')     # 双引号
        s = s.replace('{', '\\{')     # 花括号
        s = s.replace('}', '\\}')
        return s

    def _escape_html(self, s: str) -> str:
        """转义 HTML"""
        return s.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;')

    def _truncate_label(self, s: str, max_len: int) -> str:
        """截断标签"""
        if len(s) > max_len:
            return s[:max_len-3] + '...'
        return s

    def _generate_fast_scan_dot(self, file_path: str, scan_result: Dict, output_file: Path):
        """为大文件生成快速扫描结果的 DOT 文件"""
        file_name = Path(file_path).name
        line_count = scan_result.get('line_count', 0)
        size_mb = scan_result.get('size_mb', 0)
        risk_level = scan_result.get('risk_level', 'unknown')
        findings = scan_result.get('findings', [])

        # 按严重程度分组
        by_severity = {'critical': [], 'high': [], 'medium': [], 'low': []}
        for f in findings:
            sev = f.get('severity', 'low')
            by_severity[sev].append(f)

        # 颜色映射
        sev_colors = {
            'critical': '#B71C1C',
            'high': '#D32F2F',
            'medium': '#F57C00',
            'low': '#FBC02D'
        }

        dot_lines = [
            f'digraph FastScan_{file_name} {{',
            '  rankdir=TB;',
            '  splines=spline;',
            '  node [shape=box, style="filled,rounded", fontsize=10];',
            f'  label="Fast Scan: {file_name} ({line_count:,} lines, {size_mb} MB)";',
            '  labelloc="t";',
            '  fontsize=14;',
        ]

        # 添加摘要节点
        summary_label = f"File: {file_name}\\nLines: {line_count:,}\\nRisk: {risk_level.upper()}\\nFindings: {len(findings)}"
        summary_color = sev_colors.get(risk_level, '#FFFFFF')
        dot_lines.append(f'  "summary" [label="{summary_label}", fillcolor="{summary_color}", penwidth=2.5];')

        # 添加统计节点
        for sev in ['critical', 'high', 'medium', 'low']:
            count = len(by_severity[sev])
            if count > 0:
                color = sev_colors[sev]
                dot_lines.append(f'  "stat_{sev}" [label="{sev.upper()}: {count}", fillcolor="{color}"];')
                dot_lines.append(f'  "summary" -> "stat_{sev}" [style=dashed];')

        # 添加前20个发现
        shown = 0
        for sev in ['critical', 'high', 'medium', 'low']:
            for f in by_severity[sev]:
                if shown >= 20:
                    break
                line = f.get('line', '?')
                content = f.get('content', f.get('info', ''))[:60]
                content = content.replace('"', '\\"')
                dot_lines.append(f'  "finding_{shown}" [label="L{line}: {content}", fillcolor="{sev_colors[sev]}"];')
                dot_lines.append(f'  "summary" -> "finding_{shown}" [style=dashed];')
                shown += 1
            if shown >= 20:
                break

        if len(findings) > 20:
            dot_lines.append(f'  "more" [label="... and {len(findings)-20} more findings", fillcolor="#E0E0E0"];')
            dot_lines.append(f'  "summary" -> "more" [style=dashed];')

        dot_lines.append('}')

        output_file.write_text('\n'.join(dot_lines), encoding='utf-8')
        return output_file

    # ==================== 子图分割功能（弱连通分量）====================

    def _generate_sub_ddgs(self, result: Dict, output_dir: Path) -> Optional[Dict]:
        """使用完整 DDG 进行 WCC 分割（包含跨文件边）

        逻辑：
        1. 使用完整的 nodes.json 和 edges.json（包含跨文件边）
        2. 识别危险节点（来自 security_report）
        3. 在完整 DDG 上计算包含危险节点的 WCC
        4. 为每个 WCC 生成子图
        """
        import networkx as nx
        from collections import defaultdict

        nodes = result['nodes']
        edges = result['edges']
        security_report = result.get('security_report', {})

        # 创建输出目录
        output_dir.mkdir(parents=True, exist_ok=True)

        # 1. 构建 security_findings 映射
        security_findings_by_location = {}
        for finding in security_report.get('findings', []):
            key = (finding['file'], finding['line'])
            if key not in security_findings_by_location:
                security_findings_by_location[key] = []
            security_findings_by_location[key].append(finding)

        # 2. 识别危险节点
        dangerous_node_keys = set()
        dangerous_nodes_info = {}

        # 首先从 security_report 中获取危险节点
        for key, node in nodes.items():
            security_key = (node.file, node.line)
            if security_key in security_findings_by_location:
                dangerous_node_keys.add(key)
                node_id = f"{Path(node.file).name}_{node.line}"
                findings = security_findings_by_location[security_key]
                for f in findings:
                    dangerous_nodes_info[node_id] = {
                        'severity': f['severity'],
                        'category': f.get('type', 'unknown'),
                        'reason': f.get('content', '')[:50],
                        'location': {'file': node.file, 'line': node.line}
                    }
                    break

        # 如果 security_report 中没有危险节点，使用 _is_dangerous_node 进行检测
        # 这与 _generate_security_ddg 的逻辑保持一致
        if not dangerous_node_keys:
            print("  [Sub-DDG] No dangerous nodes in security_report, using pattern detection...")
            for key, node in nodes.items():
                danger_level, reason = self._is_dangerous_node(node)
                if danger_level in ['dangerous', 'suspicious']:
                    dangerous_node_keys.add(key)
                    node_id = f"{Path(node.file).name}_{node.line}"
                    # 根据 danger_level 确定 severity
                    severity = 'high' if danger_level == 'dangerous' else 'medium'
                    dangerous_nodes_info[node_id] = {
                        'severity': severity,
                        'category': reason,
                        'reason': f'{reason} - {node.source[:50]}',
                        'location': {'file': node.file, 'line': node.line}
                    }

        if not dangerous_node_keys:
            print("  [Sub-DDG] No dangerous nodes found for sub-DDG extraction")
            return None

        print(f"  [Sub-DDG] Found {len(dangerous_node_keys)} dangerous nodes")

        # 3. 构建完整 DDG 的 NetworkX 图（包含跨文件边）
        import networkx as nx
        graph = nx.DiGraph()
        node_id_to_key = {}  # node_id -> (file, line) key

        for key, node in nodes.items():
            node_id = f"{Path(node.file).name}_{node.line}"
            is_dangerous = key in dangerous_node_keys
            node_id_to_key[node_id] = key

            graph.add_node(node_id, **{
                '_file': node.file,
                '_line': node.line,
                '_key': key,
                'label': node.source[:100],
                '_source': node.source,
                'type': node.type,
                '_is_dangerous': is_dangerous,
                '_severity': dangerous_nodes_info.get(node_id, {}).get('severity', 'unknown'),
                # ✅ 修复：添加函数和类信息（用于桩程序生成）
                '_function_name': getattr(node, 'function_name', None),
                '_class_name': getattr(node, 'class_name', None)
            })

        # 添加所有边（包括跨文件边）
        for edge in edges:
            from_id = f"{Path(edge.from_node.file).name}_{edge.from_node.line}"
            to_id = f"{Path(edge.to_node.file).name}_{edge.to_node.line}"
            if from_id in graph.nodes and to_id in graph.nodes:
                graph.add_edge(from_id, to_id, **{
                    'label': edge.variable or '',
                    'type': edge.type,
                    'color': self._get_edge_color(edge)
                })

        # 统计跨文件边
        cross_file_edges = 0
        for from_id, to_id in graph.edges:
            from_file = graph.nodes[from_id]['_file']
            to_file = graph.nodes[to_id]['_file']
            if from_file != to_file:
                cross_file_edges += 1

        print(f"  [Sub-DDG] Built graph with {graph.number_of_nodes()} nodes, {graph.number_of_edges()} edges ({cross_file_edges} cross-file)")

        # 4. 使用弱连通分量（WCC）分割
        undirected = graph.to_undirected()
        weakly_connected_components = list(nx.connected_components(undirected))

        # 只保留包含危险节点的 WCC
        dangerous_components = [wcc for wcc in weakly_connected_components if any(graph.nodes[n]['_is_dangerous'] for n in wcc)]

        print(f"  [Sub-DDG] WCC partition: {len(dangerous_components)} components")

        # 5. 为每个 WCC 生成子图
        summary = {
            'total_components': len(dangerous_components),
            'by_severity': defaultdict(int),
            'components': []
        }

        for i, component_nodes in enumerate(sorted(dangerous_components, key=lambda x: -len(x)), 1):
            # 确定该分量的主要严重程度
            severities_in_component = [graph.nodes[n]['_severity'] for n in component_nodes if graph.nodes[n]['_is_dangerous']]

            highest_severity = 'unknown'
            if 'critical' in severities_in_component:
                highest_severity = 'critical'
            elif 'high' in severities_in_component:
                highest_severity = 'high'
            elif 'medium' in severities_in_component:
                highest_severity = 'medium'

            # 统计危险节点数量
            dangerous_count = sum(1 for n in component_nodes if graph.nodes[n]['_is_dangerous'])

            # 统计跨文件边
            subgraph = graph.subgraph(component_nodes).copy()
            cross_file_in_wcc = 0
            for from_id, to_id in subgraph.edges:
                from_file = subgraph.nodes[from_id]['_file']
                to_file = subgraph.nodes[to_id]['_file']
                if from_file != to_file:
                    cross_file_in_wcc += 1

            # 生成文件夹名
            folder_name = f"{i:03d}_{highest_severity}_{dangerous_count}nodes_wcc"
            sub_dir = output_dir / folder_name
            sub_dir.mkdir(exist_ok=True)

            # 保存子图
            self._save_wcc_sub_ddg_from_graph(subgraph, component_nodes, sub_dir, dangerous_nodes_info)

            summary['by_severity'][highest_severity] += 1
            summary['components'].append({
                'id': i,
                'name': folder_name,
                'severity': highest_severity,
                'total_nodes': len(component_nodes),
                'dangerous_nodes': dangerous_count,
                'cross_file_edges': cross_file_in_wcc,
                'directory': str(sub_dir)
            })

            print(f"    [{i}] {folder_name}: {len(component_nodes)} nodes ({dangerous_count} dangerous), {subgraph.number_of_edges()} edges ({cross_file_in_wcc} cross-file)")

        # 保存摘要
        with open(output_dir / 'summary.json', 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=2, ensure_ascii=False, default=dict)

        return summary

    def _save_wcc_sub_ddg_from_graph(self, subgraph: "nx.DiGraph", component_nodes: Set[str],
                                     output_dir: Path, dangerous_nodes_info: Dict):
        """从完整 DDG 图数据保存子图"""
        import json
        import networkx as nx

        # 1. 保存 nodes.json
        nodes_list = []
        for node_id in component_nodes:
            attrs = subgraph.nodes[node_id]
            nodes_list.append({
                'node_id': node_id,
                'file': attrs.get('_file', 'unknown'),
                'line': attrs.get('_line', 0),
                'code': attrs.get('_source', attrs.get('label', '')),
                'is_dangerous': attrs.get('_is_dangerous', False),
                'severity': attrs.get('_severity', 'unknown'),
                'confidence': 0.9 if attrs.get('_is_dangerous') else 0.5,
                # ✅ 修复：保存函数和类信息（用于桩程序生成）
                'function_name': attrs.get('_function_name', None),
                'class_name': attrs.get('_class_name', None)
            })

        with open(output_dir / 'nodes.json', 'w', encoding='utf-8') as f:
            json.dump(nodes_list, f, indent=2, ensure_ascii=False)

        # 2. 保存 edges.json（带跨文件信息）
        edges_list = []
        for from_node, to_node in subgraph.edges():
            from_file = subgraph.nodes[from_node]['_file']
            to_file = subgraph.nodes[to_node]['_file']
            edges_list.append({
                'from_node': from_node,
                'to_node': to_node,
                'from_file': from_file,
                'to_file': to_file,
                'is_cross_file': from_file != to_file
            })

        with open(output_dir / 'edges.json', 'w', encoding='utf-8') as f:
            json.dump(edges_list, f, indent=2, ensure_ascii=False)

        # 3. 生成子图 DOT 文件
        self._generate_sub_wcc_dot_from_graph(subgraph, component_nodes, output_dir)

        # 4. 尝试生成 PNG（如果节点数 < 200）
        if len(component_nodes) < 200:
            png_file = output_dir / 'sub_ddg.png'
            try:
                result = subprocess.run(
                    ['dot', '-Tpng', str(output_dir / 'sub_ddg.dot'), '-o', str(png_file)],
                    capture_output=True,
                    timeout=60
                )
                if result.returncode == 0:
                    print(f"      -> PNG generated")
            except:
                pass

    def _generate_sub_wcc_dot_from_graph(self, subgraph: "nx.DiGraph", component_nodes: Set[str],
                                         output_dir: Path):
        """生成子图的 DOT 文件"""
        severity_colors = {
            'critical': '#B71C1C',
            'high': '#D32F2F',
            'medium': '#F57C00',
            'low': '#FBC02D'
        }

        dot_lines = [
            'digraph SubDDG {',
            '  rankdir=TB;',
            '  splines=spline;',
            '  nodesep=0.4;',
            '  ranksep=0.6;',
            '  dpi=150;',
            '  node [shape=box, style="filled,rounded", fontname="Consolas", fontsize=7];',
            '  edge [fontname="Arial", fontsize=7];',
            f'  label="Sub-DDG WCC - {len(component_nodes)} nodes";',
            '  labelloc="t";',
            '  fontsize=12;'
        ]

        for node_id in component_nodes:
            attrs = subgraph.nodes[node_id]
            file_name = Path(attrs.get('_file', 'unknown')).name
            line = attrs.get('_line', 0)
            source = attrs.get('label', node_id)
            label = f"{file_name}:{line}\\n{source[:40]}"

            is_dangerous = attrs.get('_is_dangerous', False)
            severity = attrs.get('_severity', 'unknown')

            if is_dangerous:
                color = severity_colors.get(severity, '#D32F2F')
                dot_lines.append(f'  "{node_id}" [label="{label}", fillcolor="{color}", fontcolor="white", penwidth=2.0];')
            else:
                dot_lines.append(f'  "{node_id}" [label="{label}", fillcolor="#E0E0E0", fontcolor="black", style="filled,dashed"];')

        for from_node, to_node, attrs in subgraph.edges(data=True):
            from_file = subgraph.nodes[from_node]['_file']
            to_file = subgraph.nodes[to_node]['_file']
            is_cross = from_file != to_file
            color = '#4CAF50' if is_cross else '#616161'  # 跨文件边用绿色
            dot_lines.append(f'  "{from_node}" -> "{to_node}" [color="{color}", penwidth={2.0 if is_cross else 0.8}];')

        dot_lines.append('}')

        with open(output_dir / 'sub_ddg.dot', 'w', encoding='utf-8') as f:
            f.write('\n'.join(dot_lines))

    def _bidirectional_bfs(self, graph: "nx.DiGraph", start_node: str, max_depth: int = 5, max_nodes: int = 100) -> Set[str]:
        """双向 BFS 追踪数据流"""
        nodes_to_keep = {start_node}
        visited = {start_node}
        current_depth = 0

        # 向前追踪（数据流出的方向）
        to_visit = list(graph.successors(start_node))
        while to_visit and current_depth < max_depth and len(nodes_to_keep) < max_nodes:
            next_level = []
            for node in to_visit:
                if node not in visited:
                    visited.add(node)
                    nodes_to_keep.add(node)
                    next_level.extend(graph.successors(node))
            to_visit = next_level
            current_depth += 1

        # 向后追踪（数据流入的方向）
        current_depth = 0
        to_visit = list(graph.predecessors(start_node))
        while to_visit and current_depth < max_depth and len(nodes_to_keep) < max_nodes:
            next_level = []
            for node in to_visit:
                if node not in visited:
                    visited.add(node)
                    nodes_to_keep.add(node)
                    next_level.extend(graph.predecessors(node))
            to_visit = next_level
            current_depth += 1

        return nodes_to_keep

    def _save_sub_ddg(self, subgraph: "nx.DiGraph", flow_nodes: Set[str], primary_node: str,
                      info: Dict, output_dir: Path, dangerous_nodes: Dict):
        """保存子图分割结果"""
        import json

        # 1. 保存 nodes.json（完整代码）
        nodes_list = []
        for node_id in flow_nodes:
            attrs = subgraph.nodes[node_id]
            full_code = attrs.get('_source', attrs.get('label', ''))
            is_primary = node_id == primary_node
            is_dangerous = node_id in dangerous_nodes

            nodes_list.append({
                'node_id': node_id,
                'file': attrs.get('_file', 'unknown'),
                'line': attrs.get('_line', 0),
                'code': full_code,  # 完整代码
                'is_primary': is_primary,
                'is_dangerous': is_dangerous,
                'confidence': 0.95 if is_primary else (0.75 if is_dangerous else 0.5)
            })

        with open(output_dir / 'nodes.json', 'w', encoding='utf-8') as f:
            json.dump(nodes_list, f, indent=2, ensure_ascii=False)

        # 2. 保存 edges.json
        edges_list = []
        for from_node, to_node, attrs in subgraph.edges(data=True):
            edges_list.append({
                'from_node': from_node,
                'to_node': to_node,
                'from_file': subgraph.nodes[from_node].get('_file', 'unknown'),
                'from_line': subgraph.nodes[from_node].get('_line', 0),
                'to_file': subgraph.nodes[to_node].get('_file', 'unknown'),
                'to_line': subgraph.nodes[to_node].get('_line', 0),
                'variable': attrs.get('label', ''),
                'type': attrs.get('type', '')
            })

        with open(output_dir / 'edges.json', 'w', encoding='utf-8') as f:
            json.dump(edges_list, f, indent=2, ensure_ascii=False)

        # 3. 生成 DOT 可视化（V6.1 风格：带文件名:行号）
        self._generate_sub_ddg_dot(subgraph, flow_nodes, primary_node, info, output_dir)

        # 4. 保存源代码片段
        self._save_source_code(subgraph, flow_nodes, output_dir)

        # 5. 保存分析报告
        with open(output_dir / 'analysis_report.json', 'w', encoding='utf-8') as f:
            json.dump(info, f, indent=2, ensure_ascii=False)

    def _generate_sub_ddg_dot(self, subgraph: "nx.DiGraph", flow_nodes: Set[str],
                               primary_node: str, info: Dict, output_dir: Path):
        """生成子图 DOT 文件（V6.1 风格）"""
        severity_colors = {
            'critical': '#B71C1C',
            'high': '#D32F2F',
            'medium': '#F57C00',
            'low': '#FBC02D'
        }

        fillcolor = severity_colors.get(info['severity'], '#D32F2F')

        dot_lines = [
            'digraph SubDDG {',
            '  rankdir=TB;',
            '  splines=spline;',
            '  nodesep=0.5;',
            '  ranksep=0.7;',
            '  dpi=150;',
            '  node [shape=box, style="filled,rounded", fontname="Consolas", fontsize=8];',
            '  edge [fontname="Arial", fontsize=8];',
            f'  label="Sub-DDG: {info["category"]} ({info["severity"].upper()})";',
            '  labelloc="t";',
            '  fontsize=14;'
        ]

        # 生成节点
        for node_id in flow_nodes:
            attrs = subgraph.nodes[node_id]
            file_name = Path(attrs.get('_file', 'unknown')).name
            line = attrs.get('_line', 0)
            source = attrs.get('_source', attrs.get('label', ''))
            # 截断用于 label
            source_short = source.replace('\n', ' ')[:50]

            # V6.1 风格：文件名:行号
            label = f"{file_name}:{line}\\n{source_short}"

            is_primary = node_id == primary_node

            if is_primary:
                dot_lines.append(f'  "{node_id}" [label="{label}", fillcolor="{fillcolor}", fontcolor="white", penwidth=2.5];')
            else:
                # 检查是否是危险节点
                node_danger = self._is_dangerous_node_by_source(source)
                if node_danger == 'dangerous':
                    dot_lines.append(f'  "{node_id}" [label="{label}", fillcolor="#D32F2F", fontcolor="white", penwidth=2.0];')
                elif node_danger == 'suspicious':
                    dot_lines.append(f'  "{node_id}" [label="{label}", fillcolor="#F57C00", fontcolor="black", penwidth=1.5];')
                else:
                    dot_lines.append(f'  "{node_id}" [label="{label}", fillcolor="#E0E0E0", fontcolor="black", style="filled,dashed"];')

        # 生成边
        for from_node, to_node, attrs in subgraph.edges(data=True):
            label = attrs.get('label', '')[:15]
            color = attrs.get('color', '#616161')
            dot_lines.append(f'  "{from_node}" -> "{to_node}" [label="{label}", color="{color}", penwidth=1.0];')

        dot_lines.append('}')

        with open(output_dir / 'sub_ddg.dot', 'w', encoding='utf-8') as f:
            f.write('\n'.join(dot_lines))

        # 尝试生成 PNG（如果节点数 < 50）
        if len(flow_nodes) < 50:
            png_file = output_dir / 'sub_ddg.png'
            try:
                result = subprocess.run(
                    ['dot', '-Tpng', str(output_dir / 'sub_ddg.dot'), '-o', str(png_file)],
                    capture_output=True,
                    timeout=30
                )
                if result.returncode == 0:
                    print(f"      -> PNG generated: {png_file.name}")
            except:
                pass

    def _is_dangerous_node_by_source(self, source: str) -> str:
        """根据源代码判断危险程度"""
        pattern_result = self.pattern_loader.check_node(source, '')
        if pattern_result:
            sev = pattern_result['severity']
            if sev in ['critical', 'high']:
                return 'dangerous'
            else:
                return 'suspicious'
        return 'none'

    def _save_source_code(self, subgraph: "nx.DiGraph", flow_nodes: Set[str], output_dir: Path):
        """保存源代码片段"""
        with open(output_dir / 'source_code.txt', 'w', encoding='utf-8') as f:
            f.write(f"# Source Code Extracted from DDG\n")
            f.write(f"# Total nodes: {len(flow_nodes)}\n\n")

            # 按文件分组
            by_file = defaultdict(list)
            for node_id in flow_nodes:
                attrs = subgraph.nodes[node_id]
                file_path = attrs.get('_file', 'unknown')
                line = attrs.get('_line', 0)
                source = attrs.get('_source', attrs.get('label', ''))
                by_file[file_path].append((line, source))

            for file_path in sorted(by_file.keys()):
                f.write(f"\n{'='*60}\n")
                f.write(f"# File: {Path(file_path).name}\n")
                f.write(f"{'='*60}\n")
                for line, source in sorted(by_file[file_path]):
                    f.write(f"\n# Line {line}\n")
                    f.write(f"{source}\n")

    def _get_edge_color(self, edge) -> str:
        """获取边的颜色"""
        if hasattr(edge, 'type'):
            if edge.type == 'cross_file_call':
                return '#1E88E5'
            elif edge.type == 'cross_file_return':
                return '#43A047'
            elif edge.type == 'parameter_pass':
                return '#00ACC1'
            elif edge.type == 'intra_file_call':
                return '#7E57C2'
        return '#616161'
