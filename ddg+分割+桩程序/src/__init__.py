"""
项目级数据依赖图分析工具 V7 - 完整安全分析版

主要特性:
1. 集成 py2cfg 生成控制流图 (CFG)
2. 基于 CFG 的可达性分析
3. 精确的跨文件数据流追踪
4. 过程间控制流图 (Inter-procedural CFG)
5. [V6新增] 安全检测: 危险模式/编码/混淆
6. [V6.1新增] 供应链检测: 依赖分析/域名检查
7. [V7新增] 分层分析: 小文件完整DDG + 大文件快速安全扫描
"""

from .cfg_adapter import (
    ProjectCFGManager,
    CFGInfo,
    BlockInfo,
    LinkInfo
)

from .ddg_builder_v7 import (
    ProjectDDGBuilderV7,
    ProjectSymbolTable,
    GlobalNode,
    GlobalEdge,
    CFGAwareDDGExtractor,
    CFGAwareCrossFileAnalyzer,
    InterProceduralCFGBuilder,
    FastMalwareScannerV7
)

from .visualizer_v7 import VisualizerV7

__all__ = [
    # V7 核心组件
    'ProjectDDGBuilderV7',
    'ProjectSymbolTable',
    'GlobalNode',
    'GlobalEdge',
    # CFG 组件
    'ProjectCFGManager',
    'CFGInfo',
    'BlockInfo',
    'LinkInfo',
    # 分析器
    'CFGAwareDDGExtractor',
    'CFGAwareCrossFileAnalyzer',
    'InterProceduralCFGBuilder',
    'FastMalwareScannerV7',
    # 可视化
    'VisualizerV7',
]

__version__ = '7.0.0'
