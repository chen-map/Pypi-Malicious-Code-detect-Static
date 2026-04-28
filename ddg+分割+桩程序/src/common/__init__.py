"""
Common模块 - 统一的图分析和分割功能

整合自 graph_partitioner_v7.py 和 visualizer_v7.py
避免代码重复，提供一致的API。
"""

from .pattern_matcher import (
    DangerPatternLoader,
    SuspiciousNodeDetector,
    create_pattern_matcher,
    create_node_detector
)

from .graph_partitioner import (
    PartitionConfig,
    DOTParser,
    BidirectionalBFS,
    DataFlowExtractor,
    GraphPartitioner,
    partition_graph
)

__all__ = [
    # pattern_matcher
    'DangerPatternLoader',
    'SuspiciousNodeDetector',
    'create_pattern_matcher',
    'create_node_detector',

    # graph_partitioner
    'PartitionConfig',
    'DOTParser',
    'BidirectionalBFS',
    'DataFlowExtractor',
    'GraphPartitioner',
    'partition_graph',
]
