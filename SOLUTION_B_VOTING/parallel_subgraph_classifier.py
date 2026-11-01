"""
并行子图分析器 - 加速 LLM 批量分析

使用线程池并行处理多个子图，显著提升速度
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List
import time


class ParallelSubgraphAnalyzer:
    """并行子图分析器"""

    def __init__(self, classifier, max_workers: int = 5):
        """
        初始化并行分析器

        Args:
            classifier: V12SubgraphClassifier 实例
            max_workers: 最大并行线程数（GLM API 限流考虑）
        """
        self.classifier = classifier
        self.max_workers = max_workers

    def analyze_subgraphs_parallel(
        self,
        subgraph_jsons: List[Dict],
        package_name: str,
        ddg_v7_report: Dict,
        skip_rule_scoring: bool = False
    ) -> List[Dict]:
        """
        并行分析多个子图

        Args:
            subgraph_jsons: 子图列表
            package_name: 包名
            ddg_v7_report: DDG V7 报告
            skip_rule_scoring: 是否跳过规则评分

        Returns:
            子图判决结果列表
        """
        start_time = time.time()

        results = [None] * len(subgraph_jsons)

        # 提交任务到线程池
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # 创建任务字典：future -> subgraph_index
            future_to_index = {}

            for idx, subgraph_json in enumerate(subgraph_jsons):
                future = executor.submit(
                    self._analyze_single_subgraph,
                    subgraph_json,
                    package_name,
                    ddg_v7_report,
                    idx + 1,  # 显示用（从1开始）
                    skip_rule_scoring
                )
                future_to_index[future] = idx

            # 收集结果（按完成顺序）
            completed = 0
            for future in as_completed(future_to_index):
                idx = future_to_index[future]
                try:
                    result = future.result()
                    results[idx] = result
                    completed += 1

                    # 显示进度
                    elapsed = time.time() - start_time
                    avg_time = elapsed / completed
                    remaining = (len(subgraph_jsons) - completed) * avg_time
                    print(f"          [并行进度] {completed}/{len(subgraph_jsons)} 完成 | "
                          f"已用时: {elapsed:.1f}s | 预计剩余: {remaining:.1f}s")

                except Exception as e:
                    print(f"          [ERROR] 子图 {idx+1} 分析失败: {e}")
                    results[idx] = {
                        'subgraph_name': subgraph_jsons[idx].get('subgraph_name', 'unknown'),
                        'is_malicious': False,
                        'final_verdict': 'ERROR',
                        'error': str(e)
                    }

        total_time = time.time() - start_time
        print(f"\n          [并行分析完成] 总耗时: {total_time:.2f}s | "
              f"平均每个子图: {total_time/len(subgraph_jsons):.2f}s")

        return results

    def _analyze_single_subgraph(
        self,
        subgraph_json: Dict,
        package_name: str,
        ddg_v7_report: Dict,
        subgraph_idx: int,
        skip_rule_scoring: bool
    ) -> Dict:
        """
        分析单个子图（线程工作函数）

        Args:
            subgraph_json: 子图数据
            package_name: 包名
            ddg_v7_report: DDG V7 报告
            subgraph_idx: 子图索引（用于显示）
            skip_rule_scoring: 是否跳过规则评分

        Returns:
            子图判决结果
        """
        subgraph_name = subgraph_json.get('subgraph_name', f'subgraph_{subgraph_idx}')

        print(f"\n          [分析子图 {subgraph_idx}] {subgraph_name}")

        if skip_rule_scoring:
            # 直接使用 LLM 分析
            verdict = self.classifier.classify_subgraph(
                subgraph_json,
                package_name,
                ddg_v7_report,
                subgraph_idx,
                None  # 不传入规则评分结果
            )
            verdict['rule_based_score'] = 0.0
            verdict['rule_based_category'] = 'SKIPPED'
            verdict['rule_based_confidence'] = 0.0
        else:
            # 规则评分 + LLM 验证
            from rule_based_scorer import RuleBasedScorer
            scorer = RuleBasedScorer()

            rule_based_result = scorer.score_subgraph(subgraph_json, ddg_v7_report)

            print(f"            规则评分: {rule_based_result['total_score']:.2f}")

            verdict = self.classifier.classify_subgraph(
                subgraph_json,
                package_name,
                ddg_v7_report,
                subgraph_idx,
                rule_based_result
            )

            verdict['rule_based_score'] = rule_based_result['total_score']
            verdict['rule_based_category'] = rule_based_result['category']
            verdict['rule_based_confidence'] = rule_based_result['confidence']

        print(f"            判决: {verdict['final_verdict']} (置信度: {verdict.get('confidence_score', verdict.get('confidence', 0)):.2f})")

        return verdict


# 使用示例
if __name__ == '__main__':
    from v12_subgraph_classifier import V12SubgraphClassifier

    # 初始化分类器
    classifier = V12SubgraphClassifier(api_key='your_api_key')

    # 初始化并行分析器（5个并发线程）
    parallel_analyzer = ParallelSubgraphAnalyzer(classifier, max_workers=5)

    # 模拟子图数据
    subgraph_jsons = [
        {'subgraph_name': 'subgraph_1', 'dangerous_nodes': [], 'data_flow_paths': [], 'functions': []},
        {'subgraph_name': 'subgraph_2', 'dangerous_nodes': [], 'data_flow_paths': [], 'functions': []},
        # ... 更多子图
    ]

    # 并行分析
    results = parallel_analyzer.analyze_subgraphs_parallel(
        subgraph_jsons=subgraph_jsons,
        package_name='test_package',
        ddg_v7_report={},
        skip_rule_scoring=True
    )

    print(f"\n分析完成！共处理 {len(results)} 个子图")
