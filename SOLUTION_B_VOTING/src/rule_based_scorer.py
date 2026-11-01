"""
规则化评分系统 - 基于SpiderScan、PROFMAL、MALGUARD的维度化评分

核心思想：
1. 5个评分维度（每个有明确上限）
2. 规则化指标（每个指标有明确分值）
3. 总分封顶（1.0）
4. 分类阈值（>=0.7恶意, >=0.4可疑, <0.4良性）

参考论文：
- SpiderScan: 5维度行为建模 + 明确阈值
- PROFMAL: 静动结合行为分析 + 规则化
- MALGUARD: API敏感度权重计算
"""

from typing import Dict, List, Optional
from dataclasses import dataclass
from enum import Enum


class AttackChainType(Enum):
    """攻击链类型"""
    CODE_INJECTION = "code_injection"
    COMMAND_INJECTION = "command_injection"
    DATA_EXFILTRATION = "data_exfiltration"
    CREDENTIAL_THEFT = "credential_theft"
    PATH_TRAVERSAL = "path_traversal"
    SSRF = "ssrf"
    XSS = "xss"
    SQL_INJECTION = "sql_injection"
    SUSPICIOUS = "suspicious"
    BENIGN = "benign"


@dataclass
class DimensionScore:
    """维度分数"""
    dimension_name: str
    max_score: float
    raw_score: float
    final_score: float  # 封顶后的分数
    indicators_found: List[str]
    details: str


class RuleBasedScorer:
    """规则化评分器"""

    # 定义5个评分维度（参考SpiderScan）
    DIMENSIONS = {
        'data_exfiltration': {
            'max_score': 0.35,
            'name': 'Data Exfiltration',
            'indicators': {
                # 网络Sink（最高权重）
                'has_network_sink': 0.20,
                'has_suspicious_domain': 0.05,
                'has_external_ip': 0.05,
                # 敏感Source
                'has_sensitive_source': 0.10,
                # 完整性加成
                'complete_chain': 0.05,
            }
        },
        'code_execution': {
            'max_score': 0.30,
            'name': 'Code Execution',
            'indicators': {
                # 危险执行（最高权重）
                'has_eval_exec': 0.20,
                'has_system_call': 0.10,
                # 完整性要求
                'complete_chain': 0.00,  # 必须完整，不完整不得分
            }
        },
        'credential_theft': {
            'max_score': 0.20,
            'name': 'Credential Theft',
            'indicators': {
                'accesses_ssh_keys': 0.10,
                'accesses_env_vars': 0.05,
                'accesses_aws_credentials': 0.05,
                'exfiltrates_data': 0.05,
            }
        },
        'persistence': {
            'max_score': 0.10,
            'name': 'Persistence',
            'indicators': {
                'modifies_startup_files': 0.10,
                'installs_hooks': 0.10,
            }
        },
        'suspicious_behaviors': {
            'max_score': 0.05,
            'name': 'Suspicious Behaviors',
            'indicators': {
                'obfuscation_detected': 0.03,
                'anti_analysis_detected': 0.02,
                'typosquatting_detected': 0.05,
            }
        }
    }

    # 分类阈值（参考SpiderScan）
    THRESHOLDS = {
        'malicious': 0.70,
        'suspicious': 0.40,
        'benign': 0.0
    }

    def __init__(self):
        """初始化评分器"""
        pass

    def score_subgraph(self, subgraph: Dict, ddg_v7_report: Optional[Dict] = None) -> Dict:
        """
        对子图进行规则化评分

        Args:
            subgraph: 子图数据
            ddg_v7_report: DDG V7安全报告（可选，用于补充信息）

        Returns:
            {
                'dimension_scores': {...},
                'total_score': 0.85,
                'category': 'MALICIOUS',
                'confidence': 0.90,
                'evidence_chain': {...}
            }
        """
        print(f"          [Scorer] 开始规则化评分...")

        dimension_scores = {}
        total_score = 0.0

        # 对每个维度评分
        for dim_key, dim_config in self.DIMENSIONS.items():
            dimension_score = self._score_dimension(
                dim_key,
                subgraph,
                ddg_v7_report
            )
            dimension_scores[dim_key] = dimension_score
            total_score += dimension_score.final_score

        # 总分封顶（参考PROFMAL）
        total_score = min(total_score, 1.0)

        # 分类（参考SpiderScan阈值）
        category = self._classify(total_score)

        # 置信度计算（基于维度一致性）
        confidence = self._calculate_confidence(dimension_scores, total_score, category)

        # 打印结果
        print(f"          [Scorer] 总分: {total_score:.2f}")
        print(f"          [Scorer] 分类: {category}")
        print(f"          [Scorer] 置信度: {confidence:.2f}")

        return {
            'dimension_scores': {
                dim_key: {
                    'name': dim_config['name'],
                    'max_score': dim_config['max_score'],
                    'raw_score': ds.raw_score,
                    'final_score': ds.final_score,
                    'indicators_found': ds.indicators_found,
                    'details': ds.details
                }
                for dim_key, ds in dimension_scores.items()
            },
            'total_score': total_score,
            'category': category,
            'confidence': confidence,
            'scoring_method': 'rule_based'  # 标记方法
        }

    def _score_dimension(
        self,
        dimension_key: str,
        subgraph: Dict,
        ddg_v7_report: Optional[Dict]
    ) -> DimensionScore:
        """对单个维度评分"""
        dim_config = self.DIMENSIONS[dimension_key]
        indicators_config = dim_config['indicators']

        raw_score = 0.0
        indicators_found = []

        # 检查每个指标
        for indicator_name, indicator_points in indicators_config.items():
            if self._check_indicator(subgraph, ddg_v7_report, dimension_key, indicator_name):
                raw_score += indicator_points
                indicators_found.append(indicator_name)

        # 维度封顶（参考PROFMAL）
        final_score = min(raw_score, dim_config['max_score'])

        # 生成详情
        details = self._generate_dimension_details(dimension_key, indicators_found)

        return DimensionScore(
            dimension_name=dim_config['name'],
            max_score=dim_config['max_score'],
            raw_score=raw_score,
            final_score=final_score,
            indicators_found=indicators_found,
            details=details
        )

    def _check_indicator(
        self,
        subgraph: Dict,
        ddg_v7_report: Optional[Dict],
        dimension: str,
        indicator: str
    ) -> bool:
        """检查指标是否满足"""
        # 根据维度和指标调用相应的检测函数
        check_functions = {
            ('data_exfiltration', 'has_network_sink'): self._has_network_sink,
            ('data_exfiltration', 'has_suspicious_domain'): self._has_suspicious_domain,
            ('data_exfiltration', 'has_external_ip'): self._has_external_ip,
            ('data_exfiltration', 'has_sensitive_source'): self._has_sensitive_source,
            ('data_exfiltration', 'complete_chain'): self._is_complete_chain,
            ('code_execution', 'has_eval_exec'): self._has_eval_exec,
            ('code_execution', 'has_system_call'): self._has_system_call,
            ('code_execution', 'complete_chain'): self._is_complete_chain,
            ('credential_theft', 'accesses_ssh_keys'): self._accesses_ssh_keys,
            ('credential_theft', 'accesses_env_vars'): self._accesses_env_vars,
            ('credential_theft', 'accesses_aws_credentials'): self._accesses_aws_credentials,
            ('credential_theft', 'exfiltrates_data'): self._exfiltrates_data,
            ('persistence', 'modifies_startup_files'): self._modifies_startup_files,
            ('persistence', 'installs_hooks'): self._installs_hooks,
            ('suspicious_behaviors', 'obfuscation_detected'): self._obfuscation_detected,
            ('suspicious_behaviors', 'anti_analysis_detected'): self._anti_analysis_detected,
            ('suspicious_behaviors', 'typosquatting_detected'): self._typosquatting_detected,
        }

        func = check_functions.get((dimension, indicator))
        if func:
            return func(subgraph, ddg_v7_report)
        return False

    def _classify(self, score: float) -> str:
        """根据分数分类"""
        if score >= self.THRESHOLDS['malicious']:
            return "MALICIOUS"
        elif score >= self.THRESHOLDS['suspicious']:
            return "SUSPICIOUS"
        else:
            return "BENIGN"

    def _calculate_confidence(
        self,
        dimension_scores: Dict[str, DimensionScore],
        total_score: float,
        category: str
    ) -> float:
        """
        计算置信度（基于维度一致性）

        参考PyPI论文的因子计算方法
        """
        base = 0.50

        # 正面因子
        positive_factors = {
            'all_dimensions_aligned': 0.10,  # 所有维度指向同一方向
            'complete_attack_chain': 0.20,   # 有完整攻击链
            'high_risk_sink': 0.15,           # 高危sink
            'multiple_dimensions': 0.10,     # 多个维度有证据
        }

        # 负面因子
        negative_factors = {
            'no_complete_chain': -0.20,      # 无完整攻击链
            'single_dimension': -0.10,       # 仅单个维度有证据
            'low_score': -0.15,              # 总分低但声称恶意
        }

        # 检查因子
        # 1. 维度一致性
        active_dimensions = [d for d in dimension_scores.values() if d.final_score > 0]
        if len(active_dimensions) >= 3:
            base += positive_factors['all_dimensions_aligned']
        elif len(active_dimensions) == 1:
            base += negative_factors['single_dimension']

        # 2. 完整攻击链
        if self._has_complete_attack_chain(dimension_scores):
            base += positive_factors['complete_attack_chain']
        else:
            base += negative_factors['no_complete_chain']

        # 3. 高危sink
        if self._has_high_risk_sink(dimension_scores):
            base += positive_factors['high_risk_sink']

        # 4. 总分与类别一致性
        # （清理：原先两个分支 MALICIOUS&&total<0.5 / BENIGN&&total>0.6 与
        # 分类阈值 0.70/0.40 矛盾，永不触发，属于死代码，已删除）

        # 封顶
        confidence = min(max(base, 0.0), 1.0)

        return confidence

    def _has_complete_attack_chain(self, dimension_scores: Dict) -> bool:
        """检查是否有完整攻击链"""
        code_exec = dimension_scores.get('code_execution')
        if code_exec and 'complete_chain' in code_exec.indicators_found:
            return True
        return False

    def _has_high_risk_sink(self, dimension_scores: Dict) -> bool:
        """检查是否有高危sink"""
        code_exec = dimension_scores.get('code_execution')
        if code_exec and ('has_eval_exec' in code_exec.indicators_found or
                           'has_system_call' in code_exec.indicators_found):
            return True
        return False

    # === 指标检测函数 ===

    def _has_network_sink(self, subgraph: Dict, ddg_v7_report: Optional[Dict]) -> bool:
        """检测网络sink"""
        dangerous_nodes = subgraph.get('dangerous_nodes', [])
        for node in dangerous_nodes:
            code = node.get('code', '').lower()
            if any(api in code for api in ['requests.', 'urllib.', 'http.', 'socket.']):
                return True
        return False

    def _has_suspicious_domain(self, subgraph: Dict, ddg_v7_report: Optional[Dict]) -> bool:
        """检测可疑域名"""
        if ddg_v7_report:
            network = ddg_v7_report.get('network_behavior', {})
            suspicious_domains = network.get('suspicious_domains', [])
            if len(suspicious_domains) > 0:
                return True
        return False

    def _has_external_ip(self, subgraph: Dict, ddg_v7_report: Optional[Dict]) -> bool:
        """检测外部IP"""
        if ddg_v7_report:
            network = ddg_v7_report.get('network_behavior', {})
            ips = network.get('ips', [])
            if len(ips) > 0:
                return True
        return False

    def _has_sensitive_source(self, subgraph: Dict, ddg_v7_report: Optional[Dict]) -> bool:
        """检测敏感source"""
        data_flow_paths = subgraph.get('data_flow_paths', [])
        for path in data_flow_paths:
            for node in path:
                if isinstance(node, dict):
                    code = node.get('code', '').lower()
                    if any(pattern in code for pattern in ['.ssh/', '/.aws/', '.env', 'credential']):
                        return True
        return False

    def _is_complete_chain(self, subgraph: Dict, ddg_v7_report: Optional[Dict]) -> bool:
        """检测是否为完整攻击链"""
        # 均衡模式扩充 Source：PyPI 恶意包的真实数据源是环境变量/文件读取/
        # base64 解码，原先只有 request./input( 两个模式，complete_chain 几乎恒假
        source_patterns = [
            'request.', 'input(', 'os.environ', 'getenv',
            'open(', '.read(', 'readlines', 'b64decode', 'urlopen',
        ]
        sink_patterns = [
            'eval(', 'exec(', 'compile(', 'os.system', 'subprocess.', 'popen',
        ]
        data_flow_paths = subgraph.get('data_flow_paths', [])
        for path in data_flow_paths:
            has_source = any(any(p in str(node.get('code', '')).lower() for p in source_patterns)
                             for node in path if isinstance(node, dict))
            has_sink = any(any(p in str(node.get('code', '')).lower() for p in sink_patterns)
                           for node in path if isinstance(node, dict))
            if has_source and has_sink:
                return True
        return False

    def _has_eval_exec(self, subgraph: Dict, ddg_v7_report: Optional[Dict]) -> bool:
        """检测eval/exec"""
        dangerous_nodes = subgraph.get('dangerous_nodes', [])
        for node in dangerous_nodes:
            code = node.get('code', '').lower()
            if any(api in code for api in ['eval(', 'exec(', 'compile(']):
                return True
        return False

    def _has_system_call(self, subgraph: Dict, ddg_v7_report: Optional[Dict]) -> bool:
        """检测system调用"""
        dangerous_nodes = subgraph.get('dangerous_nodes', [])
        for node in dangerous_nodes:
            code = node.get('code', '').lower()
            if any(api in code for api in ['os.system', 'subprocess.', 'popen']):
                return True
        return False

    def _accesses_ssh_keys(self, subgraph: Dict, ddg_v7_report: Optional[Dict]) -> bool:
        """检测SSH key访问"""
        if ddg_v7_report:
            fs_ops = ddg_v7_report.get('file_system_ops', {})
            sensitive_paths = fs_ops.get('sensitive_paths', [])
            for path in sensitive_paths:
                if '.ssh' in str(path):
                    return True
        return False

    def _accesses_env_vars(self, subgraph: Dict, ddg_v7_report: Optional[Dict]) -> bool:
        """检测环境变量访问"""
        if ddg_v7_report:
            fs_ops = ddg_v7_report.get('file_system_ops', {})
            sensitive_paths = fs_ops.get('sensitive_paths', [])
            for path in sensitive_paths:
                if '.env' in str(path) or 'environ' in str(path):
                    return True
        return False

    def _accesses_aws_credentials(self, subgraph: Dict, ddg_v7_report: Optional[Dict]) -> bool:
        """检测AWS凭证访问"""
        if ddg_v7_report:
            fs_ops = ddg_v7_report.get('file_system_ops', {})
            sensitive_paths = fs_ops.get('sensitive_paths', [])
            for path in sensitive_paths:
                if '.aws' in str(path) or 'credentials' in str(path):
                    return True
        return False

    def _exfiltrates_data(self, subgraph: Dict, ddg_v7_report: Optional[Dict]) -> bool:
        """检测数据外传"""
        return self._has_network_sink(subgraph, ddg_v7_report)

    def _modifies_startup_files(self, subgraph: Dict, ddg_v7_report: Optional[Dict]) -> bool:
        """检测启动文件修改"""
        if ddg_v7_report:
            fs_ops = ddg_v7_report.get('file_system_ops', {})
            file_writes = fs_ops.get('file_writes', [])
            for write in file_writes:
                path = write.get('path', '')
                if any(pattern in path for pattern in ['/etc/systemd', '/usr/lib/systemd', '~/.bashrc']):
                    return True
        return False

    def _installs_hooks(self, subgraph: Dict, ddg_v7_report: Optional[Dict]) -> bool:
        """检测安装钩子"""
        if ddg_v7_report:
            metadata = ddg_v7_report.get('metadata', {})
            hooks = metadata.get('setup_hooks', [])
            if len(hooks) > 0:
                return True
        return False

    def _obfuscation_detected(self, subgraph: Dict, ddg_v7_report: Optional[Dict]) -> bool:
        """检测混淆"""
        if ddg_v7_report:
            obfuscation = ddg_v7_report.get('obfuscation_metrics', {})
            level = obfuscation.get('obfuscation_level', 'LOW')
            if level != 'LOW':
                return True
        return False

    def _anti_analysis_detected(self, subgraph: Dict, ddg_v7_report: Optional[Dict]) -> bool:
        """检测反分析"""
        # 这里可以添加反分析检测逻辑
        # 例如：检测虚拟机检测、调试器检测等
        return False

    def _typosquatting_detected(self, subgraph: Dict, ddg_v7_report: Optional[Dict]) -> bool:
        """检测Typosquatting"""
        if ddg_v7_report:
            typosquatting = ddg_v7_report.get('typosquatting', {})
            return typosquatting.get('is_suspicious', False)
        return False

    def _generate_dimension_details(self, dimension: str, indicators_found: List[str]) -> str:
        """生成维度详情"""
        if not indicators_found:
            return f"No indicators found for {dimension}"

        return f"Indicators: {', '.join(indicators_found)}"


def test_scorer():
    """测试评分器"""
    import json

    # 模拟子图数据（恶意包）
    malicious_subgraph = {
        'subgraph_name': 'subgraph_1',
        'dangerous_nodes': [
            {'code': 'eval(user_input)', 'node_id': 'n1'},
            {'code': 'data = requests.get("http://evil.com")', 'node_id': 'n2'},
        ],
        'data_flow_paths': [
            [{'code': 'user_input = request.form.get("data")', 'node_id': 'n3'},
             {'code': 'eval(user_input)', 'node_id': 'n1'}]
        ],
        'functions': {'process': [{'node': {'code': 'def process():'}}]}
    }

    # 模拟DDG V7报告
    ddg_report = {
        'network_behavior': {
            'suspicious_domains': [{'domain': 'evil.tk'}],
            'ips': ['192.168.1.1']
        },
        'file_system_ops': {
            'sensitive_paths': ['.ssh/id_rsa'],
            'file_writes': [{'path': '/root/.bashrc'}]
        },
        'metadata': {
            'setup_hooks': [{'type': 'cmdclass', 'hook_type': 'install'}]
        },
        'typosquatting': {
            'is_suspicious': True,
            'target_package': 'requests'
        },
        'obfuscation_metrics': {
            'obfuscation_level': 'HIGH'
        }
    }

    scorer = RuleBasedScorer()
    result = scorer.score_subgraph(malicious_subgraph, ddg_report)

    print(f"\n=== 评分结果 ===")
    print(f"总分: {result['total_score']:.2f}")
    print(f"分类: {result['category']}")
    print(f"置信度: {result['confidence']:.2f}")

    print(f"\n=== 维度分数 ===")
    for dim_key, dim_score in result['dimension_scores'].items():
        print(f"{dim_score['name']}: {dim_score['final_score']:.2f} / {dim_score['max_score']:.2f}")
        print(f"  指标: {', '.join(dim_score['indicators_found'])}")


if __name__ == '__main__':
    test_scorer()
