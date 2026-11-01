"""
batch_v20_complete_voting.py - Solution B 投票架构实现

核心改进：
1. 每个子图独立LLM分析（保留完整攻击链语义）
2. 投票机制决定包分类（顶会标准）
3. 详细记录每个子图的判决证据
"""

import json
import re
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional
from collections import defaultdict
from zhipuai import ZhipuAI
import gc  # 🔧 添加垃圾回收模块，用于内存管理

# 导入Solution B V2的模块
# Solution B的src在SOLUTION_B_VOTING子目录中
solution_b_src = Path(__file__).parent / 'SOLUTION_B_VOTING' / 'src'
sys.path.insert(0, str(solution_b_src))
solution_b_parallel = Path(__file__).parent / 'SOLUTION_B_VOTING'
sys.path.insert(0, str(solution_b_parallel))

# 主项目的ddg_builder_v7需要作为包导入（因为它使用相对导入）
# 添加项目根目录到路径
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

# 现在使用绝对导入
from src.ddg_builder_v7 import ProjectDDGBuilderV7 as DDGBuilderV7

# Solution B的模块（直接导入模块名）
from v12_subgraph_classifier import V12SubgraphClassifier
from v12_obfuscation_detector import V12ObfuscationDetector
from subgraph_prioritizer import SubgraphPrioritizer
from rule_based_scorer import RuleBasedScorer
from parallel_subgraph_classifier import ParallelSubgraphAnalyzer

# 增强检测器（检测setup.py/依赖/元数据威胁）
from src.enhanced_detector import EnhancedSecurityDetector

# 攻击链重建器（从DDG节点/边重建 数据引入→处理→危险执行→外传 四阶段攻击链）
from src.attack_chain_rebuilder import AttackChainRebuilder


class BatchAnalyzerV20Voting:
    """批量分析器 V20 - 投票架构"""

    def __init__(self, tarfile_dir: str, llm: str = 'glm', api_key: str = '', count: int = 100, extract_base: str = 'output/packages', skip_rule_scoring: bool = False, parallel_workers: int = 1, seed: int = 42, verify_pypi: bool = False, use_llm_cache: bool = True, sandbox: bool = False,
                llm_model: str = 'glm-4-flashx'):
        self.tarfile_dir = Path(tarfile_dir)
        self.llm = llm
        self.api_key = api_key
        self.count = count
        self.extract_base = Path(extract_base)
        self.skip_rule_scoring = skip_rule_scoring
        self.parallel_workers = parallel_workers  # 并行线程数（>1 时高优先级子图并行LLM分析）
        self.seed = seed  # 抽样随机种子（可复现评测）
        self.verify_pypi = verify_pypi  # 是否核验包是否存在于 PyPI（名称抢注判据）
        self.use_llm_cache = use_llm_cache  # LLM 判决缓存（--no-llm-cache 关闭）
        self.sandbox = sandbox  # 沙箱行为探针(执行 setup.py,仅隔离环境启用!)
        self.llm_model = llm_model  # LLM 模型名(--llm-model)
        self.results = []
        self.results_jsonl = None  # 增量落盘文件（analyze_all 时初始化）

        # 初始化增强检测器（检测setup.py/依赖/元数据威胁）
        self.enhanced_detector = EnhancedSecurityDetector()

        # 创建 output 目录结构
        self.extract_base.mkdir(parents=True, exist_ok=True)
        print(f"[输出目录] 所有结果将保存到: output/")
        print(f"  - 解压包: {self.extract_base}")
        print(f"  - 分析结果: output/results/")

    def analyze_all(self):
        """分析所有包（支持.tar.gz文件和文件夹）"""
        import random

        # 可复现抽样（原先无种子，每次评测结果不可复现）
        random.seed(self.seed)

        # 收集所有输入（tar.gz文件 + 文件夹）
        all_inputs = []

        # 1. 递归查找所有.tar.gz文件（包括子目录）
        all_tarfiles = list(self.tarfile_dir.rglob('*.tar.gz'))
        all_inputs.extend([(f, 'file') for f in all_tarfiles])

        # 2. 查找所有文件夹（排除.ddg_output和隐藏目录）
        if self.tarfile_dir.exists() and self.tarfile_dir.is_dir():
            for item in self.tarfile_dir.iterdir():
                if item.is_dir() and not item.name.startswith('.'):
                    # 排除非包目录（如output, src等）
                    if item.name not in ['output', 'src', 'SOLUTION_B_VOTING', 'prompts', 'scripts']:
                        all_inputs.append((item, 'dir'))

        print(f"找到 {len(all_tarfiles)} 个tar.gz文件（递归搜索）")
        print(f"找到 {len(all_inputs) - len(all_tarfiles)} 个文件夹")

        # 随机选择包
        if len(all_inputs) > self.count:
            inputs = random.sample(all_inputs, self.count)
            print(f"从 {len(all_inputs)} 个输入中随机选择 {self.count} 个（seed={self.seed}）")
        else:
            inputs = all_inputs
            print(f"分析全部 {len(inputs)} 个输入")

        # 增量落盘：每包一行 JSONL，批次结束再写汇总 JSON——
        # 原先结果只在最后一次性写出，中途崩溃全部丢失
        results_dir = Path('output/results')
        results_dir.mkdir(parents=True, exist_ok=True)
        self.results_jsonl = results_dir / f'batch_v20_voting_results_{int(time.time())}.jsonl'
        print(f"[输出目录] 增量结果: {self.results_jsonl}")

        for idx, (input_path, input_type) in enumerate(inputs, 1):
            print(f"\n{'='*80}")
            print(f"[{idx}/{len(inputs)}] 分析: {input_path.name} ({'文件' if input_type == 'file' else '文件夹'})")
            print(f"{'='*80}")

            try:
                result = self.analyze_package(input_path, input_type)
            except Exception as e:
                print(f"[ERROR] 分析失败: {e}")
                import traceback
                traceback.print_exc()
                # 修复：失败的包原先静默丢失（统计上等于漏检），
                # 现在记录为 ANALYSIS_FAILED 终态
                result = {
                    'package_name': input_path.name,
                    'final_category': 'ANALYSIS_FAILED',
                    'final_risk_score': 0.5,
                    'final_confidence': 0.3,
                    'error': str(e)[:300],
                }

            self.results.append(result)
            # 逐包追加落盘
            try:
                with open(self.results_jsonl, 'a', encoding='utf-8') as f:
                    f.write(json.dumps(result, ensure_ascii=False, default=str) + '\n')
            except Exception as write_err:
                print(f"[WARN] 增量写入失败: {write_err}")

            # 打印摘要（兼容混淆包和非混淆包）
            print(f"\n[结果摘要]")
            print(f"  分类: {result['final_category']}")
            print(f"  风险评分: {result['final_risk_score']:.2f}")
            print(f"  置信度: {result['final_confidence']:.2f}")
            # 混淆包/失败包没有子图信息，跳过
            if result['final_category'] not in ('OBFUSCATED', 'ANALYSIS_FAILED'):
                print(f"  子图数量: {result.get('total_subgraphs', 0)}")
                print(f"  恶意子图数: {result.get('malicious_subgraph_count', 0)}")

            # 🔧 强制释放内存，防止累积导致OOM
            gc.collect()

        # 保存结果
        self._save_results()

    def analyze_package(self, input_path: Path, input_type: str = 'file') -> Dict:
        """分析单个包（投票架构）- 支持文件和文件夹

        Args:
            input_path: 输入路径（tar.gz文件 或 文件夹）
            input_type: 输入类型 ('file' 或 'dir')
        """
        # 确定包名和包目录
        dist_name = None
        if input_type == 'file':
            # 发行包名（文件名）是名称抢注检测的关键证据，不能被子目录名覆盖
            dist_name = input_path.name.replace('.tar.gz', '')
            package_name = dist_name
            package_dir = self.extract_base / package_name

            print(f"[Step 1/5] 解压包...")
            self._extract_tarfile(input_path, package_dir)
            # tar 内顶级目录名可能与 tar 文件名不一致，以实际解压结果为准
            if not package_dir.exists():
                actual_dir = self._resolve_extracted_dir(input_path, self.extract_base)
                if actual_dir:
                    print(f"          [INFO] 内层目录 {actual_dir.name} 与发行名 {dist_name} 不一致"
                          f"（名称抢注信号），分析目录: {actual_dir.name}")
                    package_dir = actual_dir
        else:
            # 文件夹输入，直接使用
            package_name = input_path.name
            package_dir = input_path
            print(f"[Step 1/5] 跳过解压（使用现有文件夹）...")

        print(f"[Step 2/5] 运行DDG Builder V7...")
        ddg_output = self._run_ddg_builder(package_dir)

        print(f"[Step 3/5] 读取DDG V7安全报告和子图数据...")
        ddg_v7_report = self._read_ddg_v7_report(package_dir)
        subgraph_jsons = self._read_subgraph_jsons(package_dir)

        # 读取重建的四阶段攻击链（数据引入→处理→危险执行→外传）
        attack_chains_summary = self._read_attack_chains(package_dir)
        if attack_chains_summary['chain_count'] > 0:
            print(f"          [攻击链] {attack_chains_summary['chain_count']} 条, "
                  f"完整性={attack_chains_summary['completeness']}, "
                  f"置信度={attack_chains_summary['confidence']}")

        # 顺序调整（2026-10 大改）：增强检测（纯正则，便宜）先跑，只有 critical
        # 才短路 MALICIOUS；原先混淆短路在前，恶意混淆包只会拿到 OBFUSCATED
        # 标签，setup.py 安装钩子等威胁被整体吞掉。high 及以下作为上下文进投票。
        print(f"[Step 4/6] 增强检测（setup.py/依赖/元数据/包名）...")
        enhanced_detection_result = self.enhanced_detector.analyze_package(
            package_dir, dist_name=dist_name or package_name,
            verify_pypi=self.verify_pypi)

        # 均衡模式：只有 critical 级（真安装钩子+危险API/typosquatting/暗网）
        # 直通 MALICIOUS；high 降级进投票上下文，避免单条正则判死正常包
        if enhanced_detection_result['overall_threat_level'] == 'critical':
            print(f"[快速判定] 增强检测发现critical级别威胁！")
            print(f"  - setup.py威胁: {enhanced_detection_result['setup_py_analysis']['threat_level']}")
            print(f"  - 依赖威胁: {enhanced_detection_result['dependency_analysis']['threat_level']}")
            print(f"  - 元数据威胁: {enhanced_detection_result['metadata_analysis']['threat_level']}")

            # 构建恶意包结果
            final_result = {
                'package_name': package_name,
                'final_category': 'MALICIOUS',
                'final_risk_score': 0.95,
                'final_confidence': 0.85,
                'enhanced_threat_level': enhanced_detection_result['overall_threat_level'],
                'enhanced_threats': enhanced_detection_result['threats_found'],
                'threat_details': {
                    'setup_py': enhanced_detection_result['setup_py_analysis'],
                    'dependency': enhanced_detection_result['dependency_analysis'],
                    'metadata': enhanced_detection_result['metadata_analysis'],
                    'distribution': enhanced_detection_result.get('distribution_analysis', {}),
                },
                'ddg_risk_level': ddg_v7_report.get('risk_level', 'unknown'),
                'ddg_issues': ddg_v7_report.get('total_issues', 0),
                'attack_chains': attack_chains_summary,
                'detection_method': 'enhanced_detection'  # 标记检测方式
            }
            return final_result

        # 2026-10 行为模态(可选):沙箱探针——执行 setup.py 记录安装期
        # 网络/子进程行为。**会执行包内代码,仅在隔离 VM/容器启用!**
        if self.sandbox:
            try:
                from src.sandbox_probe import probe_setup_py
                sandbox_result = probe_setup_py(str(package_dir))
                enhanced_detection_result['sandbox'] = sandbox_result
                if sandbox_result['behavioral_level'] == 'high':
                    print(f"[快速判定] 沙箱捕获安装期行为: {sandbox_result['reason']}")
                    final_result = {
                        'package_name': package_name,
                        'final_category': 'MALICIOUS',
                        'final_risk_score': 0.95,
                        'final_confidence': 0.9,
                        'sandbox': sandbox_result,
                        'ddg_risk_level': ddg_v7_report.get('risk_level', 'unknown'),
                        'ddg_issues': ddg_v7_report.get('total_issues', 0),
                        'attack_chains': attack_chains_summary,
                        'detection_method': 'sandbox_probe',
                    }
                    return final_result
            except Exception as sbx_e:
                print(f"[WARN] 沙箱探针失败: {sbx_e}")

        print(f"[Step 4.5/6] 混淆检测（静态分析）...")
        # 使用基于静态分析的混淆检测（不调用LLM）
        obfuscation_result_internal = self._detect_obfuscation(
            str(package_dir),
            ddg_v7_report
        )

        # 转换为期望的格式
        obfuscation_result = {
            'is_obfuscated': obfuscation_result_internal['is_obfuscated'],
            'obfuscation_score': obfuscation_result_internal['obfuscation_score'],
            'obfuscation_type': 'static_analysis',
            'needs_stub_generation': obfuscation_result_internal['is_obfuscated'],
            'suspicious_patterns': list(obfuscation_result_internal['indicators'].keys()),
            'hidden_malicious_behaviors': [],
            'reason': obfuscation_result_internal['reasoning']
        }

        # 如果检测到混淆，直接标记为混淆包，跳过恶意分析
        if obfuscation_result['is_obfuscated']:
            print(f"[快速判定] 检测到混淆（{obfuscation_result['obfuscation_type']}），标记为混淆包，跳过恶意分析")
            # 精简格式：只保留核心字段（混淆分上限封顶到 1.0）
            final_result = {
                'package_name': package_name,
                'final_category': 'OBFUSCATED',
                'final_risk_score': 0.95,
                'final_confidence': min(obfuscation_result['obfuscation_score'], 1.0),
                'obfuscation_score': min(obfuscation_result['obfuscation_score'], 1.0),
                'obfuscation_reason': obfuscation_result['reason'][:200] if obfuscation_result.get('reason') else 'Obfuscation detected',  # 限制长度
                'ddg_risk_level': ddg_v7_report.get('risk_level', 'unknown'),
                'ddg_issues': ddg_v7_report.get('total_issues', 0),
                'attack_chains': attack_chains_summary,
                'needs_stub_generation': True,
            }
            return final_result

        print(f"[Step 5/6] 投票架构LLM分析（未检测到混淆，进行恶意分析）...")
        voting_result = self._v12_voting_classify_by_subgraphs(
            subgraph_jsons,
            Path(package_dir),  # 修复：转换为Path对象
            ddg_v7_report,
            enhanced_detection_result
        )

        print(f"[Step 6/6] 合并结果...")
        # 精简结果格式：只保留核心字段

        # 从DDG报告中提取关键信息
        ddg_risk_level = ddg_v7_report.get('risk_level', 'unknown')
        ddg_issues = ddg_v7_report.get('total_issues', 0)

        # 精简subgraph_verdicts（只保留关键字段）
        simplified_verdicts = []
        for verdict in voting_result['subgraph_verdicts']:
            simplified_verdict = {
                'subgraph_name': verdict.get('subgraph_name', 'unknown'),
                'attack_chain_type': verdict.get('attack_chain_type', 'Unknown'),
                'is_malicious': verdict.get('is_malicious', False),
                'final_verdict': verdict.get('final_verdict', 'UNKNOWN'),
            }
            # 如果是恶意子图，添加关键特征
            if verdict.get('is_malicious'):
                simplified_verdict['danger_score'] = verdict.get('risk_score', 0.5)
                simplified_verdict['attack_chain_complete'] = verdict.get('attack_chain_complete', False)
                simplified_verdict['key_info'] = verdict.get('key_info', verdict.get('reasoning', ''))[:200]
            simplified_verdicts.append(simplified_verdict)

        # 2026-11 包级 LLM 聚合分析：所有子图分析完后，LLM 综观全部证据
        # 做最终全局判断（替代机械投票——投票不理解"1个可疑比83个良性重要"）
        if voting_result['final_category'] in ('SUSPICIOUS',) or (
                voting_result['final_category'] == 'MALICIOUS'
                and voting_result.get('malicious_count', 0) <= 2):
            # 只在"边界情况"时做包级聚合（明确 MALICIOUS/明确 BENIGN 跳过）
            try:
                agg = self._package_level_analysis(
                    package_name, voting_result, ddg_v7_report,
                    enhanced_detection_result, attack_chains_summary,
                    obfuscation_result, package_dir=package_dir)
                if agg and agg.get('final_category'):
                    old_cat = voting_result['final_category']
                    voting_result['final_category'] = agg['final_category']
                    voting_result['final_risk_score'] = agg['risk_score']
                    voting_result['final_confidence'] = agg['confidence']
                    voting_result['voting_summary'] = (
                        f"[Package-level LLM] {old_cat} → {agg['final_category']}: "
                        f"{agg.get('reasoning', '')[:200]}")
                    print(f"        [Package-level LLM] {old_cat} → {agg['final_category']}")
            except Exception as agg_e:
                print(f"        [WARN] Package-level analysis failed: {agg_e}")

        # 精简格式：只保留核心字段
        final_result = {
            'package_name': package_name,
            'final_category': voting_result['final_category'],
            'final_risk_score': voting_result['final_risk_score'],
            'final_confidence': voting_result['final_confidence'],
            'total_subgraphs': len(subgraph_jsons),
            'malicious_subgraph_count': voting_result['malicious_count'],
            'subgraph_verdicts': simplified_verdicts,
            'ddg_risk_level': ddg_risk_level,
            'ddg_issues': ddg_issues,
            # LLM 不可用时为 True（结果为规则回退，置信度应打折看待）
            'analysis_degraded': voting_result.get('analysis_degraded', False),
            # 重建的四阶段攻击链（证据可解释性）
            'attack_chains': attack_chains_summary,
            # 增强检测结果（总是包含）
            'enhanced_detection': {
                'threat_level': enhanced_detection_result['overall_threat_level'],
                'threats_found': len(enhanced_detection_result['threats_found']),
                'setup_py_threats': enhanced_detection_result['setup_py_analysis']['has_threats'],
                'dependency_threats': enhanced_detection_result['dependency_analysis']['has_threats'],
                'metadata_threats': enhanced_detection_result['metadata_analysis']['has_threats'],
                'distribution_threats': enhanced_detection_result.get(
                    'distribution_analysis', {}).get('has_threats', False),
            }
        }

        return final_result

    def _package_level_analysis(self, package_name, voting_result,
                                ddg_v7_report, enhanced_detection_result,
                                attack_chains_summary, obfuscation_result,
                                package_dir=None):
        """包级 LLM 聚合分析(2026-11):所有通道跑完后综合判断

        与投票的区别:
        - 投票: 机械计数(几个恶意/几个良性/几个可疑)
        - 本步骤: LLM 综观全部证据(通道信号+摘要+污点链+混淆+核验)
        → 能理解"1个高危子图比83个良性重要"
        → 能理解"包级混淆信号被函数分割稀释但整体可疑"
        → 能在边界情况(SUSPICIOUS/低count MALICIOUS)做语义判断
        """
        if not self.api_key or self.api_key == 'dummy':
            return None

        # 汇总所有信号
        signals = []
        ed = enhanced_detection_result or {}
        signals.append(f"Enhanced detection: {ed.get('overall_threat_level', 'safe')} "
                       f"({ed.get('threats_found', 0)} threats)")
        if ed.get('distribution_analysis', {}).get('has_threats'):
            dist = ed['distribution_analysis']
            signals.append(f"Distribution: {dist.get('dist_name','')} vs {dist.get('metadata_name','')}")
        pypi = ed.get('pypi_verification', {})
        if pypi.get('status') and pypi['status'] != 'skipped':
            signals.append(f"PyPI verification: {pypi['status']}")
        if obfuscation_result and obfuscation_result.get('obfuscation_score', 0) > 0:
            signals.append(f"Obfuscation score: {obfuscation_result['obfuscation_score']:.2f}")
        if attack_chains_summary and attack_chains_summary.get('chain_count'):
            signals.append(f"Attack chains: {attack_chains_summary['chain_count']}")
            signals.append(f"  Summary: {attack_chains_summary.get('summary', '')[:200]}")

        # 子图判决汇总
        vs = voting_result.get('subgraph_verdicts', [])
        if vs:
            mal_names = [v.get('subgraph_name','') for v in vs if v.get('final_verdict')=='MALICIOUS']
            sus_names = [v.get('subgraph_name','') for v in vs if v.get('final_verdict')=='SUSPICIOUS']
            signals.append(f"Subgraphs: {len(vs)} total, {len(mal_names)} malicious, {len(sus_names)} suspicious")
            if mal_names:
                signals.append(f"  Malicious: {', '.join(mal_names[:5])}")
            if sus_names:
                signals.append(f"  Suspicious: {', '.join(sus_names[:5])}")

        # 关键污点链
        all_chains = []
        for v in vs:
            all_chains.extend(v.get('taint_chains', []))
        if all_chains:
            from src.taint_engine import format_for_prompt
            signals.append("Top taint chains:\n" + format_for_prompt(all_chains, max_chains=3))

        # 函数摘要（污点相关的,从已保存的摘要文件读取）
        summaries_file = Path(package_dir) / '.ddg_output' / 'function_summaries.json' \
            if hasattr(package_dir, '__truediv__') else None
        if summaries_file and summaries_file.exists():
            try:
                sdata = json.loads(summaries_file.read_text(encoding='utf-8'))
                taint_funcs = [(k, s) for k, s in sdata.get('summaries', {}).items()
                               if s.get('taint_relevant')]
                if taint_funcs:
                    signals.append(f"Taint-relevant functions: {len(taint_funcs)}")
                    for k, s in taint_funcs[:5]:
                        signals.append(f"  {s['name']}: return_tainted={s.get('return_tainted')} "
                                       f"param_to_sink={s.get('param_to_sink')}")
            except Exception:
                pass

        signals_text = '\n'.join(signals)

        prompt = f"""You are performing a FINAL package-level security assessment.
All individual analyses are complete. You must weigh ALL evidence together
and make a holistic judgment.

## Package: {package_name}

## All Detection Signals
{signals_text}

## Mechanical Voting Result
Category: {voting_result['final_category']}
Risk: {voting_result['final_risk_score']}, Confidence: {voting_result['final_confidence']}
Reason: {voting_result.get('voting_summary', '')}

## Your Task
Consider ALL signals TOGETHER. A single strong signal may outweigh many weak ones.
A pattern of subtle signals may indicate malicious intent even if no single signal is critical.
Conversely, isolated suspicious signals in an otherwise clean package may be false positives.

Output JSON:
```json
{{
  "final_category": "MALICIOUS|SUSPICIOUS|BENIGN",
  "risk_score": 0.0-1.0,
  "confidence": 0.0-1.0,
  "reasoning": "one paragraph weighing all evidence"
}}
```
"""

        client = ZhipuAI(api_key=self.api_key)
        response = client.chat.completions.create(
            model=getattr(self, 'llm_model', 'glm-4-flashx'),
            messages=[
                {"role": "system", "content":
                 "You are a senior malware analyst making a final determination "
                 "on a Python package. You have all evidence from multiple detection "
                 "channels. Weigh them together and give a definitive verdict."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.1, max_tokens=1000)

        llm_output = response.choices[0].message.content if response.choices else ''
        json_match = re.search(r'```json\s*(.*?)\s*```', llm_output, re.DOTALL)
        if json_match:
            result = json.loads(json_match.group(1))
            cat = result.get('final_category', 'SUSPICIOUS')
            if cat in ('MALICIOUS', 'SUSPICIOUS', 'BENIGN'):
                return {
                    'final_category': cat,
                    'risk_score': min(max(float(result.get('risk_score', 0.5)), 0), 1),
                    'confidence': min(max(float(result.get('confidence', 0.5)), 0), 1),
                    'reasoning': result.get('reasoning', ''),
                }
        return None

    def _v12_voting_classify_by_subgraphs(
        self,
        subgraph_jsons: List[Dict],
        package_dir: Path,
        ddg_v7_report: Dict,
        enhanced_detection_result: Dict = None
    ) -> Dict:
        """
        Solution B V2: 改进的投票架构

        改进1：SubgraphPrioritizer - 智能预处理（图中心性排序）
        改进2：RuleBasedScorer - 规则化评分（5维度评分系统）

        流程：
        1. 【改进1】子图优先级排序（MALGUARD图中心性）
        2. 【改进2】高优先级子图：规则评分 + LLM验证
        3. 【改进2】低优先级子图：仅规则评分
        4. 投票：任意子图恶意 → 包恶意
        """
        print(f"\n        [Voting Architecture V2] 子图数量: {len(subgraph_jsons)}")

        package_name = package_dir.name
        subgraph_verdicts = []

        # ===== Bug #14 Fix: 0子图情况处理 =====
        if len(subgraph_jsons) == 0:
            print(f"\n        [Bug #14 Fix] 检测到0子图，启用DDG V7报告分析...")
            return self._classify_zero_subgraph_case(package_dir, ddg_v7_report, enhanced_detection_result)

        # 初始化改进组件
        prioritizer = SubgraphPrioritizer()
        scorer = RuleBasedScorer()
        classifier = V12SubgraphClassifier(self.api_key, use_cache=self.use_llm_cache, model=self.llm_model)

        # ===== 改进1：子图优先级排序 =====
        print(f"\n        [改进1] 智能预处理（子图优先级排序）...")
        high_priority_subgraphs, low_priority_subgraphs = prioritizer.prioritize_subgraphs(
            subgraph_jsons,
            max_llm_calls=20  # 限制LLM调用次数
        )

        # ===== 高优先级子图：规则评分 + LLM验证 或 直接LLM分析 =====
        if self.skip_rule_scoring:
            print(f"\n        [改进2] 高优先级子图：直接使用LLM分析（跳过规则评分）...")
        else:
            print(f"\n        [改进2] 高优先级子图：规则评分 + LLM验证...")

        # 并行实现（2026-10 大改）：原先 parallel_workers 参数收下但从未使用，
        # >1 时高优先级子图的 LLM 调用走线程池（网络IO型，线程即可）
        high_jobs = list(enumerate(high_priority_subgraphs, 1))
        if self.parallel_workers > 1 and len(high_jobs) > 1:
            from concurrent.futures import ThreadPoolExecutor, as_completed
            print(f"\n        [Parallel] 使用 {self.parallel_workers} 个线程并行分析高优先级子图...")
            verdicts_by_idx = {}
            with ThreadPoolExecutor(max_workers=self.parallel_workers) as pool:
                futures = {
                    pool.submit(self._classify_one_high_priority, classifier, scorer,
                                subgraph_json, idx, len(high_jobs), package_name,
                                ddg_v7_report, enhanced_detection_result): idx
                    for idx, subgraph_json in high_jobs
                }
                for future in as_completed(futures):
                    verdicts_by_idx[futures[future]] = future.result()
            subgraph_verdicts = [verdicts_by_idx[i] for i in sorted(verdicts_by_idx)]
        else:
            for idx, subgraph_json in high_jobs:
                subgraph_verdicts.append(self._classify_one_high_priority(
                    classifier, scorer, subgraph_json, idx, len(high_jobs),
                    package_name, ddg_v7_report, enhanced_detection_result
                ))

        # ===== 低优先级子图：仅规则评分 或 LLM分析 =====
        if self.skip_rule_scoring:
            print(f"\n        [改进2] 低优先级子图：使用LLM分析（跳过规则评分）...")
        else:
            print(f"\n        [改进2] 低优先级子图：仅规则评分（跳过LLM）...")

        for idx, subgraph_json in enumerate(low_priority_subgraphs, 1):
            print(f"          [Low-Priority {idx}/{len(low_priority_subgraphs)}]")

            if self.skip_rule_scoring:
                # 直接使用LLM分析
                verdict = classifier.classify_subgraph(
                    subgraph_json,
                    package_name,
                    ddg_v7_report,
                    len(high_priority_subgraphs) + idx,
                    None,  # 不传入规则评分结果
                    enhanced_detection_result  # 传入增强检测结果
                )
                # 记录未使用规则评分
                verdict['rule_based_score'] = 0.0
                verdict['rule_based_category'] = 'SKIPPED'
                verdict['rule_based_confidence'] = 0.0
            else:
                # 规则化评分
                rule_based_result = scorer.score_subgraph(subgraph_json, ddg_v7_report)

                print(f"          规则评分: {rule_based_result['total_score']:.2f}")
                print(f"          规则分类: {rule_based_result['category']}")

                # 转换为verdict格式
                verdict = {
                    'subgraph_name': subgraph_json.get('subgraph_name', 'unknown'),
                    'subgraph_idx': len(high_priority_subgraphs) + idx,
                    'is_malicious': rule_based_result['category'] == 'MALICIOUS',
                    'final_verdict': rule_based_result['category'],
                    'risk_score': rule_based_result['total_score'],
                    'confidence': rule_based_result['confidence'],
                    'reasoning': f"Rule-based classification (low priority, LLM skipped)",
                    'rule_based_score': rule_based_result['total_score'],
                    'rule_based_category': rule_based_result['category'],
                    'rule_based_confidence': rule_based_result['confidence'],
                    'llm_used': False  # 标记：未使用LLM
                }

            subgraph_verdicts.append(verdict)

        # 投票合成（2026-10 大改）：
        # 1. 口径统一：全部按 final_verdict 统计（原先 malicious 按 is_malicious、
        #    其余按 final_verdict 三口径混用），ERROR 显式计数
        # 2. 零容忍分层：LLM 判 MALICIOUS 的子图 → 整包 MALICIOUS（零容忍保留）；
        #    仅规则判 MALICIOUS（低优先级子图，无 LLM 复核）需 ≥2 个一致才升
        #    MALICIOUS，孤证降级计入 SUSPICIOUS——规则通道孤证不再判死整包
        # 3. 置信度真实化：由恶意占比与子图自身置信度计算，替换硬编码值
        total_count = max(len(subgraph_verdicts), 1)

        llm_malicious = [v for v in subgraph_verdicts
                         if v.get('final_verdict') == 'MALICIOUS' and v.get('llm_used', False)]
        rule_malicious = [v for v in subgraph_verdicts
                          if v.get('final_verdict') == 'MALICIOUS' and not v.get('llm_used', False)]
        suspicious_verdicts = [v for v in subgraph_verdicts if v.get('final_verdict') == 'SUSPICIOUS']

        # ===== 跨通道交叉验证（2026-10，真实良性库测试驱动）=====
        # 单通道LLM + 零容忍，对"本身就含代码执行原语的库"(cffi的execfile、
        # astor的codegen)必然误报。LLM判MALICIOUS但规则预筛为BENIGN(<0.40)
        # 且无增强检测 critical 佐证时，证据不足→降级SUSPICIOUS。
        # skip_rule_scoring 模式显式禁用规则通道，不做此校验。
        # 2026-10 硬化教训：豁免条件只能是 critical——high 已含低精度的
        # live 索引 typosquat，用它豁免会形成循环论证（低精度信号给自己
        # 放行），packaging/pyyaml 曾因此整包误判。
        enhanced_level = (enhanced_detection_result or {}).get('overall_threat_level', 'safe')
        enhanced_strong = enhanced_level == 'critical'

        def _corroborated(v: Dict) -> bool:
            if self.skip_rule_scoring or enhanced_strong:
                return True
            return (v.get('rule_based_score') or 0.0) >= 0.40

        uncorroborated = [v for v in llm_malicious if not _corroborated(v)]
        if uncorroborated:
            for v in uncorroborated:
                v['final_verdict'] = 'SUSPICIOUS'
                v['is_malicious'] = False
                v['demoted_reason'] = 'LLM判恶意但规则预筛为BENIGN，缺少跨通道佐证'
            print(f"          [交叉验证] {len(uncorroborated)} 个LLM恶意子图缺少规则通道佐证，降级为可疑")
            llm_malicious = [v for v in llm_malicious if _corroborated(v)]
            suspicious_verdicts.extend(uncorroborated)

        benign_count = sum(1 for v in subgraph_verdicts if v.get('final_verdict') == 'BENIGN')
        error_count = sum(1 for v in subgraph_verdicts if v.get('final_verdict') == 'ERROR')
        # LLM 不可用/解析失败时走规则回退，标注为降级分析
        fallback_count = sum(1 for v in subgraph_verdicts if v.get('fallback'))

        malicious_count = len(llm_malicious) + len(rule_malicious)
        # 规则孤证降级为可疑
        if len(rule_malicious) == 1:
            malicious_count -= 1
            suspicious_verdicts.extend(rule_malicious)
        suspicious_count = len(suspicious_verdicts)

        print(f"\n        [Voting Result]")
        print(f"          恶意子图: {malicious_count} (LLM: {len(llm_malicious)}, 规则: {len(rule_malicious)})")
        print(f"          可疑子图: {suspicious_count}")
        print(f"          良性子图: {benign_count}")
        if error_count:
            print(f"          分析失败子图: {error_count}")

        def _avg_conf(verdicts: List[Dict]) -> float:
            confs = [float(v.get('confidence', 0.5) or 0.5) for v in verdicts]
            return sum(confs) / len(confs) if confs else 0.5

        # 投票规则
        if malicious_count > 0:
            mal_ratio = malicious_count / total_count
            # 无LLM语义证据(全部来自规则/回退)、且恶意子图只占少数：
            # 不足以判恶意，降为可疑。真实良性库(cffi)有 4/77=5% 的
            # 规则回退票；真实恶意包(1923tsl1)是 2/2=100%
            if not llm_malicious and mal_ratio < 0.5:
                final_category = "SUSPICIOUS"
                final_risk_score = round(0.50 + mal_ratio * 0.20, 3)
                final_confidence = round(min(1.0, 0.40 + 0.20 * mal_ratio
                                             + 0.10 * _avg_conf(rule_malicious)), 3)
                voting_summary = (f"有 {malicious_count}/{total_count} 个子图被规则判为恶意"
                                  f"(无LLM复核,占比过低)，判定为可疑包，建议人工复核")
            else:
                final_category = "MALICIOUS"
                final_risk_score = round(min(0.85 + mal_ratio * 0.15, 1.0), 3)
                final_confidence = round(min(1.0, 0.6 + 0.25 * mal_ratio
                                             + 0.15 * _avg_conf(llm_malicious or rule_malicious)), 3)
                voting_summary = (f"检测到 {malicious_count} 个恶意攻击链（子图，其中LLM复核 {len(llm_malicious)} 个），"
                                  f"按零容忍原则判定为恶意包")
        elif suspicious_count > 0:
            final_category = "SUSPICIOUS"
            sus_ratio = suspicious_count / total_count
            final_risk_score = round(0.40 + sus_ratio * 0.20, 3)
            final_confidence = round(min(1.0, 0.45 + 0.30 * sus_ratio
                                         + 0.10 * _avg_conf(suspicious_verdicts)), 3)
            voting_summary = f"检测到 {suspicious_count} 个可疑子图，但无明确恶意攻击链，判定为可疑包"
        elif benign_count == 0 and error_count > 0:
            # 全部子图分析失败：不能当良性输出
            final_category = "ANALYSIS_FAILED"
            final_risk_score = 0.5
            final_confidence = 0.3
            voting_summary = f"所有 {error_count} 个子图分析均失败，无法完成判定"
        else:
            final_category = "BENIGN"
            final_risk_score = 0.10
            final_confidence = 0.90
            voting_summary = f"所有 {benign_count} 个子图均为良性，无恶意攻击链"

        # 打印最终决策
        print(f"\n        [Final Decision]")
        print(f"          分类: {final_category}")
        print(f"          风险评分: {final_risk_score:.2f}")
        print(f"          置信度: {final_confidence:.2f}")
        print(f"          理由: {voting_summary}")

        return {
            'final_category': final_category,
            'final_risk_score': final_risk_score,
            'final_confidence': final_confidence,
            'malicious_count': malicious_count,
            'suspicious_count': suspicious_count,
            'benign_count': benign_count,
            'error_count': error_count,
            'fallback_count': fallback_count,
            'analysis_degraded': fallback_count > 0,
            'subgraph_verdicts': subgraph_verdicts,
            'voting_summary': voting_summary,
        }

    def _classify_one_high_priority(
        self,
        classifier,
        scorer,
        subgraph_json: Dict,
        idx: int,
        total: int,
        package_name: str,
        ddg_v7_report: Dict,
        enhanced_detection_result
    ) -> Dict:
        """分析单个高优先级子图（规则评分 + LLM；供串行/线程池共用）"""
        print(f"\n        [High-Priority Subgraph {idx}/{total}]")

        if self.skip_rule_scoring:
            # 直接使用LLM分析（跳过规则评分）
            verdict = classifier.classify_subgraph(
                subgraph_json,
                package_name,
                ddg_v7_report,
                idx,
                None,  # 不传入规则评分结果
                enhanced_detection_result  # 传入增强检测结果
            )
            # 记录未使用规则评分
            verdict['rule_based_score'] = 0.0
            verdict['rule_based_category'] = 'SKIPPED'
            verdict['rule_based_confidence'] = 0.0
        else:
            # 步骤1：规则化评分
            rule_based_result = scorer.score_subgraph(subgraph_json, ddg_v7_report)

            print(f"          规则评分: {rule_based_result['total_score']:.2f}")
            print(f"          规则分类: {rule_based_result['category']}")

            # 步骤2：LLM验证（传入规则结果）
            verdict = classifier.classify_subgraph(
                subgraph_json,
                package_name,
                ddg_v7_report,
                idx,
                rule_based_result,  # 传入规则评分结果
                enhanced_detection_result  # 传入增强检测结果
            )

            # 记录两种方法的结果对比
            verdict['rule_based_score'] = rule_based_result['total_score']
            verdict['rule_based_category'] = rule_based_result['category']
            verdict['rule_based_confidence'] = rule_based_result['confidence']

        # 只有真正的 LLM 判决才算"LLM复核"；API失败/解析失败的规则回退
        # 必须按规则票处理（cffi 曾因回退票被当LLM票直接判 MALICIOUS）
        verdict['llm_used'] = not verdict.get('fallback', False)
        return verdict

    def _classify_zero_subgraph_case(
        self,
        package_dir: Path,
        ddg_v7_report: Dict,
        enhanced_detection_result: Dict = None
    ) -> Dict:
        """
        Bug #14 Fix: 处理0子图情况 - 使用LLM分析DDG V7安全报告

        当SuspiciousNodeDetector未检测到危险节点时，会生成0个子图。
        此时不应直接判定为BENIGN，而应该让LLM分析DDG V7的安全报告。

        Args:
            package_dir: 包目录
            ddg_v7_report: DDG V7安全报告

        Returns:
            判决结果（与_subgraph分类结果格式一致）
        """
        print(f"\n        [Bug #14 Fix] 检测到0子图，调用LLM分析DDG V7报告...")

        package_name = package_dir.name

        # 读取DDG V7安全报告
        security_file = package_dir / '.ddg_output' / 'security_report.json'
        if not security_file.exists():
            # 修复（2026-10 大改）：DDG 构建失败（无报告）原先直接输出
            # BENIGN 0.10/0.90——基础设施故障被当成"包是安全的"。
            # 现在输出 ANALYSIS_FAILED 终态，与良性明确区分。
            print(f"          [WARN] 未找到security_report.json（DDG构建失败），标记为 ANALYSIS_FAILED")
            return {
                'final_category': 'ANALYSIS_FAILED',
                'final_risk_score': 0.5,
                'final_confidence': 0.3,
                'malicious_count': 0,
                'suspicious_count': 0,
                'benign_count': 0,
                'subgraph_verdicts': [],
                'voting_summary': 'DDG构建失败（无security_report.json），无法完成分析，不判定为良性',
            }

        # 读取安全报告
        with open(security_file, 'r', encoding='utf-8') as f:
            security_report = json.load(f)

        print(f"          [DDG V7 Report] 风险级别: {security_report.get('risk_level', 'unknown')}")
        print(f"          [DDG V7 Report] 总问题数: {security_report.get('total_issues', 0)}")

        # 加载prompt模板（修复：原先在 try 之外，文件缺失会抛异常
        # 导致整个包的结果静默丢失）
        prompt_file = Path(__file__).parent / 'SOLUTION_B_VOTING' / 'prompts' / 'ddg_v7_security_analyzer_en.txt'
        try:
            with open(prompt_file, 'r', encoding='utf-8') as f:
                prompt_template = f.read()
        except Exception as e:
            print(f"          [WARN] 读取prompt模板失败: {e}，回退到规则判定")
            return self._zero_subgraph_rule_fallback(security_report)

        # 填充prompt
        prompt = self._fill_ddg_v7_prompt(prompt_template, package_name, security_report, ddg_v7_report)

        # 调用LLM
        try:
            print(f"          [LLM] 正在分析DDG V7报告...")
            client = ZhipuAI(api_key=self.api_key)

            response = client.chat.completions.create(
                model=self.llm_model,
                messages=[
                    {"role": "system", "content": "You are a malware analysis expert specializing in Python package security assessment."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1,
                max_tokens=3000  # 增加到3000避免输出截断
            )

            llm_output = response.choices[0].message.content

            # 解析LLM输出
            verdict = self._parse_ddg_v7_llm_output(llm_output)

            print(f"          [LLM Verdict] 分类: {verdict['final_verdict']}")
            print(f"          [LLM Verdict] 风险评分: {verdict['risk_score']:.2f}")
            print(f"          [LLM Verdict] 置信度: {verdict['confidence']:.2f}")
            print(f"          [LLM Verdict] 理由: {verdict['reasoning']}")

            # 返回格式与voting一致
            return {
                'final_category': verdict['final_verdict'],
                'final_risk_score': verdict['risk_score'],
                'final_confidence': verdict['confidence'],
                'malicious_count': 1 if verdict['final_verdict'] == 'MALICIOUS' else 0,
                'suspicious_count': 1 if verdict['final_verdict'] == 'SUSPICIOUS' else 0,
                'benign_count': 1 if verdict['final_verdict'] == 'BENIGN' else 0,
                'subgraph_verdicts': [{
                    'subgraph_name': 'ddg_v7_whole_package',
                    'is_malicious': verdict.get('is_malicious', False),
                    'final_verdict': verdict['final_verdict'],
                    'risk_score': verdict['risk_score'],
                    'confidence': verdict['confidence'],
                    'reasoning': verdict['reasoning'],
                    'attack_chain_type': verdict.get('attack_chain_type', 'Unknown'),
                    'llm_used': True,
                    'analysis_type': 'DDG V7 Security Report Analysis'
                }],
                'voting_summary': f"[Bug #14 Fix] 0子图情况，基于DDG V7报告的LLM分析: {verdict['reasoning']}",
            }

        except Exception as e:
            print(f"          [ERROR] LLM分析DDG V7报告失败: {e}")
            print(f"          [WARN] 回退到基于DDG风险级别的规则判定")
            return self._zero_subgraph_rule_fallback(security_report)

    def _zero_subgraph_rule_fallback(self, security_report: Dict) -> Dict:
        """0子图场景的规则回退：按DDG V7风险级别判定"""
        risk_level = security_report.get('risk_level', 'safe').lower()
        total_issues = security_report.get('total_issues', 0)
        critical_count = security_report.get('by_severity', {}).get('critical', 0)

        if risk_level == 'critical' and critical_count > 0:
            final_category = 'MALICIOUS'
            final_risk_score = 0.85
            final_confidence = 0.70
            voting_summary = f'[Fallback] DDG V7检测到critical风险级别（{critical_count}个critical问题），判定为恶意'
        elif risk_level in ['high', 'critical']:
            final_category = 'SUSPICIOUS'
            final_risk_score = 0.50
            final_confidence = 0.60
            voting_summary = f'[Fallback] DDG V7检测到{risk_level}风险级别（{total_issues}个问题），判定为可疑'
        else:
            final_category = 'BENIGN'
            final_risk_score = 0.10
            final_confidence = 0.90
            voting_summary = f'[Fallback] DDG V7检测到{risk_level}风险级别，判定为良性'

        return {
            'final_category': final_category,
            'final_risk_score': final_risk_score,
            'final_confidence': final_confidence,
            'malicious_count': 1 if final_category == 'MALICIOUS' else 0,
            'suspicious_count': 1 if final_category == 'SUSPICIOUS' else 0,
            'benign_count': 1 if final_category == 'BENIGN' else 0,
            'subgraph_verdicts': [],
            'voting_summary': voting_summary,
        }

    def _fill_ddg_v7_prompt(
        self,
        prompt_template: str,
        package_name: str,
        security_report: Dict,
        ddg_v7_report: Dict
    ) -> str:
        """填充DDG V7安全报告分析的prompt"""
        prompt = prompt_template

        # 基本信息
        prompt = prompt.replace("{package_name}", package_name)
        prompt = prompt.replace("{total_files}", str(ddg_v7_report.get('total_files', 0)))
        prompt = prompt.replace("{total_lines}", str(ddg_v7_report.get('total_lines', 0)))
        prompt = prompt.replace("{total_nodes}", str(ddg_v7_report.get('total_nodes', 0)))

        # 风险级别
        risk_level = security_report.get('risk_level', 'unknown')
        prompt = prompt.replace("{risk_level}", risk_level)

        # 问题统计
        total_issues = security_report.get('total_issues', 0)
        prompt = prompt.replace("{total_issues}", str(total_issues))

        by_severity = security_report.get('by_severity', {})
        prompt = prompt.replace("{critical_count}", str(by_severity.get('critical', 0)))
        prompt = prompt.replace("{high_count}", str(by_severity.get('high', 0)))
        prompt = prompt.replace("{medium_count}", str(by_severity.get('medium', 0)))
        prompt = prompt.replace("{low_count}", str(by_severity.get('low', 0)))
        prompt = prompt.replace("{info_count}", str(by_severity.get('info', 0)))

        # 问题类型
        by_type = security_report.get('by_type', {})
        issues_by_type_text = "\n".join([f"- {issue_type}: {count}" for issue_type, count in by_type.items()])
        prompt = prompt.replace("{issues_by_type}", issues_by_type_text if issues_by_type_text else "None")

        # 详细发现
        detailed_findings = security_report.get('findings', [])
        detailed_findings_text = json.dumps(detailed_findings[:20], indent=2, ensure_ascii=False)  # 限制20个
        prompt = prompt.replace("{detailed_findings}", detailed_findings_text)

        # 网络行为
        network_behavior = security_report.get('network_behavior', {})
        network_behavior_text = json.dumps(network_behavior, indent=2, ensure_ascii=False)
        prompt = prompt.replace("{network_behavior}", network_behavior_text)

        # 文件系统操作
        filesystem_ops = security_report.get('filesystem_ops', {})
        filesystem_ops_text = json.dumps(filesystem_ops, indent=2, ensure_ascii=False)
        prompt = prompt.replace("{filesystem_ops}", filesystem_ops_text)

        # 进程操作
        process_ops = security_report.get('process_ops', {})
        process_ops_text = json.dumps(process_ops, indent=2, ensure_ascii=False)
        prompt = prompt.replace("{process_ops}", process_ops_text)

        # 编码/混淆检测
        encodings_detected = security_report.get('encodings_detected', {})
        encodings_text = json.dumps(encodings_detected, indent=2, ensure_ascii=False)
        prompt = prompt.replace("{encodings_detected}", encodings_text)

        # 字符串分析
        string_analysis = security_report.get('string_analysis', {})
        string_analysis_text = json.dumps(string_analysis, indent=2, ensure_ascii=False)
        prompt = prompt.replace("{string_analysis}", string_analysis_text)

        return prompt

    def _parse_ddg_v7_llm_output(self, llm_output: str) -> Dict:
        """解析LLM输出的DDG V7分析结果"""
        try:
            # 尝试提取JSON块
            json_match = re.search(r'```json\s*(\{.*?\})\s*```', llm_output, re.DOTALL)
            if json_match:
                json_str = json_match.group(1)
            else:
                # 尝试直接解析
                json_start = llm_output.find('{')
                json_end = llm_output.rfind('}') + 1
                if json_start >= 0 and json_end > json_start:
                    json_str = llm_output[json_start:json_end]
                else:
                    raise ValueError("无法找到JSON块")

            verdict = json.loads(json_str)

            # 验证必需字段
            required_fields = ['final_verdict', 'risk_score', 'confidence', 'reasoning']
            for field in required_fields:
                if field not in verdict:
                    raise ValueError(f"缺少必需字段: {field}")

            return verdict

        except Exception as e:
            print(f"          [ERROR] 解析LLM输出失败: {e}")
            print(f"          [LLM Output] {llm_output[:500]}...")

            # 回退：基于关键词判断
            output_lower = llm_output.lower()
            if 'malicious' in output_lower and 'benign' not in output_lower:
                final_verdict = 'MALICIOUS'
                risk_score = 0.75
                confidence = 0.60
            elif 'suspicious' in output_lower or 'uncertain' in output_lower:
                final_verdict = 'SUSPICIOUS'
                risk_score = 0.50
                confidence = 0.50
            else:
                final_verdict = 'BENIGN'
                risk_score = 0.15
                confidence = 0.70

            return {
                'is_malicious': final_verdict == 'MALICIOUS',
                'final_verdict': final_verdict,
                'risk_score': risk_score,
                'confidence': confidence,
                'reasoning': f'解析失败后的回退判定（关键词匹配）: {llm_output[:200]}...',
                'malicious_indicators': [],
                'benign_indicators': [],
                'attack_chain_type': 'Unknown',
                'recommendation': 'Manual review required'
            }

    def _extract_tarfile(self, tarfile: Path, package_dir: Path):
        """解压tarfile（filter='data' 防路径穿越；分析对象本身是恶意样本）"""
        import tarfile as tf_module
        if not package_dir.exists():
            # Create extract base directory if needed
            package_dir.parent.mkdir(parents=True, exist_ok=True)
            # Extract to parent directory (extract_base)
            with tf_module.open(tarfile) as tf:
                try:
                    # filter='data': 拒绝绝对路径/../穿越/设备文件，防 tar-slip
                    tf.extractall(path=str(package_dir.parent), filter='data')
                except TypeError:
                    # Python < 3.12 无 filter 参数
                    tf.extractall(path=str(package_dir.parent))

    def _resolve_extracted_dir(self, tarfile: Path, extract_base: Path) -> Optional[Path]:
        """tar 内顶级目录名与 tar 文件名不一致时，解析实际解压目录"""
        import tarfile as tf_module
        try:
            with tf_module.open(tarfile) as tf:
                for member in tf.getmembers():
                    top = member.name.replace('\\', '/').split('/')[0]
                    if top in ('.', '', '..'):
                        continue
                    candidate = extract_base / top
                    if candidate.exists() and candidate.is_dir():
                        return candidate
                    break
        except Exception:
            pass
        return None

    def _run_ddg_builder(self, package_dir: str) -> Path:
        """运行DDG Builder V7 并保存结果到磁盘"""
        package_path = Path(package_dir)

        print(f"          [Step 2.1] 构建DDG V7...")
        builder = DDGBuilderV7(package_dir)
        result = builder.build()

        # 输出结果目录（参考main.py lines 139-204）
        output_dir = package_path / '.ddg_output'
        output_dir.mkdir(parents=True, exist_ok=True)

        print(f"          [Step 2.2] 保存DDG结果...")

        # 保存安全报告（关键修复）
        if result.get('security_report'):
            security_file = output_dir / 'security_report.json'
            with open(security_file, 'w', encoding='utf-8') as f:
                json.dump(result['security_report'], f, indent=2, ensure_ascii=False)
            print(f"            [OK] Saved security_report.json")

        # 保存节点
        if result.get('nodes'):
            nodes_file = output_dir / 'nodes.json'
            nodes_data = {}
            for key, node in result['nodes'].items():
                node_dict = {
                    'file': node.file,
                    'line': node.line,
                    'type': node.type,
                    'source': node.source,
                    'function_name': getattr(node, 'function_name', None),
                    'class_name': getattr(node, 'class_name', None)
                }
                # 2026-10 图内核重构：key 统一 (file,line,col)——旧实现丢 col,
                # 同一 (file,line) 的多个节点互相覆盖只剩最后一个
                nodes_data[f"{key[0]}_{key[1]}_{key[2]}"] = node_dict

            with open(nodes_file, 'w', encoding='utf-8') as f:
                json.dump(nodes_data, f, indent=2, ensure_ascii=False)
            print(f"            [OK] Saved nodes.json ({len(nodes_data)} nodes)")

        # 保存边
        if result.get('edges'):
            edges_file = output_dir / 'edges.json'
            with open(edges_file, 'w', encoding='utf-8') as f:
                edges_data = [edge.to_dict() for edge in result['edges']]
                json.dump(edges_data, f, indent=2, ensure_ascii=False)
            print(f"            [OK] 保存 edges.json ({len(edges_data)} 边)")

        # 保存符号表
        if result.get('symbol_table'):
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
            print(f"            [OK] 保存 symbols.json ({len(functions_data)} 函数, {len(classes_data)} 类)")

        # 图分割（参考main.py lines 206-243）
        print(f"          [Step 2.3] 执行图分割...")
        if result.get('nx_graph'):
            nx_graph = result['nx_graph']

            # 导入分割模块
            from src.common import GraphPartitioner, PartitionConfig

            config = PartitionConfig(
                # 500 节点以上的"子图"等于半个模块，不是语义单元：tqdm 的
                # 500 节点子图曾让规则分虚高(0.60)并使 LLM 误判 Command Injection
                max_nodes=100,
                max_depth=10,
                timeout=30,
                max_iterations=10000,
                verbose=False
            )

            partitioner = GraphPartitioner(nx_graph, config)

            # 执行分割(2026-11: 函数级替代 WCC+BFS)
            subgraphs = partitioner.partition(method='function')

            # 保存分割结果
            if subgraphs:
                sub_output_dir = output_dir / 'sub_ddgs'
                saved_files = partitioner.save_results(subgraphs, sub_output_dir, method='function')
                print(f"            [OK] 保存 {len(subgraphs)} 个子图到 sub_ddgs/")

                # 更新安全报告
                try:
                    report_file = output_dir / 'security_report.json'
                    if report_file.exists():
                        with open(report_file, 'r', encoding='utf-8') as f:
                            report = json.load(f)

                        critical_count = sum(1 for sg in subgraphs if sg.get('severity') == 'critical')
                        high_count = sum(1 for sg in subgraphs if sg.get('severity') == 'high')
                        medium_count = sum(1 for sg in subgraphs if sg.get('severity') == 'medium')
                        low_count = sum(1 for sg in subgraphs if sg.get('severity') == 'low')

                        report['subgraphs'] = {
                            'total': len(subgraphs),
                            'critical': critical_count,
                            'high': high_count,
                            'medium': medium_count,
                            'low': low_count
                        }

                        with open(report_file, 'w', encoding='utf-8') as f:
                            json.dump(report, f, indent=2, ensure_ascii=False)

                        print(f"            [子图分布] C:{critical_count} H:{high_count} M:{medium_count} L:{low_count}")

                except Exception as e:
                    print(f"            [WARN] 更新安全报告失败: {e}")
            else:
                print(f"            [WARN] 未找到子图")
        else:
            print(f"            [WARN] 无NetworkX图，跳过分割")

        # 攻击链重建（从DDG节点/边重建 数据引入→处理→危险执行→外传 四阶段攻击链）
        print(f"          [Step 2.4] 重建攻击链（AttackChainRebuilder）...")
        try:
            ac_nodes = [
                {
                    'node_id': n.get_id(),
                    'code': n.source or '',
                    'type': n.type or '',
                    'line': n.line,
                    'file': n.file,
                }
                for n in (result.get('nodes') or {}).values()
            ]
            ac_edges = [
                {
                    'from_node': e.from_node.get_id(),
                    'to_node': e.to_node.get_id(),
                    'from_file': e.from_node.file,
                    'to_file': e.to_node.file,
                    'kind': e.edge_kind,
                }
                for e in (result.get('edges') or [])
            ]
            chain_result = AttackChainRebuilder().rebuild(ac_nodes, ac_edges)

            # 2026-10 分层 CPG-lite ②:函数摘要落盘
            try:
                summaries = result.get('function_summaries') or {}
                taint_relevant = {k: v for k, v in summaries.items() if v.get('taint_relevant')}
                with open(output_dir / 'function_summaries.json', 'w', encoding='utf-8') as f:
                    json.dump({
                        'total': len(summaries),
                        'taint_relevant': len(taint_relevant),
                        'summaries': {f"{Path(k[0]).name}:{k[1]}": v
                                      for k, v in summaries.items()},
                    }, f, indent=2, ensure_ascii=False, default=str)
                if taint_relevant:
                    sample = next(iter(taint_relevant.values()))
                    print(f"            [OK] 保存 function_summaries.json "
                          f"({len(summaries)} 个函数, {len(taint_relevant)} 个污点相关, "
                          f"如 {sample['name']}: p→ret={sample['param_to_return']} "
                          f"p→sink={sample['param_to_sink']})")
            except Exception as summ_e:
                print(f"            [WARN] 函数摘要落盘失败: {summ_e}")

            # 2026-10 结构重构：包级全图污点链（跨子图的完整链路——
            # 子图级污点被分割截断,全图级才能呈现 下载→落盘→执行 完整链）
            try:
                from src.taint_engine import analyze as taint_analyze
                global_chains = taint_analyze(ac_nodes, ac_edges)
                taint_dump = {
                    'chain_count': len(global_chains),
                    'chains': global_chains[:10],
                    'cross_file_chains': sum(1 for c in global_chains if c.get('cross_file')),
                }
                with open(output_dir / 'taint_chains.json', 'w', encoding='utf-8') as f:
                    json.dump(taint_dump, f, indent=2, ensure_ascii=False)
                if global_chains:
                    top = global_chains[0]
                    print(f"            [OK] 保存 taint_chains.json "
                          f"({len(global_chains)} 条, 主链 {top['source_category']}→"
                          f"{top['sink_category']} {len(top['steps'])} 步)")
            except Exception as taint_e:
                print(f"            [WARN] 包级污点链失败: {taint_e}")

            # 落盘（链数与体积有上限；stages只存计数，避免输出爆炸）
            chain_dump = {
                'chains': chain_result['chains'][:20],
                'stage_counts': {k: len(v) for k, v in chain_result['stages'].items()},
                'completeness': chain_result['completeness'],
                'confidence': chain_result['confidence'],
                'summary': chain_result['summary'],
            }
            chains_file = output_dir / 'attack_chains.json'
            with open(chains_file, 'w', encoding='utf-8') as f:
                json.dump(chain_dump, f, indent=2, ensure_ascii=False)
            print(f"            [OK] 保存 attack_chains.json "
                  f"({len(chain_dump['chains'])} 条攻击链, 完整性={chain_dump['completeness']})")

            # 摘要写回安全报告，供0子图兜底分析与人工复核使用
            report_file = output_dir / 'security_report.json'
            if report_file.exists():
                try:
                    with open(report_file, 'r', encoding='utf-8') as f:
                        report = json.load(f)
                    report['rebuilt_attack_chains'] = {
                        'chain_count': len(chain_result['chains']),
                        'completeness': chain_result['completeness'],
                        'confidence': chain_result['confidence'],
                        'summary': chain_result['summary'],
                    }
                    with open(report_file, 'w', encoding='utf-8') as f:
                        json.dump(report, f, indent=2, ensure_ascii=False)
                except Exception as e:
                    print(f"            [WARN] 攻击链摘要写入安全报告失败: {e}")
        except Exception as e:
            print(f"            [WARN] 攻击链重建失败（不影响主流程）: {e}")

        print(f"          [Step 2.5] DDG构建完成 → {output_dir}")
        return output_dir

    def _read_ddg_v7_report(self, package_dir: Path) -> Dict:
        """读取DDG V7安全报告"""
        report_file = Path(package_dir) / '.ddg_output' / 'security_report.json'
        if report_file.exists():
            with open(report_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        return {}

    def _read_attack_chains(self, package_dir: Path, max_chains: int = 5) -> Dict:
        """读取重建的四阶段攻击链摘要（.ddg_output/attack_chains.json）"""
        empty = {
            'chain_count': 0,
            'completeness': 0.0,
            'confidence': 0.0,
            'summary': '',
            'chains': []
        }
        chains_file = Path(package_dir) / '.ddg_output' / 'attack_chains.json'
        if not chains_file.exists():
            return empty
        try:
            with open(chains_file, 'r', encoding='utf-8') as f:
                data = json.load(f)

            chains = []
            for chain in (data.get('chains') or [])[:max_chains]:
                chains.append({
                    'length': chain.get('length', 0),
                    'stages_covered': chain.get('stages_covered', 0),
                    'covered_stages': chain.get('covered_stages', []),
                    'steps': [
                        {
                            'stage': step.get('stage', 'unknown'),
                            'code': step.get('code', ''),
                            'line': step.get('line', 0),
                            'file': Path(step.get('file', '')).name if step.get('file') else ''
                        }
                        for step in chain.get('steps', [])
                    ]
                })

            return {
                'chain_count': len(data.get('chains') or []),
                'completeness': data.get('completeness', 0.0),
                'confidence': data.get('confidence', 0.0),
                'summary': data.get('summary', ''),
                'chains': chains
            }
        except Exception as e:
            print(f"        [WARN] 读取攻击链失败: {e}")
            return empty

    def _read_subgraph_jsons(self, package_dir: Path) -> List[Dict]:
        """读取所有子图JSON"""
        subgraphs_dir = Path(package_dir) / '.ddg_output' / 'sub_ddgs'
        subgraph_jsons = []

        if not subgraphs_dir.exists():
            print(f"        [WARN] 未找到子图目录: {subgraphs_dir}")
            return subgraph_jsons

        # 读取每个子图的edges.json和nodes.json
        for subgraph_dir in sorted(subgraphs_dir.iterdir()):
            if subgraph_dir.is_dir():
                edges_json = subgraph_dir / 'edges.json'
                nodes_json = subgraph_dir / 'nodes.json'
                if edges_json.exists() and nodes_json.exists():
                    # 读取edges和nodes数据
                    with open(edges_json, 'r', encoding='utf-8') as f:
                        edges_data = json.load(f)
                    with open(nodes_json, 'r', encoding='utf-8') as f:
                        nodes_data = json.load(f)

                    # Bug #12修复：提取dangerous_nodes，让规则分类器能正常工作
                    dangerous_nodes = [
                        {
                            'code': node.get('code', ''),  # Bug #13修复：字段名是'code'不是'source'
                            'line': node.get('line', 0),
                            'file': node.get('file', ''),
                            'type': node.get('type', ''),
                            'severity': node.get('severity', 'unknown'),
                            'node_id': node.get('node_id', ''),
                            'is_dangerous': node.get('is_dangerous', False)
                        }
                        for node in nodes_data
                        if node.get('is_dangerous', False)
                    ]

                    # 构建数据流路径（从edges中）
                    data_flow_paths = []
                    for edge in edges_data:
                        from_node = edge.get('from_node', '')
                        to_node = edge.get('to_node', '')
                        if from_node and to_node:
                            from_node_data = next((n for n in nodes_data if n.get('node_id') == from_node), None)
                            to_node_data = next((n for n in nodes_data if n.get('node_id') == to_node), None)
                            if from_node_data and to_node_data:
                                data_flow_paths.append([
                                    {'code': from_node_data.get('code', ''), 'file': from_node_data.get('file', '')},  # Bug #13修复
                                    {'code': to_node_data.get('code', ''), 'file': to_node_data.get('file', '')}  # Bug #13修复
                                ])

                    # 提取函数信息（type=function的节点）
                    functions = {}
                    for node in nodes_data:
                        if node.get('type') == 'function':
                            func_name = node.get('function_name') or ''
                            if func_name:
                                functions.setdefault(func_name, []).append({'node': node})

                    # 2026-10 图内核重构：真实污点追踪（Source→Sink 反向 BFS）
                    # 替代原先"每条边一个二元路径"的伪数据流
                    taint_chains = []
                    try:
                        from src.taint_engine import analyze as taint_analyze
                        taint_chains = taint_analyze(nodes_data, edges_data)
                    except Exception as taint_err:
                        print(f"        [WARN] 污点追踪失败({subgraph_dir.name}): {taint_err}")

                    # 2026-11 函数级分割:从子图的 function 节点取函数名
                    func_name = None
                    for node in nodes_data:
                        if node.get('type') == 'function' and node.get('function_name'):
                            func_name = node['function_name']
                            break

                    # 从函数摘要文件读取对应摘要
                    func_summary = None
                    summaries_file = Path(package_dir) / '.ddg_output' / 'function_summaries.json'
                    if summaries_file.exists() and func_name:
                        try:
                            sdata = json.loads(summaries_file.read_text(encoding='utf-8'))
                            for sk, sv in sdata.get('summaries', {}).items():
                                if sv.get('name') == func_name:
                                    func_summary = sv
                                    break
                        except Exception:
                            pass

                    # 合并为期望的格式
                    subgraph_data = {
                        'edges': edges_data,
                        'nodes': nodes_data,
                        'subgraph_name': subgraph_dir.name,
                        'dangerous_nodes': dangerous_nodes,
                        'data_flow_paths': data_flow_paths,
                        'functions': functions,
                        'taint_chains': taint_chains,
                        'function_name': func_name,
                        'function_summary': func_summary,
                    }
                    subgraph_jsons.append(subgraph_data)

        print(f"        读取到 {len(subgraph_jsons)} 个子图"
              f"（含污点链 {sum(len(s.get('taint_chains') or []) for s in subgraph_jsons)} 条）")
        return subgraph_jsons

    @staticmethod
    def _is_test_file(py_file: Path, package_root: Path) -> bool:
        """判断是否为测试文件（混淆检测跳过；其他检测层仍会扫描）"""
        name = py_file.name.lower()
        if name.startswith('test_') or name.endswith('_test.py') or name == 'conftest.py':
            return True
        try:
            rel_parts = py_file.relative_to(package_root).parts[:-1]
        except ValueError:
            rel_parts = py_file.parts[:-1]
        return any(p.lower() in ('test', 'tests', 'testing') for p in rel_parts)

    @staticmethod
    def _ast_called_names(content: str) -> set:
        """返回源码中真实被调用的函数名集合（用于排除注释/文档字符串误报）

        包含裸调用名（eval/exec/compile）与 "模块.方法" 形式（pickle.loads）。
        解析失败的源文件退化为"去除行注释后再做正则"，避免整文件判定为无调用。
        """
        import ast
        names = set()
        try:
            tree = ast.parse(content)
        except SyntaxError:
            stripped = '\n'.join(line.split('#', 1)[0] for line in content.splitlines())
            for pat, name in ((r'\beval\s*\(', 'eval'), (r'\bexec\s*\(', 'exec'),
                              (r'\bcompile\s*\(', 'compile'),
                              (r'\bpickle\s*\.\s*loads\s*\(', 'pickle.loads'),
                              (r'\bmarshal\s*\.\s*loads\s*\(', 'marshal.loads')):
                if re.search(pat, stripped):
                    names.add(name)
            return names

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            f = node.func
            if isinstance(f, ast.Name):
                names.add(f.id)
            elif isinstance(f, ast.Attribute):
                if isinstance(f.value, ast.Name):
                    names.add(f'{f.value.id}.{f.attr}')
                else:
                    names.add(f.attr)
        return names

    def _detect_obfuscation(self, package_dir: str, ddg_v7_report: Dict) -> Dict:
        """
        检测包是否混淆

        Args:
            package_dir: 包目录
            ddg_v7_report: DDG V7安全报告

        Returns:
            {
                'is_obfuscated': bool,
                'obfuscation_score': float,
                'indicators': {
                    'hex_strings': int,
                    'base64_strings': int,
                    'short_variable_names': float,
                    'eval_usage': bool,
                    'compile_usage': bool,
                    'exec_usage': bool,
                    'lambda_heavy': bool,
                    'getattr_heavy': bool,
                    'string_formatting_complex': bool,
                    'typosquatting': bool,
                    'suspicious_imports': int
                },
                'reasoning': str
            }
        """
        print(f"        [混淆检测] 分析包: {package_dir}")

        package_path = Path(package_dir)
        indicators = {
            'hex_strings': 0,
            'base64_strings': 0,
            'short_variable_names': 0.0,
            'eval_usage': False,
            'compile_usage': False,
            'exec_usage': False,
            'lambda_heavy': False,
            'getattr_heavy': False,
            'string_formatting_complex': False,
            'typosquatting': False,
            'suspicious_imports': 0,
            # Bug #11增强：新增高级混淆指标
            'large_base64_strings': 0,  # 大型base64字符串（>1000字符）
            'suspicious_var_with_payload': False,  # 可疑变量名+大型数据
            'exec_base64_pattern': False,  # exec(base64.b64decode(...))
            'zlib_compression_pattern': False,  # zlib.decompress(base64...)
            # Bug #11进一步扩展：更多混淆类型
            'chinese_obfuscation': False,  # 中文混淆（中文字符/变量）
            'base32_strings': 0,  # Base32编码
            'unicode_escape': False,  # Unicode转义（\uXXXX, \UXXXXXXXX）
            'url_encoding': False,  # URL编码（%XX）
            'rot13_cipher': False,  # Rot13/凯撒密码
            'other_encoding': 0,  # 其他编码（Base58/62/91等）
            # Fernet加密检测（新增 - 最高优先级）
            'exec_fernet_pattern': False,  # exec(Fernet(...).decrypt(...))
            'fernet_encrypted_payload': False,  # Fernet加密的payload
            'exec_marshal_pattern': False,  # exec(marshal.loads(...))
            'marshal_bytecode': False,  # Marshal字节码
            'exec_pickle_pattern': False,  # exec(pickle.loads(...))
            'pickle_payload': False,  # Pickle payload
            'exec_decrypt_pattern': False,  # exec(xxx.decrypt(...))
            'eval_base64_pattern': False,  # eval(base64.b64decode(...))
            'eval_decrypt_pattern': False,  # eval(xxx.decrypt(...))
            'compile_exec_pattern': False,  # exec(compile(...))
            'bz2_compression': False,  # bz2压缩
        }

        total_python_files = 0
        total_variables = 0
        short_variables = 0
        total_lambdas = 0
        total_getattrs = 0
        total_bytes = 0
        total_unicode_escapes = 0
        total_url_encoded = 0
        total_string_formatting = 0

        # 扫描所有Python文件
        for py_file in package_path.rglob('*.py'):
            # 混淆判定面向"运行时会执行的代码"；测试文件天然包含
            # pickle.loads/exec/大段测试向量，纳入会把良性库推过阈值
            # （typing_extensions 曾因此被判 OBFUSCATED）。测试文件仍由
            # 其他检测层覆盖。
            if self._is_test_file(py_file, package_path):
                continue
            try:
                with open(py_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    total_python_files += 1
                    total_bytes += len(content)

                    # 检测hex字符串 (常见于混淆)
                    hex_matches = len([m for m in re.findall(r'\\x[0-9a-fA-F]{2}', content)])
                    if hex_matches > 5:
                        indicators['hex_strings'] += hex_matches

                    # 检测base64字符串。真 base64(≥20字符)几乎必同时含
                    # 大小写和数字;只查大小写会把 HTTPBasicAuthHandler 之类
                    # CamelCase 类名误当 base64(良性库 six 曾因此凑分误判)。
                    # = 填充是强信号,单独放行。
                    b64_candidates = re.findall(r'[A-Za-z0-9+/]{20,}={0,2}', content)
                    base64_matches = sum(
                        1 for m in b64_candidates
                        if m.endswith('=') or (
                            re.search(r'[a-z]', m) and re.search(r'[A-Z]', m) and re.search(r'\d', m)
                        )
                    )
                    if base64_matches > 3:
                        indicators['base64_strings'] += base64_matches

                    # Bug #11增强：检测大型base64字符串（>1000字符，典型shellcode特征）
                    large_base64_pattern = r'[A-Za-z0-9+/]{1000,}={0,2}'
                    large_base64_matches = re.findall(large_base64_pattern, content)
                    if large_base64_matches:
                        indicators['large_base64_strings'] += len(large_base64_matches)
                        # 检查这些大型base64字符串是否在exec/compile中使用
                        for large_b64 in large_base64_matches:
                            # re.escape：base64 片段含 +// 等正则元字符，不转义会抛异常
                            # 并被外层 except 吞掉，导致整个文件的混淆检测静默跳过
                            b64_prefix = re.escape(large_b64[:20])
                            if re.search(rf'exec\s*\(.*(base64\.b64decode|base64\.standard_b64decode).*{b64_prefix}', content, re.IGNORECASE):
                                indicators['exec_base64_pattern'] = True
                                break
                            if re.search(rf'compile\s*\(.*(base64\.b64decode|base64\.standard_b64decode).*{b64_prefix}', content, re.IGNORECASE):
                                indicators['zlib_compression_pattern'] = True
                                break

                    # Bug #11增强：检测可疑变量名+大型base64组合
                    suspicious_vars = ['metadata', 'payload', 'data', 'buffer', 'shellcode', 'code']
                    for var in suspicious_vars:
                        # 匹配可疑变量赋值大型字符串
                        pattern = rf'{var}\s*=\s*["\'][A-Za-z0-9+/]{{100,}}'
                        if re.search(pattern, content):
                            indicators['suspicious_var_with_payload'] = True
                            break

                    # Bug #11增强：检测zlib压缩+base64组合
                    if 'zlib' in content and 'decompress' in content and 'base64' in content:
                        if re.search(r'zlib\.decompress.*base64', content, re.IGNORECASE):
                            indicators['zlib_compression_pattern'] = True

                    # Bug #11进一步扩展：检测更多混淆类型

                    # 1. 中文混淆：只认"中文标识符"（变量/函数名），
                    # 中文注释/文档/数据表在正常库里很常见
                    # (charset_normalizer 含 CJK 数据、Crypto 有中文文档)
                    if re.search(r'[\u4e00-\u9fff]\w*\s*=(?!=)|def\s+\w*[\u4e00-\u9fff]', content):
                        indicators['chinese_obfuscation'] = True

                    # 2. Base32编码检测（A-Z, 2-7, =填充）— 计数，稍后按密度门控
                    base32_matches = re.findall(r'[A-Z2-7]{20,}={0,6}', content)
                    if base32_matches:
                        indicators['base32_strings'] += len(base32_matches)

                    # 3. Unicode转义 — 计数，稍后按密度门控
                    total_unicode_escapes += len(re.findall(
                        r'\\u[0-9a-fA-F]{4}|\\U[0-9a-fA-F]{8}|\\x[0-9a-fA-F]{2}', content))

                    # 4. URL编码（%XX）— 计数，稍后按密度门控
                    total_url_encoded += len(re.findall(r'%[0-9a-fA-F]{2}', content))

                    # 5. Rot13：要求真正的 rot13 字面量（原 'rot' 子串会命中
                    # rotate/rotation 等普通词）
                    if re.search(r'''['"]rot[-_]?13['"]''', content, re.IGNORECASE):
                        indicators['rot13_cipher'] = True

                    # 6. 其他编码检测（Base58/62/91等）
                    # Base58: 用于Bitcoin，去除0, O, I, l
                    base58_pattern = r'[1-9A-HJ-NP-Za-km-z]{30,}'
                    if re.search(base58_pattern, content):
                        indicators['other_encoding'] += 1

                    # Base62: 0-9, A-Z, a-z
                    base62_pattern = r'[0-9A-Za-z]{40,}'
                    if re.search(base62_pattern, content):
                        indicators['other_encoding'] += 1

                    # 检测危险函数（2026-10：改用 AST 只认真实调用。
                    # 裸子串会命中注释/文档字符串——typing_extensions 里
                    # "how eval() and exec() work" 这类说明文字曾导致误判 OBFUSCATED）
                    real_calls = self._ast_called_names(content)
                    if 'eval' in real_calls:
                        indicators['eval_usage'] = True
                    if 'compile' in real_calls:
                        indicators['compile_usage'] = True
                    if 'exec' in real_calls:
                        indicators['exec_usage'] = True

                    # ===== Fernet加密检测（新增 - 最高优先级） =====
                    # 1. Fernet + exec 模式（导致78个包误判的核心原因）
                    if re.search(r'exec\s*\(\s*Fernet\s*\([^)]*\)\.decrypt\s*\(', content, re.IGNORECASE):
                        indicators['exec_fernet_pattern'] = True

                    # 2. Fernet加密payload检测（100-500字符）
                    if 'Fernet' in content:
                        fernet_pattern = r'[A-Za-z0-9+/={-]{100,500}={0,2}'
                        if re.search(fernet_pattern, content):
                            indicators['fernet_encrypted_payload'] = True

                    # 3. Marshal + exec 模式（极危险）
                    if re.search(r'exec\s*\(\s*marshal\.loads\s*\(', content):
                        indicators['exec_marshal_pattern'] = True

                    # 4. Marshal bytecode检测（AST 只认真实调用，排除文档字符串）
                    if 'marshal.loads' in real_calls:
                        marshal_pattern = r'[A-Za-z0-9+/]{200,}={0,2}'
                        if re.search(marshal_pattern, content):
                            indicators['marshal_bytecode'] = True

                    # 5. Pickle + exec 模式（极危险）
                    if re.search(r'exec\s*\(\s*pickle\.loads\s*\(', content):
                        indicators['exec_pickle_pattern'] = True

                    # 6. Pickle payload检测（AST 只认真实调用；typing_extensions
                    # 的文档里出现 "be pickled" 曾造成误判）
                    if 'pickle.loads' in real_calls:
                        pickle_pattern = r'[A-Za-z0-9+/]{200,}={0,2}'
                        if re.search(pickle_pattern, content):
                            indicators['pickle_payload'] = True

                    # 7. 通用decrypt + exec/eval 模式
                    if re.search(r'(?:exec|eval)\s*\(\s*\w+\.decrypt\s*\(', content):
                        indicators['exec_decrypt_pattern'] = True

                    # 8. eval + base64 模式（改进：支持复杂混淆）
                    # 基础模式：eval(base64.b64decode(...))
                    if re.search(r'eval\s*\(\s*base64\.b64decode\s*\(', content):
                        indicators['eval_base64_pattern'] = True
                    # 复杂模式1：__import__(...).eval(base64.b64decode(...))
                    if re.search(r'__import__\([^)]+\)\s*\.\s*eval\s*\([^)]*base64\.b64decode', content, re.IGNORECASE):
                        indicators['eval_base64_pattern'] = True
                    # 通用模式：eval...base64...（跨行）
                    if re.search(r'eval\s*\([^)]*base64\.b64decode\s*\(', content, re.IGNORECASE | re.DOTALL):
                        indicators['eval_base64_pattern'] = True

                    # 8.5 exec + base64 模式（改进：支持复杂混淆）
                    # 基础模式：exec(base64.b64decode(...))
                    if re.search(r'exec\s*\(\s*base64\.b64decode\s*\(', content):
                        indicators['exec_base64_pattern'] = True
                    # 复杂模式1：__import__(...).exec(base64.b64decode(...))
                    if re.search(r'__import__\([^)]+\)\s*\.\s*exec\s*\([^)]*base64\.b64decode', content, re.IGNORECASE):
                        indicators['exec_base64_pattern'] = True
                    # 通用模式：exec...base64...（跨行）
                    if re.search(r'exec\s*\([^)]*base64\.b64decode\s*\(', content, re.IGNORECASE | re.DOTALL):
                        indicators['exec_base64_pattern'] = True

                    # 9. eval + decrypt 模式
                    if re.search(r'eval\s*\(\s*\w+\.decrypt\s*\(', content):
                        indicators['eval_decrypt_pattern'] = True

                    # 10. compile + exec 模式（改进：支持复杂混淆）
                    # 基础模式：exec(compile(...))
                    if re.search(r'exec\s*\(\s*compile\s*\(', content):
                        indicators['compile_exec_pattern'] = True
                    # 复杂模式1：__import__(...).exec(compile(...))
                    if re.search(r'__import__\([^)]+\)\s*\.\s*exec\s*\([^)]*\)\s*.*?compile\s*\(', content, re.IGNORECASE):
                        indicators['compile_exec_pattern'] = True
                    # 复杂模式2：__import__(...).exec(__import__(...).compile(...))
                    if re.search(r'__import__\([^)]+\)\s*\.\s*exec\s*\([^)]*__import__\([^)]+\)\s*\.\s*compile\s*\(', content, re.IGNORECASE):
                        indicators['compile_exec_pattern'] = True
                    # 复杂模式3：getattr(..., 'exec')(compile(...))
                    if re.search(r"getattr\s*\([^,]+,\s*['\"][^'\"]*exec[^'\"]*['\"]\s*\)\s*\([^)]*\)\s*.*?compile\s*\(", content, re.IGNORECASE):
                        indicators['compile_exec_pattern'] = True
                    # 通用模式：exec...compile（跨行）
                    if re.search(r'exec\s*\([^)]*compile\s*\(', content, re.IGNORECASE | re.DOTALL):
                        indicators['compile_exec_pattern'] = True

                    # 11. bz2压缩检测（收紧：要求 bz2.decompress 调用形态）
                    if re.search(r'\bbz2\s*\.\s*(decompress|decompressobj)\s*\(', content):
                        indicators['bz2_compression'] = True

                    # 统计lambda表达式（计数，稍后按密度门控）
                    total_lambdas += content.count(' lambda ')

                    # 统计getattr调用（计数，稍后按密度门控）
                    total_getattrs += content.count('getattr(')

                    # 复杂的字符串格式化（计数，稍后按密度门控）
                    if '%(' in content:
                        total_string_formatting += len(re.findall(r'%\(.{20,}\)', content))

                    # 检测可疑导入（2026-10 收紧）：
                    # 原词表含 crypto/cipher/aes/rsa/codecs 等"领域词"，
                    # 加密库(pycryptodome 473次命中)必然全中——这是误报主源。
                    # 现在只认真正的混淆工具/框架，且按去重的 import 语句计数
                    # 而非全文子串出现次数。
                    suspicious_imports = [
                        'obfuscate', 'pyarmor', 'pyminifier', 'pyobfuscate',
                        'pycrypt',  # 常见恶意加密包装名(如 pycryptex)
                    ]
                    imported_modules = set()
                    for m in re.finditer(
                        r'^\s*(?:from\s+([\w.]+)\s+import|import\s+([\w.]+))',
                        content, re.MULTILINE
                    ):
                        top = (m.group(1) or m.group(2) or '').split('.')[0].lower()
                        if top:
                            imported_modules.add(top)
                    indicators['suspicious_imports'] += sum(
                        1 for word in suspicious_imports
                        if any(word in mod for mod in imported_modules)
                    )

                    # 统计变量名长度（短变量名可能是混淆）
                    # 修复：原正则 \b([a-z]{1,2})\s*= 只捕获 1-2 字符名，
                    # 后续 len(var)<=2 恒真 → 比例恒 1.0，任何含 x= 的普通包都被加分。
                    # 改为捕获全部小写标识符赋值目标再计算真实占比。
                    variables = re.findall(r'\b([a-z_]\w*)\s*=(?!=)', content)
                    for var in variables:
                        total_variables += 1
                        if len(var) <= 2:
                            short_variables += 1

            except Exception as e:
                continue

        # 计算短变量名比例
        if total_variables > 0:
            indicators['short_variable_names'] = short_variables / total_variables

        # ===== 密度归一（2026-10，真实良性样本测试驱动）=====
        # 计数型指标若不看体量，任何大数据表/测试向量都会让分数爆掉：
        # Crypto(pycryptodome) 因 2653 个 hex 转义、473 个 crypto 关键词
        # 命中而凑到 0.81 被判 OBFUSCATED。这里按"每 KB 出现次数"门控，
        # 只有密度异常才算混淆信号。
        total_kb = max(total_bytes / 1024.0, 1.0)

        def _dense(count: int, min_count: int, per_kb: float) -> bool:
            return count >= min_count and (count / total_kb) >= per_kb

        if not _dense(indicators['hex_strings'], 5, 8.0):
            indicators['hex_strings'] = 0
        if not _dense(indicators['base64_strings'], 3, 0.30):
            indicators['base64_strings'] = 0
        if not _dense(indicators['base32_strings'], 3, 0.50):
            indicators['base32_strings'] = 0
        if not _dense(indicators['other_encoding'], 2, 0.50):
            indicators['other_encoding'] = 0
        if _dense(total_unicode_escapes, 20, 2.0):
            indicators['unicode_escape'] = True
        if _dense(total_url_encoded, 20, 2.0):
            indicators['url_encoding'] = True
        if _dense(total_lambdas, 10, 3.0):
            indicators['lambda_heavy'] = True
        if _dense(total_getattrs, 20, 4.0):
            indicators['getattr_heavy'] = True
        if _dense(total_string_formatting, 5, 1.0):
            indicators['string_formatting_complex'] = True

        # 检查DDG V7报告中的混淆迹象
        if ddg_v7_report:
            # 检测typosquatting
            typosquatting = ddg_v7_report.get('typosquatting', {})
            if typosquatting.get('is_suspicious', False):
                indicators['typosquatting'] = True

            # 检测setup.py中的混淆迹象
            metadata = ddg_v7_report.get('metadata', {})
            setup_hooks = metadata.get('setup_hooks', [])
            init_exec_code = metadata.get('init_exec_code', [])

            if len(setup_hooks) > 0 or len(init_exec_code) > 0:
                indicators['suspicious_imports'] += len(setup_hooks) + len(init_exec_code)

        # 计算混淆分数（0-1）
        obfuscation_score = 0.0

        # 1. Hex字符串（权重：0.25）
        if indicators['hex_strings'] > 0:
            hex_score = min(0.25, indicators['hex_strings'] / 100)
            obfuscation_score += hex_score

        # 2. Base64字符串（权重：0.20）
        if indicators['base64_strings'] > 0:
            base64_score = min(0.20, indicators['base64_strings'] / 50)
            obfuscation_score += base64_score

        # 3. 短变量名比例（权重：0.15）
        if indicators['short_variable_names'] > 0.5:
            var_score = min(0.15, indicators['short_variable_names'])
            obfuscation_score += var_score

        # 4. 危险函数使用（权重：0.20）
        dangerous_funcs = sum([
            indicators['eval_usage'],
            indicators['compile_usage'],
            indicators['exec_usage']
        ])
        if dangerous_funcs > 0:
            obfuscation_score += min(0.20, dangerous_funcs * 0.07)

        # 5. 高级混淆特征（权重：0.10）
        advanced_features = sum([
            indicators['lambda_heavy'],
            indicators['getattr_heavy'],
            indicators['string_formatting_complex']
        ])
        if advanced_features > 0:
            obfuscation_score += min(0.10, advanced_features * 0.04)

        # 6. 可疑导入/typosquatting（权重：0.10）
        suspicious_score = min(0.10, indicators['suspicious_imports'] * 0.02)
        if indicators['typosquatting']:
            suspicious_score = max(suspicious_score, 0.10)
        obfuscation_score += suspicious_score

        # Bug #11增强：高级混淆特征（权重：0.25，额外增加）
        advanced_obf_score = 0.0

        # 大型base64字符串（+0.15，极其可疑）
        if indicators['large_base64_strings'] > 0:
            advanced_obf_score += 0.15

        # 可疑变量名+payload（+0.05）
        if indicators['suspicious_var_with_payload']:
            advanced_obf_score += 0.05

        # exec(base64(...))模式（+0.03）
        if indicators['exec_base64_pattern']:
            advanced_obf_score += 0.03

        # zlib压缩+base64（+0.02）
        if indicators['zlib_compression_pattern']:
            advanced_obf_score += 0.02

        obfuscation_score += advanced_obf_score

        # Bug #11进一步扩展：更多混淆类型的评分（权重：0.15）
        extra_obf_score = 0.0

        # 中文混淆（+0.05，罕见但危险）
        if indicators['chinese_obfuscation']:
            extra_obf_score += 0.05

        # Base32编码（+0.03）
        if indicators['base32_strings'] > 0:
            extra_obf_score += min(0.03, indicators['base32_strings'] * 0.01)

        # Unicode转义（+0.03）
        if indicators['unicode_escape']:
            extra_obf_score += 0.03

        # URL编码（+0.02）
        if indicators['url_encoding']:
            extra_obf_score += 0.02

        # Rot13/字符替换（+0.02）
        if indicators['rot13_cipher']:
            extra_obf_score += 0.02

        # 其他编码（+0.02）
        if indicators['other_encoding'] > 0:
            extra_obf_score += min(0.02, indicators['other_encoding'] * 0.01)

        obfuscation_score += extra_obf_score

        # ===== Fernet加密检测评分（新增 - 最高优先级） =====
        # 这些检测模式具有最高权重，因为它们明确表明恶意混淆

        # 1. Fernet + exec 模式（最高危险 - 立即判定混淆）
        if indicators['exec_fernet_pattern']:
            obfuscation_score += 0.30  # 单项就达到阈值！

        # 2. Marshal + exec 模式（极高危险）
        if indicators['exec_marshal_pattern']:
            obfuscation_score += 0.25

        # 3. Pickle + exec 模式（极高危险）
        if indicators['exec_pickle_pattern']:
            obfuscation_score += 0.25

        # 4. Fernet加密payload
        if indicators['fernet_encrypted_payload']:
            obfuscation_score += 0.20

        # 5. Marshal bytecode
        if indicators['marshal_bytecode']:
            obfuscation_score += 0.20

        # 6. Pickle payload
        if indicators['pickle_payload']:
            obfuscation_score += 0.20

        # 7. 通用decrypt + exec/eval 模式
        if indicators['exec_decrypt_pattern']:
            obfuscation_score += 0.20

        # 8. eval + base64 模式
        if indicators['eval_base64_pattern']:
            obfuscation_score += 0.15

        # 9. eval + decrypt 模式
        if indicators['eval_decrypt_pattern']:
            obfuscation_score += 0.15

        # 10. compile + exec 模式
        if indicators['compile_exec_pattern']:
            obfuscation_score += 0.15

        # 11. bz2压缩
        if indicators['bz2_compression']:
            obfuscation_score += 0.10

        # 判定是否混淆
        is_obfuscated = obfuscation_score >= 0.30  # 阈值：0.30

        # 生成推理说明
        reasons = []
        if indicators['hex_strings'] > 0:
            reasons.append(f"发现{indicators['hex_strings']}个hex字符串")
        if indicators['base64_strings'] > 0:
            reasons.append(f"发现{indicators['base64_strings']}个base64字符串")
        if indicators['short_variable_names'] > 0.5:
            reasons.append(f"短变量名比例高: {indicators['short_variable_names']:.1%}")
        if dangerous_funcs > 0:
            reasons.append(f"使用危险函数: {'eval' if indicators['eval_usage'] else ''}{'compile' if indicators['compile_usage'] else ''}{'exec' if indicators['exec_usage'] else ''}")
        if advanced_features > 0:
            reasons.append("过度使用高级特性（lambda/getattr/复杂字符串格式）")
        if indicators['suspicious_imports'] > 0:
            reasons.append(f"发现{indicators['suspicious_imports']}个可疑导入或混淆库")
        if indicators['typosquatting']:
            reasons.append("检测到typosquatting")
        # Bug #11增强：添加高级混淆特征的推理说明
        if indicators['large_base64_strings'] > 0:
            reasons.append(f"发现{indicators['large_base64_strings']}个大型base64字符串（>1000字符，疑似shellcode）")
        if indicators['suspicious_var_with_payload']:
            reasons.append("检测到可疑变量名与大型payload组合")
        if indicators['exec_base64_pattern']:
            reasons.append("检测到exec(base64.b64decode(...))恶意模式")
        if indicators['zlib_compression_pattern']:
            reasons.append("检测到zlib压缩+base64混淆组合")
        # Bug #11进一步扩展：添加更多混淆类型的推理说明
        if indicators['chinese_obfuscation']:
            reasons.append("检测到中文字符混淆")
        if indicators['base32_strings'] > 0:
            reasons.append(f"发现{indicators['base32_strings']}个Base32编码字符串")
        if indicators['unicode_escape']:
            reasons.append("检测到Unicode转义序列")
        if indicators['url_encoding']:
            reasons.append("检测到URL编码")
        if indicators['rot13_cipher']:
            reasons.append("检测到Rot13/字符替换加密")
        if indicators['other_encoding'] > 0:
            reasons.append(f"发现{indicators['other_encoding']}种其他编码（Base58/62/91等）")

        # Fernet加密检测推理说明（新增 - 最高优先级）
        if indicators['exec_fernet_pattern']:
            reasons.append("检测到exec(Fernet(...).decrypt(...))加密执行模式")
        if indicators['fernet_encrypted_payload']:
            reasons.append("检测到Fernet加密payload")
        if indicators['exec_marshal_pattern']:
            reasons.append("检测到exec(marshal.loads(...))字节码执行模式")
        if indicators['marshal_bytecode']:
            reasons.append("检测到Marshal字节码")
        if indicators['exec_pickle_pattern']:
            reasons.append("检测到exec(pickle.loads(...))反序列化执行模式")
        if indicators['pickle_payload']:
            reasons.append("检测到Pickle反序列化payload")
        if indicators['exec_decrypt_pattern']:
            reasons.append("检测到exec/eval(xxx.decrypt(...))通用解密执行模式")
        if indicators['eval_base64_pattern']:
            reasons.append("检测到eval(base64.b64decode(...))动态执行模式")
        if indicators['eval_decrypt_pattern']:
            reasons.append("检测到eval(xxx.decrypt(...))解密执行模式")
        if indicators['compile_exec_pattern']:
            reasons.append("检测到exec(compile(...))编译执行模式")
        if indicators['bz2_compression']:
            reasons.append("检测到bz2压缩混淆")

        reasoning = "、".join(reasons) if reasons else "无明显混淆迹象"

        print(f"        [混淆检测结果]")
        print(f"          混淆分数: {obfuscation_score:.2f}")
        print(f"          是否混淆: {'是' if is_obfuscated else '否'}")
        print(f"          理由: {reasoning}")

        return {
            'is_obfuscated': is_obfuscated,
            'obfuscation_score': obfuscation_score,
            'indicators': indicators,
            'reasoning': reasoning
        }

    def _save_results(self):
        """保存结果"""
        # 创建 output/results 目录
        output_dir = Path('output/results')
        output_dir.mkdir(parents=True, exist_ok=True)

        # 保存汇总结果到 output/results/
        output_file = output_dir / f'batch_v20_voting_results_{int(time.time())}.json'
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False, default=str)
        print(f"\n结果已保存到: {output_file}")
        if self.results_jsonl:
            print(f"逐包增量记录: {self.results_jsonl}")

        # 分类统计摘要
        from collections import Counter
        category_counts = Counter(r.get('final_category', 'UNKNOWN') for r in self.results)
        print(f"\n[批次统计] 共 {len(self.results)} 个包: {dict(category_counts)}")


def main():
    import argparse
    import sys
    import io

    # 强制UTF-8输出（解决Windows中文乱码问题）
    if sys.platform == 'win32':
        import codecs
        import locale

        # 设置stdout为UTF-8编码
        sys.stdout = io.TextIOWrapper(
            sys.stdout.buffer,
            encoding='utf-8',
            errors='replace',
            line_buffering=True
        )
        sys.stderr = io.TextIOWrapper(
            sys.stderr.buffer,
            encoding='utf-8',
            errors='replace',
            line_buffering=True
        )

    parser = argparse.ArgumentParser(description='批量分析包 - Solution B 投票架构')
    parser.add_argument('tarfile_dir', help='tar文件目录')
    parser.add_argument('--llm', default='glm', choices=['glm', 'claude'], help='LLM类型')
    parser.add_argument('--api-key', required=True, help='API密钥')
    parser.add_argument('--count', type=int, default=100, help='分析包数量')
    parser.add_argument('--extract-base', default='output/packages', help='解压基目录')
    parser.add_argument('--skip-rule-scoring', action='store_true', help='跳过规则评分，直接使用LLM分析子图')
    parser.add_argument('--parallel-workers', type=int, default=1,
                        help='高优先级子图LLM并行线程数（默认1=串行）')
    parser.add_argument('--seed', type=int, default=42,
                        help='抽样随机种子（默认42，保证评测可复现）')
    parser.add_argument('--llm-model', default='glm-4-flashx',
                        help='LLM 模型名(glm-4-flashx/glm-4-flash/glm-4-plus 等)')
    parser.add_argument('--sandbox', action='store_true',
                        help='启用沙箱行为探针(执行 setup.py 记录安装期行为;'
                             '会执行包内代码,仅在隔离 VM/容器启用!)')
    parser.add_argument('--no-llm-cache', action='store_true',
                        help='禁用 LLM 判决缓存（默认开启：相同子图不重复调用）')
    parser.add_argument('--verify-pypi', action='store_true',
                        help='核验发行名是否存在于 PyPI 官方索引（识别名称抢注/被下架包，需联网）')

    args = parser.parse_args()

    analyzer = BatchAnalyzerV20Voting(
        tarfile_dir=args.tarfile_dir,
        llm=args.llm,
        api_key=args.api_key,
        count=args.count,
        extract_base=args.extract_base,
        skip_rule_scoring=args.skip_rule_scoring,
        parallel_workers=args.parallel_workers,
        seed=args.seed,
        verify_pypi=args.verify_pypi,
        use_llm_cache=not args.no_llm_cache,
        sandbox=args.sandbox,
        llm_model=args.llm_model
    )

    analyzer.analyze_all()


if __name__ == '__main__':
    main()
