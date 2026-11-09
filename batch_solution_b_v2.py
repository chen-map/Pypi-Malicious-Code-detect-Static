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

# SUSPICIOUS 升级门控（2026-11）:与离线重判脚本共用 taint_engine 中的同一份
# 逻辑，保证在线投票与离线重判口径一致（强源→sink / 任意→外传 才自动升级）
from src.taint_engine import escalation_gate


# ===== 单包分析超时保护（2026-11）=====
# analyze_package 在千文件级框架包上纯计算爆炸（agent_framework:
# 1093个py文件, CPU满转 40+ 分钟无产出, 卡死整个批次）。
# 每包在子进程中分析, 超过 PER_PACKAGE_TIMEOUT 秒强杀 → 记
# ANALYSIS_FAILED(timeout), 批次继续。0 = 关闭（调试用）。
PER_PACKAGE_TIMEOUT = 900

# 子图分析预算（2026-11）：超大 monorepo（ag2: 1136 个函数级子图）下游
# 成本线性爆炸 → 超时。按危险节点数保留最危险的前 N 个。
MAX_SUBGRAPHS_ANALYZED = 400

# ===== 2026-11 大包拆分阈值 =====
# 建图侧：py 文件数超过此值 → SSO 粗筛选中子集建图（agent_framework
# 1093 文件全量建图 CPU 40 分钟是 ANALYSIS_TIMEOUT 主因）
LARGE_PKG_FILE_THRESHOLD = 150
# 分析侧：子图数或全图节点数超过任一阈值 → 跳过 400 子图机器，
# 直接走块划分快路径（block_nodes=300/max_blocks=16/420s）
LARGE_PKG_SUBGRAPH_THRESHOLD = 200
LARGE_PKG_NODE_THRESHOLD = 6000
# 大包块划分预算（放大幅度受 900s 包级信封约束：SSO 已砍掉大部分建图时间）
LARGE_PKG_BLOCK_NODES = 300
LARGE_PKG_MAX_BLOCKS = 16
LARGE_PKG_TIME_BUDGET_S = 420


def _analyze_one_in_subprocess(input_path, input_type, worker_kwargs, results_jsonl_str):
    """子进程 worker: 构造独立 analyzer 分析单包并落盘结果行。

    结果直接 append 到批次 JSONL——子进程与主进程从不同时写
    （子进程写完才退出, 主进程 join 后才读）, 无竞争。
    """
    import json as _json
    import time as _time
    kw = dict(worker_kwargs)
    kw['tarfile_dir'] = str(input_path)
    analyzer = BatchAnalyzerV20Voting(**kw)
    try:
        result = analyzer.analyze_package(input_path, input_type)
    except Exception as e:
        result = {
            'package_name': input_path.name,
            'final_category': 'ANALYSIS_FAILED',
            'final_risk_score': 0.5,
            'final_confidence': 0.3,
            'error': str(e)[:300],
        }
    result['_subprocess'] = True
    result['_ts'] = _time.time()
    # 按输入文件名索引:analyze_package 返回的 package_name 是解压目录名
    # (如 "foo-1.0"), 与主进程查找键(input_path.name="foo-1.0.tar.gz")
    # 不一致——此前 92 个成功包因此被主进程误判 "died without result"
    result['_input_name'] = input_path.name
    with open(results_jsonl_str, 'a', encoding='utf-8') as f:
        f.write(_json.dumps(result, ensure_ascii=False, default=str) + '\n')


def _read_subprocess_result(jsonl_path, pkg_name):
    """从批次 JSONL 尾部找该输入由子进程写入的结果行（按 _input_name 匹配）。"""
    p = Path(jsonl_path)
    if not p.exists():
        return None
    try:
        lines = p.read_text(encoding='utf-8').splitlines()
        for line in reversed(lines):
            if not line.strip():
                continue
            row = json.loads(line)
            if (row.get('_input_name') == pkg_name or
                    (row.get('_subprocess') and row.get('package_name') == pkg_name)):
                row.pop('_subprocess', None)
                row.pop('_ts', None)
                row.pop('_input_name', None)
                return row
    except Exception:
        return None
    return None


def _flagged_code_signals(verdicts, subgraph_jsons, max_funcs=4, max_chars=1200):
    """组装可疑/恶意子图的函数代码原文（2026-11 证据完整性修复）。

    此前包级 LLM 只有下级"判决标签"——被要求复核一个看不到代码的
    判决只能回声。给代码原文它才能独立推翻或确认。
    预算: 最多 max_funcs 个函数, 每个按行号去重排序重组、截断 max_chars。
    """
    flagged = [v for v in verdicts if v.get('final_verdict') in ('SUSPICIOUS', 'MALICIOUS')]
    by_name = {s.get('subgraph_name'): s for s in (subgraph_jsons or [])}
    lines_out = []
    shown = 0
    for v in flagged[:max_funcs]:
        sg = by_name.get(v.get('subgraph_name'))
        if not sg:
            continue
        code_lines = sorted({(n.get('line', 0), n.get('code', ''))
                             for n in (sg.get('nodes') or []) if n.get('code')})
        buf, total = [], 0
        for _ln, code in code_lines:
            if total + len(code) > max_chars:
                buf.append('  ...')
                break
            buf.append(f'  {code}')
            total += len(code)
        if buf:
            lines_out.append(f"Code of flagged subgraph '{v.get('subgraph_name')}' "
                             f"(verdict={v.get('final_verdict')}):")
            lines_out.extend(buf)
            shown += 1
    if shown:
        lines_out.append(f"({shown} flagged subgraphs' code shown - judge from the code itself)")
    return lines_out


def _llm_escalation_corroborated(enhanced_detection_result, voting_result,
                                 ignore_pypi_gate=False, block_scan=None,
                                 subgraph_jsons=None):
    """包级 LLM 升级 MALICIOUS 的机械复核（2026-11）。

    弱模型实测会无视 prompt 判据（良性 fork 名被 "typosquatting high" 或
    "setup.py 有 exec" 引着升级）。结构性证据不足时升级一律驳回：
      允许升级的结构性证据（与投票层门控同口径）：
      1. 增强通道 critical（真实 critical 单信号，弱信号累加不算——Bug D）
      2. 可疑子图自带强污点链（escalation_gate）
      3. PyPI not_found（名字不存在=确定性铁证）
    返回 (是否允许, 理由字符串)。
    """
    ed = enhanced_detection_result or {}
    ed_lvl = ed.get('overall_threat_level', 'safe')
    pypi_st = (ed.get('pypi_verification') or {}).get('status', '')
    # 只统计**被判可疑/恶意**的子图——BENIGN 子图里的链不能作为升级依据。
    # （ag2 教训:400 个子图中 396 个 BENIGN,其中某函数恰有 network→sink 链,
    #  导致 strong_chain 误判为 True,弱链升级被放行。）
    flagged = [v for v in (voting_result or {}).get('subgraph_verdicts', [])
               if v.get('final_verdict') in ('SUSPICIOUS', 'MALICIOUS')]
    # 目标感知需要节点代码：从 subgraph_jsons 按名取回
    _sg_nodes = {}
    if subgraph_jsons:
        _by_name = {s.get('subgraph_name'): s for s in subgraph_jsons}
        for v in flagged:
            _sg_nodes[v.get('subgraph_name')] = \
                (_by_name.get(v.get('subgraph_name')) or {}).get('nodes')
    strong_chain = any(
        escalation_gate(v.get('taint_chains'),
                        nodes=_sg_nodes.get(v.get('subgraph_name')))
        for v in flagged)
    if ed_lvl == 'critical':
        return True, '增强通道 critical'
    if strong_chain:
        return True, '可疑子图自带强污点链'
    # 2026-11 包块划分：整包逐块读出来的链已经过 verify_paths 验证，
    # 且必须含敌意字面量（升级门收紧后两条件同时满足才到得了这里），
    # 属于结构性证据（每一跳都对应真实存在的边）。
    if (block_scan and (block_scan.get('valid_paths') or [])
            and block_scan.get('_hostile_literal')):
        return True, (f"包块划分验证链 {len(block_scan['valid_paths'])} 条"
                      f"（含敌意字面量）")
    if pypi_st == 'not_found' and not ignore_pypi_gate:
        return True, 'PyPI not_found'
    return False, (f'无结构性证据(ed={ed_lvl}, pypi={pypi_st or "n/a"}, '
                   f'强链={"Y" if strong_chain else "N"})')


def _llm_malicious_weak_only(llm_malicious, enhanced_detection_result):
    """零容忍的强证据门控（2026-11，真实误报驱动）。

    返回需要降级的 verdict 列表（空 = 保留零容忍）。

    背景：`exec(open("_version.py").read())` 是 setuptools-scm 的标准
    惯用法（file_read→code_execution 弱链），LLM 会判它恶意，零容忍
    随即判死整包——ag2 / acryl_executor / acryl_datahub_dagster 三个
    真实良性包因此误报。
    规则：所有 LLM 恶意子图都只有弱链（不满足 escalation_gate）时降级；
    只要有一个强链就保留零容忍。独立铁证（增强 critical / PyPI 404）豁免。
    **无链信息的子图不据此降级**——"没有链"不等于"弱链"（纯语义判决、
    正则命中或老数据都可能没有链，据此降级会削弱召回）。
    """
    if not llm_malicious:
        return []
    ed = enhanced_detection_result or {}
    if (ed.get('overall_threat_level') == 'critical' or
            (ed.get('pypi_verification') or {}).get('status') == 'not_found'):
        return []
    with_chains = [v for v in llm_malicious if (v.get('taint_chains') or [])]
    if not with_chains:
        return []  # 无链信息，不据此降级
    weak = [v for v in with_chains if not escalation_gate(v.get('taint_chains'))]
    # 全部恶意子图都带链且全是弱链 → 整体降级
    return weak if len(weak) == len(llm_malicious) else []


class BatchAnalyzerV20Voting:
    """批量分析器 V20 - 投票架构"""

    def __init__(self, tarfile_dir: str, llm: str = 'glm', api_key: str = '', count: int = 100, extract_base: str = 'output/packages', skip_rule_scoring: bool = False, parallel_workers: int = 1, seed: int = 42, verify_pypi: bool = False, use_llm_cache: bool = True, sandbox: bool = False,
                llm_model: str = 'glm-4-flashx', ignore_pypi_gate: bool = False,
                block_scan: bool = True, cross_scope: bool = True,
                graph_backend: str = 'builtin',
                llm_pipeline: str = 'single',
                llm_model_small: str = '', llm_model_big: str = '',
                pyflow_max_seconds: int = 60,
                pyflow_capability_model: str = '',
                coverage_max_skip: float = 0.30):
        self.tarfile_dir = Path(tarfile_dir)
        self.llm = llm
        self.api_key = api_key
        self.count = count
        self.extract_base = Path(extract_base)
        self.skip_rule_scoring = skip_rule_scoring
        self.parallel_workers = parallel_workers  # 并行线程数（>1 时高优先级子图并行LLM分析）
        self.seed = seed  # 抽样随机种子（可复现评测）
        self.verify_pypi = verify_pypi  # 是否核验包是否存在于 PyPI（名称抢注判据）
        # 消融开关（--no-pypi-gate）：registry 身份不参与判决，用于评估
        # 纯代码分析（图内核 + LLM）在不联网条件下的检出能力
        self.ignore_pypi_gate = ignore_pypi_gate
        self.use_llm_cache = use_llm_cache  # LLM 判决缓存（--no-llm-cache 关闭）
        self.sandbox = sandbox  # 沙箱行为探针(执行 setup.py,仅隔离环境启用!)
        self.llm_model = llm_model  # LLM 模型名(--llm-model)
        # 2026-11 包块划分：机械投票落在歧义区时，整包图按文件→函数分块
        # 逐块读（不看是否被正则标记），作为第二意见。--no-block-scan 关闭。
        self.block_scan = block_scan
        # 2026-11 消融开关（--no-cross-scope）：关闭跨块边 + 全图链分发，
        # 用于量化"跨作用域证据"本身的增益
        self.cross_scope = cross_scope
        # 2026-11 图后端 / LLM 管道 / 覆盖度门控
        self.graph_backend = graph_backend          # builtin | pyflow
        self.llm_pipeline = llm_pipeline            # single | two_stage
        self.llm_model_small = llm_model_small or llm_model
        self.llm_model_big = llm_model_big or llm_model
        self.pyflow_max_seconds = pyflow_max_seconds
        self.pyflow_capability_model = pyflow_capability_model
        self.coverage_max_skip = coverage_max_skip
        self._full_graph = None   # 当前包的整图快照（_run_ddg_builder 填充）
        self.results = []
        self.results_jsonl = None  # 增量落盘文件（analyze_all 时初始化）

        # 初始化增强检测器（检测setup.py/依赖/元数据威胁）
        self.enhanced_detector = EnhancedSecurityDetector()

        # 创建 output 目录结构
        self.extract_base.mkdir(parents=True, exist_ok=True)
        print(f"[输出目录] 所有结果将保存到: output/")
        print(f"  - 解压包: {self.extract_base}")
        print(f"  - 分析结果: output/results/")

    def _worker_kwargs(self) -> Dict:
        """子进程重建 analyzer 所需的构造参数（不含 tarfile_dir）"""
        return {
            'api_key': self.api_key,
            'count': 1,
            'extract_base': str(self.extract_base),
            'skip_rule_scoring': self.skip_rule_scoring,
            'parallel_workers': self.parallel_workers,
            'seed': self.seed,
            'verify_pypi': self.verify_pypi,
            'ignore_pypi_gate': self.ignore_pypi_gate,
            'use_llm_cache': self.use_llm_cache,
            'sandbox': self.sandbox,
            'llm_model': self.llm_model,
            'block_scan': self.block_scan,
            'cross_scope': self.cross_scope,
            'graph_backend': self.graph_backend,
            'llm_pipeline': self.llm_pipeline,
            'llm_model_small': self.llm_model_small,
            'llm_model_big': self.llm_model_big,
            'pyflow_max_seconds': self.pyflow_max_seconds,
            'pyflow_capability_model': self.pyflow_capability_model,
            'coverage_max_skip': self.coverage_max_skip,
        }

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

            # 2026-11 大包超时保护:analyze_package 在千文件级框架包上
            # 会纯计算爆炸(agent_framework-1.9.0: 1093个py文件, CPU满转
            # 43分钟无产出,卡死整个批次)。子进程隔离 + 硬超时:
            # 超时 → kill → ANALYSIS_FAILED(timeout),批次继续。
            result = None
            if PER_PACKAGE_TIMEOUT > 0:
                import multiprocessing as mp
                ctx = mp.get_context('spawn')
                proc = ctx.Process(
                    target=_analyze_one_in_subprocess,
                    args=(input_path, input_type, self._worker_kwargs(),
                          str(self.results_jsonl)))
                proc.start()
                proc.join(timeout=PER_PACKAGE_TIMEOUT)
                if proc.is_alive():
                    proc.kill()
                    proc.join(5)
                    print(f"[TIMEOUT] 单包分析超过 {PER_PACKAGE_TIMEOUT}s，强制终止，标记 ANALYSIS_FAILED")
                    result = {
                        'package_name': input_path.name,
                        'final_category': 'ANALYSIS_FAILED',
                        'final_risk_score': 0.5,
                        'final_confidence': 0.3,
                        'error': f'analysis timeout ({PER_PACKAGE_TIMEOUT}s)',
                        'timeout': True,
                    }
                else:
                    result = _read_subprocess_result(self.results_jsonl, input_path.name)
                    if result is None:
                        # 子进程崩溃且未落盘
                        result = {
                            'package_name': input_path.name,
                            'final_category': 'ANALYSIS_FAILED',
                            'final_risk_score': 0.5,
                            'final_confidence': 0.3,
                            'error': 'subprocess died without result',
                        }
                    else:
                        # 子进程已把该行写进 JSONL,主进程不再重复落盘
                        result['_already_written'] = True
            else:
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
            # 逐包追加落盘（子进程已写入的行不重复——此前每包双行,
            # 统计与审计都要先去重）
            if result.pop('_already_written', False):
                pass
            else:
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

        # ===== 顺序重排（2026-11）:便宜的先跑 =====
        # 原顺序先建 DDG(昂贵)再跑增强检测(纯正则),结果:千文件级 monorepo
        # 包在 DDG 上烧满 15 分钟被超时杀掉,而它本可以被零成本的增强检测
        # 直接短路。现在:增强检测 → critical 短路 → 规模预判 → DDG 构建。
        print(f"[Step 2/6] 增强检测（setup.py/依赖/元数据/包名）...")
        enhanced_detection_result = self.enhanced_detector.analyze_package(
            package_dir, dist_name=dist_name or package_name,
            verify_pypi=self.verify_pypi,
            ignore_pypi_gate=self.ignore_pypi_gate)

        def _enhanced_shortcut(report):
            return {
                'package_name': package_name,
                'final_category': 'MALICIOUS',
                'final_risk_score': 0.95,
                'final_confidence': 0.85,
                'voting_summary': '增强检测命中 critical 级威胁（安装钩子/名称抢注/暗网外传），'
                                  '直接判定恶意，未进入图分析',
                'enhanced_threat_level': report['overall_threat_level'],
                'enhanced_threats': report['threats_found'],
                'threat_details': {
                    'setup_py': report['setup_py_analysis'],
                    'dependency': report['dependency_analysis'],
                    'metadata': report['metadata_analysis'],
                    'distribution': report.get('distribution_analysis', {}),
                },
                'ddg_risk_level': 'skipped',
                'ddg_issues': 0,
                'attack_chains': {'chain_count': 0, 'completeness': 0.0,
                                  'confidence': 0.0, 'summary': ''},
                'detection_method': 'enhanced_detection',
            }

        # 均衡模式：只有 critical 级（真安装钩子+危险API/typosquatting/暗网）
        # 直通 MALICIOUS；high 降级进投票上下文，避免单条正则判死正常包。
        # 2026-11:critical 必须由真实 critical 单信号支撑（见 enhanced_detector），
        # 弱信号累加不再能凑出 critical。
        if enhanced_detection_result['overall_threat_level'] == 'critical':
            print(f"[快速判定] 增强检测发现critical级别威胁（跳过图构建）！")
            for _k in ('setup_py_analysis', 'dependency_analysis', 'metadata_analysis'):
                print(f"  - {_k}: {enhanced_detection_result[_k]['threat_level']}")
            return _enhanced_shortcut(enhanced_detection_result)

        print(f"[Step 3/6] 运行DDG Builder V7...")
        ddg_output = self._run_ddg_builder(package_dir)

        print(f"[Step 4/6] 读取DDG V7安全报告和子图数据...")
        ddg_v7_report = self._read_ddg_v7_report(package_dir)
        subgraph_jsons = self._read_subgraph_jsons(package_dir)

        # 读取重建的四阶段攻击链（数据引入→处理→危险执行→外传）
        attack_chains_summary = self._read_attack_chains(package_dir)
        if attack_chains_summary['chain_count'] > 0:
            print(f"          [攻击链] {attack_chains_summary['chain_count']} 条, "
                  f"完整性={attack_chains_summary['completeness']}, "
                  f"置信度={attack_chains_summary['confidence']}")

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
                        'voting_summary': '沙箱探针捕获安装期高危行为，直接判定恶意',
                        'sandbox': sandbox_result,
                        'ddg_risk_level': 'skipped',
                        'ddg_issues': 0,
                        'attack_chains': {'chain_count': 0, 'completeness': 0.0,
                                          'confidence': 0.0, 'summary': ''},
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
                # 2026-11 升级审计：污点链计数 + 升级标记（离线重判依赖此字段）
                'taint_chain_count': verdict.get('taint_chain_count', 0),
                'taint_categories': [
                    {'source_category': c.get('source_category', ''),
                     'sink_category': c.get('sink_category', ''),
                     'cross_file': c.get('cross_file', False)}
                    for c in (verdict.get('taint_chains') or [])[:3]
                ],
                'escalated': verdict.get('escalated', False),
            }
            # 如果是恶意子图，添加关键特征
            if verdict.get('is_malicious'):
                simplified_verdict['danger_score'] = verdict.get('risk_score', 0.5)
                simplified_verdict['attack_chain_complete'] = verdict.get('attack_chain_complete', False)
                simplified_verdict['key_info'] = verdict.get('key_info', verdict.get('reasoning', ''))[:200]
            simplified_verdicts.append(simplified_verdict)

        # ===== 2026-11 包块划分（歧义区第二意见 / 大包主路径）=====
        # 投票路径只看"被标记的函数"——召回上限 = 标记器召回率。机械投票
        # 落在 SUSPICIOUS 时，用整包图按文件→函数分块逐块读，粗筛只用于
        # 预算排序。只有**验证通过的链**才允许升级（反幻觉契约不变）。
        # 大包（_is_large）走块划分是**主路径**：rule-only 投票没有 LLM
        # 语义判断，不再有"歧义区"概念，直接整包读。
        _is_large = (len(subgraph_jsons) > LARGE_PKG_SUBGRAPH_THRESHOLD
                     or len((self._full_graph or {}).get('nodes') or [])
                     > LARGE_PKG_NODE_THRESHOLD)
        block_scan = None
        _block_gate = (voting_result['final_category'] in ('SUSPICIOUS', 'UNKNOWN')
                       or (_is_large and not self.skip_rule_scoring))
        if self.block_scan and _block_gate:
            if self.llm_pipeline == 'two_stage':
                # 2026-11 两阶段接管块划分：小模型提链 → 验证 → 大模型判定
                block_scan = self._two_stage_scan(
                    package_name, package_dir,
                    block_nodes=LARGE_PKG_BLOCK_NODES if _is_large else 250,
                    max_blocks=LARGE_PKG_MAX_BLOCKS if _is_large else 6,
                    time_budget_s=LARGE_PKG_TIME_BUDGET_S if _is_large else 240)
            else:
                block_scan = self._full_block_scan(
                    package_name,
                    block_nodes=LARGE_PKG_BLOCK_NODES if _is_large else 250,
                    max_blocks=LARGE_PKG_MAX_BLOCKS if _is_large else 6,
                    time_budget_s=LARGE_PKG_TIME_BUDGET_S if _is_large else 240)
            if (block_scan and block_scan.get('verdict') == 'MALICIOUS'
                    and block_scan.get('valid_paths')):
                # 2026-11 升级收紧（google_re2 误升级驱动）：verify_paths
                # 只保证边存在——正则库 re2.compile 的链同样是真实边。
                # 升级要求链上至少一个敌意字面量节点；否则维持原判决，
                # 交给包级 LLM 做语义判断。
                from src.graph_digest import any_hostile_literal
                _hostile = any_hostile_literal(
                    block_scan['valid_paths'],
                    (self._full_graph or {}).get('nodes') or [])
                if _hostile:
                    voting_result['final_category'] = 'MALICIOUS'
                    voting_result['block_scan_escalated'] = True
                    block_scan['_hostile_literal'] = True
                    print("        [包块划分] 验证链成立 → 升级 MALICIOUS")
                else:
                    block_scan['escalation_blocked'] = (
                        'no hostile literal in verified paths')
                    print("        [包块划分] 验证链无敌意字面量 → 不升级"
                          "（维持 " + voting_result['final_category'] + "）")

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
                    obfuscation_result, package_dir=package_dir,
                    subgraph_jsons=subgraph_jsons)
                if agg and agg.get('final_category'):
                    old_cat = voting_result['final_category']
                    new_cat = agg['final_category']

                    # ===== 机械复核门（2026-11，_llm_escalation_corroborated）=====
                    # 弱模型实测会无视 prompt 判据:良性 fork 名(acryl_*)被
                    # "typosquatting high"或"setup.py 有 exec"引着升级
                    # MALICIOUS。结构性证据不足时,LLM 升级一律降回 SUSPICIOUS。
                    if (new_cat == 'MALICIOUS' and old_cat != 'MALICIOUS'):
                        ok, why = _llm_escalation_corroborated(
                            enhanced_detection_result, voting_result,
                            ignore_pypi_gate=self.ignore_pypi_gate,
                            block_scan=block_scan,
                            subgraph_jsons=subgraph_jsons)
                        if not ok:
                            new_cat = 'SUSPICIOUS'
                            voting_result['llm_escalation_demoted'] = True
                            agg['final_category'] = 'SUSPICIOUS'
                            agg['demote_reason'] = f'LLM升级被机械复核驳回: {why}'
                            print(f"        [机械复核] LLM升级被驳回({why}) → SUSPICIOUS")

                    voting_result['final_category'] = new_cat
                    voting_result['final_risk_score'] = agg['risk_score']
                    voting_result['final_confidence'] = agg['confidence']
                    voting_result['voting_summary'] = (
                        f"[Package-level LLM] {old_cat} → {new_cat}: "
                        f"{agg.get('reasoning', '')[:200]}")
                    print(f"        [Package-level LLM] {old_cat} → {new_cat}")
            except Exception as agg_e:
                print(f"        [WARN] Package-level analysis failed: {agg_e}")

        # ===== 最终证据一致性保险（2026-11，ag2 误报驱动）=====
        # 不管 MALICIOUS 来自投票层、包级 LLM 还是任何其他路径，
        # 落盘前统一检查：无结构性证据（增强 critical / 强污点链 / PyPI 404）
        # 的 MALICIOUS 一律降为 SUSPICIOUS。原先只在包级 LLM 升级分支
        # 做检查，其他路径（如投票层零容忍）漏网——ag2 就是这样被判死的。
        if voting_result['final_category'] == 'MALICIOUS':
            _ok, _why = _llm_escalation_corroborated(
                enhanced_detection_result, voting_result,
                ignore_pypi_gate=self.ignore_pypi_gate,
                block_scan=block_scan,
                subgraph_jsons=subgraph_jsons)
            if not _ok:
                print(f"        [最终保险] MALICIOUS 无结构性证据({_why}) → SUSPICIOUS")
                voting_result['final_category'] = 'SUSPICIOUS'
                voting_result['voting_summary'] = (
                    f"[最终保险] 原判MALICIOUS降级: {_why}; "
                    + (voting_result.get('voting_summary') or '')[:200])
                voting_result['final_confidence'] = min(
                    float(voting_result.get('final_confidence') or 0.5), 0.6)

        # ===== 2026-11 覆盖度门控（unknown ≠ safe）=====
        # PyFlow 如实报告 entries_analyzed/entries_total。分析没覆盖到的
        # 部分，"没找到证据"不等于"干净"——只因分析不完整而 BENIGN 的判决
        # 一律降为 SUSPICIOUS，理由可审计。只降不升，且已有 Tier-1 能力
        # 时不受影响。
        coverage_info = None
        if self.graph_backend == 'pyflow':
            try:
                from src.coverage_gate import apply_to_verdict
                _cov = (getattr(self, '_graph_coverage', None) or {})
                _caps = (getattr(self, '_graph_capabilities', None) or {})
                _tier1 = any(c in ('process_spawn', 'code_eval', 'network_out',
                                   'privilege', 'credential_access')
                             for c in _caps)
                _new_cat, _assess = apply_to_verdict(
                    voting_result['final_category'], _cov,
                    has_tier1_capability=_tier1,
                    max_skip_ratio=self.coverage_max_skip)
                coverage_info = _assess
                if _new_cat != voting_result['final_category']:
                    print(f"        [覆盖度门控] BENIGN → SUSPICIOUS: {_assess['reason']}")
                    voting_result['final_category'] = _new_cat
                    voting_result['voting_summary'] = (
                        f"[覆盖度] {_assess['reason']}; "
                        + (voting_result.get('voting_summary') or '')[:200])
                    voting_result['final_confidence'] = min(
                        float(voting_result.get('final_confidence') or 0.5), 0.55)
            except Exception as _cg_err:
                print(f"        [WARN] 覆盖度门控失败: {_cg_err}")

        # 精简格式：只保留核心字段
        final_result = {
            'package_name': package_name,
            'final_category': voting_result['final_category'],
            'final_risk_score': voting_result['final_risk_score'],
            'final_confidence': voting_result['final_confidence'],
            # 2026-11 可观测性:判决理由必须落盘(此前包级聚合的理由
            # 只在内存里,JSONL 中 summary 全空,审计/误报复盘无从下手)
            'voting_summary': (voting_result.get('voting_summary') or '')[:300],
            'total_subgraphs': len(subgraph_jsons),
            'malicious_subgraph_count': voting_result['malicious_count'],
            'subgraph_verdicts': simplified_verdicts,
            'ddg_risk_level': ddg_risk_level,
            'ddg_issues': ddg_issues,
            # LLM 不可用时为 True（结果为规则回退，置信度应打折看待）
            'analysis_degraded': voting_result.get('analysis_degraded', False),
            # 重建的四阶段攻击链（证据可解释性）
            'attack_chains': attack_chains_summary,
            # 2026-11 包块划分（歧义区第二意见）：块数/节点数/判决/验证链
            'block_scan': ({
                'verdict': block_scan.get('verdict'),
                'confidence': block_scan.get('confidence'),
                'blocks_analyzed': block_scan.get('blocks_analyzed'),
                'nodes_total': block_scan.get('nodes_total'),
                'valid_paths': len(block_scan.get('valid_paths') or []),
                'reasoning': (block_scan.get('reasoning') or '')[:200],
            } if block_scan else None),
            # 2026-11 图后端与覆盖度审计
            'graph_backend': getattr(self, '_graph_backend', 'builtin'),
            'coverage': coverage_info,
            'capabilities': (getattr(self, '_graph_capabilities', {}) or None),
            'execution_phases': (getattr(self, '_graph_phases', {}) or None),
            'llm_pipeline': self.llm_pipeline,
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

    def _two_stage_scan(self, package_name: str, package_dir,
                        block_nodes: int = 250, max_blocks: int = 6,
                        time_budget_s: float = 240):
        """两阶段块扫描：小模型提链 → 程序验证 → 大模型判定（2026-11 接线）。

        与 _full_block_scan 的差别：后者一个模型干两件事（读图找链 + 判定），
        这里按认知任务拆分：
          Stage 1 小模型（大输入，机械任务）：读 digest 提议路径
          程序验证：每跳必须是真实边（反幻觉契约不变）
          Stage 2 强模型（小输入，语义任务）：只看已验证路径 + 源码 + 包意图

        返回与 analyze_package_graph 同形的 dict，供上层统一消费。
        """
        if not self.api_key or self.api_key == 'dummy':
            return None
        g = self._full_graph
        if not g or not g.get('nodes'):
            return None

        try:
            from src.two_stage_judge import analyze_two_stage
            from src.package_graph_analysis import _split_blocks
            from zhipuai import ZhipuAI

            client = ZhipuAI(api_key=self.api_key)
            # 2026-11 函数目录选 top-N（替代按文件/函数预算切块）：
            # 出入度 + 能力等级 + 执行时机 + 敌意字面量打分，
            # 让 LLM 只看"最可能有链"的 N 个完整函数，而不是随机切块。
            try:
                from src.function_catalog import (
                    build_catalog, select_top, expand_functions,
                    build_function_graph, select_clusters, expand_clusters)
                _cat = build_catalog(g['nodes'], g['edges'])
                # 2026-11 按簇交付（解决 A→B 拆分攻击）：种子函数 +
                # 函数图上的调用闭包，一起给 LLM，避免"各自清白"。
                _fadj = build_function_graph(g['nodes'], g['edges'])
                _clusters = select_clusters(
                    _cat, _fadj, top_n=max_blocks, expand_hops=2)
                if _clusters:
                    blocks = expand_clusters(g['nodes'], g['edges'], _clusters)
                    print(f"        [函数簇] {len(_cat)} 函数 → "
                          f"{len(_clusters)} 簇 / "
                          f"{sum(len(c) for c in _clusters)} 函数")
                    for _b in blocks[:5]:
                        print(f"          · {_b['label']} "
                              f"({len(_b['nodes'])} stmt)")
                elif _cat:
                    _top = select_top(_cat, n=max_blocks, min_score=2.0)
                    blocks = expand_functions(g['nodes'], g['edges'], _top)
                    print(f"        [函数目录] 回退单函数 top{len(_top)}")
                else:
                    blocks = _split_blocks(g['nodes'], g['edges'],
                                           block_nodes=block_nodes,
                                           max_blocks=max_blocks)
            except Exception as _cat_err:
                print(f"        [WARN] 函数目录失败，回退切块: {_cat_err}")
                blocks = _split_blocks(g['nodes'], g['edges'],
                                       block_nodes=block_nodes,
                                       max_blocks=max_blocks)
            import time as _time
            t0 = _time.time()
            block_results, all_paths = [], []
            mal_blocks = []
            for label, b_nodes, b_edges, b_boundary in blocks:
                if _time.time() - t0 > time_budget_s:
                    print(f"        [两阶段] 超时预算 {time_budget_s:.0f}s，"
                          f"停在 {len(block_results)}/{len(blocks)} 块")
                    break
                r = analyze_two_stage(
                    b_nodes, b_edges,
                    client, self.llm_model_small,
                    client, self.llm_model_big,
                    samples=1, package_dir=package_dir)
                r['block'] = label
                r['block_nodes'] = len(b_nodes)
                block_results.append(r)
                if r.get('verdict') == 'MALICIOUS' and r.get('stage1_paths'):
                    mal_blocks.append((label, r))
            verdict = ('MALICIOUS' if mal_blocks else
                       'SUSPICIOUS' if any(b.get('verdict') == 'SUSPICIOUS'
                                           for b in block_results) else
                       'BENIGN' if block_results else 'UNKNOWN')
            print(f"        [两阶段] {len(block_results)} 块 → {verdict} "
                  f"(小={self.llm_model_small}, 大={self.llm_model_big})")
            return {
                'verdict': verdict,
                'confidence': 0.8 if verdict == 'BENIGN' else 0.6,
                'reasoning': '; '.join(f"{lb}: {r.get('stage2_summary', '')[:60]}"
                                       for lb, r in mal_blocks[:3]),
                'block_results': block_results,
                'valid_paths': all_paths,
                'blocks_analyzed': len(block_results),
                'nodes_total': len(g['nodes']),
                'truncated_by_budget': len(block_results) < len(blocks),
                'pipeline': 'two_stage',
            }
        except Exception as e:
            print(f"        [WARN] 两阶段扫描失败: {e}")
            return None

    def _full_block_scan(self, package_name: str, block_nodes: int = 250,
                         max_blocks: int = 6, time_budget_s: float = 240):
        """包块划分：整包图按文件→函数分块，逐块读图找链（2026-11）。

        与投票路径的区别：
        - 投票路径只看"被标记的函数"（含危险节点的组），召回上限就是
          标记器的召回率
        - 这里每一块都读，粗筛（外部交互密度）只用于**预算排序**
        - 判决要求 verify_paths 通过的真实链，幻觉路径不升级

        调用时机：歧义区（SUSPICIOUS/UNKNOWN）作为第二意见；大包作为
        **主路径**（rule-only 投票没有语义判断，预算让给块划分）。

        Returns:
            analyze_package_graph 的结果 dict，失败返回 None
        """
        if not self.block_scan or not self.api_key or self.api_key == 'dummy':
            return None
        g = self._full_graph
        if not g or not g.get('nodes'):
            return None

        try:
            from src.package_graph_analysis import analyze_package_graph
            from zhipuai import ZhipuAI

            client = ZhipuAI(api_key=self.api_key)
            # 2026-11 时间预算（实测驱动）：只限块数挡不住"块本身很大"。
            # 预算由调用方给定（歧义区 250/6/240s，大包 300/16/420s）。
            r = analyze_package_graph(
                g['nodes'], g['edges'], client, self.llm_model,
                samples=1, block_nodes=block_nodes, max_blocks=max_blocks,
                time_budget_s=time_budget_s)
        except Exception as e:
            print(f"        [WARN] 包块划分失败: {e}")
            return None

        print(f"        [包块划分] {r.get('blocks_analyzed', 0)} 块 / "
              f"{r.get('nodes_total', 0)} 节点 → {r.get('verdict')} "
              f"(验证路径 {len(r.get('valid_paths') or [])} 条)")
        return r

    def _package_level_analysis(self, package_name, voting_result,
                                ddg_v7_report, enhanced_detection_result,
                                attack_chains_summary, obfuscation_result,
                                package_dir=None, subgraph_jsons=None):
        """包级 LLM 聚合分析(2026-11):所有通道跑完后综合判断

        与投票的区别:
        - 投票: 机械计数(几个恶意/几个良性/几个可疑)
        - 本步骤: LLM 综观全部证据(通道信号+摘要+污点链+混淆+核验)
        → 能理解"1个高危子图比83个良性重要"
        → 能理解"包级混淆信号被函数分割稀释但整体可疑"
        → 能在边界情况(SUSPICIOUS/低count MALICIOUS)做语义判断

        2026-11 证据完整性修复: 附带可疑/恶意子图的函数代码原文。
        此前包级 LLM 只有下级"判决标签"——它被要求复核一个它看不到
        代码的判决,只能回声。现在它能亲自读代码推翻或确认。
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
            # completeness 必须 present:0.37 的"4条链"不构成完整攻击链证据,
            # 缺了这个数 LLM 会按"有链→MALICIOUS"拍板(a2a_sdk 误报根因)
            comp = attack_chains_summary.get('completeness')
            signals.append(f"Attack chains: {attack_chains_summary['chain_count']} "
                           f"(completeness={comp if comp is not None else '?'} — "
                           f"below 0.5 means incomplete, NOT conclusive)")
            signals.append(f"  Summary: {attack_chains_summary.get('summary', '')[:200]}")

        # 2026-11 跨工件：.pth / .sh / data_files 不在代码图上（DDG 只解析 .py），
        # 但它们才是安装期持久化的落点。单独渲染一段给包级判断。
        try:
            from src.artifact_scanner import render_for_prompt
            _art_text = render_for_prompt(ed.get('artifact_analysis') or {})
            if _art_text:
                signals.append(_art_text)
        except Exception:
            pass

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

        # 2026-11 证据完整性:可疑/恶意子图的函数代码原文（见 _flagged_code_signals）
        signals.extend(_flagged_code_signals(vs, subgraph_jsons))

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

## Decision Criteria (apply strictly)
- MALICIOUS — any ONE of:
  * A STRONG taint chain exists: source is network/socket/deserialization/
    decoded data, OR the sink is data-exfiltration — and no benign
    explanation covers it. These chain shapes are rare in benign software.
  * Code downloads/executes payloads, exfiltrates data, or backdoors
    installs, even across multiple functions/files (you verified this
    from the flagged code itself, not just from labels).
  * Install-time (setup.py) code execution or exfiltration.
  * Identity fraud: the distribution name does NOT exist on PyPI
    (verification status "not_found") while claiming to be a real package.
- SUSPICIOUS — dangerous-API usage with NO strong chain and a plausible
  benign explanation. IMPORTANT: environment/file_read/user_input ->
  exec/file_write chains are ROUTINE in build tools, plugin loaders and
  test-data generators — such weak-source chains alone stay SUSPICIOUS
  unless the flagged code itself shows malicious intent.
  Corporate-prefixed or internal fork names missing from PyPI are NOT
  identity fraud by themselves. Name-similarity (typosquat heuristics)
  at "high" level alone is NOT proof — require the not_found status or
  corroborating code evidence.
- BENIGN — no taint chains, dangerous APIs clearly used in benign context.

Do NOT default to SUSPICIOUS when a STRONG chain is present: a chain is
structural evidence from the graph kernel, independent of your confidence.
Do NOT upgrade to MALICIOUS on weak-source chains or name-similarity
signals alone — that is how false positives happen.

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
        # 2026-11 大包快路径：子图数超限（ag2 1136 个）或全图节点超限时，
        # 20 次 LLM 高优先级投票对 400 个子图是又贵又浅——直接全部
        # rule-only，把预算交给块划分（验证链 + 单节点敌意字面量门）。
        _is_large = (len(subgraph_jsons) > LARGE_PKG_SUBGRAPH_THRESHOLD
                     or len((self._full_graph or {}).get('nodes') or [])
                     > LARGE_PKG_NODE_THRESHOLD)
        print(f"\n        [改进1] 智能预处理（子图优先级排序）...")
        high_priority_subgraphs, low_priority_subgraphs = prioritizer.prioritize_subgraphs(
            subgraph_jsons,
            max_llm_calls=0 if _is_large else 20
        )
        if _is_large:
            print(f"        [大包快路径] 子图 {len(subgraph_jsons)} / 节点 "
                  f"{len((self._full_graph or {}).get('nodes') or [])} → "
                  f"跳过高优 LLM 投票，预算交给块划分")

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
                # 2026-11 升级证据链：规则票同样携带污点链（升级门控统一口径）
                _chains = subgraph_json.get('taint_chains') or []
                verdict['taint_chain_count'] = len(_chains)
                verdict['taint_chains'] = _chains[:3]

            subgraph_verdicts.append(verdict)

        # 投票合成（2026-10 大改）：
        # 1. 口径统一：全部按 final_verdict 统计（原先 malicious 按 is_malicious、
        #    其余按 final_verdict 三口径混用），ERROR 显式计数
        # 2. 零容忍分层：LLM 判 MALICIOUS 的子图 → 整包 MALICIOUS（零容忍保留）；
        #    仅规则判 MALICIOUS（低优先级子图，无 LLM 复核）需 ≥2 个一致才升
        #    MALICIOUS，孤证降级计入 SUSPICIOUS——规则通道孤证不再判死整包
        # 3. 置信度真实化：由恶意占比与子图自身置信度计算，替换硬编码值
        # 4. SUSPICIOUS 升级（2026-11）：可疑子图自带强污点链（强源→sink /
        #    任意→外传）或增强通道 critical 佐证时 → MALICIOUS。
        #    门控只认良性软件中罕见的链形态，environment→exec 不自动升级。
        total_count = max(len(subgraph_verdicts), 1)

        llm_malicious = [v for v in subgraph_verdicts
                         if v.get('final_verdict') == 'MALICIOUS' and v.get('llm_used', False)]
        rule_malicious = [v for v in subgraph_verdicts
                          if v.get('final_verdict') == 'MALICIOUS' and not v.get('llm_used', False)]
        suspicious_verdicts = [v for v in subgraph_verdicts if v.get('final_verdict') == 'SUSPICIOUS']

        # ===== 零容忍的强证据门控（2026-11，真实误报驱动）=====
        # 见 _llm_malicious_weak_only：LLM 恶意子图必须至少有一个满足
        # escalation_gate，否则降 SUSPICIOUS（exec(open(_version.py)) 惯用法）。
        _weak_llm_mal = _llm_malicious_weak_only(llm_malicious, enhanced_detection_result)
        if _weak_llm_mal:
            for v in _weak_llm_mal:
                v['final_verdict'] = 'SUSPICIOUS'
                v['is_malicious'] = False
                v['demoted_reason'] = ('LLM判恶意但仅有弱污点链'
                                       '（如 file_read→exec 属构建工具惯用法）')
            print(f"          [零容忍门控] {len(_weak_llm_mal)} 个LLM恶意子图仅有弱链，降级为可疑")
            suspicious_verdicts.extend(_weak_llm_mal)
            llm_malicious = []

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
            # 2026-11 SUSPICIOUS 升级机制：可疑不再是终点。
            # 升级条件（证据必须与可疑子图同源——链就挂在该可疑子图上）：
            #   A. 可疑子图自带满足升级门控的污点链（强源→sink 或 任意→外传）
            #      ——图内核与 LLM/规则双通道独立佐证同一函数
            #   B. 增强通道 critical 佐证（high 含低精度 live 索引信号，
            #      用它会循环论证，不用）
            escalation_reasons = []
            escalated_verdicts = []
            for v in suspicious_verdicts:
                # 2026-11 目标感知：把子图节点传给门，EXFIL sink 按
                # 目的地分层定罪（twirp/pyslack 类自有服务不再定罪）
                reason = escalation_gate(
                    v.get('taint_chains'),
                    nodes=v.get('nodes') or None,
                    project_dir=package_dir)
                if reason:
                    escalation_reasons.append(f"{v.get('subgraph_name', '?')}: {reason}")
                    escalated_verdicts.append(v)
            if not escalation_reasons and enhanced_strong:
                escalation_reasons.append("增强通道 critical 信号佐证可疑子图")
                escalated_verdicts = list(suspicious_verdicts)

            if escalation_reasons:
                final_category = "MALICIOUS"
                n_esc = min(len(escalated_verdicts), 3)
                final_risk_score = round(0.72 + 0.03 * n_esc, 3)
                final_confidence = round(min(1.0, 0.60 + 0.06 * n_esc
                                             + 0.05 * _avg_conf(suspicious_verdicts)), 3)
                voting_summary = (f"[升级] 可疑→恶意: {'; '.join(escalation_reasons[:3])}"
                                  f"（{len(escalated_verdicts)}/{suspicious_count} 个可疑子图有图内核级佐证）")
                for v in escalated_verdicts:
                    v['escalated'] = True
                print(f"          [升级] SUSPICIOUS → MALICIOUS")
                for r in escalation_reasons[:3]:
                    print(f"            -> {r}")
            else:
                final_category = "SUSPICIOUS"
                sus_ratio = suspicious_count / total_count
                final_risk_score = round(0.40 + sus_ratio * 0.20, 3)
                final_confidence = round(min(1.0, 0.45 + 0.30 * sus_ratio
                                             + 0.10 * _avg_conf(suspicious_verdicts)), 3)
                voting_summary = f"检测到 {suspicious_count} 个可疑子图，无完整污点链佐证，判定为可疑包"
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

        # 2026-11 升级证据链修复：verdict 必须携带污点链。
        # 此前 _package_level_analysis 从 verdicts 收集 taint_chains，而
        # verdicts 从未携带过 → 包级 LLM 从未见过任何污点链，最关键的
        # 升级证据在其视野之外（SUSPICIOUS 无法升级的根因之一）。
        chains = subgraph_json.get('taint_chains') or []
        verdict['taint_chain_count'] = len(chains)
        verdict['taint_chains'] = chains[:3]  # 上限防内存膨胀，格式化层再裁剪
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
        """解压发行包（filter='data' 防路径穿越；分析对象本身是恶意样本）

        2026-11:按文件魔数识别真实格式。此前一律用 tarfile 打开,
        导致 wheel（zip 格式）报 "method gz: ReadError" 并被记为
        ANALYSIS_FAILED——5000 包语料里约 5% 是 wheel。魔数判断比
        扩展名可靠（样本常把 .whl 命名为 .tar.gz）。
        """
        import tarfile as tf_module
        import zipfile
        if package_dir.exists():
            return
        package_dir.parent.mkdir(parents=True, exist_ok=True)

        # 魔数探测: PK\x03\x04 = zip/wheel; \x1f\x8b = gzip; 其余按 tar
        is_zip = False
        try:
            with open(tarfile, 'rb') as _f:
                is_zip = _f.read(4)[:2] == b'PK'
        except OSError:
            pass

        if is_zip:
            with zipfile.ZipFile(tarfile) as zf:
                for member in zf.infolist():
                    name = member.filename.replace('\\', '/')
                    # 防 zip-slip: 拒绝绝对路径与 .. 穿越
                    if name.startswith('/') or '..' in name.split('/'):
                        continue
                    zf.extract(member, path=str(package_dir.parent))
            return

        with tf_module.open(tarfile) as tf:
            try:
                # filter='data': 拒绝绝对路径/../穿越/设备文件，防 tar-slip
                tf.extractall(path=str(package_dir.parent), filter='data')
            except TypeError:
                # Python < 3.12 无 filter 参数
                tf.extractall(path=str(package_dir.parent))

    def _resolve_extracted_dir(self, tarfile: Path, extract_base: Path) -> Optional[Path]:
        """包内顶级目录名与文件名不一致时，解析实际解压目录

        2026-11: 兼容 zip/wheel（按魔数判断，与 _extract_tarfile 一致）。
        """
        import tarfile as tf_module
        import zipfile
        try:
            with open(tarfile, 'rb') as _f:
                is_zip = _f.read(4)[:2] == b'PK'
            if is_zip:
                with zipfile.ZipFile(tarfile) as zf:
                    names = zf.namelist()
            else:
                with tf_module.open(tarfile) as tf:
                    names = [m.name for m in tf.getmembers()]
            for name in names:
                top = name.replace('\\', '/').split('/')[0]
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

        # ===== 2026-11 SSO 接线（大包建图侧治本）=====
        # extract_sso/select_files_for_graph 此前从未被调用——1093 文件的
        # agent_framework 全量建图 CPU 40 分钟是 ANALYSIS_TIMEOUT 主因。
        # 大包只对 SSO 选中的子集建图（Tier-1 永不裁剪，import 闭包与
        # 长常量补偿保证链的起点不断）；小包全量，行为不变。
        include_files = None
        try:
            _py_count = len([p for p in package_path.rglob('*.py')
                             if '__pycache__' not in str(p)
                             and '.ddg_output' not in str(p)])
            if _py_count > LARGE_PKG_FILE_THRESHOLD:
                from src.sso_extractor import extract_sso, select_files_for_graph
                _t_sso = time.time()
                sso = extract_sso(package_path)
                include_files = select_files_for_graph(
                    sso, max_files=120, project_dir=package_path)
                print(f"          [SSO 粗筛] {_py_count} 个 .py → "
                      f"建图 {len(include_files)} 个 "
                      f"({time.time()-_t_sso:.1f}s, "
                      f"module级 {sum(1 for f in sso.get('module_level_capabilities') or {})})")
        except Exception as sso_err:
            print(f"          [WARN] SSO 粗筛失败,回退全量建图: {sso_err}")
            include_files = None

        # ===== 2026-11 图后端选择 =====
        # pyflow: 工业化前端（IFDS/别名/capability/覆盖度），秒级；
        #         产出同形 result，下游零改动。
        # builtin: 手写 DDG（默认，保持现网行为）。
        result = None
        if self.graph_backend == 'pyflow':
            try:
                from src import pyflow_backend
                if pyflow_backend.available():
                    _t_pf = time.time()
                    result = pyflow_backend.build_result(
                        package_dir,
                        max_seconds=self.pyflow_max_seconds,
                        capability_model=self.pyflow_capability_model)
                    if result:
                        print(f"          [PyFlow] {len(result['nodes'])} 节点 / "
                              f"{len(result['edges'])} 边 "
                              f"({time.time()-_t_pf:.1f}s, "
                              f"coverage {result.get('coverage', {}).get('entries_analyzed', '?')}"
                              f"/{result.get('coverage', {}).get('entries_total', '?')})")
                    else:
                        print("          [PyFlow] 无产出，回退 builtin")
                else:
                    print("          [PyFlow] 不可用（无 py3.10 venv），回退 builtin")
            except Exception as _pf_err:
                print(f"          [PyFlow] 异常，回退 builtin: {_pf_err}")
                result = None

        if result is None:
            builder = DDGBuilderV7(package_dir, include_files=include_files)
            result = builder.build()

        # 2026-11 图后端元信息（覆盖度门控 + 审计用）
        self._graph_backend = result.get('backend', 'builtin')
        self._graph_coverage = result.get('coverage') or {}
        self._graph_capabilities = result.get('capabilities') or {}
        if result.get('execution_phases'):
            self._graph_phases = result['execution_phases']
            print(f"          [执行时机] {self._graph_phases}")

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

            # project_dir 传给良性上下文判定（版本惯用法需要读目标文件）
            partitioner = GraphPartitioner(nx_graph, config,
                                           project_dir=package_path)

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
                    # 2026-11 包块划分:函数归属用于 _split_blocks 的文件→函数切分
                    'function_name': getattr(n, 'function_name', None),
                    'class_name': getattr(n, 'class_name', None),
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
            # 整图快照留给包块划分（只在歧义区用；子进程一包一进程，内存可控）
            self._full_graph = {'nodes': ac_nodes, 'edges': ac_edges}
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
                    # 2026-11 划分越界修复：落盘量 10 → 40。下游
                    # _read_subgraph_jsons 会按块内节点集合过滤后才进 prompt，
                    # 在这里截太狠会让跨函数链分不到它该出现的块。
                    'chains': global_chains[:40],
                    'all_chain_count': len(global_chains),
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

        # 2026-11 性能修复:函数摘要文件在循环外读一次并建索引。
        # 原实现每个子图都重新 read_text + 线性遍历 summaries——
        # ag2 有 1136 个子图,仅这一项就是 1136 次文件 IO + 百万级比较。
        _summaries_by_name = {}
        _summ_file = Path(package_dir) / '.ddg_output' / 'function_summaries.json'
        if _summ_file.exists():
            try:
                _sdata = json.loads(_summ_file.read_text(encoding='utf-8'))
                for _sk, _sv in (_sdata.get('summaries') or {}).items():
                    _n = _sv.get('name')
                    if _n and _n not in _summaries_by_name:
                        _summaries_by_name[_n] = _sv
            except Exception:
                _summaries_by_name = {}

        # ===== 2026-11 划分越界修复：全图污点链 =====
        # 函数级划分用诱导子图切块，跨函数/跨文件边在落盘时被丢掉，
        # 子图级 taint_analyze 只能重建函数内部的链。全图链其实已经在
        # _run_ddg_builder 里算好落盘（taint_chains.json），此前从没被读过。
        # 这里按块内节点集合分发给各子图，让跨函数链进得了 prompt。
        _global_chains = []
        _global_file = Path(package_dir) / '.ddg_output' / 'taint_chains.json'
        if self.cross_scope and _global_file.exists():
            try:
                _gdata = json.loads(_global_file.read_text(encoding='utf-8'))
                _global_chains = _gdata.get('chains') or []
            except Exception:
                _global_chains = []

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

                    # 2026-11 跨块边（可选；旧 .ddg_output 没有这个文件）
                    boundary_edges = {}
                    _be_file = subgraph_dir / 'boundary_edges.json'
                    if self.cross_scope and _be_file.exists():
                        try:
                            boundary_edges = json.loads(
                                _be_file.read_text(encoding='utf-8'))
                        except Exception:
                            boundary_edges = {}

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
                    # 2026-11 性能修复:原实现对每条边做两次 next() 线性扫描
                    # (O(E×N)),千节点级子图上直接爆炸——ag2 有 1136 个子图,
                    # 单包分析超时 15 分钟。改 dict 索引 O(E+N)。
                    _node_index = {n.get('node_id'): n for n in nodes_data
                                   if n.get('node_id')}
                    data_flow_paths = []
                    for edge in edges_data:
                        from_node = edge.get('from_node', '')
                        to_node = edge.get('to_node', '')
                        if from_node and to_node:
                            from_node_data = _node_index.get(from_node)
                            to_node_data = _node_index.get(to_node)
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
                    # 2026-11 性能门控:无危险节点的子图跳过污点分析——
                    # 污点从 sink 反向 BFS,没有 sink 的图跑一遍纯属浪费。
                    # ag2(1136 子图)里绝大多数函数没有任何危险调用。
                    taint_chains = []
                    if dangerous_nodes:
                        try:
                            from src.taint_engine import analyze as taint_analyze
                            taint_chains = taint_analyze(nodes_data, edges_data)
                        except Exception as taint_err:
                            print(f"        [WARN] 污点追踪失败({subgraph_dir.name}): {taint_err}")

                    # 2026-11 全图链分发：块内链只覆盖函数内部，跨函数/跨文件
                    # 的链必须从全图结果里按节点交集取回。跨块链优先（排前面），
                    # 去重后每块最多 8 条。
                    if _global_chains:
                        try:
                            from src.taint_engine import (
                                distribute_chains, merge_chains)
                            _block_ids = {n.get('node_id') for n in nodes_data
                                          if n.get('node_id')}
                            _global_matched = distribute_chains(
                                _global_chains, _block_ids)
                            if _global_matched:
                                taint_chains = merge_chains(
                                    _global_matched, taint_chains, max_chains=8)
                        except Exception as dist_err:
                            print(f"        [WARN] 全图链分发失败"
                                  f"({subgraph_dir.name}): {dist_err}")

                    # 2026-11 函数级分割:从子图的 function 节点取函数名
                    func_name = None
                    for node in nodes_data:
                        if node.get('type') == 'function' and node.get('function_name'):
                            func_name = node['function_name']
                            break

                    # 从函数摘要索引取（循环外已加载）
                    func_summary = _summaries_by_name.get(func_name) if func_name else None

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
                        # 2026-11 跨块边：不把外部节点拉进块，只告知
                        # "本函数的参数从哪来、返回值去了哪"
                        'boundary_edges': boundary_edges,
                    }
                    subgraph_jsons.append(subgraph_data)

        # 2026-11 子图预算门控:超大 monorepo(ag2 有 1136 个函数级子图)
        # 的下游成本(规则评分 + 投票 + 序列化)线性爆炸。按"危险节点数"
        # 降序保留最危险的前 MAX_SUBGRAPHS_ANALYZED 个——恶意信号集中在
        # 有危险调用的函数里,丢弃的绝大多数是纯工具函数。
        _total_read = len(subgraph_jsons)
        if _total_read > MAX_SUBGRAPHS_ANALYZED:
            subgraph_jsons.sort(
                key=lambda s: (len(s.get('dangerous_nodes') or []),
                               len(s.get('taint_chains') or [])),
                reverse=True)
            subgraph_jsons = subgraph_jsons[:MAX_SUBGRAPHS_ANALYZED]
            print(f"        [预算门控] 子图 {_total_read} 个超过上限 "
                  f"{MAX_SUBGRAPHS_ANALYZED}，按危险节点数保留前 "
                  f"{MAX_SUBGRAPHS_ANALYZED} 个")

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
    parser.add_argument('--no-pypi-gate', action='store_true',
                        help='消融开关:registry 身份(404/未发布版本)不作为判决证据。'
                             '用于评估纯代码分析(图内核+LLM)不依赖联网时的检出能力。'
                             '仍会做核验并记录结果,只是不参与判决')
    parser.add_argument('--graph-backend', default='builtin',
                        choices=['builtin', 'pyflow'],
                        help='图后端：builtin=手写DDG（默认），pyflow=PyFlow分析引擎')
    parser.add_argument('--llm-pipeline', default='single',
                        choices=['single', 'two_stage'],
                        help='LLM 管道：single=现状，two_stage=小模型提链+大模型判定')
    parser.add_argument('--llm-model-small', default='',
                        help='两阶段 Stage1 小模型（默认回落到 --llm-model）')
    parser.add_argument('--llm-model-big', default='',
                        help='两阶段 Stage2 强模型（默认回落到 --llm-model）')
    parser.add_argument('--pyflow-max-seconds', type=int, default=60,
                        help='PyFlow 单命令时间预算（秒）')
    parser.add_argument('--pyflow-capability-model', default='',
                        help='PyFlow --capability-model 配置路径（我们的 PyPI 威胁模型）')
    parser.add_argument('--coverage-max-skip', type=float, default=0.30,
                        help='覆盖度门控阈值：跳过 entry 占比超过此值则不判 BENIGN')
    parser.add_argument('--no-cross-scope', action='store_true',
                        help='消融开关:关闭跨块边与全图链分发（量化跨作用域证据的增益）')
    parser.add_argument('--no-block-scan', action='store_true',
                        help='关闭包块划分（默认开启：投票落在 SUSPICIOUS 时'
                             '整包图按文件→函数分块逐块读，作为第二意见）')

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
        llm_model=args.llm_model,
        ignore_pypi_gate=args.no_pypi_gate,
        block_scan=not args.no_block_scan,
        cross_scope=not args.no_cross_scope,
        graph_backend=args.graph_backend,
        llm_pipeline=args.llm_pipeline,
        llm_model_small=args.llm_model_small,
        llm_model_big=args.llm_model_big,
        pyflow_max_seconds=args.pyflow_max_seconds,
        pyflow_capability_model=args.pyflow_capability_model,
        coverage_max_skip=args.coverage_max_skip,
    )

    analyzer.analyze_all()


if __name__ == '__main__':
    main()
