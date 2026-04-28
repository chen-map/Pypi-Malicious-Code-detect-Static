"""
DDG V7 批量处理器 - 批量分析多个压缩包项目

功能：
1. 遍历父目录，查找所有 .tar.gz 和 .gz 压缩包
2. 自动解压到临时目录
3. 对每个项目运行 DDG V7 完整分析
4. 生成汇总报告
5. 清理临时文件（修复 Windows PermissionError）

使用方法:
    python batch_processor.py <parent_directory> [output_directory]

示例:
    python batch_processor.py C:/projects C:/analysis_results
"""

import sys
import json
import io
import tarfile
import gzip
import shutil
import os
import time
import stat
import threading
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from datetime import datetime
from collections import defaultdict

# 设置标准输出编码为 UTF-8（处理 Windows 中文问题）
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

# 添加 src 目录到路径
current_script_dir = Path(__file__).parent
sys.path.insert(0, str(current_script_dir / 'src'))

# 导入 V7 组件
from src.ddg_builder_v7 import ProjectDDGBuilderV7, ProjectSymbolTable, GlobalNode, GlobalEdge
from src.visualizer_v7 import VisualizerV7


class CleanupHandler:
    """处理文件和目录清理，解决 Windows 下的权限问题"""

    @staticmethod
    def is_safe_path(path: str) -> bool:
        """检查路径是否安全（防止路径遍历攻击）"""
        try:
            # 绝对路径检查
            if Path(path).is_absolute():
                return False
            # 路径遍历检查
            if '..' in Path(path).parts:
                return False
            return True
        except Exception:
            return False

    @staticmethod
    def remove_readonly(func, path, excinfo):
        """
        错误处理函数：用于处理 shutil.rmtree 遇到的只读文件问题
        """
        try:
            os.chmod(path, stat.S_IWRITE)
            func(path)
        except Exception:
            pass  # 忽略无法删除的文件

    @staticmethod
    def safe_remove_directory(path: Path, max_retries: int = 5, retry_delay: float = 1.0) -> bool:
        """
        安全删除目录，包含重试机制，解决 Windows 文件占用问题

        Args:
            path: 要删除的目录路径
            max_retries: 最大重试次数
            retry_delay: 重试间隔（秒）

        Returns:
            bool: 是否成功删除
        """
        if not path.exists():
            return True

        for attempt in range(max_retries):
            try:
                # 先尝试关闭可能打开的文件句柄（通过强制垃圾回收）
                import gc
                gc.collect()

                # 使用 onexc 参数处理权限问题 (Python 3.12+)
                # 对于旧版本 Python，使用 onerror
                if sys.version_info >= (3, 12):
                    shutil.rmtree(path, onexc=CleanupHandler.remove_readonly)
                else:
                    shutil.rmtree(path, onerror=CleanupHandler.remove_readonly)

                print(f"  [Cleanup] Successfully removed: {path.name}")
                return True

            except PermissionError as e:
                if attempt < max_retries - 1:
                    print(f"  [Warning] Cannot delete {path.name}, retrying in {retry_delay}s... (Attempt {attempt + 1}/{max_retries})")
                    time.sleep(retry_delay)
                else:
                    print(f"  [Error] Failed to remove {path.name} after {max_retries} attempts: {e}")
                    return False

            except Exception as e:
                print(f"  [Error] Failed to remove {path.name}: {e}")
                return False

        return False

    @staticmethod
    def safe_remove_file(path: Path, max_retries: int = 3) -> bool:
        """安全删除单个文件"""
        if not path.exists():
            return True

        for attempt in range(max_retries):
            try:
                import gc
                gc.collect()

                path.unlink(missing_ok=True)
                return True

            except PermissionError:
                if attempt < max_retries - 1:
                    time.sleep(0.5)
                else:
                    return False

        return False


class ArchiveExtractor:
    """压缩包解压器"""

    SUPPORTED_FORMATS = ['.tar.gz', '.tgz', '.tar', '.gz']

    @staticmethod
    def is_supported_archive(archive_path: Path) -> bool:
        """检查是否是支持的压缩包格式"""
        archive_str = str(archive_path).lower()
        return any(archive_str.endswith(ext) for ext in ArchiveExtractor.SUPPORTED_FORMATS)

    @staticmethod
    def decompress(archive_path: Path, extract_to: Path) -> Tuple[bool, str]:
        """
        解压压缩包到指定目录

        Returns:
            (success, message): 成功状态和消息
        """
        extract_to.mkdir(parents=True, exist_ok=True)
        print(f"  [Decompressing] {archive_path.name} -> {extract_to.name}")

        try:
            archive_str = str(archive_path).lower()

            # 处理 .tar.gz 或 .tgz
            if archive_str.endswith('.tar.gz') or archive_str.endswith('.tgz'):
                with tarfile.open(archive_path, 'r:gz') as tar:
                    # Python 3.12+ 需要使用 filter 参数
                    if sys.version_info >= (3, 12):
                        # 使用 'data' filter 过滤，跳过不安全的路径
                        def filter_function(member, path):
                            # 检查路径是否安全
                            if not CleanupHandler.is_safe_path(path):
                                print(f"    [Warning] Skipping unsafe path: {path}")
                                return None
                            return member

                        # 获取所有成员并检查
                        safe_members = []
                        for member in tar.getmembers():
                            if CleanupHandler.is_safe_path(member.name):
                                safe_members.append(member)
                            else:
                                print(f"    [Warning] Skipping unsafe path: {member.name}")

                        # 使用 filter='data' 默认过滤器，只解压安全成员
                        tar.extractall(path=extract_to, members=safe_members)
                    else:
                        # 旧版本：手动检查并解压
                        safe_members = []
                        for member in tar.getmembers():
                            if CleanupHandler.is_safe_path(member.name):
                                safe_members.append(member)
                            else:
                                print(f"    [Warning] Skipping unsafe path: {member.name}")
                        tar.extractall(path=extract_to, members=safe_members)
                print(f"  [Success] Extracted {archive_path.name}")
                return True, "OK"

            # 处理 .tar
            elif archive_str.endswith('.tar'):
                with tarfile.open(archive_path, 'r:') as tar:
                    safe_members = []
                    for member in tar.getmembers():
                        if CleanupHandler.is_safe_path(member.name):
                            safe_members.append(member)
                    tar.extractall(path=extract_to, members=safe_members)
                print(f"  [Success] Extracted {archive_path.name}")
                return True, "OK"

            # 处理单独的 .gz
            elif archive_str.endswith('.gz'):
                # 尝试作为 tar.gz 处理
                try:
                    with tarfile.open(archive_path, 'r:gz') as tar:
                        safe_members = []
                        for member in tar.getmembers():
                            if CleanupHandler.is_safe_path(member.name):
                                safe_members.append(member)
                        tar.extractall(path=extract_to, members=safe_members)
                    print(f"  [Success] Extracted {archive_path.name}")
                    return True, "OK"
                except tarfile.ReadError:
                    # 纯 gzip 文件
                    output_file = extract_to / archive_path.stem
                    with gzip.open(archive_path, 'rb') as gz_file:
                        with open(output_file, 'wb') as out_file:
                            shutil.copyfileobj(gz_file, out_file)
                    print(f"  [Success] Extracted {archive_path.name} (plain gzip)")
                    return True, "OK"

            else:
                return False, f"Unsupported archive format: {archive_path.suffix}"

        except Exception as e:
            return False, f"Decompression failed: {e}"

    @staticmethod
    def find_project_root(extracted_dir: Path) -> Optional[Path]:
        """
        在解压目录中查找项目根目录

        查找策略：
        1. 如果包含 setup.py 或 pyproject.toml，返回该目录
        2. 如果包含多个 .py 文件的子目录，返回该子目录
        3. 否则返回解压目录本身
        """
        # 检查解压目录本身
        if ArchiveExtractor._is_project_root(extracted_dir):
            return extracted_dir

        # 检查直接子目录（处理 tar 包含单个子目录的情况）
        subdirs = [d for d in extracted_dir.iterdir() if d.is_dir() and not d.name.startswith('.')]
        for subdir in subdirs:
            if ArchiveExtractor._is_project_root(subdir):
                return subdir

        # 如果子目录包含 Python 文件，选择文件最多的目录
        py_file_counts = []
        for subdir in subdirs:
            py_files = list(subdir.rglob('*.py'))
            if len(py_files) > 0:
                py_file_counts.append((subdir, len(py_files)))

        if py_file_counts:
            py_file_counts.sort(key=lambda x: x[1], reverse=True)
            return py_file_counts[0][0]

        # 最后尝试：返回任何包含 .py 文件的目录
        for subdir in subdirs:
            if list(subdir.glob('*.py')):
                return subdir

        return extracted_dir  # 默认返回解压目录

    @staticmethod
    def _is_project_root(directory: Path) -> bool:
        """检查目录是否是项目根目录"""
        py_files = list(directory.glob('*.py'))
        if len(py_files) >= 2:
            return True
        if (directory / 'setup.py').exists():
            return True
        if (directory / 'pyproject.toml').exists():
            return True
        if (directory / 'requirements.txt').exists():
            return True
        return False


class ProjectAnalyzer:
    """单个项目分析器"""

    # 每个项目的最大分析时间（秒）
    ANALYSIS_TIMEOUT = 120  # 2分钟

    def __init__(self, project_path: Path, output_base_dir: Path, timeout: int = None):
        self.project_path = project_path
        self.output_base_dir = output_base_dir
        self.project_name = project_path.name
        self.timeout = timeout or self.ANALYSIS_TIMEOUT
        self.result = {
            'project_name': self.project_name,
            'project_path': str(project_path),
            'status': 'pending',
            'error': None,
            'analysis_time': None,
            'summary': {}
        }
        self._analysis_complete = threading.Event()
        self._analysis_thread = None
        self._analysis_result = None

    def analyze(self) -> Dict:
        """运行 DDG V7 分析（带超时保护）"""
        print(f"\n  [Analyzing] Project: {self.project_name} (timeout: {self.timeout}s)")
        start_time = time.time()

        # 在单独的线程中运行分析
        self._analysis_complete.clear()
        self._analysis_thread = threading.Thread(
            target=self._run_analysis,
            daemon=True  # 设为守护线程，主程序退出时自动结束
        )
        self._analysis_thread.start()

        # 等待分析完成或超时
        self._analysis_thread.join(timeout=self.timeout)

        if self._analysis_thread.is_alive():
            # 超时了，线程仍在运行
            self.result['status'] = 'timeout'
            self.result['error'] = f'Analysis timeout after {self.timeout}s'
            print(f"  [Timeout] Analysis exceeded {self.timeout}s, skipping...")
            # 注意：我们不能强制杀死线程，只能标记为超时
            # 守护线程会在主程序退出时自动结束
            return self.result

        # 分析完成（成功或失败）
        if self._analysis_result:
            self.result.update(self._analysis_result)
            analysis_time = time.time() - start_time
            self.result['analysis_time'] = round(analysis_time, 2)
            if self.result['status'] == 'success':
                print(f"  [Done] Analysis complete in {analysis_time:.2f}s")

        return self.result

    def _run_analysis(self):
        """在后台线程中运行的实际分析逻辑"""
        try:
            # 创建项目专用输出目录
            project_output_dir = self.output_base_dir / self.project_name
            project_output_dir.mkdir(parents=True, exist_ok=True)

            # 运行 DDG V7 分析
            builder = ProjectDDGBuilderV7(str(self.project_path))
            analysis_result = builder.build()

            # 保存分析结果
            self._save_results(analysis_result, project_output_dir)

            # 生成可视化
            viz = VisualizerV7(str(project_output_dir))
            viz_files = viz.visualize_all(analysis_result, str(self.project_path))

            # 构建结果
            self._analysis_result = {
                'status': 'success',
                'summary': self._generate_summary(analysis_result),
                'output_dir': str(project_output_dir),
                'viz_files': viz_files
            }

        except Exception as e:
            self._analysis_result = {
                'status': 'error',
                'error': str(e)
            }
            print(f"  [Error] Analysis failed: {e}")

        finally:
            self._analysis_complete.set()

    def _save_results(self, analysis_result: Dict, output_dir: Path):
        """保存分析结果到 JSON 文件"""
        # 保存节点
        nodes_file = output_dir / 'nodes.json'
        with open(nodes_file, 'w', encoding='utf-8') as f:
            nodes_data = {}
            for key, node in analysis_result['nodes'].items():
                nodes_data[f"{key[0]}_{key[1]}"] = {
                    'file': node.file,
                    'line': node.line,
                    'type': node.type,
                    'source': node.source[:500],  # 限制长度
                    # ✅ 修复：保存函数和类信息（用于桩程序生成）
                    'function_name': getattr(node, 'function_name', None),
                    'class_name': getattr(node, 'class_name', None)
                }
            json.dump(nodes_data, f, indent=2, ensure_ascii=False)

        # 保存边
        edges_file = output_dir / 'edges.json'
        with open(edges_file, 'w', encoding='utf-8') as f:
            edges_data = [edge.to_dict() for edge in analysis_result['edges']]
            json.dump(edges_data, f, indent=2, ensure_ascii=False)

        # 保存安全报告
        if analysis_result.get('security_report'):
            security_file = output_dir / 'security_report.json'
            with open(security_file, 'w', encoding='utf-8') as f:
                json.dump(analysis_result['security_report'], f, indent=2, ensure_ascii=False)

        # 保存快速扫描结果
        if analysis_result.get('fast_scan_results'):
            scan_file = output_dir / 'fast_scan_results.json'
            with open(scan_file, 'w', encoding='utf-8') as f:
                json.dump(analysis_result['fast_scan_results'], f, indent=2, ensure_ascii=False)

    def _generate_summary(self, analysis_result: Dict) -> Dict:
        """生成分析摘要"""
        security_report = analysis_result.get('security_report', {})

        return {
            'total_nodes': len(analysis_result.get('nodes', {})),
            'total_edges': len(analysis_result.get('edges', [])),
            'total_functions': len(analysis_result.get('symbol_table', {}).functions) if analysis_result.get('symbol_table') else 0,
            'total_classes': len(analysis_result.get('symbol_table', {}).classes) if analysis_result.get('symbol_table') else 0,
            'cross_file_calls': len(analysis_result.get('cross_file_calls', [])),
            'security_issues': security_report.get('total_issues', 0),
            'risk_level': security_report.get('risk_level', 'unknown'),
            'by_severity': security_report.get('by_severity', {}),
            'fast_scanned_files': len(analysis_result.get('fast_scan_results', {}))
        }


class BatchProcessor:
    """批量处理器主类"""

    def __init__(self, parent_dir: Path, output_dir: Optional[Path] = None, timeout: int = 120):
        self.parent_dir = Path(parent_dir)
        self.output_dir = Path(output_dir) if output_dir else self.parent_dir / 'batch_analysis_results'
        self.temp_dir = self.output_dir / '_temp_extract'
        self.timeout = timeout
        self.results = []
        self.summary = {
            'start_time': datetime.now().isoformat(),
            'total_archives': 0,
            'successful': 0,
            'failed': 0,
            'timeout': 0,
            'skipped': 0,
            'projects': []
        }

    def run(self) -> Dict:
        """执行批量处理"""
        print("\n" + "=" * 70)
        print("  DDG V7 - Batch Project Analyzer")
        print("  Batch processing of compressed project archives")
        print("=" * 70)

        # 创建输出目录
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # 查找所有压缩包
        print(f"\n[Step 1/5] Scanning for archives in: {self.parent_dir}")
        archives = self._find_archives()
        self.summary['total_archives'] = len(archives)

        if not archives:
            print("  [Info] No supported archives found")
            return self.summary

        print(f"  [Found] {len(archives)} archive(s) to process")

        # 批量处理每个压缩包
        print(f"\n[Step 2/5] Processing archives...")
        for i, archive_path in enumerate(archives, 1):
            print(f"\n--- [{i}/{len(archives)}] Processing: {archive_path.name} ---")
            result = self._process_archive(archive_path)
            self.results.append(result)
            self.summary['projects'].append(result)

            # 更新统计
            status = result['status']
            if status == 'success':
                self.summary['successful'] += 1
            elif status == 'timeout':
                self.summary['timeout'] += 1
            elif status == 'skipped':
                self.summary['skipped'] += 1
            else:
                self.summary['failed'] += 1

        # 生成汇总报告
        print(f"\n[Step 3/5] Generating summary report...")
        self._generate_summary_report()

        # 生成对比分析
        print(f"[Step 4/5] Generating comparison analysis...")
        self._generate_comparison()

        # 清理临时文件
        print(f"\n[Step 5/5] Cleaning up temporary files...")
        self._cleanup()

        # 打印最终统计
        self._print_final_summary()

        self.summary['end_time'] = datetime.now().isoformat()
        return self.summary

    def _find_archives(self) -> List[Path]:
        """查找所有支持的压缩包"""
        # 用于去重的字典：base_key -> archive_path (按优先级)
        archive_dict = {}

        # 定义优先级：tar.gz > tgz > tar > gz
        def get_priority(name: str) -> int:
            if name.endswith('.tar.gz'):
                return 0
            elif name.endswith('.tgz'):
                return 1
            elif name.endswith('.tar'):
                return 2
            elif name.endswith('.gz'):
                return 3
            return 99

        # 获取基础名称（去掉所有压缩扩展名）
        def get_base_name(name: str) -> str:
            base = name
            for ext in ['.tar.gz', '.tgz', '.tar', '.gz']:
                if base.endswith(ext):
                    base = base[:-len(ext)]
                    break
            return base

        # 递归查找所有支持的格式
        for pattern in ['*.tar.gz', '*.tgz', '*.tar', '*.gz']:
            for item in self.parent_dir.rglob(pattern):
                # 只处理文件，跳过目录
                if not item.is_file():
                    continue

                # 跳过隐藏文件、输出目录和临时目录
                if (item.name.startswith('.') or
                    self.output_dir in item.parents or
                    any(temp_dir_name in item.parts for temp_dir_name in ['_temp_extract', 'temp_', '__temp'])):
                    continue

                base_name = get_base_name(item.name)
                key = (item.parent, base_name)
                priority = get_priority(item.name)

                # 只保留优先级最高的版本
                if key not in archive_dict or priority < get_priority(archive_dict[key].name):
                    archive_dict[key] = item

        # 转换为排序后的列表
        result = list(archive_dict.values())
        return sorted(result)

    def _process_archive(self, archive_path: Path) -> Dict:
        """处理单个压缩包"""
        result = {
            'archive_name': archive_path.name,
            'archive_path': str(archive_path),
            'status': 'pending',
            'error': None
        }

        # 创建临时解压目录
        temp_extract_dir = self.temp_dir / archive_path.stem
        temp_extract_dir.mkdir(parents=True, exist_ok=True)

        try:
            # 解压
            success, message = ArchiveExtractor.decompress(archive_path, temp_extract_dir)
            if not success:
                result['status'] = 'error'
                result['error'] = f"Decompression failed: {message}"
                return result

            # 查找项目根目录
            project_root = ArchiveExtractor.find_project_root(temp_extract_dir)
            print(f"  [Project Root] {project_root.relative_to(temp_extract_dir)}")

            # 检查是否是 Python 项目
            py_files = list(project_root.rglob('*.py'))
            if len(py_files) == 0:
                result['status'] = 'skipped'
                result['error'] = 'No Python files found'
                return result

            print(f"  [Python Files] {len(py_files)} file(s)")

            # 运行分析（带超时）
            analyzer = ProjectAnalyzer(project_root, self.output_dir, timeout=self.timeout)
            analysis_result = analyzer.analyze()

            result.update(analysis_result)
            result['status'] = analysis_result.get('status', 'error')

        except Exception as e:
            result['status'] = 'error'
            result['error'] = str(e)
            import traceback
            traceback.print_exc()

        return result

    def _generate_summary_report(self):
        """生成汇总报告"""
        summary_file = self.output_dir / 'batch_summary.json'

        # 生成统计信息
        risk_distribution = defaultdict(int)
        total_security_issues = 0
        severity_totals = defaultdict(int)

        for result in self.results:
            if result.get('status') == 'success':
                summary = result.get('summary', {})
                risk_level = summary.get('risk_level', 'unknown')
                risk_distribution[risk_level] += 1
                total_security_issues += summary.get('security_issues', 0)

                for sev, count in summary.get('by_severity', {}).items():
                    severity_totals[sev] += count

        self.summary['risk_distribution'] = dict(risk_distribution)
        self.summary['total_security_issues'] = total_security_issues
        self.summary['severity_totals'] = dict(severity_totals)

        # 保存 JSON 报告
        with open(summary_file, 'w', encoding='utf-8') as f:
            json.dump(self.summary, f, indent=2, ensure_ascii=False, default=str)

        print(f"  [Saved] {summary_file}")

    def _generate_comparison(self):
        """生成项目对比分析"""
        comparison = {
            'projects': [],
            'comparison_metrics': [
                'total_nodes',
                'total_edges',
                'total_functions',
                'security_issues',
                'analysis_time'
            ]
        }

        for result in self.results:
            if result.get('status') == 'success':
                comparison['projects'].append({
                    'name': result.get('project_name', 'unknown'),
                    'summary': result.get('summary', {}),
                    'risk_level': result.get('summary', {}).get('risk_level', 'unknown')
                })

        # 排序：按安全风险等级
        risk_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'safe': 4}
        comparison['projects'].sort(key=lambda x: risk_order.get(x['risk_level'], 5))

        comparison_file = self.output_dir / 'comparison.json'
        with open(comparison_file, 'w', encoding='utf-8') as f:
            json.dump(comparison, f, indent=2, ensure_ascii=False, default=str)

        print(f"  [Saved] {comparison_file}")

    def _cleanup(self):
        """清理临时文件"""
        if self.temp_dir.exists():
            success = CleanupHandler.safe_remove_directory(self.temp_dir)
            if success:
                print(f"  [Cleanup] Temporary files removed")
            else:
                print(f"  [Warning] Some temporary files remain at: {self.temp_dir}")

    def _print_final_summary(self):
        """打印最终统计"""
        print("\n" + "=" * 70)
        print("  BATCH ANALYSIS COMPLETE")
        print("=" * 70)

        print(f"\n  Processed: {self.summary['total_archives']} archive(s)")
        print(f"  Successful: {self.summary['successful']}")
        print(f"  Failed: {self.summary['failed']}")
        if self.summary.get('timeout', 0) > 0:
            print(f"  Timeout: {self.summary['timeout']}")
        if self.summary.get('skipped', 0) > 0:
            print(f"  Skipped: {self.summary['skipped']}")

        if self.summary.get('risk_distribution'):
            print(f"\n  Risk Distribution:")
            for risk, count in sorted(self.summary['risk_distribution'].items(),
                                     key=lambda x: risk_order.get(x[0], 5)):
                print(f"    {risk.upper()}: {count}")

        if self.summary.get('total_security_issues', 0) > 0:
            print(f"\n  Total Security Issues: {self.summary['total_security_issues']}")
            for sev, count in self.summary.get('severity_totals', {}).items():
                print(f"    {sev.upper()}: {count}")

        # 列出高风险项目
        high_risk_projects = [
            r for r in self.results
            if r.get('status') == 'success' and
            r.get('summary', {}).get('risk_level') in ['critical', 'high']
        ]

        if high_risk_projects:
            print(f"\n  [!] High Risk Projects ({len(high_risk_projects)}):")
            for proj in high_risk_projects:
                name = proj.get('project_name', 'unknown')
                risk = proj.get('summary', {}).get('risk_level', 'unknown')
                issues = proj.get('summary', {}).get('security_issues', 0)
                print(f"    - {name}: {risk.upper()} ({issues} issues)")

        # 列出超时的项目
        timeout_projects = [
            r for r in self.results
            if r.get('status') == 'timeout'
        ]

        if timeout_projects:
            print(f"\n  [⏱] Timeout Projects ({len(timeout_projects)}):")
            for proj in timeout_projects[:10]:  # 只显示前10个
                name = proj.get('archive_name', 'unknown')
                print(f"    - {name}")
            if len(timeout_projects) > 10:
                print(f"    ... and {len(timeout_projects) - 10} more")

        print(f"\n  Results saved to: {self.output_dir}")
        print("=" * 70)


# 风险等级排序（用于显示）
risk_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'safe': 4}


def main():
    """主入口函数"""
    # 解析命令行参数
    if len(sys.argv) < 2:
        print("DDG V7 Batch Processor")
        print("\nUsage:")
        print("  python batch_processor.py <parent_directory> [output_directory] [timeout_seconds]")
        print("\nExample:")
        print("  python batch_processor.py C:/projects C:/analysis_results 120")
        print("\nOr enter interactively:")
        parent_dir = input("\nEnter parent directory path: ").strip().strip('"').strip("'")
        if not parent_dir:
            print("Error: Parent directory is required")
            return

        output_dir = input("Enter output directory (optional, press Enter to skip): ").strip().strip('"').strip("'")
        timeout_input = input("Enter timeout per project (seconds, default 120): ").strip()
        timeout = int(timeout_input) if timeout_input.isdigit() else 120
    else:
        parent_dir = sys.argv[1]
        output_dir = sys.argv[2] if len(sys.argv) > 2 else None
        timeout = int(sys.argv[3]) if len(sys.argv) > 3 and sys.argv[3].isdigit() else 120

    parent_path = Path(parent_dir)

    # 验证输入
    if not parent_path.exists():
        print(f"Error: Directory does not exist: {parent_dir}")
        return

    if not parent_path.is_dir():
        print(f"Error: Path is not a directory: {parent_dir}")
        return

    print(f"\n[Config] Timeout per project: {timeout}s")

    # 运行批量处理
    processor = BatchProcessor(parent_path, output_dir, timeout=timeout)
    processor.run()

    # 防止窗口闪退
    print("\nPress Enter to exit...")
    input()


if __name__ == '__main__':
    main()
