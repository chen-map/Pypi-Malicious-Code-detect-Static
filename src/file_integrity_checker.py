"""
文件完整性检查器 - 检测安全软件干扰

功能：
1. 对比tar.gz文件列表和实际解压文件
2. 检测被安全软件删除的文件
3. 标记分析不完整的情况
"""

import tarfile
import json
from pathlib import Path
from typing import List, Dict, Tuple, Optional


class FileIntegrityChecker:
    """文件完整性检查器"""

    def __init__(self, project_dir: Path):
        """
        初始化检查器

        Args:
            project_dir: 项目目录路径
        """
        self.project_dir = Path(project_dir)
        self.integrity_report = {
            'passed': True,
            'missing_files': [],
            'tar_py_files': [],
            'disk_py_files': [],
            'warnings': []
        }

    def find_tarball(self) -> Optional[Path]:
        """查找对应的tar.gz文件"""
        # 尝试多种可能的tarball位置
        possible_locations = [
            # 当前目录（压缩包直接解压到当前目录）
            self.project_dir.parent / (self.project_dir.name + '.tar.gz'),
            self.project_dir.parent / (self.project_dir.name + '.tar.bz2'),
            self.project_dir.parent / (self.project_dir.name + '.zip'),
            # 上上级目录（tarball和项目目录在同一级）
            self.project_dir.parent.parent / (self.project_dir.name + '.tar.gz'),
            self.project_dir.parent.parent / (self.project_dir.name + '.tar.bz2'),
            self.project_dir.parent.parent / (self.project_dir.name + '.zip'),
            # 当前目录本身
            self.project_dir / (self.project_dir.name + '.tar.gz'),
        ]

        for location in possible_locations:
            if location.exists():
                return location

        # 如果找不到，尝试在项目目录及父目录中查找任何.tar.gz文件
        for search_dir in [self.project_dir, self.project_dir.parent, self.project_dir.parent.parent]:
            if search_dir.exists():
                tarballs = list(search_dir.glob('*.tar.gz'))
                if tarballs:
                    # 返回找到的第一个tarball
                    return tarballs[0]

        return None

    def get_tarball_files(self, tarball_path: Path) -> List[str]:
        """
        获取tarball中的Python文件列表

        Args:
            tarball_path: tarball文件路径

        Returns:
            Python文件路径列表
        """
        py_files = []

        try:
            if tarball_path.suffix == '.gz':
                with tarfile.open(tarball_path, 'r:gz') as tar:
                    for member in tar.getmembers():
                        if member.name.endswith('.py'):
                            # 提取相对于项目根目录的路径
                            py_files.append(member.name)
            elif tarball_path.suffix == '.bz2':
                with tarfile.open(tarball_path, 'r:bz2') as tar:
                    for member in tar.getmembers():
                        if member.name.endswith('.py'):
                            py_files.append(member.name)
            elif tarball_path.suffix == '.zip':
                import zipfile
                with zipfile.ZipFile(tarball_path, 'r') as zf:
                    for name in zf.namelist():
                        if name.endswith('.py'):
                            py_files.append(name)

        except Exception as e:
            self.integrity_report['warnings'].append(
                f'Failed to read tarball: {e}'
            )

        return py_files

    def get_disk_files(self) -> List[str]:
        """
        获取磁盘上的Python文件列表

        Returns:
            Python文件路径列表
        """
        py_files = []

        try:
            for py_file in self.project_dir.rglob('*.py'):
                # 排除输出目录和缓存
                if '__pycache__' not in str(py_file) and '.ddg_output' not in str(py_file):
                    # 获取相对于项目根目录的路径
                    rel_path = py_file.relative_to(self.project_dir)
                    py_files.append(str(rel_path))
        except Exception as e:
            self.integrity_report['warnings'].append(
                f'Failed to scan disk files: {e}'
            )

        return py_files

    def normalize_paths(self, paths: List[str]) -> set:
        """
        标准化路径以便比较

        Args:
            paths: 路径列表

        Returns:
            标准化后的路径集合
        """
        normalized = set()
        for path in paths:
            # 转换为正斜杠
            path = path.replace('\\', '/')
            # 移除开头的 ./ 或 /
            path = path.lstrip('./')
            normalized.add(path)
        return normalized

    def check_integrity(self) -> Dict:
        """
        执行文件完整性检查

        Returns:
            完整性检查报告
        """
        print(f"[Integrity Check] Checking file integrity...")

        # 1. 查找tarball
        tarball = self.find_tarball()
        if not tarball:
            self.integrity_report['warnings'].append(
                'Cannot find tarball for comparison'
            )
            print(f"  [WARN] No tarball found, skipping integrity check")
            return self.integrity_report

        print(f"  [INFO] Found tarball: {tarball.name}")

        # 2. 获取tarball中的文件
        tar_files = self.get_tarball_files(tarball)
        tar_files_normalized = self.normalize_paths(tar_files)
        self.integrity_report['tar_py_files'] = list(tar_files_normalized)

        print(f"  [INFO] Python files in tarball: {len(tar_files_normalized)}")

        # 3. 获取磁盘上的文件
        disk_files = self.get_disk_files()
        disk_files_normalized = self.normalize_paths(disk_files)
        self.integrity_report['disk_py_files'] = list(disk_files_normalized)

        print(f"  [INFO] Python files on disk: {len(disk_files_normalized)}")

        # 4. 检查缺失的文件
        missing_files = tar_files_normalized - disk_files_normalized

        if missing_files:
            self.integrity_report['passed'] = False
            self.integrity_report['missing_files'] = list(missing_files)

            print(f"  [ALERT] ⚠️  Missing {len(missing_files)} Python file(s):")
            for missing in sorted(missing_files):
                print(f"    - {missing}")

            # 添加警告
            self.integrity_report['warnings'].append(
                f'⚠️  SECURITY SOFTWARE INTERFERENCE DETECTED!\n'
                f'    {len(missing_files)} Python file(s) missing from disk.\n'
                f'    These files may have been quarantined by antivirus software.\n'
                f'    Analysis results may be INCOMPLETE.'
            )

            # 检查是否是关键文件
            critical_files = {'setup.py', '__init__.py'}
            missing_critical = missing_files.intersection(critical_files)

            if missing_critical:
                self.integrity_report['warnings'].append(
                    f'    CRITICAL: {missing_critical} are missing!\n'
                    f'    This package cannot be reliably classified.'
                )
        else:
            print(f"  [OK] All files present")

        # 5. 检查是否有新增文件（可能可疑）
        extra_files = disk_files_normalized - tar_files_normalized
        if extra_files:
            print(f"  [INFO] Extra files on disk (not in tarball): {len(extra_files)}")
            self.integrity_report['warnings'].append(
                f'Found {len(extra_files)} file(s) on disk not in tarball'
            )

        return self.integrity_report

    def save_report(self, output_dir: Path):
        """
        保存完整性检查报告

        Args:
            output_dir: 输出目录
        """
        report_file = output_dir / 'file_integrity.json'

        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(self.integrity_report, f, indent=2, ensure_ascii=False)

        print(f"[Integrity Check] Report saved: {report_file}")

    @staticmethod
    def create_incomplete_classification(missing_files: List[str]) -> Dict:
        """
        创建分析不完整的分类结果

        Args:
            missing_files: 缺失的文件列表

        Returns:
            分类结果字典
        """
        return {
            'category': 'INCOMPLETE_ANALYSIS',
            'risk_score': 0.5,
            'confidence': 0.3,
            'reason': (
                f'安全软件可能干扰了分析 - {len(missing_files)} 个文件缺失\n'
                f'缺失文件: {", ".join(sorted(missing_files)[:3])}'
                f'{"..." if len(missing_files) > 3 else ""}\n'
                f'建议: 禁用实时防护后重新分析'
            ),
            'missing_files': missing_files,
            'analysis_details': {
                'integrity_check': {
                    'passed': False,
                    'missing_files_count': len(missing_files),
                    'missing_files': missing_files,
                    'note': 'Antivirus software may have quarantined malicious files'
                }
            }
        }
