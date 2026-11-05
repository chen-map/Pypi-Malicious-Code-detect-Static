"""
增强检测器 - 修复NEW_DDG的检测盲点

检测范围：
1. setup.py安装钩子恶意代码
2. 依赖关系攻击
3. 元数据可疑性（钓鱼包名、可疑作者）

作者：NEW_DDG Team
日期：2026-06-12
"""

import ast
import re
import json
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from collections import defaultdict


class EnhancedSecurityDetector:
    """增强安全检测器 - 检测代码之外的威胁"""

    def __init__(self):
        # 危险的setup.py模式（均衡模式重分级 2026-10）：
        # - console_scripts 是 setuptools 声明 CLI 入口的正常实践，从
        #   post_install 拆出为 entry_points(low)，不再单条规则判死整包
        # - eval/exec/__import__ 在正常构建脚本里常用于计算版本号，降为 high
        # - subprocess+shell=True 保持 critical；class \w*Install\w* 单独
        #   出现过于宽泛，降为 high
        self.dangerous_setup_patterns = {
            'install_hooks': [
                # cmdclass 里出现 install 键本身就是安装钩子(类定义通常在上方,
                # 不应要求 class/lambda 字样与 install 同行)
                r'cmdclass\s*=\s*\{[^}]*[\'"]install[\'"]\s*:',
                r'cmdclass\[[\'"]install[\'"]\]\s*=',
            ],
            'install_hook_class': [
                r'class\s+\w*Install\w*.*:',
            ],
            'post_install': [
                r'post_install\s*=\s*',
            ],
            'entry_points': [
                r'entry_points\s*=.*console_scripts',
            ],
            'dangerous_imports': [
                r'(?:__import__|exec|eval|compile)\s*\(',
                r'os\.system\s*\(',
            ],
            'shell_true_exec': [
                r'subprocess\.\w+.*shell\s*=\s*True',
            ]
        }

        # 可疑的包名模式（钓鱼）
        self.suspicious_name_patterns = {
            'typosquatting': [
                r'\b(reqeusts?|requsets?|requets?|requests2)\b',  # requests (但不包括正常的requests)
                r'\b(numpyy|numpys|numby)\b',  # numpy (但不包括正常的numpy)
                r'\b(pandass|pandas2)\b',  # pandas (但不包括正常的pandas)
                r'\b(flask2|flas|flaskk)\b',  # flask (但不包括正常的flask)
                r'\b(django2|djanggo|djnago)\b',  # django (但不包括正常的django)
            ],
            'popular_mod_mimic': [
                r'(.+)-utils\d*$',  # 模拟工具包
                r'(.+)-tools\d*$',  # 模拟工具
                r'(.+)-lib\d*$',  # 模拟库
                r'(.+)-helper\d*$',  # 模拟辅助
            ],
            # 均衡模式：强恶意词(带词界)与弱可疑词分档，避免 shell/crypto 等
            # 常见词把正常包名判死
            'obvious_malicious': [
                r'\b(getshell|backdoor|rootkit|malware|trojan)\b',
            ],
            'suspicious_words': [
                r'\b(inject|pwn|attack|payload|shell|hack|exploit)\b',
                r'\b(bitcoin|crypto|mining|steal|credential|password)\b',
            ]
        }

        # 可疑的作者/项目信息（短链/pastebin 降为 medium，暗网保持 high）
        self.suspicious_metadata_patterns = {
            'author': [
                r'(test|anonymous|unknown|none|null)',  # 匿名作者
                r'(bitbucket|github|gitlab)\.com.*',  # 使用仓库URL作为作者名
            ],
            'url': [
                r'(shortened\.|bit\.ly|tinyurl|goo\.gl)',  # 短链接服务
                r'(pastebin|github\.com/gist)',  # Pastebin/Gist
            ],
            'url_darknet': [
                r'(\.onion|\.i2p)',  # 暗网URL
            ],
            'email': [
                r'(temp|disposable|10minutemail|guerrillamail)',  # 临时邮箱（修复 ' disposable' 前导空格笔误）
            ]
        }

        # 已知的恶意依赖模式
        self.malicious_dependency_patterns = {
            'remote_code': [
                r'git\+https?://.*\.py$',  # 从远程直接执行.py
                r'pip\s+install.*-e\s+.*',  # 可编辑安装远程包
            ],
            'pinned_to_malicious': [
                r'(reqeusts|numpy-utils)\s*==\s*[\d.]+',  # 错误拼写
            ]
        }

    # 严重程度等级序（修复：原先三处 max() 按字符串字典序比较，
    # 'medium' > 'low' > 'high' > 'critical'，会把真实 critical 威胁降级）
    SEVERITY_RANK = {'critical': 3, 'high': 2, 'medium': 1, 'low': 0}

    # 安装期外传：setup.py 里同时出现"环境侦察"和"网络发送"即信息窃取
    # (真实样本 openvc: getpass.getuser + socket.gethostname + platform.platform
    #  + 本机 IP，base64 后 POST 到 checkVersion.php)
    SETUP_RECON_PATTERNS = [
        r'getpass\.getuser', r'socket\.gethostname', r'socket\.gethostbyname',
        r'platform\.platform', r'platform\.system', r'locale\.getdefaultlocale',
        r'os\.environ', r'getpass\.getuser', r'uuid\.getnode',
    ]
    SETUP_NETWORK_PATTERNS = [
        r'\burlopen\s*\(', r'requests\.(get|post|put|head)\s*\(',
        r'http\.client', r'urllib\.request', r'socket\.(connect|create_connection)\s*\(',
        r'smtplib\.', r'ftplib\.',
    ]

    # 被抢注/仿冒的高频目标（用于发行包名的编辑距离检测）
    POPULAR_PACKAGES = [
        'requests', 'urllib3', 'boto3', 'numpy', 'pandas', 'flask', 'django',
        'opencv-python', 'opencv', 'python-dateutil', 'pycryptodome',
        'cryptography', 'tensorflow', 'torch', 'colorama', 'six', 'setuptools',
        'pip', 'discord-py', 'discord.py', 'pytesseract', 'selenium', 'aiohttp',
        'httpx', 'tqdm', 'pyyaml', 'pillow', 'matplotlib', 'scipy', 'pycparser',
        'psutil', 'pyinstaller', 'paramiko', 'sqlalchemy', 'botocore',
        'pynput', 'pyautogui', 'keyboard', 'mouse', 'clipboard', 'pywin32',
    ]

    @staticmethod
    def _normalize_name(name: str) -> str:
        return re.sub(r'[-_.]+', '-', (name or '').strip().lower())

    @staticmethod
    def _edit_distance_le1(a: str, b: str) -> bool:
        """编辑距离是否 <= 1（用于 typosquat）"""
        la, lb = len(a), len(b)
        if abs(la - lb) > 1:
            return False
        if la == lb:
            return sum(1 for x, y in zip(a, b) if x != y) <= 1
        if la > lb:
            a, b, la, lb = b, a, lb, la
        i = 0
        while i < la and a[i] == b[i]:
            i += 1
        return a[i:] == b[i + 1:]

    @staticmethod
    def _strip_version(dist_name: str) -> str:
        """从发行文件名剥离版本与 wheel 标记：python-dateutils-3.0.3 → python-dateutils"""
        n = re.sub(r'\.(tar\.gz|whl|zip)$', '', dist_name or '', flags=re.IGNORECASE)
        n = re.sub(r'-py\d[\w.]*-none-any$', '', n)
        n = re.sub(r'-\d[\w.]*$', '', n)
        return n

    def _analyze_distribution_name(self, dist_name: str, metadata_name: str,
                                   use_live_index: bool = False,
                                   metadata_source: str = '') -> Dict:
        """发行包名分析：名称抢注 / 依赖混淆（2026-10，真实样本驱动）

        恶意包的代码常常是抄来的真实包(甚至完全干净)，攻击在"名字"上：
        - 发行名与元数据 Name 不一致(botaa3 → boto3)
        - 发行名与流行包编辑距离 <= 1(python-dateutils → python-dateutil)

        2026-10 硬化：use_live_index 时比对目标从 40 个硬编码清单升级为
        PyPI simple index 全量包名（磁盘缓存 24h）；索引不可用时回退清单。

        2026-11 硬化：name_mismatch 只认 PKG-INFO/METADATA（构建系统生成的
        权威元数据）。setup.py 解析出的名字可以是任意字面量（模板/夹具），
        用它判 critical 会冤枉正常包。
        """
        result = {'threats': [], 'has_threats': False, 'threat_level': 'safe',
                  'dist_name': dist_name or '', 'metadata_name': metadata_name or ''}

        dn = self._normalize_name(self._strip_version(dist_name))
        mn = self._normalize_name(self._strip_version(metadata_name))
        candidates = [c for c in (dn, mn) if c]

        if dn and mn and dn != mn:
            # 来源门控:只有权威元数据(PKG-INFO/METADATA)的不一致才是铁证。
            # setup.py 来源降为 medium 并注明来源——它可能是模板/示例字面量。
            authoritative = metadata_source in ('pkg_info', 'metadata')
            result['threats'].append({
                'type': 'name_mismatch',
                # critical: 正常发行流程中 sdist/wheel 文件名与 PKG-INFO Name
                # 必然一致，不一致本身就是名称抢注/依赖混淆的决定性证据
                'severity': 'critical' if authoritative else 'medium',
                'dist_name': dist_name,
                'metadata_name': metadata_name,
                'metadata_source': metadata_source or 'unknown',
                'reason': ('发行包名与元数据 Name 不一致（典型名称抢注/依赖混淆特征）'
                           if authoritative else
                           '发行包名与 setup.py 中 name 不一致（setup.py 是代码，'
                           '可能为模板/示例字面量，仅作弱信号）'),
            })

        typosquat_found = False
        live_buckets = None
        if use_live_index:
            try:
                from src.pypi_index import load_index, build_length_buckets
                index_names = load_index()
                if index_names:
                    live_buckets = build_length_buckets(index_names)
            except Exception:
                live_buckets = None

        def _is_typosquat(cand: str):
            """返回 (目标名, 来源)，无则 None

            来源决定严重度：curated（人工精选清单，高精度）→ critical；
            live（全量索引，任何短名在 50 万包里必有编辑距离邻居——低精度）
            → high。教训：全量索引的 critical 曾把 attrs/click/jinja2 全部
            误判（attrs→aptrs、click→aclick 这类随机邻居）。
            """
            if live_buckets:
                from src.pypi_index import find_near_neighbors
                hits = find_near_neighbors(cand, live_buckets)
                if hits:
                    return sorted(hits)[0], 'live'
            for popular in self.POPULAR_PACKAGES:
                p = self._normalize_name(popular)
                if cand == p or len(p) < 5:
                    continue
                if self._edit_distance_le1(cand, p):
                    return popular, 'curated'
            return None

        for cand in candidates:
            if typosquat_found:
                break
            hit = _is_typosquat(cand)
            if hit:
                target, source = hit
                result['threats'].append({
                    'type': 'typosquatting',
                    # curated=高精度判死；live=低精度信号，降 high 交投票层
                    'severity': 'critical' if source == 'curated' else 'high',
                    'source': source,
                    'dist_name': dist_name,
                    'target': target,
                    'reason': (f'包名与流行包 {target} 仅差一个字符（typosquatting'
                               f'，{"精选清单" if source == "curated" else "实时索引"}命中）'),
                })
                typosquat_found = True

        if result['threats']:
            result['has_threats'] = True
            result['threat_level'] = self._max_severity(result['threats'])
        return result

    def _max_severity(self, threats: List[Dict]) -> str:
        """按等级序取 threats 中的最高 severity"""
        if not threats:
            return 'safe'
        best = max(threats, key=lambda t: self.SEVERITY_RANK.get(t.get('severity', 'low'), -1))
        return best.get('severity', 'low')

    def analyze_package(self, extracted_dir: Path, dist_name: Optional[str] = None,
                        verify_pypi: bool = False,
                        ignore_pypi_gate: bool = False) -> Dict:
        """
        分析包的非代码威胁

        Args:
            extracted_dir: 解压后的包目录
            dist_name: 发行包名（tar.gz/whl 文件名去掉版本），用于名称抢注检测。
                       不传时退化为从元数据读取。
            verify_pypi: 是否核验包是否存在于 PyPI 官方索引（需要网络）。
                         真实恶意抢注包的代码常常完全干净，这是关键判据。

        Returns:
            检测报告字典
        """
        metadata_result = self._analyze_metadata(extracted_dir)
        report = {
            'setup_py_analysis': self._analyze_setup_py(extracted_dir),
            'dependency_analysis': self._analyze_dependencies(extracted_dir),
            'metadata_analysis': metadata_result,
            'distribution_analysis': self._analyze_distribution_name(
                dist_name or metadata_result.get('package_name', ''),
                metadata_result.get('package_name', ''),
                use_live_index=bool(verify_pypi),  # 硬化：实时全量名比对
                metadata_source=metadata_result.get('package_name_source', ''),
            ),
            'pypi_verification': {'status': 'skipped', 'reason': '未启用'},
            'overall_threat_level': 'safe',
            'threats_found': []
        }

        if verify_pypi and dist_name:
            from src.pypi_verifier import verify_distribution, strip_version
            name, version = strip_version(dist_name)
            vr = verify_distribution(name, version)
            report['pypi_verification'] = vr

            # 2026-10 硬化：发布信号——首发 <30 天且版本号 ≥2.0（跳版本）
            # 是"新账号抢发"的典型形态；仅在能拿到统计时报告
            stats = vr.get('release_stats') or {}
            age = stats.get('first_release_age_days')
            if vr['status'] == 'exists' and age is not None and age < 30:
                try:
                    major = int(re.match(r'(\d+)', version or '0').group(1))
                except (AttributeError, ValueError):
                    major = 0
                if major >= 2:
                    report['distribution_analysis']['threats'].append({
                        'type': 'young_release_version_jump',
                        'severity': 'high',
                        'dist_name': dist_name,
                        'reason': (f'官方记录首发仅 {age} 天且版本号已到 {version} '
                                   '——新发布包版本跳变，抢发特征'),
                    })
                    report['distribution_analysis']['has_threats'] = True
                    report['distribution_analysis']['threat_level'] = self._max_severity(
                        report['distribution_analysis']['threats'])

            # 2026-10 硬化：近重复检测——name_mismatch 时下载真包比对
            # 文件哈希，抓"抄真包代码、只改名字"族(botaa3)
            mismatch = any(t.get('type') == 'name_mismatch'
                           for t in report['distribution_analysis']['threats'])
            if mismatch and metadata_result.get('package_name'):
                try:
                    from src.duplicate_detector import check_duplicate
                    # 关键：真包版本取元数据 Version（botaa3 的元数据写着
                    # boto3 1.20.7）——发行名的版本号是仿冒者的，会下错真包
                    genuine_version = (metadata_result.get('package_version')
                                       or version or '')
                    dup = check_duplicate(extracted_dir,
                                          metadata_result['package_name'],
                                          genuine_version)
                    report['duplicate_check'] = dup
                    if dup['status'] == 'duplicate':
                        report['distribution_analysis']['threats'].append({
                            'type': 'code_duplicate_of_genuine',
                            'severity': 'critical',
                            'dist_name': dist_name,
                            'reason': dup['reason'],
                        })
                        report['distribution_analysis']['has_threats'] = True
                        report['distribution_analysis']['threat_level'] = self._max_severity(
                            report['distribution_analysis']['threats'])
                    elif dup['status'] == 'similar':
                        report['distribution_analysis']['threats'].append({
                            'type': 'code_similar_to_genuine',
                            'severity': 'medium',
                            'dist_name': dist_name,
                            'reason': dup['reason'],
                        })
                        report['distribution_analysis']['has_threats'] = True
                        report['distribution_analysis']['threat_level'] = self._max_severity(
                            report['distribution_analysis']['threats'])
                except Exception as dup_err:
                    report['duplicate_check'] = {'status': 'unknown',
                                                 'reason': str(dup_err)[:100]}

            # 2026-11 消融开关:ignore_pypi_gate=True 时,registry 身份
            # 不作为判决证据(仍记录在 pypi_verification 里供审计)。
            # 用于评估"纯代码分析(图内核+LLM)不依赖联网也能抓到多少"。
            if (vr['status'] in ('not_found', 'unpublished_version')
                    and not ignore_pypi_gate):
                report['distribution_analysis']['threats'].append({
                    'type': f'pypi_{vr["status"]}',
                    'severity': 'critical',
                    'dist_name': dist_name,
                    'reason': vr['reason'],
                })
                report['distribution_analysis']['has_threats'] = True
                report['distribution_analysis']['threat_level'] = 'critical'

        # 汇总威胁等级
        threats = []
        threat_scores = {
            'critical': 10,
            'high': 7,
            'medium': 4,
            'low': 1
        }

        total_score = 0

        # 检查setup.py
        if report['setup_py_analysis']['has_threats']:
            threats.extend(report['setup_py_analysis']['threats'])
            total_score += threat_scores.get(report['setup_py_analysis']['threat_level'], 0)

        # 检查依赖
        if report['dependency_analysis']['has_threats']:
            threats.extend(report['dependency_analysis']['threats'])
            total_score += threat_scores.get(report['dependency_analysis']['threat_level'], 0)

        # 检查元数据
        if report['metadata_analysis']['has_threats']:
            threats.extend(report['metadata_analysis']['threats'])
            total_score += threat_scores.get(report['metadata_analysis']['threat_level'], 0)

        # 检查发行包名（名称抢注/依赖混淆）
        if report['distribution_analysis']['has_threats']:
            threats.extend(report['distribution_analysis']['threats'])
            total_score += threat_scores.get(report['distribution_analysis']['threat_level'], 0)

        # 确定总体威胁等级
        # 2026-11 硬化:critical 必须有真实的 critical 单信号支撑。
        # 此前纯累加评分:medium(4)+high(7)=11 → critical → 触发短路判死,
        # 两个低精度信号(live索引typosquat + 依赖名形似)就能冤枉良性包
        # (a2a_sdk: a2p-sdk 差一字符 + grpcio-tools 形似)。
        # 累加只能区分 high/medium/low,不能凭空造出最高等级。
        report['threats_found'] = threats
        has_critical_signal = any(
            (t.get('severity') or '').lower() == 'critical' for t in threats)
        if total_score >= 10 and has_critical_signal:
            report['overall_threat_level'] = 'critical'
        elif total_score >= 7:
            report['overall_threat_level'] = 'high'
        elif total_score >= 4:
            report['overall_threat_level'] = 'medium'
        elif total_score >= 1:
            report['overall_threat_level'] = 'low'

        return report

    def _analyze_setup_py(self, extracted_dir: Path) -> Dict:
        """分析setup.py中的恶意模式"""
        result = {
            'has_threats': False,
            'threat_level': 'safe',
            'threats': [],
            'file_exists': False
        }

        setup_files = [
            extracted_dir / 'setup.py',
            extracted_dir / 'setup.cfg',
            extracted_dir / 'pyproject.toml'
        ]

        for setup_file in setup_files:
            if not setup_file.exists():
                continue

            result['file_exists'] = True

            try:
                content = setup_file.read_text(encoding='utf-8', errors='ignore')

                # 检测危险模式
                for category, patterns in self.dangerous_setup_patterns.items():
                    for pattern in patterns:
                        if re.search(pattern, content, re.IGNORECASE):
                            threat = {
                                'type': 'setup_py_malicious',
                                'category': category,
                                'pattern': pattern,
                                'file': str(setup_file.name),
                                'severity': self._get_severity_for_category(category)
                            }
                            result['threats'].append(threat)

                # 安装期信息窃取：环境侦察(getpass/hostname/platform/IP/环境变量)
                # 与网络发送(urlopen/requests/socket)在同一安装脚本中同现。
                # 真实样本 openvc: checkVersion() 收集 用户名+主机名+平台+本机IP,
                # base64 后 POST 到 checkVersion.php ——此前完全没有规则覆盖。
                recon = [p for p in self.SETUP_RECON_PATTERNS
                         if re.search(p, content, re.IGNORECASE)]
                network = [p for p in self.SETUP_NETWORK_PATTERNS
                           if re.search(p, content, re.IGNORECASE)]
                if recon and network:
                    result['threats'].append({
                        'type': 'install_time_exfiltration',
                        'category': 'install_time_exfil',
                        'file': str(setup_file.name),
                        'severity': 'critical',
                        'reason': ('安装脚本同时进行系统环境侦察与网络发送'
                                   f'（侦察: {recon[0]}；网络: {network[0]}），'
                                   '典型安装期信息窃取'),
                    })
                elif network:
                    result['threats'].append({
                        'type': 'setup_py_malicious',
                        'category': 'network_in_setup',
                        'file': str(setup_file.name),
                        'severity': 'high',
                        'reason': f'安装脚本包含网络调用: {network[0]}',
                    })

            except Exception as e:
                # 读取失败，也算可疑
                result['threats'].append({
                    'type': 'setup_py_unreadable',
                    'reason': f'Cannot read {setup_file.name}: {e}',
                    'severity': 'medium'
                })

        # 确定威胁等级（按等级序比较，非字符串字典序）
        if result['threats']:
            result['has_threats'] = True
            result['threat_level'] = self._max_severity(result['threats'])

        return result

    def _analyze_dependencies(self, extracted_dir: Path) -> Dict:
        """分析依赖关系中的威胁"""
        result = {
            'has_threats': False,
            'threat_level': 'safe',
            'threats': [],
            'dependencies': []
        }

        # 读取依赖文件
        dep_files = {
            'requirements.txt': extracted_dir / 'requirements.txt',
            'setup.py': extracted_dir / 'setup.py',
            'setup.cfg': extracted_dir / 'setup.cfg',
            'pyproject.toml': extracted_dir / 'pyproject.toml'
        }

        all_deps = set()

        for file_type, file_path in dep_files.items():
            if not file_path.exists():
                continue

            try:
                content = file_path.read_text(encoding='utf-8', errors='ignore')

                # 提取依赖（原先 pyproject.toml/setup.cfg 读了内容但恒返回空，
                # 现代包的主要依赖声明在 PEP 621 里，导致依赖投毒检测失效）
                if file_type == 'requirements.txt':
                    deps = self._extract_requirements(content)
                    # 远程直装模式检查（原先定义了模式但从未接入）
                    for group, severity in [('remote_code', 'high'),
                                            ('pinned_to_malicious', 'high')]:
                        for pattern in self.malicious_dependency_patterns[group]:
                            if re.search(pattern, content, re.IGNORECASE):
                                result['threats'].append({
                                    'type': 'remote_code_dependency',
                                    'file': file_type,
                                    'pattern': pattern,
                                    'severity': severity
                                })
                elif file_type == 'setup.py':
                    deps = self._extract_setup_dependencies(content)
                elif file_type == 'pyproject.toml':
                    deps = self._extract_pyproject_dependencies(content)
                elif file_type == 'setup.cfg':
                    deps = self._extract_setupcfg_dependencies(content)
                else:
                    deps = []

                all_deps.update(deps)

            except Exception:
                continue

        result['dependencies'] = list(all_deps)

        # 检测可疑依赖
        for dep in all_deps:
            # 检查拼写错误（typosquatting）
            for pattern_type, patterns in self.suspicious_name_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, dep, re.IGNORECASE):
                        result['threats'].append({
                            'type': 'suspicious_dependency',
                            'dependency': dep,
                            'pattern_type': pattern_type,
                            'severity': 'high' if pattern_type == 'typosquatting' else 'medium'
                        })

        # 确定威胁等级（按等级序比较，非字符串字典序）
        if result['threats']:
            result['has_threats'] = True
            result['threat_level'] = self._max_severity(result['threats'])

        return result

    def _analyze_metadata(self, extracted_dir: Path) -> Dict:
        """分析元数据的可疑性

        2026-11 硬化:package_name 必须记录来源。setup.py 是**代码**不是
        元数据,从中解析出的 name 可能是模板示例/测试夹具的字面量
        (acryl_datahub_actions 的 setup.py 解析出 '"hello_world"' →
        name_mismatch critical → 短路判死)。只有 PKG-INFO/METADATA
        (构建系统生成的权威元数据)才允许作为名称抢注判据。
        """
        result = {
            'has_threats': False,
            'threat_level': 'safe',
            'threats': [],
            'package_name': '',
            'package_name_source': '',
            'author': '',
            'url': '',
            'email': ''
        }

        # 权威元数据优先(PKG-INFO/METADATA 由构建系统生成);setup.py 垫底
        # 仅用于填充 author/url 等辅助字段,名称判据会检查来源
        metadata_files = [
            (extracted_dir / 'PKG-INFO', 'pkg_info'),
            (extracted_dir / 'METADATA', 'metadata'),
            (extracted_dir / 'setup.py', 'setup_py'),
        ]

        metadata = {}
        name_source = ''
        for meta_file, source in metadata_files:
            if not meta_file.exists():
                continue

            try:
                content = meta_file.read_text(encoding='utf-8', errors='ignore')
                parsed = self._parse_metadata(content)
            except Exception:
                continue
            # 名称与版本按"权威优先"合并:PKG-INFO 已有名字就不让 setup.py 覆盖
            if parsed.get('name') and not metadata.get('name'):
                metadata['name'] = parsed['name']
                name_source = source
            if parsed.get('version') and not metadata.get('version'):
                metadata['version'] = parsed['version']
            for k, v in parsed.items():
                if k not in ('name', 'version'):
                    metadata.setdefault(k, v)

        result['package_name'] = (metadata.get('name') or '').strip().strip('"\'')
        result['package_name_source'] = name_source
        result['package_version'] = metadata.get('version', '')  # 真包版本（近重复检测用）
        result['author'] = metadata.get('author', '')
        result['url'] = metadata.get('home_page', metadata.get('url', ''))
        result['email'] = metadata.get('author_email', metadata.get('email', ''))

        # 检查包名
        if result['package_name']:
            for pattern_type, patterns in self.suspicious_name_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, result['package_name'], re.IGNORECASE):
                        result['threats'].append({
                            'type': 'suspicious_package_name',
                            'name': result['package_name'],
                            'pattern_type': pattern_type,
                            'severity': self._get_name_severity(pattern_type)
                        })

        # 检查作者
        if result['author']:
            for pattern in self.suspicious_metadata_patterns['author']:
                if re.search(pattern, result['author'], re.IGNORECASE):
                    result['threats'].append({
                        'type': 'suspicious_author',
                        'author': result['author'],
                        'severity': 'medium'
                    })

        # 检查URL（短链/pastebin=medium，暗网=high）
        if result['url']:
            for pattern in self.suspicious_metadata_patterns['url']:
                if re.search(pattern, result['url'], re.IGNORECASE):
                    result['threats'].append({
                        'type': 'suspicious_url',
                        'url': result['url'],
                        'severity': 'medium'
                    })
            for pattern in self.suspicious_metadata_patterns['url_darknet']:
                if re.search(pattern, result['url'], re.IGNORECASE):
                    result['threats'].append({
                        'type': 'suspicious_url',
                        'url': result['url'],
                        'severity': 'high'
                    })

        # 检查Email
        if result['email']:
            for pattern in self.suspicious_metadata_patterns['email']:
                if re.search(pattern, result['email'], re.IGNORECASE):
                    result['threats'].append({
                        'type': 'suspicious_email',
                        'email': result['email'],
                        'severity': 'low'
                    })

        # 确定威胁等级（按等级序比较，非字符串字典序）
        if result['threats']:
            result['has_threats'] = True
            result['threat_level'] = self._max_severity(result['threats'])

        return result

    def _extract_requirements(self, content: str) -> List[str]:
        """从requirements.txt提取依赖"""
        deps = []
        for line in content.split('\n'):
            line = line.strip()
            if line and not line.startswith('#'):
                # 提取包名（忽略版本号）
                match = re.match(r'^([a-zA-Z0-9_-]+)', line)
                if match:
                    deps.append(match.group(1))
        return deps

    def _extract_setup_dependencies(self, content: str) -> List[str]:
        """从setup.py提取依赖"""
        deps = []

        try:
            # 尝试解析AST
            tree = ast.parse(content)

            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    # 检查setup()调用
                    if isinstance(node.func, ast.Name) and node.func.id == 'setup':
                        for keyword in node.keywords:
                            if keyword.arg in ['install_requires', 'requires']:
                                if isinstance(keyword.value, (ast.List, ast.Tuple)):
                                    for elt in keyword.value.elts:
                                        if isinstance(elt, ast.Constant):
                                            # 提取包名
                                            match = re.match(r'^([a-zA-Z0-9_-]+)', elt.value)
                                            if match:
                                                deps.append(match.group(1))
        except Exception:
            # AST解析失败，尝试正则匹配
            match = re.search(r'install_requires\s*=\s*\[(.*?)\]', content, re.DOTALL)
            if match:
                for dep in re.findall(r'["\']([^"\']+)["\']', match.group(1)):
                    match2 = re.match(r'^([a-zA-Z0-9_-]+)', dep)
                    if match2:
                        deps.append(match2.group(1))

        return deps

    def _extract_pyproject_dependencies(self, content: str) -> List[str]:
        """从pyproject.toml提取依赖（PEP 621 + poetry）"""
        deps: List[str] = []
        try:
            import tomllib
            data = tomllib.loads(content)
        except Exception:
            return deps

        project = data.get('project') or {}
        candidates = list(project.get('dependencies') or [])
        for group in (project.get('optional-dependencies') or {}).values():
            candidates.extend(group or [])
        poetry = ((data.get('tool') or {}).get('poetry') or {})
        candidates.extend(str(k) for k in (poetry.get('dependencies') or {}))

        for dep in candidates:
            m = re.match(r'^([a-zA-Z0-9_-]+)', str(dep))
            if m:
                deps.append(m.group(1))
        return deps

    def _extract_setupcfg_dependencies(self, content: str) -> List[str]:
        """从setup.cfg的install_requires提取依赖"""
        deps = []
        match = re.search(r'install_requires\s*=?\s*\n((?:[ \t]+.+\n?)+)', content)
        if match:
            for line in match.group(1).split('\n'):
                line = line.strip()
                if line and not line.startswith('#'):
                    m = re.match(r'^([a-zA-Z0-9_-]+)', line)
                    if m:
                        deps.append(m.group(1))
        return deps

    def _parse_metadata(self, content: str) -> Dict:
        """解析 PKG-INFO/METADATA 格式（RFC822 风格头部）

        2026-11 修复:同名字段**首见优先**,不允许后出现的覆盖前面的。
        PKG-INFO 头部的 Name/Version 是构建系统写入的权威元数据,而
        Description 正文(README 内容)里常有 yaml/代码示例形如
        `name: hello_world` —— 顺序覆盖会让正文覆盖头部,
        acryl_datahub_actions 因此解析出 name='hello_world',
        伪造出 name_mismatch critical 并短路判死。

        另加保护:进入 Description 之后的正文不再解析字段(正文可能
        有任意 `word: value` 行),只保留头部元数据。
        """
        metadata = {}
        current_field = None
        in_body = False

        for line in content.split('\n'):
            line = line.rstrip()

            # Description 之后是正文,不再解析字段
            if in_body:
                continue

            # 检查字段行
            match = re.match(r'^([A-Za-z-]+):\s*(.*)', line)
            if match:
                field_name, value = match.groups()
                key = field_name.lower()
                current_field = key
                if key == 'description':
                    in_body = True  # 后续全是正文
                # 首见优先:头部字段不被正文/重复字段覆盖
                if key not in metadata:
                    metadata[key] = value
            elif current_field and line.startswith(' '):
                # 续行
                metadata[current_field] = (
                    metadata.get(current_field, '') + ' ' + line.strip())

        return metadata

    def _get_severity_for_category(self, category: str) -> str:
        """根据威胁类别获取严重程度（均衡模式重分级）"""
        severity_map = {
            'install_hooks': 'critical',
            'install_hook_class': 'high',
            'post_install': 'high',
            'entry_points': 'low',       # console_scripts 是正常实践
            'dangerous_imports': 'high', # eval/exec 常见于版本号计算
            'shell_true_exec': 'critical',
            'setup_cfg_danger': 'medium'
        }
        return severity_map.get(category, 'low')

    def _get_name_severity(self, pattern_type: str) -> str:
        """根据包名模式类型获取严重程度"""
        severity_map = {
            'typosquatting': 'critical',
            'obvious_malicious': 'high',
            'suspicious_words': 'medium',
            'popular_mod_mimic': 'medium'
        }
        return severity_map.get(pattern_type, 'low')


def test_enhanced_detector():
    """测试增强检测器"""
    detector = EnhancedSecurityDetector()

    # 测试用例
    print("=== 增强检测器测试 ===\n")

    # 测试setup.py检测
    test_setup = """
from setuptools import setup

class MaliciousInstall:
    def run(self):
        __import__('os').system('rm -rf /')

setup(
    name='malicious-package',
    install_requires=['requests'],
    cmdclass={'install': MaliciousInstall}
)
"""

    # 保存测试文件
    test_dir = Path('/tmp/test_enhanced')
    test_dir.mkdir(exist_ok=True)

    setup_file = test_dir / 'setup.py'
    setup_file.write_text(test_setup)

    result = detector._analyze_setup_py(test_dir)
    print(f"setup.py检测:")
    print(f"  发现威胁: {result['has_threats']}")
    print(f"  威胁等级: {result['threat_level']}")
    if result['threats']:
        for threat in result['threats']:
            print(f"  - {threat}")

    # 清理
    import shutil
    shutil.rmtree(test_dir)


if __name__ == '__main__':
    test_enhanced_detector()
