"""
V12 混淆检测器 - LLM-based混淆检测

功能：
- 使用LLM检测代码混淆
- 检测隐藏在正常代码中的恶意行为
- 输出结构化的混淆检测结果
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Optional
from zhipuai import ZhipuAI


class V12ObfuscationDetector:
    """V12 混淆检测器 - LLM-based混淆分析"""

    def __init__(self, api_key: str):
        """
        初始化混淆检测器

        Args:
            api_key: ZhipuAI API密钥
        """
        self.api_key = api_key
        self.client = ZhipuAI(api_key=api_key)

        # 加载prompt模板
        prompt_file = Path(__file__).parent.parent.parent / "prompts" / "v12_obfuscation_detector_en.txt"
        with open(prompt_file, 'r', encoding='utf-8') as f:
            self.prompt_template = f.read()

    def detect_obfuscation(
        self,
        package_dir: str,
        package_name: str,
        ddg_v7_report: Optional[Dict] = None
    ) -> Dict:
        """
        LLM-based混淆检测

        Args:
            package_dir: 包目录
            package_name: 包名
            ddg_v7_report: DDG V7安全报告（可选）

        Returns:
            {
                'is_obfuscated': bool,
                'is_semantically_unclear': bool,
                'obfuscation_type': str,
                'obfuscation_confidence': float,
                'needs_stub_analysis': bool,
                'suspicious_patterns': List[str],
                'hidden_malicious_behaviors': List[Dict],
                'reason': str
            }
        """
        print(f"        [LLM混淆检测] 分析包: {package_name}")

        # 收集DDG信息用于填充prompt
        ddg_info = self._collect_ddg_info(package_dir, ddg_v7_report)

        # 填充prompt
        prompt = self._fill_obfuscation_prompt(
            package_name,
            ddg_info,
            ddg_v7_report
        )

        # 调用LLM
        try:
            response = self.client.chat.completions.create(
                model="glm-4.7-flash",  # 使用glm-4.7-flash模型
                messages=[
                    {"role": "system", "content": "You are an expert code analysis system specializing in detecting code obfuscation and suspicious patterns."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1,  # 低温度保证稳定性
                max_tokens=3000
            )

            llm_output = response.choices[0].message.content

            # 解析LLM输出
            result = self._parse_llm_output(llm_output)

            print(f"          [LLM判决] 混淆: {result['is_obfuscated']}, 类型: {result['obfuscation_type']}")
            print(f"          [置信度] {result['obfuscation_confidence']:.2f}")
            print(f"          [需要桩分析] {result['needs_stub_analysis']}")

            return result

        except Exception as e:
            print(f"          [ERROR] LLM混淆检测失败: {e}")
            # 回退：基于规则判定
            return self._fallback_rule_based_detection(package_dir)

    def _collect_ddg_info(self, package_dir: str, ddg_v7_report: Dict) -> Dict:
        """收集DDG信息"""
        package_path = Path(package_dir)

        # 统计Python文件
        py_files = list(package_path.rglob('*.py'))
        total_lines = 0

        dangerous_nodes = []
        data_flow_paths = []
        functions = {}
        string_literals = {}
        variable_assignments = []
        sensitive_patterns = []

        for py_file in py_files:
            try:
                with open(py_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    total_lines += len(content.splitlines())

                    # 提取危险节点（eval, exec等）
                    dangerous_apis = ['eval', 'exec', 'compile', '__import__']
                    for api in dangerous_apis:
                        if f'{api}(' in content:
                            lines = content.splitlines()
                            for idx, line in enumerate(lines):
                                if api in line:
                                    dangerous_nodes.append({
                                        'file': str(py_file.relative_to(package_path)),
                                        'line': idx + 1,
                                        'code': line.strip()[:200]
                                    })

                    # 提取函数定义
                    func_matches = re.finditer(r'def\s+(\w+)\s*\(', content)
                    for match in func_matches:
                        func_name = match.group(1)
                        if func_name not in functions:
                            functions[func_name] = []
                        # 简单收集函数位置
                        functions[func_name].append({
                            'file': str(py_file.relative_to(package_path)),
                            'line': content[:match.start()].count('\n') + 1
                        })

                    # 提取字符串字面量
                    str_matches = re.finditer(r'["\']([^"\']{20,})["\']', content)
                    for match in str_matches:
                        str_value = match.group(1)
                        if len(str_value) >= 20:  # 只收集长字符串
                            str_key = f"str_{len(string_literals)}"
                            string_literals[str_key] = str_value

                    # 提取变量赋值（特别是短变量名）
                    var_matches = re.finditer(r'([a-z]{1,2})\s*=', content)
                    for match in var_matches:
                        var_name = match.group(1)
                        variable_assignments.append({
                            'variable': var_name,
                            'file': str(py_file.relative_to(package_path)),
                            'line': content[:match.start()].count('\n') + 1
                        })

                    # 检测敏感模式
                    if 'base64' in content:
                        sensitive_patterns.append('base64 encoding detected')
                    if 'eval(' in content:
                        sensitive_patterns.append('dynamic code execution (eval)')
                    if 'exec(' in content:
                        sensitive_patterns.append('dynamic code execution (exec)')
                    if re.search(r'\\x[0-9a-fA-F]{2}', content):
                        sensitive_patterns.append('hex encoding detected')

            except Exception as e:
                continue

        return {
            'package_name': package_dir,
            'source_files': len(py_files),
            'total_lines': total_lines,
            'dangerous_nodes_count': len(dangerous_nodes),
            'data_flow_paths_count': 0,  # 暂时设为0
            'functions_count': len(functions),
            'subgraphs_count': 0,  # 暂时设为0
            'dangerous_nodes_sample': dangerous_nodes[:10],
            'data_flow_paths_sample': [],
            'string_literals': string_literals,
            'variable_assignments': variable_assignments[:20],
            'sensitive_patterns': sensitive_patterns
        }

    def _fill_obfuscation_prompt(
        self,
        package_name: str,
        ddg_info: Dict,
        ddg_v7_report: Optional[Dict]
    ) -> str:
        """填充混淆检测prompt"""
        prompt = self.prompt_template

        # 填充基本统计信息
        prompt = prompt.replace("{package_name}", package_name)
        prompt = prompt.replace("{source_files}", str(ddg_info['source_files']))
        prompt = prompt.replace("{total_lines}", str(ddg_info['total_lines']))
        prompt = prompt.replace("{dangerous_nodes_count}", str(ddg_info['dangerous_nodes_count']))
        prompt = prompt.replace("{data_flow_paths_count}", str(ddg_info['data_flow_paths_count']))
        prompt = prompt.replace("{functions_count}", str(ddg_info['functions_count']))
        prompt = prompt.replace("{subgraphs_count}", str(ddg_info['subgraphs_count']))

        # 填充危险节点样本
        nodes_text = self._format_dangerous_nodes(ddg_info['dangerous_nodes_sample'])
        prompt = prompt.replace("{dangerous_nodes_sample}", nodes_text)

        # 填充数据流路径样本
        paths_text = self._format_data_flow_paths(ddg_info['data_flow_paths_sample'])
        prompt = prompt.replace("{data_flow_paths_sample}", paths_text)

        # 填充字符串字面量
        strings_text = self._format_string_literals(ddg_info['string_literals'])
        prompt = prompt.replace("{string_literals}", strings_text)

        # 填充变量赋值
        vars_text = self._format_variable_assignments(ddg_info['variable_assignments'])
        prompt = prompt.replace("{variable_assignments}", vars_text)

        # 填充敏感模式
        patterns_text = "\n".join([f"  - {p}" for p in ddg_info['sensitive_patterns']])
        prompt = prompt.replace("{sensitive_patterns}", patterns_text if patterns_text else "None")

        return prompt

    def _format_dangerous_nodes(self, nodes: List[Dict]) -> str:
        """格式化危险节点"""
        if not nodes:
            return "None"

        lines = []
        for node in nodes[:10]:
            lines.append(f"  - {node['file']}:{node['line']}: {node['code']}")

        return "\n".join(lines) if lines else "None"

    def _format_data_flow_paths(self, paths: List) -> str:
        """格式化数据流路径"""
        if not paths:
            return "None"

        return "  - (Data flow analysis not implemented yet)"

    def _format_string_literals(self, literals: Dict) -> str:
        """格式化字符串字面量"""
        if not literals:
            return "None"

        lines = []
        for key, value in list(literals.items())[:10]:
            value_str = str(value)[:100]
            lines.append(f"  - {key} = {value_str}")

        return "\n".join(lines) if lines else "None"

    def _format_variable_assignments(self, assignments: List[Dict]) -> str:
        """格式化变量赋值"""
        if not assignments:
            return "None"

        lines = []
        for assignment in assignments[:20]:
            lines.append(f"  - {assignment['variable']} at {assignment['file']}:{assignment['line']}")

        return "\n".join(lines) if lines else "None"

    def _parse_llm_output(self, llm_output: str) -> Dict:
        """解析LLM输出"""
        try:
            # 尝试提取JSON
            json_match = re.search(r'```json\s*(.*?)\s*```', llm_output, re.DOTALL)
            if json_match:
                json_str = json_match.group(1)
            else:
                # 如果没有markdown格式，尝试直接解析
                json_str = llm_output

            result = json.loads(json_str)

            # 确保必需字段存在
            result.setdefault('is_obfuscated', False)
            result.setdefault('is_semantically_unclear', False)
            result.setdefault('obfuscation_type', 'none')
            result.setdefault('obfuscation_confidence', 0.5)
            result.setdefault('needs_stub_analysis', False)
            result.setdefault('suspicious_patterns', [])
            result.setdefault('hidden_malicious_behaviors', [])
            result.setdefault('reason', '')

            return result

        except Exception as e:
            print(f"          [WARN] LLM输出解析失败: {e}")
            print(f"          LLM输出: {llm_output[:500]}")

            # 回退：基于关键词判断
            return self._fallback_keyword_detection(llm_output)

    def _fallback_rule_based_detection(self, package_dir: str) -> Dict:
        """回退：基于规则的混淆检测"""
        package_path = Path(package_dir)

        # 统计短变量名
        py_files = list(package_path.rglob('*.py'))
        total_vars = 0
        short_vars = 0

        for py_file in py_files:
            try:
                with open(py_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    var_matches = re.findall(r'\b([a-z]{1,2})\s*=', content)
                    for var in var_matches:
                        total_vars += 1
                        if len(var) <= 2:
                            short_vars += 1
            except:
                continue

        # 计算混淆比例
        if total_vars > 0:
            short_var_ratio = short_vars / total_vars
        else:
            short_var_ratio = 0

        # 简单判定
        is_obfuscated = short_var_ratio > 0.5

        return {
            'is_obfuscated': is_obfuscated,
            'is_semantically_unclear': is_obfuscated,
            'obfuscation_type': 'name' if is_obfuscated else 'none',
            'obfuscation_confidence': short_var_ratio if is_obfuscated else 0.0,
            'needs_stub_analysis': is_obfuscated,
            'suspicious_patterns': [f'short variable ratio: {short_var_ratio:.2%}'],
            'hidden_malicious_behaviors': [],
            'reason': f'Rule-based fallback: short variable ratio {short_var_ratio:.2%}'
        }

    def _fallback_keyword_detection(self, llm_output: str) -> Dict:
        """回退：基于关键词的LLM输出检测"""
        output_lower = llm_output.lower()

        # 检测关键词
        is_obfuscated = any(word in output_lower for word in [
            'obfuscation', 'obfuscated', 'hidden malicious', 'suspicious pattern'
        ])
        is_malicious = any(word in output_lower for word in [
            'malicious behavior', 'hidden intent', 'malicious side effect'
        ])

        if is_obfuscated or is_malicious:
            obfuscation_type = 'hidden_malicious' if is_malicious else 'mixed'
        else:
            obfuscation_type = 'none'

        return {
            'is_obfuscated': is_obfuscated,
            'is_semantically_unclear': is_obfuscated,
            'obfuscation_type': obfuscation_type,
            'obfuscation_confidence': 0.7 if (is_obfuscated or is_malicious) else 0.3,
            'needs_stub_analysis': is_obfuscated or is_malicious,
            'suspicious_patterns': ['keyword-based detection'],
            'hidden_malicious_behaviors': [],
            'reason': f'Keyword-based fallback: detected "{obfuscation_type}"'
        }
