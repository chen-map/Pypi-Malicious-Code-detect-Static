"""
批量检测恶意样本 - 直接从tar.gz读取，避免解压bug
"""
import os
import json
import re
import tarfile
from pathlib import Path
from random import sample

# 配置
SAMPLES_DIR = r"C:\Users\85864\Downloads\output_line(1)\0-50"
NUM_SAMPLES = 10  # 随机选择数量
PATTERNS_FILE = "danger_patterns.json"

def find_tar_gz_files(directory):
    """查找所有.tar.gz文件"""
    tar_files = []
    for root, dirs, files in os.walk(directory):
        for f in files:
            if f.endswith('.tar.gz'):
                tar_files.append(os.path.join(root, f))
    return tar_files

def detect_patterns_in_code(code, patterns):
    """使用regex检测危险模式"""
    issues = []

    lines = code.split('\n')

    # 检测custom_rules
    for rule in patterns['custom_rules']['rules']:
        regex = rule['regex']
        try:
            pattern = re.compile(regex)
            for i, line in enumerate(lines, 1):
                if pattern.search(line):
                    issues.append({
                        'severity': rule['severity'],
                        'pattern': rule['name'],
                        'description': rule['description'],
                        'line': i,
                        'matched_text': line.strip()[:100]
                    })
                    # 只记录第一个匹配，避免重复
                    break
        except Exception as e:
            pass  # 忽略无效regex

    return issues

def detect_package(tar_gz_path, patterns):
    """检测单个包"""

    package_name = os.path.basename(tar_gz_path).replace('.tar.gz', '')

    try:
        with tarfile.open(tar_gz_path, 'r:gz') as tar:
            all_issues = []

            # 扫描所有.py文件
            for member in tar.getmembers():
                if member.name.endswith('.py'):
                    try:
                        content = tar.extractfile(member).read().decode('utf-8', errors='ignore')
                        issues = detect_patterns_in_code(content, patterns)
                        if issues:
                            all_issues.extend(issues)
                    except:
                        pass

            return package_name, all_issues

    except Exception as e:
        return package_name, None

def main():
    print("="*60)
    print("批量恶意样本检测 - 从tar.gz直接读取")
    print("="*60)

    # 加载危险模式
    with open(PATTERNS_FILE, 'r', encoding='utf-8') as f:
        patterns = json.load(f)

    # 查找所有样本
    all_samples = find_tar_gz_files(SAMPLES_DIR)
    print(f"\n找到 {len(all_samples)} 个样本")

    if len(all_samples) == 0:
        print("[ERROR] No samples found!")
        return

    # 随机选择
    selected = sample(all_samples, min(NUM_SAMPLES, len(all_samples)))
    print(f"随机选择 {len(selected)} 个样本进行检测\n")

    # 统计
    results = {
        'malicious': [],
        'safe': [],
        'errors': []
    }

    # 检测
    for i, tar_gz in enumerate(selected, 1):
        package_name, issues = detect_package(tar_gz, patterns)

        if issues is None:
            print(f"[{i}/{len(selected)}] [ERROR] {package_name}")
            results['errors'].append(package_name)
        elif len(issues) > 0:
            # 统计严重级别
            critical = sum(1 for i in issues if i['severity'] == 'critical')
            high = sum(1 for i in issues if i['severity'] == 'high')

            print(f"[{i}/{len(selected)}] [MALICIOUS] {package_name}")
            print(f"    Issues: {len(issues)} (Critical: {critical}, High: {high})")

            # 显示第一个CRITICAL问题
            critical_issues = [i for i in issues if i['severity'] == 'critical']
            if critical_issues:
                issue = critical_issues[0]
                print(f"    Main: {issue['pattern']}")
                print(f"      {issue['description']}")

            results['malicious'].append({
                'name': package_name,
                'issues': issues,
                'critical': critical,
                'high': high
            })
        else:
            print(f"[{i}/{len(selected)}] [SAFE] {package_name}")
            results['safe'].append(package_name)

    # 汇总
    print("\n" + "="*60)
    print("检测结果汇总")
    print("="*60)
    print(f"总计: {len(selected)} 个样本")
    print(f"检测到恶意: {len(results['malicious'])} 个 ({len(results['malicious'])/len(selected)*100:.1f}%)")
    print(f"标记为安全: {len(results['safe'])} 个 ({len(results['safe'])/len(selected)*100:.1f}%)")
    print(f"检测错误: {len(results['errors'])} 个")

    if results['malicious']:
        print(f"\n恶意样本详情:")
        for pkg in results['malicious']:
            print(f"  - {pkg['name']}: {pkg['issues']} issues")
            print(f"    Critical: {pkg['critical']}, High: {pkg['high']}")

    print("="*60)

    # 保存结果
    report = {
        'total': len(selected),
        'malicious_count': len(results['malicious']),
        'safe_count': len(results['safe']),
        'error_count': len(results['errors']),
        'detection_rate': len(results['malicious']) / len(selected) if len(selected) > 0 else 0,
        'malicious_samples': results['malicious'],
        'safe_samples': results['safe'],
        'errors': results['errors']
    }

    with open('batch_test_report.json', 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print(f"\n[SAVE] 报告已保存到: batch_test_report.json")

if __name__ == '__main__':
    main()
