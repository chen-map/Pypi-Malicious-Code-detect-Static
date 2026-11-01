# NEW_DDG 增强检测器配置

## 概述

增强检测器修复了NEW_DDG的三个主要检测盲点：
1. **setup.py安装钩子恶意代码**
2. **依赖关系攻击**（Typosquatting）
3. **元数据可疑性**（钓鱼包名、可疑作者）

## 威胁等级体系

### Critical（10分）
**触发条件**：
- setup.py install钩子包含`exec`/`eval`/`compile`
- setup.py install钩子包含`os.system`/`subprocess.*shell=True`
- 包名包含明显的恶意词：getshell/backdoor/hack/exploit/malware/trojan/virus

**影响**：立即判定为MALICIOUS，跳过DDG+LLM分析

**误报率**：<1%

### High（7分）
**触发条件**：
- 包名包含inject/pwn/attack/payload/shell/rootkit
- 包名包含bitcoin/crypto/mining/steal/credential/password
- Typosquatting：reqeusts/numpyy/pandass等常见包的拼写错误

**影响**：立即判定为MALICIOUS，跳过DDG+LLM分析

**误报率**：<5%

### Medium（4分）
**触发条件**：
- 包名模仿流行包：xxx-utils/xxx-tools/xxx-lib
- 可疑依赖：依赖包名不常见或可疑
- 匿名作者：author为test/anonymous/unknown/none
- URL使用短链接服务：bit.ly/tinyurl/goo.gl

**影响**：记录在enhanced_detection字段中，不改变最终判定

**误报率**：~10-20%

### Low（1分）
**触发条件**：
- 作者使用仓库URL作为作者名
- Email使用临时邮箱服务
- 混淆检测发现可疑导入库

**影响**：记录在enhanced_detection字段中，不改变最终判定

**误报率**：~20-30%

## 配置选项

### 1. 调整自动判定阈值

如果想要更保守或更激进的检测，可以修改`batch_solution_b_v2.py`第194行：

```python
# 当前配置：只有critical/high才自动判定为恶意
if enhanced_detection_result['overall_threat_level'] in ['critical', 'high']:
    # 立即判定为恶意

# 修改为更保守：只有critical才自动判定
if enhanced_detection_result['overall_threat_level'] in ['critical']:
    # 立即判定为恶意

# 修改为更激进：critical/high/medium都自动判定
if enhanced_detection_result['overall_threat_level'] in ['critical', 'high', 'medium']:
    # 立即判定为恶意
```

### 2. 禁用增强检测

如果不需要增强检测，可以注释掉相关代码：

```python
# batch_solution_b_v2.py 第190-217行
# 注释掉以下代码：
# print(f"[Step 4.5/6] 增强检测（setup.py/依赖/元数据）...")
# enhanced_detection_result = self.enhanced_detector.analyze_package(package_dir)
# if enhanced_detection_result['overall_threat_level'] in ['critical', 'high']:
#     ...
```

### 3. 自定义检测规则

编辑`src/enhanced_detector.py`中的模式：

```python
# 第40-60行：添加新的包名检测模式
self.suspicious_name_patterns['custom_pattern'] = [
    r'your-custom-pattern',
]

# 第30-40行：添加新的setup.py危险模式
self.dangerous_setup_patterns['custom_hook'] = [
    r'your-custom-pattern',
]
```

## 输出示例

### Case 1: Critical威胁（立即判定为恶意）
```json
{
    "package_name": "getshell-utils-1.0.0",
    "final_category": "MALICIOUS",
    "final_risk_score": 0.95,
    "final_confidence": 0.85,
    "detection_method": "enhanced_detection",
    "enhanced_threat_level": "critical",
    "threat_details": {
        "metadata_analysis": {
            "has_threats": true,
            "threats": [
                {
                    "type": "suspicious_package_name",
                    "pattern_type": "obvious_malicious",
                    "severity": "high"
                }
            ]
        }
    }
}
```

### Case 2: Low威胁（记录在结果中，不影响判定）
```json
{
    "package_name": "maratlib-0.5",
    "final_category": "BENIGN",  // LLM判定仍为BENIGN
    "final_risk_score": 0.10,
    "enhanced_detection": {
        "threat_level": "low",  // 记录low威胁
        "threats_found": 1,
        "metadata_threats": true  // 例如：作者为test
    }
}
```

## 性能影响

- **额外时间开销**：每个包 +0.5-2秒
- **内存开销**：可忽略不计
- **整体速度**：几乎无影响（远小于DDG构建时间）

## 建议

**生产环境使用**：
- ✅ 保持当前配置（critical/high自动判定）
- ✅ 定期review medium/low威胁的包

**研发/测试环境**：
- ✅ 可以设置为更激进（包含medium）
- ✅ 用于收集更多可疑样本

## 贡献

如果发现新的误报案例，请更新以下文件：
1. `src/enhanced_detector.py`：调整检测模式
2. `docs/ENHANCED_DETECTION_CONFIG.md`：更新文档

---

**最后更新**: 2026-06-12
**作者**: NEW_DDG Team
