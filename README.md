# NEW_DDG V20 - 最终版本

## 核心流程

```
DDG分割（3个子图）
    ↓
V12提取信息（12个特征类）
    ↓
生成JSON（nodes.json + edges.json）
    ↓
合并所有子图信息
    ↓
生成统一prompt（不截断、不限制）
    ↓
JSON + prompt → LLM
    ↓
桩程序（100%恶意行为执行）
```

## 使用方法

### 1. 分析单个包并生成桩程序

```bash
python test_v20_all_subgraphs.py
```

### 2. 批量分析

```bash
python batch2_analyze_tar.py <目录> --llm glm --count 10 --api-key YOUR_KEY
```

## 核心文件

### 输入
- `src/` - 核心算法代码
- `config/` - 配置文件
- `batch2_analyze_tar.py` - 批量分析脚本

### 输出
- `generated_stub_v20.py` - V20生成的桩程序（示例）
- `llm_prompt_v20.txt` - V20的prompt（示例）
- `test_v16_subgraph.json` - V12提取的JSON（示例）

### 备份
- `backup_<timestamp>/` - 原始系统备份
- `archive_old_tests/` - 旧版本测试文件（V15-V19）

## V20改进点

1. ✅ 使用所有3个子图的JSON（合并）
2. ✅ 不截断代码（完整包含）
3. ✅ 不限制token数量
4. ✅ 100%恶意行为执行成功率

## 执行结果示例

```
[SUCCESS] setup() executed
[SUCCESS] eval executed
[SUCCESS] second eval executed
[SUCCESS] test() executed
```

成功率：4/4（100%）
