# 恶意代码测试模式

这是5个常见的恶意代码模式，用于测试DDG分析器和桩程序生成器。

## 测试用例列表

### 01 - 命令注入 (Command Injection)
- **恶意行为**: `os.system(user_input)` - 执行用户提供的命令
- **危险输入**: `sys.argv[1]` - 命令行参数
- **测试命令**:
  ```bash
  python main.py test_patterns/01_command_injection
  ```

### 02 - 文件加密 (File Encryption/Ransomware)
- **恶意行为**: 遍历目录并修改文件内容
- **危险输入**: `sys.argv[1]` - 目标目录路径
- **测试命令**:
  ```bash
  python main.py test_patterns/02_file_encryption
  ```

### 03 - 数据泄露 (Data Exfiltration)
- **恶意行为**: 收集系统信息并发送到远程服务器
- **危险输入**: `sys.argv[1]` - 服务器URL
- **测试命令**:
  ```bash
  python main.py test_patterns/03_data_exfiltration
  ```

### 04 - 代码执行 (Code Execution/Webshell)
- **恶意行为**: `subprocess.run()` 和 `eval()` 执行任意代码
- **危险输入**: `sys.argv[2]` - 要执行的命令/代码
- **测试命令**:
  ```bash
  python main.py test_patterns/04_code_execution
  ```

### 05 - 持久化 (Persistence)
- **恶意行为**: 修改注册表或创建计划任务
- **危险输入**: 无（模块级代码）
- **测试命令**:
  ```bash
  python main.py test_patterns/05_persistence
  ```

## 测试流程

对每个测试用例：

1. **运行DDG分析**:
   ```bash
   python main.py test_patterns/XX_malware_name
   ```

2. **检查生成的桩程序**:
   - 位置: `test_patterns/XX_malware_name/.ddg_output/sub_ddgs/XXX_*/test_ddg_results.py`
   - 查看是否包含真正的函数调用（而不是exec）

3. **执行桩程序**:
   ```bash
   python test_patterns/XX_malware_name/.ddg_output/sub_ddgs/XXX_*/test_ddg_results.py
   ```

4. **验证结果**:
   - ✅ 桩程序应该调用原包的恶意函数
   - ✅ 应该看到 `result = malware.function_name(...)` 这样的代码
   - ✅ 执行时应该创建测试文件或显示执行结果

## 预期结果

每个测试用例的桩程序应该：
- ✅ 生成 `import malware` 语句
- ✅ 生成真正的函数调用，如 `malware.execute_user_command(test_argv)`
- ❌ **不应该**只是复制粘贴原代码或使用exec()
