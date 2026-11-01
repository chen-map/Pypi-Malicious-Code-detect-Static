# -*- coding: utf-8 -*-
"""回归测试:混淆检测(短变量名比例/re.escape/收紧后的子串)"""
import sys
import tempfile
from pathlib import Path

NEW_DDG = Path(__file__).parent.parent
sys.path.insert(0, str(NEW_DDG))

from batch_solution_b_v2 import BatchAnalyzerV20Voting


def make_analyzer():
    return BatchAnalyzerV20Voting(
        tarfile_dir=str(NEW_DDG), api_key='dummy', count=1,
        extract_base=str(Path(tempfile.mkdtemp(prefix="obf_test_")) / 'out')
    )


def make_pkg(files: dict) -> Path:
    d = Path(tempfile.mkdtemp(prefix="obf_pkg_"))
    for name, content in files.items():
        p = d / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return d


def test_short_variable_ratio():
    """修复回归:普通变量名混合的代码,短变量比例不再恒等于 1.0"""
    analyzer = make_analyzer()
    pkg = make_pkg({'normal.py': "x = 1\nvalue = 2\nresult = compute(value)\ntotal_count = 3\n"})
    result = analyzer._detect_obfuscation(str(pkg), {})
    ratio = result['indicators'].get('short_variable_names', 0.0)
    assert 0.0 < ratio <= 0.5, f"4个变量只有1个短名,比例应≈0.25, 实际 {ratio}"
    assert ratio < 1.0, "短变量比例恒1.0的bug回归了"
    print(f"[OK] 短变量名比例 = {ratio:.2f}(原bug恒1.0)")


def test_exec_fernet_still_detected():
    """真混淆(exec+Fernet解密)仍应检出"""
    analyzer = make_analyzer()
    pkg = make_pkg({'bad.py': "from cryptography.fernet import Fernet\n"
                              "f = Fernet('key')\n"
                              "exec(f.decrypt(b'gAAAAA'))\n"})
    result = analyzer._detect_obfuscation(str(pkg), {})
    assert result['is_obfuscated'], f"exec(Fernet) 应判混淆: score={result['obfuscation_score']}"
    print(f"[OK] exec+Fernet 混淆检出 (score={result['obfuscation_score']:.2f})")


def test_pickle_substring_tightened():
    """修复回归:'pickleball'/'description' 等普通词不再触发 payload 检测"""
    analyzer = make_analyzer()
    pkg = make_pkg({'README_like.py': "# we play pickleball every description day\n"
                                      "words = 'pickleball sports description marshal loads of fun'\n"
                                      "text = words.replace('pickleball', 'sport')\n"})
    result = analyzer._detect_obfuscation(str(pkg), {})
    assert not result['indicators'].get('pickle_payload'), \
        "普通单词 pickleball 不应触发 pickle payload"
    assert not result['indicators'].get('marshal_bytecode'), \
        "普通单词 marshal 不应触发 marshal bytecode"
    print("[OK] pickle/marshal 子串误报已收紧")


def test_regex_escape_no_crash():
    """修复回归:内容里含 base64 串(带 +/)时检测不抛异常"""
    analyzer = make_analyzer()
    pkg = make_pkg({'b64.py': "data = 'abcdefghij+/ABCDEFGHIJ+/0123456789+/'\n"
                              "print(len(data))\n"})
    try:
        result = analyzer._detect_obfuscation(str(pkg), {})
        assert isinstance(result, dict)
    except Exception as e:
        raise AssertionError(f"含+/的内容不应导致正则崩溃: {e}")
    print("[OK] 含正则元字符内容不再崩溃")


def test_benign_dense_data_not_obfuscated():
    """核心验收(真实良性库驱动):数据密集的良性代码不得判 OBFUSCATED

    复现 pycryptodome/bs4/idna 的误报特征：\\xHH 转义、re.compile、
    crypto 域导入、CJK 数据、Base32 表、Unicode 转义——但包级密度正常。
    真实良性库实测：包级 hex 密度最高仅 0.33/KB。
    """
    analyzer = make_analyzer()

    # 数据表文件：40 行 hex 常量(长变量名)，共 320 个转义
    hex_table = "\n".join(
        f'TABLE_ENTRY_{i:02d} = b"\\x00\\x01\\x02\\x03\\x04\\x05\\x06\\x07"' for i in range(40)
    )
    # 正常代码填充，使包级规模接近真实库(总 ~50KB)
    filler_funcs = "\n\n".join(
        f"def compute_metric_{i}(input_value, scale_factor=1.0):\n"
        f"    \"\"\"Compute metric {i} with configurable scaling.\"\"\"\n"
        f"    intermediate = input_value * scale_factor\n"
        f"    result_value = intermediate + {i}\n"
        f"    return result_value\n"
        for i in range(200)
    )

    pkg = make_pkg({
        'tables.py': hex_table,
        'core.py': (
            "import re\n"
            "import codecs\n"
            "from Crypto.Cipher import AES\n"
            "\n"
            "PATTERN = re.compile(r'\\d+')\n"
            "# 中文注释：编码表说明\n"
            "CJK_TABLE = '中文数据表内容用于字符集映射'\n"
            "BASE32_VECTOR = 'MZXW6YTBOI======MZXW6YTBOI======'\n"
            "UNICODE_SAMPLE = '\\u4e00\\u4e8c\\u4e09'\n\n"
            + filler_funcs[:25000]
        ),
        'utils.py': (filler_funcs[:25000] + "\n"),
    })

    result = analyzer._detect_obfuscation(str(pkg), {})
    assert not result['is_obfuscated'], \
        f"良性数据密集代码不应判混淆: score={result['obfuscation_score']} " \
        f"indicators={ {k:v for k,v in result['indicators'].items() if v} }"
    print(f"[OK] 良性数据密集代码不误判 (score={result['obfuscation_score']:.2f})")


def test_dense_hex_payload_still_detected():
    """真混淆:高密度 hex 载荷(20KB 内数千转义)仍应得分"""
    analyzer = make_analyzer()
    payload = "exec(b'" + "\\x41\\x42\\x43\\x44" * 3000 + "')"
    pkg = make_pkg({'payload.py': payload})
    result = analyzer._detect_obfuscation(str(pkg), {})
    assert result['indicators']['hex_strings'] > 0, "高密度 hex 载荷应被识别"
    print(f"[OK] 高密度hex载荷仍识别 (score={result['obfuscation_score']:.2f})")


if __name__ == '__main__':
    test_short_variable_ratio()
    test_exec_fernet_still_detected()
    test_pickle_substring_tightened()
    test_regex_escape_no_crash()
    test_benign_dense_data_not_obfuscated()
    test_dense_hex_payload_still_detected()
    print("\n===== test_obfuscation 全部通过 =====")
