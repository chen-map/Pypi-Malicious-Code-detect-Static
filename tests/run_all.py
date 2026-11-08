# -*- coding: utf-8 -*-
"""运行全部回归测试"""
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).parent

TESTS = [
    'test_enhanced_detector.py',
    'test_voting.py',
    'test_obfuscation.py',
    'test_partitioner.py',
    'test_pipeline.py',
    'test_graph_kernel.py',
    'test_llm_hardening.py',
    'test_cross_file_taint.py',
    'test_escalation.py',
    'test_escalation_e2e.py',
    'test_graph_digest.py',
    'test_package_graph.py',
    'test_sso_extractor.py',
    'test_two_stage.py',
    'test_cross_scope.py',
    'test_benign_context.py',
    'test_artifact_scanner.py',
]


def main():
    failed = []
    for test in TESTS:
        print(f"\n{'='*60}\n运行 {test}\n{'='*60}")
        proc = subprocess.run(
            [sys.executable, str(HERE / test)],
            capture_output=True, text=True, encoding='utf-8', errors='replace'
        )
        # 只打印每个测试的最后几行与失败信息
        lines = (proc.stdout or '').strip().splitlines()
        for line in lines[-6:]:
            print(f"  {line}")
        if proc.returncode != 0:
            failed.append(test)
            print(f"  [FAIL] stderr: {(proc.stderr or '')[-800:]}")
        else:
            print(f"  [PASS] {test}")

    print(f"\n{'='*60}")
    if failed:
        print(f"[结果] {len(failed)}/{len(TESTS)} 个测试文件失败: {failed}")
        sys.exit(1)
    print(f"[结果] 全部 {len(TESTS)} 个测试文件通过")


if __name__ == '__main__':
    main()
