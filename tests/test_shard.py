# -*- coding: utf-8 -*-
"""分片（--shard-index/--shard-count）正确性

多进程并行跑同一份抽样时必须保证：互斥 + 并集完整 + 抽样可复现。
"""
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from batch_solution_b_v2 import shard_partition  # noqa: E402

PASS = FAIL = 0


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ✓ {name}")
    else:
        FAIL += 1
        print(f"  ✗ {name}")


def main():
    print("[1] 基本切分")
    items = list(range(10))
    check("4 片并集 = 全集", sorted(sum((shard_partition(items, i, 4)
                                        for i in range(4)), [])) == items)
    check("4 片互斥", len({x for i in range(4)
                          for x in shard_partition(items, i, 4)}) == 10)
    check("片大小差 ≤1", max(len(shard_partition(items, i, 4))
                             for i in range(4))
          - min(len(shard_partition(items, i, 4)) for i in range(4)) <= 1)
    check("空输入不炸", shard_partition([], 2, 4) == [])

    print("[2] 退化情形")
    check("shard_count=1 原样返回", shard_partition(items, 0, 1) == items)
    check("shard_count>len 时有的片为空",
          shard_partition([1, 2], 5, 8) == [])
    check("元素少时仍互斥",
          sorted(shard_partition([1, 2, 3], 0, 5)
                 + shard_partition([1, 2, 3], 1, 5)
                 + shard_partition([1, 2, 3], 2, 5)
                 + shard_partition([1, 2, 3], 3, 5)
                 + shard_partition([1, 2, 3], 4, 5)) == [1, 2, 3])

    print("[3] 越界报错")
    try:
        shard_partition(items, 4, 4)
        check("index==count 应抛错", False)
    except ValueError:
        check("index==count 抛 ValueError", True)
    try:
        shard_partition(items, -1, 4)
        check("负 index 应抛错", False)
    except ValueError:
        check("负 index 抛 ValueError", True)

    print("[4] 与真实抽样组合可复现")
    pool = [(f'pkg{i}.tar.gz', 'file') for i in range(2000)]

    def sample_and_shard(shard):
        random.seed(20261109)
        picked = random.sample(pool, 1000)
        return shard_partition(picked, shard, 4)

    shards = [sample_and_shard(i) for i in range(4)]
    union = [x for s in shards for x in s]
    check("1000 包 4 片并集 = 1000", len(union) == 1000)
    check("无重复", len(set(x[0] for x in union)) == 1000)
    check("同片两次调用结果相同", shards[0] == sample_and_shard(0))
    check("每片数量都是 250", [len(s) for s in shards] == [250] * 4)

    print(f"\n分片: PASS={PASS} FAIL={FAIL}")
    return 0 if FAIL == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
