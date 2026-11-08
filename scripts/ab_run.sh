#!/usr/bin/env bash
# 100 恶意 + 100 良性 三档消融（A 基线 / B 跨作用域 / C 全开）
#
# 用法:
#   export API_KEY=xxxx
#   bash scripts/ab_run.sh <repo_dir> <mal_dir> <ben_dir> [out_dir]
#
# 可选环境变量:
#   NW=4            并行子图 LLM 线程数
#   OUT=/disk2/wch/ab100
#   BASE_FLAGS="--verify-pypi"   额外基础开关（默认空，纯离线图+LLM）
set -uo pipefail

REPO=${1:?usage: ab_run.sh <repo> <mal_dir> <ben_dir> [out]}
MAL=${2:?malicious corpus dir}
BEN=${3:?benign corpus dir}
OUT=${4:-${OUT:-/disk2/wch/ab100}}
NW=${NW:-4}
BASE_FLAGS=${BASE_FLAGS:-}
CFGS=${CFGS:-"A B C"}   # 例: CFGS="C" 只跑全开，先拿信号
PY=${PY:-python3}

if [ -z "${API_KEY:-}" ]; then
  echo "ERROR: export API_KEY first" >&2
  exit 1
fi

mkdir -p "$OUT"
cd "$REPO" || exit 1

run_one () {           # $1=cfg  $2=corpus  $3=tag  rest=extra flags
  local cfg=$1 corpus=$2 tag=$3; shift 3
  local extra=("$@")
  local base="$OUT/pkgs_${cfg}_${tag}"
  if [ -f "$OUT/results_${cfg}_${tag}.json" ]; then
    echo "[skip] $cfg/$tag 已有结果（删除 $OUT/results_${cfg}_${tag}.json 可重跑）"
    return 0
  fi
  echo ""
  echo "########## [$cfg/$tag] $(basename "$corpus") ##########"
  rm -rf "$base"
  "$PY" batch_solution_b_v2.py \
      --api-key "$API_KEY" \
      --count 100 \
      --extract-base "$base" \
      --parallel-workers "$NW" \
      $BASE_FLAGS \
      "${extra[@]}" 2>&1 | tee "$OUT/run_${cfg}_${tag}.log" | tail -6

  local latest
  latest=$(ls -t output/results/batch_v20_voting_results_*.json 2>/dev/null | head -1)
  if [ -n "$latest" ]; then
    cp "$latest" "$OUT/results_${cfg}_${tag}.json"
  else
    echo "WARN: no results json for $cfg/$tag" >&2
  fi
}

for cfg in $CFGS; do
  case $cfg in
    A) EXTRA=(--no-cross-scope --no-block-scan);;
    B) EXTRA=(--no-block-scan);;
    C) EXTRA=();;
  esac
  run_one "$cfg" "$MAL" mal "${EXTRA[@]}"
  run_one "$cfg" "$BEN" ben "${EXTRA[@]}"
done

echo ""
echo "================ SUMMARY ================"
for cfg in $CFGS; do
  for tag in mal ben; do
    f="$OUT/results_${cfg}_${tag}.json"
    [ -f "$f" ] && "$PY" scripts/ab_summary.py "$f" \
        --label "config $cfg / $tag" --kind "$tag"
  done
done
echo ""
echo "结果文件: $OUT/results_{A,B,C}_{mal,ben}.json"
echo "日志:     $OUT/run_{A,B,C}_{mal,ben}.log"
