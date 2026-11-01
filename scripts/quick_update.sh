#!/bin/bash
# 快速部署脚本 - Windows Git Bash

PASSWORD="[REDACTED]"
SERVER="wch@<analysis-host>"
PORT="<ssh-port>"
REMOTE_DIR="/disk2/wch/projects/NEW_DDG"

echo "================================================"
echo "  NEW_DDG Enhanced Detection Deployment"
echo "================================================"
echo ""

cd "C:/Users/85864/.claude/NEW_DDG"

echo "[1/5] Stopping remote tasks..."
ssh -p $PORT $SERVER "pkill -f 'batch_solution_b_v2.py'"
sleep 2

echo "[2/5] Uploading batch_solution_b_v2.py..."
scp -P $PORT batch_solution_b_v2.py $SERVER:$REMOTE_DIR/

echo "[3/5] Uploading enhanced_detector.py..."
scp -P $PORT src/enhanced_detector.py $SERVER:$REMOTE_DIR/src/

echo "[4/5] Uploading v12_subgraph_classifier.py..."
scp -P $PORT SOLUTION_B_VOTING/src/v12_subgraph_classifier.py $SERVER:$REMOTE_DIR/SOLUTION_B_VOTING/src/

echo "[5/5] Uploading v12_subgraph_analyzer_en_v2.txt..."
scp -P $PORT SOLUTION_B_VOTING/prompts/v12_subgraph_analyzer_en_v2.txt $SERVER:$REMOTE_DIR/SOLUTION_B_VOTING/prompts/

echo ""
echo "================================================"
echo "Upload complete! Restarting tasks..."
echo "================================================"
echo ""

ssh -p $PORT $SERVER << 'ENDSSH'
cd /disk2/wch/projects/NEW_DDG
export PYTHONPATH=/disk2/wch/lib/python3.8/site-packages

# Task 1: 3000 packages
nohup python3 batch_solution_b_v2.py /disk2/wch/data/pypi_cache \
  --llm glm \
  --api-key 0aab67b249814048b4e78ebf238b83a4.OMNLhTOBhvJhWrpp \
  --count 3000 \
  --skip-rule-scoring \
  > output_test_3000_fixed.log 2>&1 &

# Task 2: 255 malicious packages
nohup python3 batch_solution_b_v2.py /disk2/wch/data/pypi_malregistry/linux/0-50 \
  --llm glm \
  --api-key 0aab67b249814048b4e78ebf238b83a4.OMNLhTOBhvJhWrpp \
  --count 255 \
  --skip-rule-scoring \
  > output_test_m_0-50_fixed.log 2>&1 &

echo "Tasks started!"
ps aux | grep 'batch_solution_b_v2.py' | grep -v grep
ENDSSH

echo ""
echo "================================================"
echo "Deployment Complete!"
echo "================================================"
echo "Monitor with:"
echo "  ssh -p <ssh-port> wch@<analysis-host>"
echo "  tail -f /disk2/wch/projects/NEW_DDG/output_test_m_0-50_fixed.log"
echo ""
