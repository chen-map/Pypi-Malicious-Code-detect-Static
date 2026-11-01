#!/bin/bash

# 设置变量
PASSWORD="[REDACTED]"
SERVER="wch@<analysis-host>"
PORT="<ssh-port>"
REMOTE_DIR="/disk2/wch/projects/NEW_DDG"
LOCAL_DIR="C:/Users/85864/.claude/NEW_DDG"

echo "📦 准备上传文件到远程服务器..."

# 使用scp上传文件（Windows Git Bash路径转换)
echo "📤 上传 batch_solution_b_v2.py..."
scp -P $PORT "$LOCAL_DIR/batch_solution_b_v2.py" "$SERVER:$REMOTE_DIR/"

echo "📤 上传 enhanced_detector.py..."
scp -P $PORT "$LOCAL_DIR/src/enhanced_detector.py" "$SERVER:$REMOTE_DIR/src/"

echo "📤 上传 v12_subgraph_classifier.py..."
scp -P $PORT "$LOCAL_DIR/SOLUTION_B_VOTING/src/v12_subgraph_classifier.py" "$SERVER:$REMOTE_DIR/SOLUTION_B_VOTING/src/"

echo "📤 上传 v12_subgraph_analyzer_en_v2.txt..."
scp -P $PORT "$LOCAL_DIR/SOLUTION_B_VOTING/prompts/v12_subgraph_analyzer_en_v2.txt" "$SERVER:$REMOTE_DIR/SOLUTION_B_VOTING/prompts/"

echo "✅ 文件上传完成！"
