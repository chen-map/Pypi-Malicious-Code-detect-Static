# 自动部署脚本 - 只需输入一次密码
$PASSWORD = Read-Host "请输入SSH密码 ([REDACTED])" -AsSecureString
$PASSWORD_PLAIN = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PASSWORD))

$SERVER = "wch@<analysis-host>"
$PORT = "<ssh-port>"
$REMOTE_DIR = "/disk2/wch/projects/NEW_DDG"
$LOCAL_DIR = "C:\Users\85864\.claude\NEW_DDG"

Write-Host "================================================"
Write-Host "  NEW_DDG Enhanced Detection Auto Deployment"
Write-Host "================================================"
Write-Host ""

# 使用plink（PuTTY）进行自动化SSH
$plinkPath = "C:\Program Files\PuTTY\plink.exe"
if (-not (Test-Path $plinkPath)) {
    Write-Host "错误: 未找到plink.exe" -ForegroundColor Red
    Write-Host "请安装PuTTY或使用Git Bash手动执行" -ForegroundColor Yellow
    pause
    exit 1
}

$pscpPath = "C:\Program Files\PuTTY\pscp.exe"

Write-Host "[1/4] 上传 batch_solution_b_v2.py..." -ForegroundColor Yellow
& $pscpPath -P $PORT -pw $PASSWORD_PLAIN "$LOCAL_DIR\batch_solution_b_v2.py" "$SERVER`:$REMOTE_DIR/"

Write-Host "[2/4] 上传 enhanced_detector.py..." -ForegroundColor Yellow
& $pscpPath -P $PORT -pw $PASSWORD_PLAIN "$LOCAL_DIR\src\enhanced_detector.py" "$SERVER`:$REMOTE_DIR/src/"

Write-Host "[3/4] 上传 v12_subgraph_classifier.py..." -ForegroundColor Yellow
& $pscpPath -P $PORT -pw $PASSWORD_PLAIN "$LOCAL_DIR\SOLUTION_B_VOTING\src\v12_subgraph_classifier.py" "$SERVER`:$REMOTE_DIR/SOLUTION_B_VOTING/src/"

Write-Host "[4/4] 上传 v12_subgraph_analyzer_en_v2.txt..." -ForegroundColor Yellow
& $pscpPath -P $PORT -pw $PASSWORD_PLAIN "$LOCAL_DIR\SOLUTION_B_VOTING\prompts\v12_subgraph_analyzer_en_v2.txt" "$SERVER`:$REMOTE_DIR/SOLUTION_B_VOTING/prompts/"

Write-Host ""
Write-Host "================================================"
Write-Host "  文件上传完成！正在重启任务..."
Write-Host "================================================"
Write-Host ""

# 重启任务
$restartCmd = @"
cd $REMOTE_DIR && pkill -f 'batch_solution_b_v2.py' && sleep 2 && export PYTHONPATH=/disk2/wch/lib/python3.8/site-packages && nohup python3 batch_solution_b_v2.py /disk2/wch/data/pypi_malregistry/linux/0-50 --llm glm --api-key 0aab67b249814048b4e78ebf238b83a4.OMNLhTOBhvJhWrpp --count 255 --skip-rule-scoring > output_test_m_0-50_fixed.log 2>&1 & sleep 1 && ps aux | grep 'batch_solution' | grep -v grep
"@

& $plinkPath -P $PORT -pw $PASSWORD_PLAIN $SERVER $restartCmd

Write-Host ""
Write-Host "================================================"
Write-Host "  部署完成！"
Write-Host "================================================"
Write-Host ""
Write-Host "监控日志: ssh -p $PORT $SERVER"
Write-Host "查看日志: tail -f $REMOTE_DIR/output_test_m_0-50_fixed.log"
Write-Host ""
pause
