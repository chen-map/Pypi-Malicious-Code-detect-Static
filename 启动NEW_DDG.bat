@echo off
chcp 65001 >nul
title NEW_DDG - PyPI恶意包检测系统

echo.
echo ========================================
echo NEW_DDG - PyPI恶意包检测系统
echo 基于 CFG + CG + DDG + LLM 的静态分析
echo ========================================
echo.

REM 获取脚本所在目录
cd /d "%~dp0"

echo [信息] 启动GUI界面...
echo.

REM 启动GUI
python new_ddg_gui.py

REM 如果GUI异常退出，暂停以查看错误
if errorlevel 1 (
    echo.
    echo [错误] GUI启动失败！
    echo.
    pause
)
