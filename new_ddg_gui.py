#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NEW_DDG PyPI恶意包检测系统 - GUI界面
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import os
import sys
import subprocess
import platform
from pathlib import Path
import threading


class NEWDDGGUI:
    """NEW_DDG GUI界面"""

    def __init__(self, root):
        self.root = root
        self.root.title("NEW_DDG - PyPI恶意包检测系统")
        self.root.geometry("900x750")

        # 配置变量
        self.test_dir = tk.StringVar()
        self.extract_base = tk.StringVar()
        self.llm_model = tk.StringVar(value="glm")
        self.api_key = tk.StringVar()
        self.package_count = tk.StringVar(value="100")
        self.skip_rule_scoring = tk.BooleanVar(value=True)

        self.process = None
        self.analysis_running = False

        self.create_widgets()

    def create_widgets(self):
        """创建界面组件"""

        # 标题
        title_label = tk.Label(
            self.root,
            text="NEW_DDG - PyPI恶意包检测系统",
            font=("Arial", 18, "bold"),
            fg="#2c3e50"
        )
        title_label.pack(pady=10)

        # 副标题
        subtitle_label = tk.Label(
            self.root,
            text="基于 CFG + CG + DDG + LLM 的静态分析系统",
            font=("Arial", 12),
            fg="#7f8c8d"
        )
        subtitle_label.pack(pady=5)

        # 创建主框架
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # ========== 配置区域 ==========
        config_frame = ttk.LabelFrame(main_frame, text="配置选项", padding="10")
        config_frame.pack(fill=tk.X, pady=10)

        # 测试目录
        ttk.Label(config_frame, text="测试目录 (包含待分析的PyPI包):").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.test_dir_entry = ttk.Entry(config_frame, textvariable=self.test_dir, width=60)
        self.test_dir_entry.grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(config_frame, text="浏览", command=self.browse_test_dir).grid(row=0, column=2, pady=5)

        # 解压目录
        ttk.Label(config_frame, text="解压目录 (包解压位置):").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.extract_base_entry = ttk.Entry(config_frame, textvariable=self.extract_base, width=60)
        self.extract_base_entry.grid(row=1, column=1, padx=5, pady=5)
        ttk.Button(config_frame, text="浏览", command=self.browse_extract_base).grid(row=1, column=2, pady=5)

        # LLM模型
        ttk.Label(config_frame, text="LLM模型:").grid(row=2, column=0, sticky=tk.W, pady=5)
        llm_frame = ttk.Frame(config_frame)
        llm_frame.grid(row=2, column=1, sticky=tk.W, padx=5, pady=5)

        ttk.Radiobutton(llm_frame, text="GLM (智谱AI)", variable=self.llm_model, value="glm").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(llm_frame, text="Claude (Anthropic)", variable=self.llm_model, value="claude").pack(side=tk.LEFT, padx=5)

        # API密钥
        ttk.Label(config_frame, text="API密钥:").grid(row=3, column=0, sticky=tk.W, pady=5)
        self.api_key_entry = ttk.Entry(config_frame, textvariable=self.api_key, width=60, show="*")
        self.api_key_entry.grid(row=3, column=1, padx=5, pady=5)

        # 跳过规则评分
        ttk.Label(config_frame, text="分析模式:").grid(row=4, column=0, sticky=tk.W, pady=5)
        mode_frame = ttk.Frame(config_frame)
        mode_frame.grid(row=4, column=1, sticky=tk.W, padx=5, pady=5)

        ttk.Checkbutton(
            mode_frame,
            text="跳过规则评分，直接使用LLM分析子图",
            variable=self.skip_rule_scoring
        ).pack(side=tk.LEFT, padx=5)

        # 处理包数量
        ttk.Label(config_frame, text="处理包数量:").grid(row=5, column=0, sticky=tk.W, pady=5)
        self.package_count_entry = ttk.Entry(config_frame, textvariable=self.package_count, width=20)
        self.package_count_entry.grid(row=5, column=1, sticky=tk.W, padx=5, pady=5)

        # ========== 操作按钮 ==========
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=20)

        # 启动分析按钮
        self.start_button = ttk.Button(
            button_frame,
            text="🚀 开始分析",
            command=self.start_analysis,
            style="Accent.TButton"
        )
        self.start_button.pack(side=tk.LEFT, padx=10, ipadx=20, ipady=10)

        # 停止按钮
        self.stop_button = ttk.Button(
            button_frame,
            text="⏹ 停止分析",
            command=self.stop_analysis,
            state=tk.DISABLED
        )
        self.stop_button.pack(side=tk.LEFT, padx=10, ipadx=20, ipady=10)

        # 清空日志按钮
        ttk.Button(
            button_frame,
            text="🗑 清空日志",
            command=self.clear_log
        ).pack(side=tk.LEFT, padx=10, ipadx=20, ipady=10)

        # ========== 进度条 ==========
        self.progress = ttk.Progressbar(
            main_frame,
            mode='indeterminate',
            length=400
        )
        self.progress.pack(fill=tk.X, pady=10)

        # ========== 日志输出 ==========
        log_label = ttk.Label(main_frame, text="分析日志:")
        log_label.pack(anchor=tk.W, pady=(10, 5))

        self.log_text = scrolledtext.ScrolledText(
            main_frame,
            width=100,
            height=20,
            font=("Consolas", 9)
        )
        self.log_text.pack(fill=tk.BOTH, expand=True, pady=5)

        # 配置日志颜色标签
        self.log_text.tag_config("INFO", foreground="#0066cc")
        self.log_text.tag_config("SUCCESS", foreground="#009900", font=("Consolas", 9, "bold"))
        self.log_text.tag_config("ERROR", foreground="#cc0000", font=("Consolas", 9, "bold"))
        self.log_text.tag_config("WARNING", foreground="#cc6600")

        # ========== 状态栏 ==========
        status_frame = ttk.Frame(main_frame)
        status_frame.pack(fill=tk.X, pady=(10, 0))

        self.status_label = ttk.Label(
            status_frame,
            text="就绪",
            relief=tk.SUNKEN,
            anchor=tk.W
        )
        self.status_label.pack(fill=tk.X)

        # 初始化默认路径
        self._init_default_paths()

    def _init_default_paths(self):
        """初始化默认路径"""
        # 获取脚本所在目录
        script_dir = Path(__file__).parent

        # 默认测试目录
        default_test_dir = script_dir / "batch_1"
        if default_test_dir.exists():
            self.test_dir.set(str(default_test_dir))

        # 默认解压目录
        default_extract_dir = script_dir / "output"
        if not default_extract_dir.exists():
            default_extract_dir.mkdir(parents=True, exist_ok=True)
        self.extract_base.set(str(default_extract_dir))

    def browse_test_dir(self):
        """浏览测试目录"""
        directory = filedialog.askdirectory(
            title="选择测试目录",
            initialdir=self.test_dir.get()
        )
        if directory:
            self.test_dir.set(directory)
            self.log(f"[INFO] 测试目录设置为: {directory}", "INFO")

    def browse_extract_base(self):
        """浏览解压目录"""
        directory = filedialog.askdirectory(
            title="选择解压目录",
            initialdir=self.extract_base.get()
        )
        if directory:
            self.extract_base.set(directory)
            self.log(f"[INFO] 解压目录设置为: {directory}", "INFO")

    def validate_inputs(self):
        """验证输入参数"""
        errors = []

        # 检查测试目录
        test_dir = self.test_dir.get().strip()
        if not test_dir:
            errors.append("请选择测试目录")
        elif not os.path.exists(test_dir):
            errors.append(f"测试目录不存在: {test_dir}")
        elif not os.path.isdir(test_dir):
            errors.append(f"测试路径不是目录: {test_dir}")

        # 检查解压目录
        extract_base = self.extract_base.get().strip()
        if not extract_base:
            errors.append("请选择解压目录")
        else:
            # 尝试创建解压目录
            try:
                os.makedirs(extract_base, exist_ok=True)
            except Exception as e:
                errors.append(f"无法创建解压目录: {e}")

        # 检查API密钥
        api_key = self.api_key.get().strip()
        if not api_key:
            errors.append("请输入API密钥")

        # 检查包数量
        try:
            count = int(self.package_count.get().strip())
            if count <= 0:
                errors.append("处理包数量必须大于0")
        except ValueError:
            errors.append("处理包数量必须是整数")

        return errors

    def start_analysis(self):
        """启动分析"""
        # 验证输入
        errors = self.validate_inputs()
        if errors:
            error_msg = "\n".join(errors)
            messagebox.showerror("输入错误", f"请修正以下错误:\n\n{error_msg}")
            return

        # 确认开始
        test_dir = self.test_dir.get().strip()
        package_count = self.package_count.get().strip()
        skip_rule = "是" if self.skip_rule_scoring.get() else "否"
        confirm = messagebox.askyesno(
            "确认开始",
            f"即将开始分析:\n\n"
            f"测试目录: {test_dir}\n"
            f"解压目录: {self.extract_base.get().strip()}\n"
            f"LLM模型: {self.llm_model.get().upper()}\n"
            f"跳过规则评分: {skip_rule}\n"
            f"处理数量: {package_count}\n\n"
            f"是否继续?"
        )

        if not confirm:
            return

        # 清空日志并开始
        self.clear_log()
        self.log("=" * 80, "INFO")
        self.log("NEW_DDG 分析启动", "SUCCESS")
        self.log("=" * 80, "INFO")
        self.log(f"测试目录: {test_dir}", "INFO")
        self.log(f"解压目录: {self.extract_base.get().strip()}", "INFO")
        self.log(f"LLM模型: {self.llm_model.get().upper()}", "INFO")
        self.log(f"跳过规则评分: {'是' if self.skip_rule_scoring.get() else '否'}", "INFO")
        self.log(f"处理数量: {package_count}", "INFO")
        self.log("=" * 80, "INFO")
        self.log("", "INFO")

        # 在新线程中运行分析
        self.analysis_running = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.progress.start()

        thread = threading.Thread(target=self._run_analysis)
        thread.daemon = True
        thread.start()

    def _run_analysis(self):
        """在后台线程中运行分析"""
        try:
            # 构建命令
            script_path = Path(__file__).parent / "batch_solution_b_v2.py"

            cmd = [
                sys.executable,
                "-u",  # 无缓冲模式，确保实时输出
                str(script_path),
                self.test_dir.get().strip(),
                "--extract-base", self.extract_base.get().strip(),
                "--llm", self.llm_model.get(),
                "--api-key", self.api_key.get().strip(),
                "--count", self.package_count.get().strip()
            ]

            # 添加skip-rule-scoring参数（如果选中）
            if self.skip_rule_scoring.get():
                cmd.append("--skip-rule-scoring")

            self.log(f"执行命令: {' '.join(cmd)}", "INFO")
            self.log("", "INFO")

            # 启动进程（强制UTF-8编码）
            env = os.environ.copy()
            env['PYTHONUNBUFFERED'] = '1'  # 强制无缓冲输出
            env['PYTHONIOENCODING'] = 'utf-8'  # 强制UTF-8编码

            # Windows下设置控制台为UTF-8模式
            creation_flags = 0
            if platform.system() == 'Windows':
                # 设置输出代码页为UTF-8 (CP 65001)
                env['PYTHONLEGACYWINDOWSSTDIO'] = '0'  # 禁用legacy stdio
                creation_flags = subprocess.CREATE_NO_WINDOW

            # 统一使用UTF-8读取输出
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding='utf-8',
                errors='replace',  # 无法解码时用替换字符
                bufsize=1,
                env=env,
                creationflags=creation_flags
            )

            # 实时读取输出
            for line in iter(self.process.stdout.readline, ''):
                if line:
                    # 移除行尾的换行符
                    line_text = line.rstrip('\r\n')
                    self.log(line_text, "INFO")

            # 等待进程结束
            return_code = self.process.wait()

            self.log("", "INFO")
            self.log("=" * 80, "INFO")

            if return_code == 0:
                self.log("分析完成!", "SUCCESS")
                messagebox.showinfo("完成", "分析已成功完成!")
            else:
                self.log(f"分析结束 (返回码: {return_code})", "WARNING")
                messagebox.showwarning(
                    "结束",
                    f"分析已结束 (返回码: {return_code})\n请查看日志了解详情"
                )

        except Exception as e:
            self.log(f"错误: {e}", "ERROR")
            messagebox.showerror("错误", f"分析过程中出错:\n\n{e}")

        finally:
            self.analysis_running = False
            self.root.after(0, self._analysis_finished)

    def stop_analysis(self):
        """停止分析"""
        if self.process and self.analysis_running:
            confirm = messagebox.askyesno(
                "确认停止",
                "确定要停止当前分析吗?"
            )

            if confirm:
                self.log("\n[WARNING] 正在停止分析...", "WARNING")
                self.process.terminate()
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.process.kill()

                self.log("[WARNING] 分析已停止", "WARNING")
                messagebox.showinfo("已停止", "分析已停止")

    def _analysis_finished(self):
        """分析完成后的UI更新"""
        self.progress.stop()
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.status_label.config(text="分析完成")

    def clear_log(self):
        """清空日志"""
        self.log_text.delete(1.0, tk.END)

    def log(self, message, level="INFO"):
        """添加日志"""
        self.log_text.insert(tk.END, message + "\n", level)
        self.log_text.see(tk.END)
        self.status_label.config(text=f"状态: {message[:50]}")

        # 自动滚动
        self.log_text.update()


def main():
    """主函数"""
    root = tk.Tk()
    app = NEWDDGGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
